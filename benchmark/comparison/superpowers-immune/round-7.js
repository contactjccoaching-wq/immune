'use strict';

/**
 * Webhook Receiver — Production-ready Node.js (no Express, stdlib only)
 *
 * Features:
 *  - HMAC-SHA256 signature validation with timing-safe comparison
 *  - Idempotent event processing (deduplication by event ID, atomic check-and-set)
 *  - Retry logic with exponential backoff + jitter (non-retryable errors skip retries)
 *  - Per-type event routing to registered handlers
 *  - Dead-letter queue for permanently failed events
 *  - Structured JSON request logging with requestId tracing
 *  - Health check endpoint (/health GET)
 *  - Per-IP sliding-window rate limiting with automatic cleanup
 *  - Graceful shutdown with connection draining + force-exit timeout
 *  - Handler timeout to prevent stuck handlers blocking retry loops
 *  - HMAC algorithm locked to sha256 (no attacker-controlled algorithm selection)
 *  - X-Forwarded-For only trusted when TRUST_PROXY env is set
 *  - Body size limit (slow-loris / unbounded buffer protection)
 *  - Prototype pollution prevention on parsed payloads
 *  - Security headers on every response
 *  - Startup env-var validation (fail fast)
 *
 * Usage:
 *   WEBHOOK_SECRET=<secret> PORT=3000 node round-7.js
 *
 * module.exports exposes { server, app, registerHandler, deadLetterQueue }
 * for unit tests.
 */

const http = require('http');
const crypto = require('crypto');

// ─── 1. Startup env validation ────────────────────────────────────────────────

const REQUIRED_ENV = ['WEBHOOK_SECRET', 'PORT'];
const missingEnv = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missingEnv.length) {
  process.stderr.write(
    JSON.stringify({
      level: 'fatal',
      ts: new Date().toISOString(),
      msg: 'Missing required environment variables',
      missing: missingEnv,
    }) + '\n'
  );
  process.exit(1);
}

// ─── 2. Configuration (env-based, no hardcoded secrets or unsafe fallbacks) ───

/** @type {string} — never exposed outside this module */
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const CONFIG = Object.freeze({
  port: parseInt(process.env.PORT, 10),
  /**
   * CORS: no wildcard default for server-to-server webhooks.
   * Leave unset to disable CORS header entirely.
   */
  corsOrigin: process.env.CORS_ORIGIN || null,
  /**
   * Set TRUST_PROXY=1 only when behind a known trusted reverse-proxy.
   * Otherwise X-Forwarded-For is ignored (rate-limit bypass prevention).
   */
  trustProxy: process.env.TRUST_PROXY === '1',
  maxBodyBytes: parseInt(process.env.MAX_BODY_BYTES || String(512 * 1024), 10), // 512 KB
  /** How long a processed event ID is retained for deduplication */
  dedupTtlMs: parseInt(process.env.DEDUP_TTL_MS || String(24 * 60 * 60 * 1000), 10),
  dedupMaxSize: parseInt(process.env.DEDUP_MAX_SIZE || '100000', 10),
  /** Rate limiting */
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  rateLimitMaxWebhook: parseInt(process.env.RATE_LIMIT_MAX_WEBHOOK || '120', 10),
  rateLimitMaxHealth: parseInt(process.env.RATE_LIMIT_MAX_HEALTH || '300', 10),
  rateLimitStoreMax: parseInt(process.env.RATE_LIMIT_STORE_MAX || '50000', 10),
  /** Retry */
  retryMaxAttempts: parseInt(process.env.RETRY_MAX_ATTEMPTS || '5', 10),
  retryBaseDelayMs: parseInt(process.env.RETRY_BASE_DELAY_MS || '500', 10),
  retryMaxDelayMs: parseInt(process.env.RETRY_MAX_DELAY_MS || '30000', 10),
  /** Handler timeout per single attempt */
  handlerTimeoutMs: parseInt(process.env.HANDLER_TIMEOUT_MS || '10000', 10),
  /** Dead-letter queue max size (oldest evicted when full) */
  dlqMaxSize: parseInt(process.env.DLQ_MAX_SIZE || '1000', 10),
  /** Background cleanup interval */
  cleanupIntervalMs: parseInt(process.env.CLEANUP_INTERVAL_MS || String(5 * 60 * 1000), 10),
  /** Graceful shutdown timeout */
  shutdownTimeoutMs: parseInt(process.env.SHUTDOWN_TIMEOUT_MS || '10000', 10),
  /** Slow-loris: max time to receive the full request body */
  bodyReadTimeoutMs: parseInt(process.env.BODY_READ_TIMEOUT_MS || '5000', 10),
});

// ─── 3. Structured JSON logger ────────────────────────────────────────────────

const log = (() => {
  function write(level, msg, meta) {
    const entry = Object.assign({ level, ts: new Date().toISOString(), msg }, meta);
    const stream = level === 'error' || level === 'fatal' ? process.stderr : process.stdout;
    stream.write(JSON.stringify(entry) + '\n');
  }
  return Object.freeze({
    info:  (msg, meta = {}) => write('info',  msg, meta),
    warn:  (msg, meta = {}) => write('warn',  msg, meta),
    error: (msg, meta = {}) => write('error', msg, meta),
    fatal: (msg, meta = {}) => write('fatal', msg, meta),
    debug: (msg, meta = {}) => write('debug', msg, meta),
  });
})();

// ─── 4. Custom error types ────────────────────────────────────────────────────

class AppError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    /** When false the RetryExecutor will not re-attempt */
    this.retryable = retryable;
  }
}

const Errors = Object.freeze({
  badRequest:       (msg)  => new AppError(400, 'BAD_REQUEST',       msg,            false),
  invalidSignature: ()     => new AppError(401, 'INVALID_SIGNATURE', 'Invalid HMAC signature', false),
  rateLimited:      ()     => new AppError(429, 'RATE_LIMITED',      'Too many requests', false),
  payloadTooLarge:  ()     => new AppError(413, 'PAYLOAD_TOO_LARGE', 'Request body exceeds size limit', false),
  handlerFailed:    ()     => new AppError(500, 'HANDLER_ERROR',     'Event processing failed', false),
  notFound:         ()     => new AppError(404, 'NOT_FOUND',         'Route not found', false),
});

// ─── 5. BoundedTTLMap — O(1) get/set, bounded size, TTL-based expiry ──────────

class BoundedTTLMap {
  /**
   * @param {object} opts
   * @param {number} opts.maxSize
   * @param {number} opts.ttlMs
   * @param {string} opts.name   — for log context
   */
  constructor({ maxSize, ttlMs, name }) {
    /** @type {Map<string, {value: any, expiresAt: number}>} */
    this._map = new Map();
    this._maxSize = maxSize;
    this._ttlMs = ttlMs;
    this._name = name;
  }

  /**
   * Atomic check-and-set: returns the existing value if present (not expired),
   * otherwise sets the new value and returns undefined.
   * Eliminates the TOCTOU race between has() and set() on duplicate events.
   *
   * @param {string} key
   * @param {any} value
   * @returns {any|undefined}  — existing value if already present, else undefined
   */
  checkAndSet(key, value) {
    const existing = this._map.get(key);
    if (existing) {
      if (Date.now() <= existing.expiresAt) {
        return existing.value; // already exists — return current value
      }
      // expired — fall through to overwrite
    }
    this._evictIfFull(key);
    this._map.set(key, { value, expiresAt: Date.now() + this._ttlMs });
    return undefined; // was not present (or expired) — new entry created
  }

  set(key, value) {
    this._evictIfFull(key);
    this._map.set(key, { value, expiresAt: Date.now() + this._ttlMs });
  }

  get(key) {
    const entry = this._map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this._map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  /** Remove all expired entries */
  prune() {
    const now = Date.now();
    let removed = 0;
    for (const [k, v] of this._map) {
      if (now > v.expiresAt) {
        this._map.delete(k);
        removed++;
      }
    }
    if (removed > 0) {
      log.debug('BoundedTTLMap pruned', { name: this._name, removed, remaining: this._map.size });
    }
    return removed;
  }

  get size() { return this._map.size; }

  _evictIfFull(keyBeingSet) {
    if (this._map.size >= this._maxSize && !this._map.has(keyBeingSet)) {
      const oldestKey = this._map.keys().next().value;
      this._map.delete(oldestKey);
      log.warn('BoundedTTLMap evicted oldest entry', { name: this._name, evictedKey: oldestKey });
    }
  }
}

// ─── 6. Sliding-window rate limiter (per-IP, per-endpoint) ────────────────────

class RateLimiter {
  /**
   * @param {object} opts
   * @param {number} opts.windowMs
   * @param {number} opts.max
   * @param {number} opts.storeMax  — max tracked IPs (prevents unbounded Map growth)
   * @param {string} opts.name
   */
  constructor({ windowMs, max, storeMax, name }) {
    /** @type {Map<string, {count: number, resetAt: number}>} */
    this._store = new Map();
    this._windowMs = windowMs;
    this._max = max;
    this._storeMax = storeMax;
    this._name = name;
  }

  /** Returns true if the request is within quota */
  allow(ip) {
    const now = Date.now();
    let entry = this._store.get(ip);

    if (!entry || now > entry.resetAt) {
      // Evict oldest if store is full before inserting new IP
      if (this._store.size >= this._storeMax && !this._store.has(ip)) {
        const oldest = this._store.keys().next().value;
        this._store.delete(oldest);
      }
      entry = { count: 1, resetAt: now + this._windowMs };
      this._store.set(ip, entry);
      return true;
    }

    entry.count++;
    if (entry.count > this._max) {
      log.warn('Rate limit exceeded', { limiter: this._name, ip, count: entry.count, max: this._max });
      return false;
    }
    return true;
  }

  /** Remove expired windows — called by background cleanup */
  prune() {
    const now = Date.now();
    for (const [ip, entry] of this._store) {
      if (now > entry.resetAt) this._store.delete(ip);
    }
  }

  get retryAfterSecs() { return Math.ceil(this._windowMs / 1000); }
}

// ─── 7. Dead-letter queue — bounded, thread-safe append ───────────────────────

class DeadLetterQueue {
  constructor(maxSize) {
    /** @type {Array<DLQEntry>} */
    this._entries = [];
    this._maxSize = maxSize;
  }

  /**
   * @typedef {object} DLQEntry
   * @property {string} eventId
   * @property {string} eventType
   * @property {any}    payload
   * @property {string} error
   * @property {string} enqueuedAt  — ISO timestamp
   * @property {number} attempts
   * @property {string} requestId
   */

  /**
   * @param {DLQEntry} entry
   */
  push(entry) {
    if (this._entries.length >= this._maxSize) {
      const evicted = this._entries.shift(); // evict oldest
      log.warn('DLQ evicted oldest entry (at capacity)', {
        evictedEventId: evicted.eventId,
        dlqSize: this._maxSize,
      });
    }
    this._entries.push(Object.assign({ enqueuedAt: new Date().toISOString() }, entry));
    log.error('Event added to dead-letter queue', {
      eventId: entry.eventId,
      eventType: entry.eventType,
      error: entry.error,
      attempts: entry.attempts,
      requestId: entry.requestId,
    });
  }

  /** @returns {ReadonlyArray<DLQEntry>} */
  get entries() { return this._entries; }

  get size() { return this._entries.length; }

  /** Remove entries by eventId (e.g. after manual reprocessing) */
  remove(eventId) {
    const before = this._entries.length;
    this._entries = this._entries.filter((e) => e.eventId !== eventId);
    return before - this._entries.length;
  }
}

// ─── 8. Retry executor with exponential backoff + jitter ─────────────────────

class RetryExecutor {
  /**
   * @param {object} opts
   * @param {number} opts.maxAttempts
   * @param {number} opts.baseDelayMs
   * @param {number} opts.maxDelayMs
   * @param {number} opts.handlerTimeoutMs  — per-attempt timeout
   */
  constructor({ maxAttempts, baseDelayMs, maxDelayMs, handlerTimeoutMs }) {
    this._maxAttempts = maxAttempts;
    this._baseDelayMs = baseDelayMs;
    this._maxDelayMs = maxDelayMs;
    this._handlerTimeoutMs = handlerTimeoutMs;
  }

  /**
   * Execute fn with automatic retries.
   * @param {function(number): Promise<any>} fn  — called with attempt number (1-based)
   * @param {object} context  — logged on each retry
   * @returns {Promise<any>}
   * @throws the last error after all attempts are exhausted
   */
  async execute(fn, context = {}) {
    let lastError;
    for (let attempt = 1; attempt <= this._maxAttempts; attempt++) {
      try {
        const result = await this._withTimeout(fn(attempt), this._handlerTimeoutMs);
        if (attempt > 1) {
          log.info('Handler succeeded after retry', { ...context, attempt });
        }
        return result;
      } catch (err) {
        lastError = err;

        // Non-retryable errors (validation, auth) skip all remaining attempts
        if (err.retryable === false) {
          log.warn('Non-retryable error — skipping retries', { ...context, attempt, error: err.message });
          throw err;
        }

        const isLast = attempt === this._maxAttempts;
        log.warn('Handler attempt failed', {
          ...context,
          attempt,
          maxAttempts: this._maxAttempts,
          error: err.message,
          willRetry: !isLast,
        });

        if (!isLast) {
          await this._sleep(this._backoffDelay(attempt));
        }
      }
    }
    throw lastError;
  }

  /** Wraps a promise with a timeout that rejects after ms */
  _withTimeout(promise, ms) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Handler timed out after ${ms}ms`));
      }, ms);
      Promise.resolve(promise).then(
        (val) => { clearTimeout(timer); resolve(val); },
        (err) => { clearTimeout(timer); reject(err); }
      );
    });
  }

  /** Full jitter backoff: uniform [0, cappedExponential] */
  _backoffDelay(attempt) {
    const cap = Math.min(this._baseDelayMs * Math.pow(2, attempt - 1), this._maxDelayMs);
    return Math.random() * cap;
  }

  _sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// ─── 9. HMAC signature validation ────────────────────────────────────────────

/**
 * Validates a webhook HMAC-SHA256 signature.
 *
 * Algorithm is LOCKED to sha256 regardless of what the signature header says.
 * The header may carry the algorithm prefix ("sha256=<hex>") for GitHub/Stripe
 * compatibility, but we always compute with sha256 — never trusting user input
 * to select a weaker algorithm.
 *
 * @param {Buffer} rawBody
 * @param {string} signatureHeader  — "sha256=<hex>" or raw "<hex>"
 * @returns {boolean}
 */
function validateHmacSignature(rawBody, signatureHeader) {
  if (!signatureHeader || typeof signatureHeader !== 'string') return false;

  // Strip optional "sha256=" prefix (GitHub/Stripe style). Algorithm is ALWAYS sha256.
  const hexSig = signatureHeader.startsWith('sha256=')
    ? signatureHeader.slice(7)
    : signatureHeader;

  // Guard against non-hex / length-mismatched values before timingSafeEqual
  if (!/^[0-9a-f]{64}$/i.test(hexSig)) return false;

  try {
    const expected = crypto
      .createHmac('sha256', WEBHOOK_SECRET)
      .update(rawBody)
      .digest('hex');

    // Both buffers are exactly 64 hex chars — safe to compare without length check
    return crypto.timingSafeEqual(
      Buffer.from(hexSig.toLowerCase(), 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch {
    return false;
  }
}

// ─── 10. Event handler registry ───────────────────────────────────────────────

/**
 * Event type → handler function(s).
 * Supports multiple handlers per type (fan-out).
 * @type {Map<string, Array<function>>}
 */
const eventHandlerRegistry = new Map();

/**
 * Register a handler for a given event type.
 * Multiple handlers for the same type are all executed (fan-out).
 *
 * @param {string} eventType
 * @param {function(object, {requestId: string, attempt: number}): Promise<void>} handler
 */
function registerHandler(eventType, handler) {
  if (typeof eventType !== 'string' || !eventType) throw new TypeError('eventType must be a non-empty string');
  if (typeof handler !== 'function') throw new TypeError('handler must be a function');
  const existing = eventHandlerRegistry.get(eventType) || [];
  existing.push(handler);
  eventHandlerRegistry.set(eventType, existing);
}

// Built-in example handlers — replace with real business logic
registerHandler('payment.completed', async (event, { requestId, attempt }) => {
  log.info('Handler: payment.completed', { eventId: event.id, attempt, requestId });
  // Simulate occasional transient failure for testing retry logic
  if (attempt === 1 && Math.random() < 0.1) throw new Error('Simulated transient payment service timeout');
});

registerHandler('user.created', async (event, { requestId, attempt }) => {
  log.info('Handler: user.created', { eventId: event.id, attempt, requestId });
});

registerHandler('subscription.cancelled', async (event, { requestId, attempt }) => {
  log.info('Handler: subscription.cancelled', { eventId: event.id, attempt, requestId });
});

// ─── 11. Shared singletons ────────────────────────────────────────────────────

const processedEvents = new BoundedTTLMap({
  maxSize: CONFIG.dedupMaxSize,
  ttlMs:   CONFIG.dedupTtlMs,
  name:    'processedEvents',
});

const webhookRateLimiter = new RateLimiter({
  windowMs:  CONFIG.rateLimitWindowMs,
  max:       CONFIG.rateLimitMaxWebhook,
  storeMax:  CONFIG.rateLimitStoreMax,
  name:      'webhook',
});

const healthRateLimiter = new RateLimiter({
  windowMs:  CONFIG.rateLimitWindowMs,
  max:       CONFIG.rateLimitMaxHealth,
  storeMax:  CONFIG.rateLimitStoreMax,
  name:      'health',
});

const retryExecutor = new RetryExecutor({
  maxAttempts:      CONFIG.retryMaxAttempts,
  baseDelayMs:      CONFIG.retryBaseDelayMs,
  maxDelayMs:       CONFIG.retryMaxDelayMs,
  handlerTimeoutMs: CONFIG.handlerTimeoutMs,
});

const deadLetterQueue = new DeadLetterQueue(CONFIG.dlqMaxSize);

// ─── 12. Request body reader — bounded + slow-loris timeout ──────────────────

/**
 * Reads the full request body, enforcing a max size limit and a read timeout
 * to prevent slow-loris style attacks.
 *
 * @param {http.IncomingMessage} req
 * @returns {Promise<Buffer>}
 */
function readBodyBounded(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    let settled = false;

    // Body read timeout (slow-loris protection)
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      req.destroy();
      reject(Errors.badRequest('Request body read timed out'));
    }, CONFIG.bodyReadTimeoutMs);

    req.on('data', (chunk) => {
      if (settled) return;
      totalBytes += chunk.length;
      if (totalBytes > CONFIG.maxBodyBytes) {
        settled = true;
        clearTimeout(timer);
        req.destroy();
        reject(Errors.payloadTooLarge());
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });

    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ─── 13. Payload validation ───────────────────────────────────────────────────

/**
 * Validates a parsed webhook payload.
 * Defense-in-depth: parse → structure → type → length → format → prototype.
 *
 * @param {unknown} parsed
 * @returns {{ id: string, type: string, data: object, timestamp: string }}
 */
function validateWebhookPayload(parsed) {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw Errors.badRequest('Payload must be a JSON object');
  }

  // Prototype pollution guard — reject any keys that would shadow Object.prototype
  const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
  for (const key of Object.keys(parsed)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw Errors.badRequest('Payload contains forbidden keys');
    }
  }

  if (typeof parsed.id !== 'string' || parsed.id.trim() === '') {
    throw Errors.badRequest('Field "id" must be a non-empty string');
  }
  if (parsed.id.length > 256) {
    throw Errors.badRequest('Field "id" must not exceed 256 characters');
  }
  if (typeof parsed.type !== 'string' || parsed.type.trim() === '') {
    throw Errors.badRequest('Field "type" must be a non-empty string');
  }
  if (parsed.type.length > 128) {
    throw Errors.badRequest('Field "type" must not exceed 128 characters');
  }

  // Sanitize: only include known safe fields in the event object
  return {
    id:        parsed.id.trim(),
    type:      parsed.type.trim(),
    data:      (parsed.data && typeof parsed.data === 'object' && !Array.isArray(parsed.data))
                 ? parsed.data
                 : {},
    timestamp: typeof parsed.timestamp === 'string' ? parsed.timestamp : new Date().toISOString(),
  };
}

// ─── 14. Client IP extraction ─────────────────────────────────────────────────

/**
 * Returns the best-available client IP.
 * X-Forwarded-For is ONLY trusted when CONFIG.trustProxy is true,
 * preventing rate-limit bypass via header spoofing.
 *
 * @param {http.IncomingMessage} req
 * @returns {string}
 */
function getClientIp(req) {
  if (CONFIG.trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

// ─── 15. Security + CORS headers ─────────────────────────────────────────────

/**
 * Applies a hardened set of security headers to every response.
 * @param {http.ServerResponse} res
 */
function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options',      'nosniff');
  res.setHeader('X-Frame-Options',             'DENY');
  res.setHeader('X-XSS-Protection',            '0');           // CSP supersedes this
  res.setHeader('Strict-Transport-Security',   'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy',     "default-src 'none'");
  res.setHeader('Referrer-Policy',             'no-referrer');
  res.setHeader('Cache-Control',               'no-store');
  res.setHeader('Permissions-Policy',          'camera=(), microphone=(), geolocation=()');
}

/**
 * Applies CORS headers only when CORS_ORIGIN is explicitly configured.
 * No wildcard default — this is a server-to-server webhook receiver.
 * @param {http.ServerResponse} res
 */
function applyCorsHeaders(res) {
  if (!CONFIG.corsOrigin) return;
  res.setHeader('Access-Control-Allow-Origin',  CONFIG.corsOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Webhook-Signature, X-Hub-Signature-256');
  res.setHeader('Vary', 'Origin');
}

// ─── 16. JSON response helpers ────────────────────────────────────────────────

/**
 * @param {http.ServerResponse} res
 * @param {number} statusCode
 * @param {object} body
 */
function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  // Use Buffer.byteLength for accurate Content-Length (handles multi-byte chars)
  res.writeHead(statusCode, {
    'Content-Type':   'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload, 'utf8'),
  });
  res.end(payload);
}

/**
 * Sends a standardised error response.
 * Never leaks stack traces or internal error messages to clients.
 * @param {http.ServerResponse} res
 * @param {AppError|Error} err
 * @param {string} requestId
 */
function sendErrorResponse(res, err, requestId) {
  const statusCode  = err.statusCode || 500;
  const code        = err.code        || 'INTERNAL_ERROR';
  const message     = (err instanceof AppError) ? err.message : 'Internal server error';

  if (statusCode === 429) {
    res.setHeader('Retry-After', String(webhookRateLimiter.retryAfterSecs));
  }

  sendJson(res, statusCode, {
    error:     { code, message },
    requestId,
  });
}

// ─── 17. Core event processor ─────────────────────────────────────────────────

/**
 * Processes a validated webhook event:
 *  - atomic idempotency check
 *  - handler routing
 *  - retry with backoff
 *  - dead-letter queue on permanent failure
 *
 * @param {object} event  — validated event object
 * @param {string} requestId
 * @returns {Promise<{status: string, eventId: string, requestId: string}>}
 */
async function processEvent(event, requestId) {
  const { id: eventId, type: eventType } = event;

  // Atomic check-and-set: if the event is already processing/processed, return existing status.
  // This eliminates the TOCTOU race on concurrent duplicate deliveries.
  const existingStatus = processedEvents.checkAndSet(eventId, { status: 'processing', requestId });
  if (existingStatus !== undefined) {
    log.info('Duplicate event suppressed', { eventId, eventType, requestId, existingStatus: existingStatus.status });
    return { status: 'duplicate', eventId, requestId };
  }

  // Resolve handlers
  const handlers = eventHandlerRegistry.get(eventType);
  if (!handlers || handlers.length === 0) {
    processedEvents.set(eventId, { status: 'no_handler', requestId });
    log.warn('No handler registered for event type', { eventId, eventType, requestId });
    return { status: 'no_handler', eventId, requestId };
  }

  log.info('Dispatching event', { eventId, eventType, requestId, handlerCount: handlers.length });

  const handlerResults = [];
  let allSucceeded = true;

  for (const handler of handlers) {
    const handlerName = handler.name || 'anonymous';
    try {
      await retryExecutor.execute(
        (attempt) => handler(event, { requestId, attempt }),
        { eventId, eventType, requestId, handlerName }
      );
      handlerResults.push({ handler: handlerName, status: 'ok' });
    } catch (err) {
      allSucceeded = false;
      handlerResults.push({ handler: handlerName, status: 'failed', error: err.message });
    }
  }

  if (!allSucceeded) {
    // Mark event as failed in idempotency store — allows future retry if desired
    processedEvents.set(eventId, { status: 'failed', requestId, results: handlerResults });

    // Push permanently failed events to DLQ for manual inspection / replay
    deadLetterQueue.push({
      eventId,
      eventType,
      payload: event,
      error: handlerResults.find((r) => r.status === 'failed')?.error || 'unknown',
      attempts: CONFIG.retryMaxAttempts,
      requestId,
    });

    log.error('Event processing failed — added to DLQ', { eventId, eventType, requestId, results: handlerResults });
    throw Errors.handlerFailed();
  }

  processedEvents.set(eventId, { status: 'processed', requestId, results: handlerResults });
  log.info('Event processed successfully', { eventId, eventType, requestId });
  return { status: 'ok', eventId, requestId };
}

// ─── 18. Route handlers ───────────────────────────────────────────────────────

/**
 * POST /webhook
 * Full pipeline: rate-limit → body read → content-type → signature → parse → validate → process
 */
async function handleWebhook(req, res, requestId) {
  const ip = getClientIp(req);

  // Rate limiting before any body parsing
  if (!webhookRateLimiter.allow(ip)) {
    throw Errors.rateLimited();
  }

  // Content-Type validation before reading body
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  if (contentType !== 'application/json') {
    throw Errors.badRequest('Content-Type must be application/json');
  }

  // Read body (bounded + timeout)
  const rawBody = await readBodyBounded(req);

  // HMAC signature validation — operates on raw bytes before parsing
  const sigHeader = req.headers['x-webhook-signature']
    || req.headers['x-hub-signature-256']
    || '';
  if (!validateHmacSignature(rawBody, sigHeader)) {
    log.warn('HMAC validation failed', { requestId, ip });
    throw Errors.invalidSignature();
  }

  // Parse JSON
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw Errors.badRequest('Malformed JSON body');
  }

  // Validate payload structure and content
  const event = validateWebhookPayload(parsed);

  log.info('Webhook received', { requestId, eventId: event.id, eventType: event.type, ip });

  const result = await processEvent(event, requestId);

  sendJson(res, 200, result);
}

/**
 * GET /health
 */
function handleHealth(req, res, requestId) {
  const ip = getClientIp(req);
  if (!healthRateLimiter.allow(ip)) {
    throw Errors.rateLimited();
  }

  sendJson(res, 200, {
    status:              'ok',
    ts:                  new Date().toISOString(),
    uptime:              process.uptime(),
    processedEvents:     processedEvents.size,
    deadLetterQueue:     deadLetterQueue.size,
    registeredHandlers:  eventHandlerRegistry.size,
  });
}

/**
 * GET /dlq
 * Returns dead-letter queue contents for manual inspection.
 * In production, protect this behind auth middleware.
 */
function handleDlq(req, res, requestId) {
  sendJson(res, 200, {
    count:   deadLetterQueue.size,
    entries: deadLetterQueue.entries,
  });
}

// ─── 19. Main request dispatcher (security-first middleware ordering) ─────────

/**
 * Security middleware ordering:
 * security headers → CORS → method check → route dispatch → error handler
 */
async function dispatch(req, res) {
  const requestId = crypto.randomUUID();

  // Apply security + CORS headers before anything else
  applySecurityHeaders(res);
  applyCorsHeaders(res);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  let pathname;
  try {
    // Use URL constructor for safe path parsing (no path-traversal via malformed URLs)
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    pathname = url.pathname;
  } catch {
    if (!res.headersSent) sendJson(res, 400, { error: { code: 'BAD_REQUEST', message: 'Invalid URL' }, requestId });
    return;
  }

  try {
    if (pathname === '/webhook' && req.method === 'POST') {
      await handleWebhook(req, res, requestId);
    } else if (pathname === '/health' && req.method === 'GET') {
      handleHealth(req, res, requestId);
    } else if (pathname === '/dlq' && req.method === 'GET') {
      handleDlq(req, res, requestId);
    } else {
      throw Errors.notFound();
    }
  } catch (err) {
    if (res.headersSent) {
      log.error('Error after headers sent', { requestId, error: err.message });
      return;
    }

    if (err instanceof AppError) {
      log.warn('Request error', { requestId, code: err.code, status: err.statusCode, msg: err.message });
    } else {
      log.error('Unhandled exception in request handler', { requestId, error: err.message, stack: err.stack });
    }

    sendErrorResponse(res, err, requestId);
  }
}

// ─── 20. HTTP server + connection tracking ────────────────────────────────────

/** Tracks in-flight responses for graceful shutdown connection draining */
const activeConnections = new Set();

const server = http.createServer(async (req, res) => {
  activeConnections.add(res);
  res.on('finish', () => activeConnections.delete(res));
  res.on('close',  () => activeConnections.delete(res));

  await dispatch(req, res);
});

// Slow-loris: enforce a hard limit on the time between headers and first byte
server.headersTimeout  = 10_000;
server.requestTimeout  = CONFIG.bodyReadTimeoutMs + 5000; // body timeout + processing margin
server.keepAliveTimeout = 65_000;

// ─── 21. Background cleanup (TTL expiry + rate-limiter window eviction) ───────

const cleanupInterval = setInterval(() => {
  processedEvents.prune();
  webhookRateLimiter.prune();
  healthRateLimiter.prune();
}, CONFIG.cleanupIntervalMs);

// .unref() ensures the interval does not prevent the process from exiting naturally
cleanupInterval.unref();

// ─── 22. Graceful shutdown ────────────────────────────────────────────────────

let isShuttingDown = false;

async function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  log.info('Graceful shutdown initiated', { signal, activeConnections: activeConnections.size });

  // Cancel background cleanup first (prevents race on shutdown)
  clearInterval(cleanupInterval);

  // Stop accepting new connections
  server.close(() => {
    log.info('Server closed — no new connections accepted');
  });

  // Force-exit timer runs in background so it doesn't block the event loop
  const forceTimer = setTimeout(() => {
    log.warn('Forcing shutdown — destroying remaining connections', { count: activeConnections.size });
    for (const res of activeConnections) {
      try { res.destroy(); } catch { /* ignore */ }
    }
    process.exit(1);
  }, CONFIG.shutdownTimeoutMs);
  forceTimer.unref(); // won't prevent exit if everything else finishes

  // Drain active connections
  const deadline = Date.now() + CONFIG.shutdownTimeoutMs;
  while (activeConnections.size > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  if (activeConnections.size === 0) {
    log.info('All connections drained — shutdown complete');
    clearTimeout(forceTimer);
    process.exit(0);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  log.fatal('Uncaught exception', { error: err.message, stack: err.stack });
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  log.error('Unhandled promise rejection', {
    reason: reason instanceof Error ? reason.message : String(reason),
    stack:  reason instanceof Error ? reason.stack   : undefined,
  });
  // Do not exit on unhandledRejection — log and continue (let graceful shutdown handle it)
});

// ─── 23. Start server ─────────────────────────────────────────────────────────

server.listen(CONFIG.port, () => {
  log.info('Webhook receiver started', {
    port:            CONFIG.port,
    trustProxy:      CONFIG.trustProxy,
    corsOrigin:      CONFIG.corsOrigin,
    maxBodyBytes:    CONFIG.maxBodyBytes,
    dedupTtlMs:      CONFIG.dedupTtlMs,
    retryMaxAttempts: CONFIG.retryMaxAttempts,
    handlerTimeoutMs: CONFIG.handlerTimeoutMs,
    dlqMaxSize:      CONFIG.dlqMaxSize,
  });
});

// ─── 24. Exports for unit testing ────────────────────────────────────────────

module.exports = {
  server,
  registerHandler,
  deadLetterQueue,
  processedEvents,
  // Expose internals for white-box testing
  _internals: {
    validateHmacSignature,
    validateWebhookPayload,
    BoundedTTLMap,
    RetryExecutor,
    DeadLetterQueue,
    RateLimiter,
    getClientIp,
  },
};
