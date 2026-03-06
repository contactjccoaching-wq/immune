'use strict';

const http = require('http');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Environment validation (mandatory at startup)
// ---------------------------------------------------------------------------
const REQUIRED_ENV = ['WEBHOOK_SECRET', 'PORT'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(JSON.stringify({ level: 'fatal', message: `Missing required env var: ${key}`, ts: new Date().toISOString() }));
    process.exit(1);
  }
}

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const PORT = parseInt(process.env.PORT, 10);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX_WEBHOOK = parseInt(process.env.RATE_LIMIT_MAX_WEBHOOK || '60', 10);
const RATE_LIMIT_MAX_HEALTH = parseInt(process.env.RATE_LIMIT_MAX_HEALTH || '120', 10);
const DEDUP_TTL_MS = parseInt(process.env.DEDUP_TTL_MS || '3600000', 10); // 1h
const DEDUP_MAX_SIZE = parseInt(process.env.DEDUP_MAX_SIZE || '10000', 10);
const CLEANUP_INTERVAL_MS = parseInt(process.env.CLEANUP_INTERVAL_MS || '300000', 10); // 5 min

// ---------------------------------------------------------------------------
// Structured JSON logger
// ---------------------------------------------------------------------------
const log = {
  _write(level, message, meta = {}) {
    const entry = { level, message, ts: new Date().toISOString(), ...meta };
    process.stdout.write(JSON.stringify(entry) + '\n');
  },
  info:  (msg, meta) => log._write('info', msg, meta),
  warn:  (msg, meta) => log._write('warn', msg, meta),
  error: (msg, meta) => log._write('error', msg, meta),
  debug: (msg, meta) => log._write('debug', msg, meta),
};

// ---------------------------------------------------------------------------
// Bounded Map with TTL for idempotency / deduplication
// ---------------------------------------------------------------------------
class BoundedTTLMap {
  constructor({ maxSize, ttlMs, name }) {
    this._map = new Map();   // key -> { value, expiresAt }
    this._maxSize = maxSize;
    this._ttlMs = ttlMs;
    this._name = name;
  }

  has(key) {
    const entry = this._map.get(key);
    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this._map.delete(key);
      return false;
    }
    return true;
  }

  set(key, value) {
    if (this._map.size >= this._maxSize && !this._map.has(key)) {
      // Evict oldest entry
      const firstKey = this._map.keys().next().value;
      this._map.delete(firstKey);
      log.warn('BoundedTTLMap eviction', { name: this._name, evictedKey: firstKey });
    }
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

  cleanup() {
    const now = Date.now();
    let removed = 0;
    for (const [key, entry] of this._map) {
      if (now > entry.expiresAt) {
        this._map.delete(key);
        removed++;
      }
    }
    if (removed > 0) {
      log.debug('BoundedTTLMap cleanup', { name: this._name, removed, remaining: this._map.size });
    }
  }

  get size() { return this._map.size; }
}

// ---------------------------------------------------------------------------
// Rate limiter (per-IP, per-endpoint)
// ---------------------------------------------------------------------------
class RateLimiter {
  constructor({ windowMs, max, name }) {
    this._windowMs = windowMs;
    this._max = max;
    this._name = name;
    this._counters = new Map(); // ip -> { count, resetAt }
  }

  check(ip) {
    const now = Date.now();
    let entry = this._counters.get(ip);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + this._windowMs };
      this._counters.set(ip, entry);
    }
    entry.count++;
    if (entry.count > this._max) {
      log.warn('Rate limit exceeded', { limiter: this._name, ip, count: entry.count, max: this._max });
      return false;
    }
    return true;
  }

  cleanup() {
    const now = Date.now();
    for (const [ip, entry] of this._counters) {
      if (now > entry.resetAt) this._counters.delete(ip);
    }
  }
}

// ---------------------------------------------------------------------------
// Retry logic with exponential backoff (class-based, bounded attempts)
// ---------------------------------------------------------------------------
class RetryExecutor {
  constructor({ maxAttempts = 5, baseDelayMs = 200, maxDelayMs = 30000, jitter = true } = {}) {
    this._maxAttempts = maxAttempts;
    this._baseDelayMs = baseDelayMs;
    this._maxDelayMs = maxDelayMs;
    this._jitter = jitter;
  }

  _delay(attempt) {
    const exp = Math.min(this._baseDelayMs * Math.pow(2, attempt), this._maxDelayMs);
    return this._jitter ? exp * (0.5 + Math.random() * 0.5) : exp;
  }

  async execute(fn, context = {}) {
    let lastError;
    for (let attempt = 0; attempt < this._maxAttempts; attempt++) {
      try {
        const result = await fn(attempt);
        if (attempt > 0) {
          log.info('Retry succeeded', { ...context, attempt });
        }
        return result;
      } catch (err) {
        lastError = err;
        const isLast = attempt === this._maxAttempts - 1;
        log.warn('Handler attempt failed', {
          ...context,
          attempt,
          maxAttempts: this._maxAttempts,
          error: err.message,
          willRetry: !isLast,
        });
        if (!isLast) {
          const delayMs = this._delay(attempt);
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      }
    }
    throw lastError;
  }
}

// ---------------------------------------------------------------------------
// Event handlers registry
// ---------------------------------------------------------------------------
const eventHandlers = new Map();

function registerHandler(eventType, handler) {
  eventHandlers.set(eventType, handler);
}

// Example handlers
registerHandler('payment.completed', async (event) => {
  log.info('Processing payment.completed', { eventId: event.id, amount: event.data?.amount });
  // Simulate occasional failure for demonstration
  if (Math.random() < 0.1) throw new Error('Simulated transient failure');
});

registerHandler('user.created', async (event) => {
  log.info('Processing user.created', { eventId: event.id, userId: event.data?.userId });
});

registerHandler('subscription.cancelled', async (event) => {
  log.info('Processing subscription.cancelled', { eventId: event.id });
});

// ---------------------------------------------------------------------------
// HMAC signature validation
// ---------------------------------------------------------------------------
function validateHmacSignature(rawBody, signatureHeader) {
  if (!signatureHeader) return false;

  // Support "sha256=<hex>" format (GitHub/Stripe style)
  const parts = signatureHeader.split('=');
  const algorithm = parts.length === 2 ? parts[0] : 'sha256';
  const providedSig = parts.length === 2 ? parts[1] : parts[0];

  try {
    const expected = crypto
      .createHmac(algorithm, WEBHOOK_SECRET)
      .update(rawBody)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(providedSig, 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Request body reader
// ---------------------------------------------------------------------------
function readBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new PayloadTooLargeError('Request body exceeds limit'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Custom error types
// ---------------------------------------------------------------------------
class HttpError extends Error {
  constructor(statusCode, message, code) {
    super(message);
    this.name = 'HttpError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

class ValidationError extends HttpError {
  constructor(message) {
    super(400, message, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
  }
}

class AuthError extends HttpError {
  constructor(message = 'Invalid signature') {
    super(401, message, 'AUTH_ERROR');
    this.name = 'AuthError';
  }
}

class RateLimitError extends HttpError {
  constructor() {
    super(429, 'Too many requests', 'RATE_LIMIT_ERROR');
    this.name = 'RateLimitError';
  }
}

class PayloadTooLargeError extends HttpError {
  constructor(message = 'Payload too large') {
    super(413, message, 'PAYLOAD_TOO_LARGE');
    this.name = 'PayloadTooLargeError';
  }
}

class DuplicateEventError extends HttpError {
  constructor(eventId) {
    super(200, `Duplicate event: ${eventId}`, 'DUPLICATE_EVENT');
    this.name = 'DuplicateEventError';
    this.isDuplicate = true;
  }
}

// ---------------------------------------------------------------------------
// Core storage
// ---------------------------------------------------------------------------
const processedEvents = new BoundedTTLMap({
  maxSize: DEDUP_MAX_SIZE,
  ttlMs: DEDUP_TTL_MS,
  name: 'processedEvents',
});

const webhookRateLimiter = new RateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX_WEBHOOK,
  name: 'webhook',
});

const healthRateLimiter = new RateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX_HEALTH,
  name: 'health',
});

const retryExecutor = new RetryExecutor({
  maxAttempts: 5,
  baseDelayMs: 200,
  maxDelayMs: 30000,
  jitter: true,
});

// ---------------------------------------------------------------------------
// Security middleware helpers
// ---------------------------------------------------------------------------
function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
}

function applyCorsHeaders(res, origin) {
  const allowed = ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN;
  res.setHeader('Access-Control-Allow-Origin', allowed);
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Webhook-Signature, X-Hub-Signature-256');
  res.setHeader('Vary', 'Origin');
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

// ---------------------------------------------------------------------------
// JSON response helpers
// ---------------------------------------------------------------------------
function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
  res.end(payload);
}

function sendError(res, err) {
  const statusCode = err.statusCode || 500;
  const body = {
    error: { code: err.code || 'INTERNAL_ERROR', message: err.message },
    requestId: err.requestId || crypto.randomUUID(),
  };
  sendJson(res, statusCode, body);
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------
function validateWebhookPayload(parsed) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ValidationError('Payload must be a JSON object');
  }
  if (!parsed.id || typeof parsed.id !== 'string' || parsed.id.trim() === '') {
    throw new ValidationError('Field "id" must be a non-empty string');
  }
  if (!parsed.type || typeof parsed.type !== 'string' || parsed.type.trim() === '') {
    throw new ValidationError('Field "type" must be a non-empty string');
  }
  if (parsed.id.length > 256) {
    throw new ValidationError('Field "id" must not exceed 256 characters');
  }
  if (parsed.type.length > 128) {
    throw new ValidationError('Field "type" must not exceed 128 characters');
  }
  return {
    id: parsed.id.trim(),
    type: parsed.type.trim(),
    data: parsed.data || {},
    timestamp: parsed.timestamp || new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Webhook handler
// ---------------------------------------------------------------------------
async function handleWebhook(req, res) {
  const requestId = crypto.randomUUID();
  const ip = getClientIp(req);
  const startMs = Date.now();

  // Rate limiting (differentiated: webhook endpoint)
  if (!webhookRateLimiter.check(ip)) {
    throw new RateLimitError();
  }

  // Read body
  let rawBody;
  try {
    rawBody = await readBody(req);
  } catch (err) {
    if (err instanceof PayloadTooLargeError) throw err;
    throw new ValidationError('Failed to read request body');
  }

  // Validate content-type
  const contentType = (req.headers['content-type'] || '').split(';')[0].trim();
  if (contentType !== 'application/json') {
    throw new ValidationError('Content-Type must be application/json');
  }

  // HMAC signature validation
  const sigHeader = req.headers['x-webhook-signature'] || req.headers['x-hub-signature-256'] || '';
  if (!validateHmacSignature(rawBody, sigHeader)) {
    log.warn('Invalid HMAC signature', { requestId, ip, sigHeader: sigHeader.substring(0, 20) });
    throw new AuthError('Invalid HMAC signature');
  }

  // Parse JSON
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw new ValidationError('Invalid JSON payload');
  }

  // Validate payload structure
  const event = validateWebhookPayload(parsed);

  // Idempotency / deduplication
  if (processedEvents.has(event.id)) {
    const existing = processedEvents.get(event.id);
    log.info('Duplicate event received', { requestId, eventId: event.id, eventType: event.type, status: existing?.status });
    sendJson(res, 200, { status: 'duplicate', eventId: event.id, requestId });
    return;
  }

  // Mark as processing (optimistic lock)
  processedEvents.set(event.id, { status: 'processing', requestId, startedAt: new Date().toISOString() });

  log.info('Webhook received', { requestId, eventId: event.id, eventType: event.type, ip });

  // Dispatch to handler with retry
  const handler = eventHandlers.get(event.type);
  if (!handler) {
    log.warn('No handler for event type', { requestId, eventId: event.id, eventType: event.type });
    processedEvents.set(event.id, { status: 'ignored', requestId, reason: 'no_handler' });
    sendJson(res, 200, { status: 'ignored', eventId: event.id, reason: 'no_handler', requestId });
    return;
  }

  try {
    await retryExecutor.execute(
      async (attempt) => handler(event, { requestId, attempt }),
      { requestId, eventId: event.id, eventType: event.type }
    );

    processedEvents.set(event.id, {
      status: 'processed',
      requestId,
      processedAt: new Date().toISOString(),
      durationMs: Date.now() - startMs,
    });

    log.info('Webhook processed successfully', {
      requestId,
      eventId: event.id,
      eventType: event.type,
      durationMs: Date.now() - startMs,
    });

    sendJson(res, 200, { status: 'ok', eventId: event.id, requestId });
  } catch (err) {
    processedEvents.set(event.id, {
      status: 'failed',
      requestId,
      error: err.message,
      failedAt: new Date().toISOString(),
    });

    log.error('Webhook handler failed after all retries', {
      requestId,
      eventId: event.id,
      eventType: event.type,
      error: err.message,
      durationMs: Date.now() - startMs,
    });

    throw new HttpError(500, 'Event processing failed', 'HANDLER_ERROR');
  }
}

// ---------------------------------------------------------------------------
// Health check handler
// ---------------------------------------------------------------------------
function handleHealth(req, res) {
  const ip = getClientIp(req);
  if (!healthRateLimiter.check(ip)) {
    throw new RateLimitError();
  }
  sendJson(res, 200, {
    status: 'ok',
    ts: new Date().toISOString(),
    processedEventsCount: processedEvents.size,
  });
}

// ---------------------------------------------------------------------------
// Global error handler
// ---------------------------------------------------------------------------
function globalErrorHandler(err, res, requestId) {
  err.requestId = requestId;

  if (err instanceof ValidationError) {
    log.warn('Validation error', { requestId, code: err.code, message: err.message });
    sendError(res, err);
  } else if (err instanceof AuthError) {
    log.warn('Auth error', { requestId, code: err.code, message: err.message });
    sendError(res, err);
  } else if (err instanceof RateLimitError) {
    res.setHeader('Retry-After', Math.ceil(RATE_LIMIT_WINDOW_MS / 1000));
    sendError(res, err);
  } else if (err instanceof PayloadTooLargeError) {
    sendError(res, err);
  } else if (err instanceof HttpError) {
    log.error('HTTP error', { requestId, code: err.code, statusCode: err.statusCode, message: err.message });
    sendError(res, err);
  } else {
    log.error('Unhandled error', { requestId, error: err.message, stack: err.stack });
    sendError(res, new HttpError(500, 'Internal server error', 'INTERNAL_ERROR'));
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
const activeConnections = new Set();

const server = http.createServer(async (req, res) => {
  const requestId = crypto.randomUUID();

  // Track active connections for graceful shutdown
  activeConnections.add(res);
  res.on('finish', () => activeConnections.delete(res));
  res.on('close', () => activeConnections.delete(res));

  // Apply security & CORS headers to all responses
  applySecurityHeaders(res);
  applyCorsHeaders(res, req.headers.origin);

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/webhook' && req.method === 'POST') {
      await handleWebhook(req, res);
    } else if (url.pathname === '/health' && req.method === 'GET') {
      handleHealth(req, res);
    } else {
      sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Route not found' }, requestId });
    }
  } catch (err) {
    if (!res.headersSent) {
      globalErrorHandler(err, res, requestId);
    } else {
      log.error('Error after headers sent', { requestId, error: err.message });
    }
  }
});

// ---------------------------------------------------------------------------
// Periodic cleanup
// ---------------------------------------------------------------------------
const cleanupInterval = setInterval(() => {
  processedEvents.cleanup();
  webhookRateLimiter.cleanup();
  healthRateLimiter.cleanup();
}, CLEANUP_INTERVAL_MS);

cleanupInterval.unref();

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------
let isShuttingDown = false;

async function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  log.info('Graceful shutdown initiated', { signal, activeConnections: activeConnections.size });

  clearInterval(cleanupInterval);

  // Stop accepting new connections
  server.close(() => {
    log.info('Server closed — no new connections accepted');
  });

  // Give active connections time to complete
  const shutdownTimeout = parseInt(process.env.SHUTDOWN_TIMEOUT_MS || '10000', 10);
  const deadline = Date.now() + shutdownTimeout;

  while (activeConnections.size > 0 && Date.now() < deadline) {
    log.debug('Waiting for active connections', { count: activeConnections.size });
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  if (activeConnections.size > 0) {
    log.warn('Forcibly closing remaining connections', { count: activeConnections.size });
    for (const res of activeConnections) {
      try { res.destroy?.(); } catch {}
    }
  }

  log.info('Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  log.error('Uncaught exception', { error: err.message, stack: err.stack });
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  log.error('Unhandled rejection', { reason: String(reason) });
  gracefulShutdown('unhandledRejection');
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
server.listen(PORT, () => {
  log.info('Webhook receiver started', {
    port: PORT,
    allowedOrigin: ALLOWED_ORIGIN,
    rateLimitWebhook: RATE_LIMIT_MAX_WEBHOOK,
    rateLimitHealth: RATE_LIMIT_MAX_HEALTH,
    dedupTtlMs: DEDUP_TTL_MS,
    dedupMaxSize: DEDUP_MAX_SIZE,
  });
});
