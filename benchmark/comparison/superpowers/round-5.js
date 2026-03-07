'use strict';

/**
 * Rate-Limited API Proxy
 *
 * Features:
 * - Rate limiting (sliding window, per client IP)
 * - In-memory response cache with TTL
 * - API key rotation on 401
 * - Circuit breaker pattern
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

// ─── Configuration ────────────────────────────────────────────────────────────

const CONFIG = {
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
  rateLimit: {
    windowMs: 60_000,       // 1 minute sliding window
    maxRequests: 100,       // max requests per window per client
  },
  cache: {
    ttlMs: 30_000,          // 30 seconds default TTL
    maxEntries: 500,        // max cache entries (LRU eviction)
  },
  circuitBreaker: {
    failureThreshold: 5,    // open after N consecutive failures
    successThreshold: 2,    // close after N consecutive successes in half-open
    openDurationMs: 15_000, // stay open for 15s before half-open
  },
  target: {
    baseUrl: process.env.TARGET_API_URL || 'https://api.example.com',
    timeoutMs: 10_000,
  },
  apiKeys: (process.env.API_KEYS || 'key-a,key-b,key-c').split(',').filter(Boolean),
};

// ─── Validation ───────────────────────────────────────────────────────────────

function validateConfig(config) {
  if (!config.apiKeys.length) {
    throw new Error('At least one API key must be configured via API_KEYS env var');
  }
  if (!config.target.baseUrl) {
    throw new Error('TARGET_API_URL must be configured');
  }
  try {
    new URL(config.target.baseUrl);
  } catch {
    throw new Error(`Invalid TARGET_API_URL: ${config.target.baseUrl}`);
  }
}

// ─── Rate Limiter (sliding window per client) ─────────────────────────────────

class RateLimiter {
  constructor({ windowMs, maxRequests }) {
    this._windowMs = windowMs;
    this._maxRequests = maxRequests;
    // Map<clientId, number[]> — stores timestamps of requests
    this._windows = new Map();
    // Periodic cleanup to avoid unbounded growth
    this._cleanupInterval = setInterval(() => this._cleanup(), windowMs * 2);
    this._cleanupInterval.unref?.();
  }

  /**
   * Check if a client is allowed to make a request.
   * @param {string} clientId
   * @returns {{ allowed: boolean, remaining: number, resetInMs: number }}
   */
  check(clientId) {
    if (!clientId || typeof clientId !== 'string') {
      clientId = 'unknown';
    }

    const now = Date.now();
    const windowStart = now - this._windowMs;

    let timestamps = this._windows.get(clientId);
    if (!timestamps) {
      timestamps = [];
      this._windows.set(clientId, timestamps);
    }

    // Evict timestamps outside the window
    let i = 0;
    while (i < timestamps.length && timestamps[i] <= windowStart) i++;
    if (i > 0) timestamps.splice(0, i);

    const remaining = this._maxRequests - timestamps.length;
    const allowed = remaining > 0;

    if (allowed) {
      timestamps.push(now);
    }

    const resetInMs = timestamps.length > 0
      ? (timestamps[0] - windowStart)
      : this._windowMs;

    return { allowed, remaining: Math.max(0, remaining - (allowed ? 1 : 0)), resetInMs };
  }

  _cleanup() {
    const cutoff = Date.now() - this._windowMs;
    for (const [clientId, timestamps] of this._windows) {
      // Remove all old timestamps
      let i = 0;
      while (i < timestamps.length && timestamps[i] <= cutoff) i++;
      if (i > 0) timestamps.splice(0, i);
      if (timestamps.length === 0) this._windows.delete(clientId);
    }
  }

  destroy() {
    clearInterval(this._cleanupInterval);
    this._windows.clear();
  }
}

// ─── Cache (in-memory, TTL + LRU eviction) ────────────────────────────────────

class Cache {
  constructor({ ttlMs, maxEntries }) {
    this._ttlMs = ttlMs;
    this._maxEntries = maxEntries;
    // Map preserves insertion order — used for LRU
    this._store = new Map();
  }

  /**
   * Build a normalized cache key.
   * @param {string} method
   * @param {string} path
   * @param {string|null} body
   * @returns {string}
   */
  static buildKey(method, path, body) {
    return `${method}:${path}:${body ?? ''}`;
  }

  /**
   * Get a cached entry if still valid.
   * @param {string} key
   * @returns {any|null}
   */
  get(key) {
    if (!key) return null;
    const entry = this._store.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this._store.delete(key);
      return null;
    }

    // Refresh LRU position
    this._store.delete(key);
    this._store.set(key, entry);
    return entry.value;
  }

  /**
   * Store a value with optional custom TTL.
   * @param {string} key
   * @param {any} value
   * @param {number} [ttlMs]
   */
  set(key, value, ttlMs) {
    if (!key) return;
    const effectiveTtl = ttlMs ?? this._ttlMs;

    // Evict LRU entry if at capacity
    if (this._store.size >= this._maxEntries && !this._store.has(key)) {
      const oldestKey = this._store.keys().next().value;
      this._store.delete(oldestKey);
    }

    // Remove and re-insert to update LRU position
    this._store.delete(key);
    this._store.set(key, {
      value,
      expiresAt: Date.now() + effectiveTtl,
    });
  }

  /** Remove a specific key. */
  delete(key) {
    this._store.delete(key);
  }

  /** Remove all expired entries. */
  purgeExpired() {
    const now = Date.now();
    for (const [key, entry] of this._store) {
      if (now > entry.expiresAt) this._store.delete(key);
    }
  }

  get size() { return this._store.size; }

  destroy() {
    this._store.clear();
  }
}

// ─── API Key Rotator ──────────────────────────────────────────────────────────

class ApiKeyRotator {
  constructor(keys) {
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new Error('ApiKeyRotator requires a non-empty array of keys');
    }
    this._keys = [...keys];
    this._index = 0;
    this._exhausted = new Set();
  }

  /** Returns the current active key. */
  get currentKey() {
    return this._keys[this._index];
  }

  /**
   * Mark the current key as failed (401) and rotate to the next available one.
   * @returns {boolean} true if a new key is available, false if all exhausted
   */
  rotateOnUnauthorized() {
    this._exhausted.add(this._keys[this._index]);

    // Find next non-exhausted key
    for (let i = 0; i < this._keys.length; i++) {
      const candidate = this._keys[(this._index + 1 + i) % this._keys.length];
      if (!this._exhausted.has(candidate)) {
        this._index = this._keys.indexOf(candidate);
        return true;
      }
    }

    return false; // all keys exhausted
  }

  /**
   * Reset exhausted state (e.g., after a successful request suggests keys are valid again).
   */
  resetExhausted() {
    this._exhausted.clear();
  }

  get keyCount() { return this._keys.length; }
  get exhaustedCount() { return this._exhausted.size; }
}

// ─── Circuit Breaker ──────────────────────────────────────────────────────────

const CircuitState = Object.freeze({
  CLOSED: 'CLOSED',
  OPEN: 'OPEN',
  HALF_OPEN: 'HALF_OPEN',
});

class CircuitBreaker {
  constructor({ failureThreshold, successThreshold, openDurationMs }) {
    this._failureThreshold = failureThreshold;
    this._successThreshold = successThreshold;
    this._openDurationMs = openDurationMs;

    this._state = CircuitState.CLOSED;
    this._failureCount = 0;
    this._successCount = 0;
    this._openedAt = null;
  }

  get state() { return this._state; }
  get isOpen() { return this._state === CircuitState.OPEN; }

  /**
   * Check whether the circuit allows a request to pass through.
   * Transitions OPEN → HALF_OPEN after the open duration expires.
   * @returns {boolean}
   */
  allowRequest() {
    if (this._state === CircuitState.CLOSED) return true;

    if (this._state === CircuitState.OPEN) {
      if (Date.now() - this._openedAt >= this._openDurationMs) {
        this._transitionTo(CircuitState.HALF_OPEN);
        return true;
      }
      return false;
    }

    // HALF_OPEN: allow one probe request
    return true;
  }

  /** Record a successful downstream response. */
  onSuccess() {
    if (this._state === CircuitState.HALF_OPEN) {
      this._successCount++;
      if (this._successCount >= this._successThreshold) {
        this._transitionTo(CircuitState.CLOSED);
      }
    } else if (this._state === CircuitState.CLOSED) {
      this._failureCount = 0; // reset on success
    }
  }

  /**
   * Record a downstream failure.
   * Transitions CLOSED → OPEN or HALF_OPEN → OPEN.
   */
  onFailure() {
    if (this._state === CircuitState.HALF_OPEN) {
      this._transitionTo(CircuitState.OPEN);
      return;
    }

    if (this._state === CircuitState.CLOSED) {
      this._failureCount++;
      if (this._failureCount >= this._failureThreshold) {
        this._transitionTo(CircuitState.OPEN);
      }
    }
  }

  _transitionTo(newState) {
    console.log(`[CircuitBreaker] ${this._state} → ${newState}`);
    this._state = newState;

    if (newState === CircuitState.OPEN) {
      this._openedAt = Date.now();
      this._successCount = 0;
    } else if (newState === CircuitState.CLOSED) {
      this._failureCount = 0;
      this._successCount = 0;
      this._openedAt = null;
    } else if (newState === CircuitState.HALF_OPEN) {
      this._successCount = 0;
    }
  }

  /** Current diagnostic snapshot. */
  get diagnostics() {
    return {
      state: this._state,
      failureCount: this._failureCount,
      successCount: this._successCount,
      openedAt: this._openedAt,
    };
  }
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

/**
 * Forward a request to the target API.
 * Returns { statusCode, headers, body } or throws on network error / timeout.
 *
 * @param {object} opts
 * @param {string} opts.targetBaseUrl
 * @param {string} opts.path
 * @param {string} opts.method
 * @param {Record<string,string>} opts.headers
 * @param {string|null} opts.body
 * @param {string} opts.apiKey
 * @param {number} opts.timeoutMs
 * @returns {Promise<{ statusCode: number, headers: object, body: string }>}
 */
function forwardRequest({ targetBaseUrl, path, method, headers, body, apiKey, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let targetUrl;
    try {
      targetUrl = new URL(path, targetBaseUrl);
    } catch (err) {
      return reject(new Error(`Invalid target path: ${path} — ${err.message}`));
    }

    const isHttps = targetUrl.protocol === 'https:';
    const lib = isHttps ? https : http;

    const reqHeaders = {
      ...headers,
      Authorization: `Bearer ${apiKey}`,
      Host: targetUrl.hostname,
    };
    // Remove hop-by-hop headers
    const hopByHop = ['connection', 'keep-alive', 'proxy-authenticate',
      'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'];
    for (const h of hopByHop) delete reqHeaders[h.toLowerCase()];

    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: method.toUpperCase(),
      headers: reqHeaders,
      timeout: timeoutMs,
    };

    const req = lib.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
      res.on('error', reject);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Upstream request timed out after ${timeoutMs}ms`));
    });

    req.on('error', reject);

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// ─── API Proxy (orchestrator) ─────────────────────────────────────────────────

class ApiProxy {
  constructor(config) {
    validateConfig(config);
    this._config = config;
    this._rateLimiter = new RateLimiter(config.rateLimit);
    this._cache = new Cache(config.cache);
    this._keyRotator = new ApiKeyRotator(config.apiKeys);
    this._circuitBreaker = new CircuitBreaker(config.circuitBreaker);

    // Periodic cache maintenance
    this._cacheCleanupInterval = setInterval(
      () => this._cache.purgeExpired(),
      config.cache.ttlMs
    );
    this._cacheCleanupInterval.unref?.();
  }

  /**
   * Handle an incoming proxy request.
   * @param {http.IncomingMessage} req
   * @param {http.ServerResponse} res
   */
  async handleRequest(req, res) {
    const clientIp = this._extractClientIp(req);
    const { method, url } = req;

    // 1. Read body
    let body = null;
    try {
      body = await this._readBody(req);
    } catch (err) {
      return this._sendError(res, 400, 'Failed to read request body', err.message);
    }

    // 2. Rate limiting
    const rl = this._rateLimiter.check(clientIp);
    res.setHeader('X-RateLimit-Limit', this._config.rateLimit.maxRequests);
    res.setHeader('X-RateLimit-Remaining', rl.remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(rl.resetInMs / 1000));
    if (!rl.allowed) {
      return this._sendError(res, 429, 'Too Many Requests',
        `Rate limit exceeded. Try again in ${Math.ceil(rl.resetInMs / 1000)}s`);
    }

    // 3. Cache lookup (only for safe methods)
    const isCacheable = ['GET', 'HEAD'].includes(method.toUpperCase());
    let cacheKey = null;
    if (isCacheable) {
      cacheKey = Cache.buildKey(method, url, null);
      const cached = this._cache.get(cacheKey);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return this._sendCachedResponse(res, cached);
      }
      res.setHeader('X-Cache', 'MISS');
    }

    // 4. Circuit breaker check
    if (!this._circuitBreaker.allowRequest()) {
      const diag = this._circuitBreaker.diagnostics;
      return this._sendError(res, 503, 'Service Unavailable',
        `Circuit breaker is OPEN. Retry after ${Math.ceil(
          (this._config.circuitBreaker.openDurationMs - (Date.now() - diag.openedAt)) / 1000
        )}s`);
    }

    // 5. Forward request (with API key rotation on 401)
    let response;
    try {
      response = await this._forwardWithKeyRotation({ method, url, req, body });
    } catch (err) {
      this._circuitBreaker.onFailure();
      if (err.code === 'TIMEOUT') {
        return this._sendError(res, 504, 'Gateway Timeout', err.message);
      }
      return this._sendError(res, 502, 'Bad Gateway', err.message);
    }

    // 6. Update circuit breaker
    const isServerError = response.statusCode >= 500;
    if (isServerError) {
      this._circuitBreaker.onFailure();
    } else {
      this._circuitBreaker.onSuccess();
    }

    // 7. Cache successful GET responses
    if (isCacheable && response.statusCode >= 200 && response.statusCode < 300 && cacheKey) {
      this._cache.set(cacheKey, {
        statusCode: response.statusCode,
        headers: response.headers,
        body: response.body,
      });
    }

    // 8. Send response to client
    this._sendUpstreamResponse(res, response);
  }

  /**
   * Forward with automatic API key rotation on 401.
   * Retries up to the number of available keys.
   */
  async _forwardWithKeyRotation({ method, url, req, body }) {
    const maxAttempts = this._keyRotator.keyCount;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const apiKey = this._keyRotator.currentKey;

      // Build safe forwarding headers (strip sensitive client headers)
      const forwardHeaders = this._buildForwardHeaders(req.headers);

      let response;
      try {
        response = await forwardRequest({
          targetBaseUrl: this._config.target.baseUrl,
          path: url,
          method,
          headers: forwardHeaders,
          body,
          apiKey,
          timeoutMs: this._config.target.timeoutMs,
        });
      } catch (err) {
        // Network / timeout error — do not rotate key, propagate
        const wrapped = new Error(err.message);
        if (err.message.includes('timed out')) wrapped.code = 'TIMEOUT';
        throw wrapped;
      }

      if (response.statusCode === 401) {
        console.warn(`[ApiProxy] 401 on key index ${attempt}. Rotating key...`);
        const hasNext = this._keyRotator.rotateOnUnauthorized();
        if (!hasNext) {
          console.error('[ApiProxy] All API keys exhausted.');
          return response; // return the 401 — nothing else we can do
        }
        continue; // retry with new key
      }

      // Non-401: reset exhausted state if the response is a success
      if (response.statusCode >= 200 && response.statusCode < 300) {
        this._keyRotator.resetExhausted();
      }

      return response;
    }

    throw new Error('All API keys exhausted after rotation attempts');
  }

  // ─── Internal helpers ──────────────────────────────────────────────────────

  _extractClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
    return req.socket?.remoteAddress ?? 'unknown';
  }

  _readBody(req) {
    return new Promise((resolve, reject) => {
      const MAX_BODY = 1024 * 1024; // 1MB guard
      const chunks = [];
      let size = 0;

      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          req.destroy();
          return reject(new Error('Request body too large (max 1MB)'));
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(chunks.length ? Buffer.concat(chunks).toString('utf8') : null));
      req.on('error', reject);
    });
  }

  _buildForwardHeaders(incomingHeaders) {
    const safe = { ...incomingHeaders };
    // Strip headers that must not be forwarded as-is
    const strip = ['host', 'authorization', 'content-length'];
    for (const h of strip) delete safe[h];
    return safe;
  }

  _sendError(res, status, title, detail) {
    const body = JSON.stringify({ error: { title, detail } });
    if (!res.headersSent) {
      res.writeHead(status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      });
    }
    res.end(body);
  }

  _sendCachedResponse(res, cached) {
    const responseHeaders = this._filterResponseHeaders(cached.headers);
    responseHeaders['Content-Type'] = responseHeaders['Content-Type'] ?? 'application/json';
    res.writeHead(cached.statusCode, responseHeaders);
    res.end(cached.body);
  }

  _sendUpstreamResponse(res, { statusCode, headers, body }) {
    const responseHeaders = this._filterResponseHeaders(headers);
    res.writeHead(statusCode, responseHeaders);
    res.end(body);
  }

  _filterResponseHeaders(headers) {
    const filtered = {};
    const passThrough = [
      'content-type', 'cache-control', 'etag', 'last-modified',
      'x-request-id', 'x-ratelimit-limit', 'x-ratelimit-remaining',
    ];
    for (const key of passThrough) {
      if (headers[key]) filtered[key] = headers[key];
    }
    return filtered;
  }

  // Diagnostic endpoint payload
  get diagnostics() {
    return {
      circuitBreaker: this._circuitBreaker.diagnostics,
      cache: { size: this._cache.size },
      apiKeys: {
        total: this._keyRotator.keyCount,
        exhausted: this._keyRotator.exhaustedCount,
      },
    };
  }

  destroy() {
    clearInterval(this._cacheCleanupInterval);
    this._rateLimiter.destroy();
    this._cache.destroy();
  }
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────

function createServer(proxy) {
  const server = http.createServer(async (req, res) => {
    // Internal diagnostics endpoint — not rate-limited
    if (req.url === '/_health' && req.method === 'GET') {
      const body = JSON.stringify({ status: 'ok', ...proxy.diagnostics });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(body);
    }

    // All other requests go through the proxy
    try {
      await proxy.handleRequest(req, res);
    } catch (err) {
      // Last-resort safety net — should not normally be reached
      console.error('[Server] Unhandled error in handleRequest:', err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { title: 'Internal Server Error', detail: err.message } }));
      }
    }
  });

  server.on('error', (err) => {
    console.error('[Server] Fatal error:', err);
    process.exit(1);
  });

  return server;
}

// ─── Graceful shutdown ────────────────────────────────────────────────────────

function setupGracefulShutdown(server, proxy) {
  let shuttingDown = false;

  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n[Shutdown] Received ${signal}. Closing...`);

    server.close((err) => {
      if (err) console.error('[Shutdown] Server close error:', err);
      proxy.destroy();
      console.log('[Shutdown] Clean exit.');
      process.exit(err ? 1 : 0);
    });

    // Force exit after 10s
    setTimeout(() => {
      console.error('[Shutdown] Forced exit after timeout.');
      process.exit(1);
    }, 10_000).unref?.();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  process.on('uncaughtException', (err) => {
    console.error('[Process] Uncaught exception:', err);
    shutdown('uncaughtException');
  });

  process.on('unhandledRejection', (reason) => {
    console.error('[Process] Unhandled rejection:', reason);
    shutdown('unhandledRejection');
  });
}

// ─── Entrypoint ───────────────────────────────────────────────────────────────

function main() {
  let proxy;
  try {
    proxy = new ApiProxy(CONFIG);
  } catch (err) {
    console.error('[Startup] Configuration error:', err.message);
    process.exit(1);
  }

  const server = createServer(proxy);
  setupGracefulShutdown(server, proxy);

  server.listen(CONFIG.server.port, CONFIG.server.host, () => {
    console.log(`[Server] Proxy listening on http://${CONFIG.server.host}:${CONFIG.server.port}`);
    console.log(`[Server] Target: ${CONFIG.target.baseUrl}`);
    console.log(`[Server] API keys loaded: ${CONFIG.apiKeys.length}`);
    console.log(`[Server] Diagnostics: http://${CONFIG.server.host}:${CONFIG.server.port}/_health`);
  });
}

main();
