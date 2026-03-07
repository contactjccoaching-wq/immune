'use strict';

/**
 * Rate-Limited API Proxy
 * Features: sliding-window rate limiting, in-memory TTL cache,
 * circuit breaker (closed/open/half-open), configurable upstream,
 * health endpoint, structured request/response logging.
 *
 * Run: node round-5.js
 * Required env vars:
 *   UPSTREAM_URL       — target base URL (e.g. https://api.example.com)
 *   ALLOWED_ORIGINS    — comma-separated CORS whitelist (e.g. https://app.example.com)
 * Optional env vars:
 *   PORT               — listen port (default 3000)
 *   TRUST_PROXY        — "true" to parse x-forwarded-for (default false)
 *   RATE_LIMIT_MAX     — requests per window per IP (default 60)
 *   RATE_LIMIT_WINDOW  — window duration in ms (default 60000)
 *   CACHE_TTL          — cache entry TTL in ms (default 30000)
 *   CACHE_MAX_SIZE     — max cache entries (default 500)
 *   CB_THRESHOLD       — failures before circuit opens (default 5)
 *   CB_RESET_TIMEOUT   — ms before half-open attempt (default 30000)
 *   CB_HALF_OPEN_MAX   — max concurrent half-open probes (default 1)
 *   REQUEST_TIMEOUT    — upstream request timeout in ms (default 10000)
 *   LOG_LEVEL          — "debug" | "info" | "warn" | "error" (default "info")
 */

// ─── Dependencies ─────────────────────────────────────────────────────────────

const http = require('http');
const https = require('https');
const { URL } = require('url');

let express, cors, helmet;
try {
  express = require('express');
  cors = require('cors');
  helmet = require('helmet');
} catch (e) {
  console.error('[boot] Missing dependencies. Run: npm install express cors helmet');
  process.exit(1);
}

// ─── Config ───────────────────────────────────────────────────────────────────

/**
 * CS-CODE-006: Startup config validation — fail fast with detailed errors.
 * AB-001: No secret fallbacks. Fail if required vars are absent.
 */
function loadConfig() {
  const errors = [];

  const raw = {
    upstreamUrl:      process.env.UPSTREAM_URL,
    allowedOrigins:   process.env.ALLOWED_ORIGINS,
    port:             process.env.PORT               || '3000',
    trustProxy:       process.env.TRUST_PROXY        || 'false',
    rateLimitMax:     process.env.RATE_LIMIT_MAX     || '60',
    rateLimitWindow:  process.env.RATE_LIMIT_WINDOW  || '60000',
    cacheTtl:         process.env.CACHE_TTL          || '30000',
    cacheMaxSize:     process.env.CACHE_MAX_SIZE     || '500',
    cbThreshold:      process.env.CB_THRESHOLD       || '5',
    cbResetTimeout:   process.env.CB_RESET_TIMEOUT   || '30000',
    cbHalfOpenMax:    process.env.CB_HALF_OPEN_MAX   || '1',
    requestTimeout:   process.env.REQUEST_TIMEOUT    || '10000',
    logLevel:        (process.env.LOG_LEVEL          || 'info').toLowerCase(),
  };

  // Required
  if (!raw.upstreamUrl) {
    errors.push('UPSTREAM_URL is required (e.g. https://api.example.com)');
  } else {
    try { new URL(raw.upstreamUrl); } catch {
      errors.push(`UPSTREAM_URL "${raw.upstreamUrl}" is not a valid URL`);
    }
  }

  // AB-006: No CORS wildcard fallback — require explicit origins.
  if (!raw.allowedOrigins) {
    errors.push('ALLOWED_ORIGINS is required (comma-separated list of allowed origins)');
  }

  // Numeric fields
  const numerics = {
    port:            { val: raw.port,            min: 1,  max: 65535 },
    rateLimitMax:    { val: raw.rateLimitMax,    min: 1,  max: 100000 },
    rateLimitWindow: { val: raw.rateLimitWindow, min: 100, max: 3600000 },
    cacheTtl:        { val: raw.cacheTtl,        min: 100, max: 3600000 },
    cacheMaxSize:    { val: raw.cacheMaxSize,    min: 1,  max: 100000 },
    cbThreshold:     { val: raw.cbThreshold,     min: 1,  max: 1000 },
    cbResetTimeout:  { val: raw.cbResetTimeout,  min: 1000, max: 3600000 },
    cbHalfOpenMax:   { val: raw.cbHalfOpenMax,   min: 1,  max: 100 },
    requestTimeout:  { val: raw.requestTimeout,  min: 100, max: 120000 },
  };

  const parsed = {};
  for (const [key, { val, min, max }] of Object.entries(numerics)) {
    const n = Number(val);
    if (!Number.isFinite(n) || n < min || n > max) {
      errors.push(`${key.toUpperCase()} must be a number between ${min} and ${max}, got: "${val}"`);
    } else {
      parsed[key] = n;
    }
  }

  const validLevels = new Set(['debug', 'info', 'warn', 'error']);
  if (!validLevels.has(raw.logLevel)) {
    errors.push(`LOG_LEVEL must be one of: debug, info, warn, error — got: "${raw.logLevel}"`);
  }

  if (errors.length > 0) {
    console.error('[boot] Configuration errors:\n' + errors.map(e => `  - ${e}`).join('\n'));
    process.exit(1);
  }

  // AB-006: Parse and validate each origin individually.
  const allowedOrigins = raw.allowedOrigins
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  for (const origin of allowedOrigins) {
    try { new URL(origin); } catch {
      console.error(`[boot] ALLOWED_ORIGINS contains invalid URL: "${origin}"`);
      process.exit(1);
    }
  }

  return Object.freeze({
    upstreamUrl:     raw.upstreamUrl.replace(/\/+$/, ''),
    allowedOrigins,
    trustProxy:      raw.trustProxy === 'true',
    logLevel:        raw.logLevel,
    ...parsed,
  });
}

const CONFIG = loadConfig();

// ─── Logger ───────────────────────────────────────────────────────────────────

const LOG_LEVELS = Object.freeze({ debug: 0, info: 1, warn: 2, error: 3 });
const currentLogLevel = LOG_LEVELS[CONFIG.logLevel];

const logger = Object.freeze({
  debug: (msg, meta) => log('debug', msg, meta),
  info:  (msg, meta) => log('info',  msg, meta),
  warn:  (msg, meta) => log('warn',  msg, meta),
  error: (msg, meta) => log('error', msg, meta),
});

function log(level, msg, meta) {
  if (LOG_LEVELS[level] < currentLogLevel) return;
  const entry = {
    ts:    new Date().toISOString(),
    level,
    msg,
    ...(meta !== undefined ? { meta } : {}),
  };
  const output = JSON.stringify(entry);
  if (level === 'error' || level === 'warn') {
    process.stderr.write(output + '\n');
  } else {
    process.stdout.write(output + '\n');
  }
}

// ─── Rate Limiter (sliding window, per IP) ────────────────────────────────────

/**
 * CS-CODE-009: Sliding window with automatic memory cleanup.
 * CS-CODE-010: Closure-based isolation with frozen public API.
 */
const rateLimiter = (() => {
  // Map<ip, number[]> — array of request timestamps within the current window
  const windows = new Map();

  // AB-007: Cleanup interval is stored for clearInterval on shutdown.
  const cleanupInterval = setInterval(() => {
    const cutoff = Date.now() - CONFIG.rateLimitWindow;
    for (const [ip, timestamps] of windows) {
      const trimmed = timestamps.filter(t => t > cutoff);
      if (trimmed.length === 0) {
        windows.delete(ip);
      } else {
        windows.set(ip, trimmed);
      }
    }
    logger.debug('[rate-limiter] cleanup', { active_ips: windows.size });
  }, CONFIG.rateLimitWindow);
  cleanupInterval.unref(); // CS-CODE-005: unref so it doesn't block process exit

  function check(ip) {
    const now = Date.now();
    const cutoff = now - CONFIG.rateLimitWindow;
    const timestamps = (windows.get(ip) || []).filter(t => t > cutoff);
    if (timestamps.length >= CONFIG.rateLimitMax) {
      const oldestInWindow = timestamps[0];
      const retryAfterMs = CONFIG.rateLimitWindow - (now - oldestInWindow);
      return { allowed: false, remaining: 0, retryAfterMs: Math.ceil(retryAfterMs) };
    }
    timestamps.push(now);
    windows.set(ip, timestamps);
    return {
      allowed: true,
      remaining: CONFIG.rateLimitMax - timestamps.length,
      retryAfterMs: 0,
    };
  }

  function destroy() {
    clearInterval(cleanupInterval);
    windows.clear();
  }

  return Object.freeze({ check, destroy });
})();

// ─── In-Memory Cache with TTL ──────────────────────────────────────────────────

/**
 * AB-009: TTL enforced + max size to prevent unbounded growth.
 * CS-CODE-014: Auto-cleanup on interval — prevents stale state leaks.
 * CS-CODE-010: Closure-based isolation.
 */
const cache = (() => {
  // Map<key, { value, expiresAt }>
  const store = new Map();

  // AB-007: Stored for clearInterval on shutdown.
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    let evicted = 0;
    for (const [key, entry] of store) {
      if (entry.expiresAt <= now) {
        store.delete(key);
        evicted++;
      }
    }
    if (evicted > 0) logger.debug('[cache] ttl-eviction', { evicted, size: store.size });
  }, Math.min(CONFIG.cacheTtl, 30000));
  cleanupInterval.unref();

  function get(key) {
    const entry = store.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      store.delete(key);
      return null;
    }
    return entry.value;
  }

  function set(key, value) {
    // Evict oldest entry if at capacity
    if (store.size >= CONFIG.cacheMaxSize && !store.has(key)) {
      const oldestKey = store.keys().next().value;
      store.delete(oldestKey);
      logger.debug('[cache] capacity-eviction', { evicted_key: oldestKey });
    }
    store.set(key, { value, expiresAt: Date.now() + CONFIG.cacheTtl });
  }

  function invalidate(key) {
    return store.delete(key);
  }

  function stats() {
    return { size: store.size, maxSize: CONFIG.cacheMaxSize };
  }

  function destroy() {
    clearInterval(cleanupInterval);
    store.clear();
  }

  return Object.freeze({ get, set, invalidate, stats, destroy });
})();

// ─── Circuit Breaker ──────────────────────────────────────────────────────────

/**
 * Three states: CLOSED (normal), OPEN (blocking), HALF_OPEN (probing).
 * CS-CODE-010: Closure-based isolation.
 * CS-CODE-013: Per-operation error handling.
 */
const circuitBreaker = (() => {
  const STATES = Object.freeze({ CLOSED: 'closed', OPEN: 'open', HALF_OPEN: 'half_open' });

  let state = STATES.CLOSED;
  let failureCount = 0;
  let lastFailureTime = 0;
  let halfOpenProbes = 0;
  let openedAt = null;

  function isOpen() {
    if (state === STATES.OPEN) {
      const elapsed = Date.now() - openedAt;
      if (elapsed >= CONFIG.cbResetTimeout) {
        state = STATES.HALF_OPEN;
        halfOpenProbes = 0;
        logger.info('[circuit-breaker] -> HALF_OPEN', { elapsed_ms: elapsed });
        return false; // Allow a probe
      }
      return true;
    }
    return false;
  }

  function canAttempt() {
    if (state === STATES.CLOSED) return true;
    if (isOpen()) return false; // Still OPEN
    if (state === STATES.HALF_OPEN) {
      if (halfOpenProbes < CONFIG.cbHalfOpenMax) {
        halfOpenProbes++;
        return true;
      }
      return false; // Too many concurrent probes
    }
    return false;
  }

  function recordSuccess() {
    if (state === STATES.HALF_OPEN) {
      logger.info('[circuit-breaker] -> CLOSED (probe succeeded)');
    }
    state = STATES.CLOSED;
    failureCount = 0;
    halfOpenProbes = 0;
    openedAt = null;
  }

  function recordFailure() {
    lastFailureTime = Date.now();
    if (state === STATES.HALF_OPEN) {
      // Probe failed — reopen immediately
      state = STATES.OPEN;
      openedAt = Date.now();
      halfOpenProbes = 0;
      logger.warn('[circuit-breaker] -> OPEN (probe failed)', { threshold: CONFIG.cbThreshold });
      return;
    }
    failureCount++;
    if (failureCount >= CONFIG.cbThreshold) {
      state = STATES.OPEN;
      openedAt = Date.now();
      logger.warn('[circuit-breaker] -> OPEN', {
        failures: failureCount,
        threshold: CONFIG.cbThreshold,
      });
    }
  }

  function getState() {
    return {
      state,
      failureCount,
      lastFailureTime: lastFailureTime ? new Date(lastFailureTime).toISOString() : null,
      openedAt: openedAt ? new Date(openedAt).toISOString() : null,
    };
  }

  return Object.freeze({ canAttempt, recordSuccess, recordFailure, getState, STATES });
})();

// ─── Upstream Proxy ───────────────────────────────────────────────────────────

/**
 * Forwards requests to upstream with configurable timeout.
 * CS-CODE-013: try-catch on every external interaction.
 */
function buildCacheKey(req) {
  return `${req.method}:${req.path}:${req.headers['accept'] || ''}:${new URL(req.url, 'http://x').search}`;
}

function isCacheable(req) {
  return req.method === 'GET' || req.method === 'HEAD';
}

function proxyRequest(req, res, next) {
  // CS-CODE-013: Per-operation error handling.
  try {
    const targetUrl = CONFIG.upstreamUrl + req.path + (new URL(req.url, 'http://x').search || '');
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch {
      logger.error('[proxy] invalid upstream URL', { targetUrl });
      return res.status(502).json({ error: 'Bad Gateway', detail: 'Invalid upstream URL constructed' });
    }

    const isHttps = parsed.protocol === 'https:';
    const transport = isHttps ? https : http;
    const port = parsed.port ? parseInt(parsed.port) : (isHttps ? 443 : 80);

    // Forward safe headers, strip hop-by-hop
    const hopByHop = new Set([
      'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
      'te', 'trailers', 'transfer-encoding', 'upgrade',
      'host', // rewritten below
    ]);
    const forwardHeaders = {};
    for (const [key, val] of Object.entries(req.headers)) {
      if (!hopByHop.has(key.toLowerCase())) {
        forwardHeaders[key] = val;
      }
    }
    forwardHeaders['host'] = parsed.host;
    forwardHeaders['x-forwarded-for'] = req.ip;
    forwardHeaders['x-forwarded-proto'] = req.protocol;

    const options = {
      hostname: parsed.hostname,
      port,
      path: parsed.pathname + parsed.search,
      method: req.method,
      headers: forwardHeaders,
      timeout: CONFIG.requestTimeout,
    };

    const upstreamReq = transport.request(options, (upstreamRes) => {
      try {
        circuitBreaker.recordSuccess();

        const statusCode = upstreamRes.statusCode || 502;
        const responseHeaders = {};
        for (const [key, val] of Object.entries(upstreamRes.headers)) {
          if (!hopByHop.has(key.toLowerCase())) {
            responseHeaders[key] = val;
          }
        }

        res.writeHead(statusCode, responseHeaders);

        const chunks = [];
        upstreamRes.on('data', (chunk) => chunks.push(chunk));
        upstreamRes.on('end', () => {
          try {
            const body = Buffer.concat(chunks);
            res.end(body);

            logger.info('[proxy] upstream-response', {
              method: req.method,
              path: req.path,
              status: statusCode,
              bytes: body.length,
            });

            // Cache successful GET/HEAD responses
            if (isCacheable(req) && statusCode >= 200 && statusCode < 300) {
              const key = buildCacheKey(req);
              cache.set(key, {
                statusCode,
                headers: responseHeaders,
                body: body.toString('base64'),
              });
            }
          } catch (endErr) {
            logger.error('[proxy] response-end error', { err: endErr.message });
          }
        });

        upstreamRes.on('error', (err) => {
          logger.error('[proxy] upstream-response stream error', { err: err.message });
          circuitBreaker.recordFailure();
          if (!res.headersSent) {
            res.status(502).json({ error: 'Bad Gateway', detail: 'Upstream stream error' });
          }
        });

      } catch (resErr) {
        logger.error('[proxy] response handler error', { err: resErr.message });
        circuitBreaker.recordFailure();
        if (!res.headersSent) {
          res.status(502).json({ error: 'Bad Gateway' });
        }
      }
    });

    upstreamReq.on('timeout', () => {
      logger.warn('[proxy] upstream timeout', { timeout_ms: CONFIG.requestTimeout, path: req.path });
      circuitBreaker.recordFailure();
      upstreamReq.destroy();
      if (!res.headersSent) {
        res.status(504).json({ error: 'Gateway Timeout', detail: 'Upstream did not respond in time' });
      }
    });

    upstreamReq.on('error', (err) => {
      logger.error('[proxy] upstream-request error', { err: err.message, path: req.path });
      circuitBreaker.recordFailure();
      if (!res.headersSent) {
        res.status(502).json({ error: 'Bad Gateway', detail: err.message });
      }
    });

    // Pipe request body for non-GET methods
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      const bodyStr = JSON.stringify(req.body);
      upstreamReq.setHeader('content-length', Buffer.byteLength(bodyStr));
      upstreamReq.write(bodyStr);
    }

    upstreamReq.end();

  } catch (err) {
    logger.error('[proxy] unexpected error', { err: err.message });
    next(err);
  }
}

// ─── Middlewares ──────────────────────────────────────────────────────────────

/**
 * AB-008: Client IP extraction gated by TRUST_PROXY config flag.
 */
function resolveClientIp(req, res, next) {
  if (CONFIG.trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded && typeof forwarded === 'string') {
      req.ip = forwarded.split(',')[0].trim();
    } else {
      req.ip = req.socket.remoteAddress || 'unknown';
    }
  } else {
    req.ip = req.socket.remoteAddress || 'unknown';
  }
  next();
}

/**
 * CS-CODE-009: Sliding window rate limiting middleware.
 * AB-002: Applied before routes.
 */
function rateLimitMiddleware(req, res, next) {
  // Skip rate limiting for health check
  if (req.path === '/health') return next();

  const result = rateLimiter.check(req.ip);

  res.setHeader('X-RateLimit-Limit', CONFIG.rateLimitMax);
  res.setHeader('X-RateLimit-Remaining', result.remaining);
  res.setHeader('X-RateLimit-Window', CONFIG.rateLimitWindow);

  if (!result.allowed) {
    res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000));
    logger.warn('[rate-limit] exceeded', { ip: req.ip, retryAfterMs: result.retryAfterMs });
    return res.status(429).json({
      error: 'Too Many Requests',
      retryAfterMs: result.retryAfterMs,
    });
  }

  next();
}

/**
 * Circuit breaker middleware — blocks requests when upstream is failing.
 */
function circuitBreakerMiddleware(req, res, next) {
  if (req.path === '/health') return next();

  if (!circuitBreaker.canAttempt()) {
    const state = circuitBreaker.getState();
    logger.warn('[circuit-breaker] request blocked', { state: state.state });
    return res.status(503).json({
      error: 'Service Unavailable',
      detail: 'Circuit breaker is open — upstream is unavailable',
      circuitBreaker: state,
    });
  }

  next();
}

/**
 * Cache middleware — serve cached responses for GET/HEAD.
 */
function cacheMiddleware(req, res, next) {
  if (!isCacheable(req)) return next();

  const key = buildCacheKey(req);
  const cached = cache.get(key);

  if (cached) {
    logger.debug('[cache] hit', { key, path: req.path });
    res.setHeader('X-Cache', 'HIT');
    res.writeHead(cached.statusCode, cached.headers);
    res.end(Buffer.from(cached.body, 'base64'));
    return;
  }

  res.setHeader('X-Cache', 'MISS');
  next();
}

/**
 * Request logging middleware.
 */
function requestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    logger.info('[request]', {
      method:   req.method,
      path:     req.path,
      ip:       req.ip,
      status:   res.statusCode,
      ms:       Date.now() - start,
      ua:       req.headers['user-agent'] || '',
    });
  });

  next();
}

// ─── App Setup ────────────────────────────────────────────────────────────────

const app = express();

/**
 * CS-CODE-008: Security middleware ordering:
 *   headers (helmet) → CORS → IP resolution → request logger → rate limit → body parser → routes
 *
 * AB-004: Security headers via helmet.
 * AB-005/AB-006: CORS with explicit origin whitelist — no wildcard fallback.
 */

// Helmet: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
    },
  },
}));

// CORS — AB-005, AB-006: explicit whitelist, no wildcard.
app.use(cors({
  origin: (origin, callback) => {
    // Allow server-to-server requests (no origin) only in non-production.
    if (!origin) {
      const env = process.env.NODE_ENV || 'development';
      if (env !== 'production') return callback(null, true);
      return callback(new Error('CORS: missing origin'));
    }
    if (CONFIG.allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    logger.warn('[cors] rejected origin', { origin });
    return callback(new Error(`CORS: origin "${origin}" not allowed`));
  },
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: true,
}));

// IP resolution — must be before rate limiter.
app.use(resolveClientIp);

// Request logging
app.use(requestLogger);

// Rate limiting — AB-002
app.use(rateLimitMiddleware);

// CS-CODE-004: Body size limit to prevent payload explosion DoS.
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check — bypasses rate limiter and circuit breaker.
app.get('/health', (req, res) => {
  const cb = circuitBreaker.getState();
  const cacheStats = cache.stats();
  const healthy = cb.state !== circuitBreaker.STATES.OPEN;

  res.status(healthy ? 200 : 503).json({
    status:       healthy ? 'ok' : 'degraded',
    ts:           new Date().toISOString(),
    upstream:     CONFIG.upstreamUrl,
    circuitBreaker: cb,
    cache:        cacheStats,
    rateLimit: {
      maxRequests: CONFIG.rateLimitMax,
      windowMs:    CONFIG.rateLimitWindow,
    },
  });
});

// Proxy routes — circuit breaker → cache → proxy
app.use(circuitBreakerMiddleware);
app.use(cacheMiddleware);

// CS-CODE-007: Validate body type for mutation methods before forwarding.
app.use((req, res, next) => {
  const mutationMethods = new Set(['POST', 'PUT', 'PATCH']);
  if (mutationMethods.has(req.method)) {
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('application/json')) {
      if (req.body !== undefined && (typeof req.body !== 'object' || Array.isArray(req.body) || req.body === null)) {
        return res.status(400).json({ error: 'Bad Request', detail: 'Request body must be a JSON object' });
      }
    }
  }
  next();
});

// Forward all other requests to upstream.
app.all('*', proxyRequest);

// ─── Error Handler ────────────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error('[error-handler]', { err: err.message, path: req.path });

  if (err.message && err.message.startsWith('CORS:')) {
    return res.status(403).json({ error: 'Forbidden', detail: err.message });
  }

  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ─── Server Lifecycle ─────────────────────────────────────────────────────────

/**
 * CS-CODE-005: Graceful shutdown with timeout enforcement + unref().
 * AB-007: All intervals cleared on shutdown.
 */
let server;

function startServer() {
  server = http.createServer(app);

  server.listen(CONFIG.port, () => {
    logger.info('[boot] server started', {
      port:          CONFIG.port,
      upstream:      CONFIG.upstreamUrl,
      trustProxy:    CONFIG.trustProxy,
      rateLimitMax:  CONFIG.rateLimitMax,
      rateLimitWindow: CONFIG.rateLimitWindow,
      cacheTtl:      CONFIG.cacheTtl,
      cacheMaxSize:  CONFIG.cacheMaxSize,
      cbThreshold:   CONFIG.cbThreshold,
      cbResetTimeout: CONFIG.cbResetTimeout,
    });
  });

  server.on('error', (err) => {
    logger.error('[server] error', { err: err.message });
    process.exit(1);
  });

  return server;
}

function shutdown(signal) {
  logger.info('[shutdown] received signal', { signal });

  // AB-007: Clear all background intervals.
  rateLimiter.destroy();
  cache.destroy();

  if (!server) {
    process.exit(0);
  }

  server.close((err) => {
    if (err) {
      logger.error('[shutdown] server close error', { err: err.message });
      process.exit(1);
    }
    logger.info('[shutdown] clean exit');
    process.exit(0);
  });

  // Enforce shutdown timeout — CS-CODE-005.
  const forceExit = setTimeout(() => {
    logger.warn('[shutdown] forced exit after timeout');
    process.exit(1);
  }, 10000);
  forceExit.unref(); // CS-CODE-005: unref so it doesn't block exit if clean shutdown finishes first.
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('[uncaughtException]', { err: err.message, stack: err.stack });
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  logger.error('[unhandledRejection]', { reason: String(reason) });
  shutdown('unhandledRejection');
});

// ─── Boot ─────────────────────────────────────────────────────────────────────

if (require.main === module) {
  startServer();
}

// ─── Exports (for testing) ────────────────────────────────────────────────────

module.exports = Object.freeze({
  app,
  startServer,
  shutdown,
  rateLimiter,
  cache,
  circuitBreaker,
  CONFIG,
  logger,
});
