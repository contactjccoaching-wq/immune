import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import https from 'https';
import http from 'http';

// ─── Config Validation ───────────────────────────────────────────────────────

const REQUIRED_ENV = ['TARGET_API_BASE_URL', 'API_KEYS'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`FATAL: Missing required env var: ${key}`);
    process.exit(1);
  }
}

const CONFIG = {
  port: parseInt(process.env.PORT || '3000', 10),
  targetApiBaseUrl: process.env.TARGET_API_BASE_URL,
  apiKeys: process.env.API_KEYS.split(',').map(k => k.trim()).filter(Boolean),
  cacheTtlMs: parseInt(process.env.CACHE_TTL_MS || '30000', 10),
  cacheMaxSize: parseInt(process.env.CACHE_MAX_SIZE || '1000', 10),
  cbFailureThreshold: parseInt(process.env.CB_FAILURE_THRESHOLD || '5', 10),
  cbResetTimeoutMs: parseInt(process.env.CB_RESET_TIMEOUT_MS || '30000', 10),
  cbHalfOpenRequests: parseInt(process.env.CB_HALF_OPEN_REQUESTS || '2', 10),
};

if (CONFIG.apiKeys.length === 0) {
  console.error('FATAL: API_KEYS must contain at least one key');
  process.exit(1);
}

// ─── Validation Constants ─────────────────────────────────────────────────────

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PATH_REGEX = /^\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$/;
const MAX_PATH_LENGTH = 2048;
const MAX_BODY_SIZE = '1mb';
const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);

// ─── In-Memory Cache ──────────────────────────────────────────────────────────

class TTLCache {
  constructor(maxSize, ttlMs) {
    this.store = new Map();
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  _isExpired(entry) {
    return Date.now() > entry.expiresAt;
  }

  get(key) {
    const entry = this.store.get(key);
    if (!entry) { this.misses++; return null; }
    if (this._isExpired(entry)) {
      this.store.delete(key);
      this.misses++;
      return null;
    }
    this.hits++;
    return entry.value;
  }

  set(key, value) {
    if (this.store.size >= this.maxSize) {
      const firstKey = this.store.keys().next().value;
      this.store.delete(firstKey);
      this.evictions++;
    }
    this.store.set(key, {
      value,
      expiresAt: Date.now() + this.ttlMs,
      createdAt: Date.now(),
    });
  }

  delete(key) {
    return this.store.delete(key);
  }

  clear() {
    this.store.clear();
  }

  purgeExpired() {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) {
        this.store.delete(key);
        this.evictions++;
      }
    }
  }

  stats() {
    this.purgeExpired();
    return {
      size: this.store.size,
      maxSize: this.maxSize,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      hitRate: this.hits + this.misses > 0
        ? (this.hits / (this.hits + this.misses)).toFixed(4)
        : '0.0000',
    };
  }
}

const cache = new TTLCache(CONFIG.cacheMaxSize, CONFIG.cacheTtlMs);

// ─── API Key Rotation ─────────────────────────────────────────────────────────

class ApiKeyRotator {
  constructor(keys) {
    this.keys = [...keys];
    this.currentIndex = 0;
    this.failedKeys = new Map(); // key -> { failedAt, count }
    this.rotations = 0;
  }

  current() {
    return this.keys[this.currentIndex];
  }

  rotate() {
    const failed = this.current();
    const failedEntry = this.failedKeys.get(failed) || { failedAt: Date.now(), count: 0 };
    failedEntry.count++;
    failedEntry.failedAt = Date.now();
    this.failedKeys.set(failed, failedEntry);

    // Find next non-recently-failed key
    let attempts = 0;
    do {
      this.currentIndex = (this.currentIndex + 1) % this.keys.length;
      attempts++;
    } while (
      attempts < this.keys.length &&
      this._isRecentlyFailed(this.current())
    );

    this.rotations++;
    console.log(`[KeyRotator] Rotated to key index ${this.currentIndex} (${this.rotations} total rotations)`);
    return this.current();
  }

  _isRecentlyFailed(key) {
    const entry = this.failedKeys.get(key);
    if (!entry) return false;
    return Date.now() - entry.failedAt < 60000; // 1 min cooldown
  }

  stats() {
    return {
      totalKeys: this.keys.length,
      currentIndex: this.currentIndex,
      rotations: this.rotations,
      failedKeys: this.failedKeys.size,
    };
  }
}

const keyRotator = new ApiKeyRotator(CONFIG.apiKeys);

// ─── Circuit Breaker ──────────────────────────────────────────────────────────

const CB_STATES = { CLOSED: 'CLOSED', OPEN: 'OPEN', HALF_OPEN: 'HALF_OPEN' };

class CircuitBreaker {
  constructor(failureThreshold, resetTimeoutMs, halfOpenRequests) {
    this.failureThreshold = failureThreshold;
    this.resetTimeoutMs = resetTimeoutMs;
    this.halfOpenRequests = halfOpenRequests;
    this.state = CB_STATES.CLOSED;
    this.failures = 0;
    this.successes = 0;
    this.halfOpenAttempts = 0;
    this.lastFailureTime = null;
    this.openedAt = null;
    this.totalTrips = 0;
    this.totalRequests = 0;
  }

  canRequest() {
    this.totalRequests++;
    if (this.state === CB_STATES.CLOSED) return true;
    if (this.state === CB_STATES.OPEN) {
      if (Date.now() - this.openedAt >= this.resetTimeoutMs) {
        this.state = CB_STATES.HALF_OPEN;
        this.halfOpenAttempts = 0;
        console.log('[CircuitBreaker] Transitioning to HALF_OPEN');
        return true;
      }
      return false;
    }
    // HALF_OPEN
    if (this.halfOpenAttempts < this.halfOpenRequests) {
      this.halfOpenAttempts++;
      return true;
    }
    return false;
  }

  recordSuccess() {
    this.successes++;
    if (this.state === CB_STATES.HALF_OPEN) {
      if (this.halfOpenAttempts >= this.halfOpenRequests) {
        this.state = CB_STATES.CLOSED;
        this.failures = 0;
        this.halfOpenAttempts = 0;
        console.log('[CircuitBreaker] Transitioning to CLOSED (recovered)');
      }
    } else {
      this.failures = Math.max(0, this.failures - 1);
    }
  }

  recordFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();
    if (this.state === CB_STATES.HALF_OPEN) {
      this.state = CB_STATES.OPEN;
      this.openedAt = Date.now();
      this.totalTrips++;
      console.log('[CircuitBreaker] HALF_OPEN -> OPEN (still failing)');
    } else if (this.state === CB_STATES.CLOSED && this.failures >= this.failureThreshold) {
      this.state = CB_STATES.OPEN;
      this.openedAt = Date.now();
      this.totalTrips++;
      console.log(`[CircuitBreaker] CLOSED -> OPEN (${this.failures} failures)`);
    }
  }

  stats() {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      totalTrips: this.totalTrips,
      totalRequests: this.totalRequests,
      openedAt: this.openedAt,
      halfOpenAttempts: this.halfOpenAttempts,
      failureThreshold: this.failureThreshold,
    };
  }
}

const circuitBreaker = new CircuitBreaker(
  CONFIG.cbFailureThreshold,
  CONFIG.cbResetTimeoutMs,
  CONFIG.cbHalfOpenRequests
);

// ─── Sliding Window Rate Limiter (per-key, in-memory) ────────────────────────

class SlidingWindowLimiter {
  constructor(windowMs, maxRequests) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.windows = new Map(); // key -> timestamps[]
  }

  isAllowed(key) {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    let timestamps = this.windows.get(key) || [];
    timestamps = timestamps.filter(t => t > cutoff);
    if (timestamps.length >= this.maxRequests) {
      this.windows.set(key, timestamps);
      return false;
    }
    timestamps.push(now);
    this.windows.set(key, timestamps);
    return true;
  }

  remaining(key) {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const timestamps = (this.windows.get(key) || []).filter(t => t > cutoff);
    return Math.max(0, this.maxRequests - timestamps.length);
  }

  purge() {
    const now = Date.now();
    for (const [key, timestamps] of this.windows) {
      const filtered = timestamps.filter(t => t > now - this.windowMs);
      if (filtered.length === 0) this.windows.delete(key);
      else this.windows.set(key, filtered);
    }
  }
}

// Different limiters for different endpoint sensitivities
const limiters = {
  proxy: new SlidingWindowLimiter(60000, 100),     // 100 req/min for proxy
  admin: new SlidingWindowLimiter(60000, 20),       // 20 req/min for admin/metrics
  health: new SlidingWindowLimiter(10000, 30),      // 30 req/10s for health
};

// ─── Metrics ──────────────────────────────────────────────────────────────────

const metrics = {
  requestsTotal: 0,
  requestsSucceeded: 0,
  requestsFailed: 0,
  requestsRateLimited: 0,
  requestsCachedServed: 0,
  requestsCircuitBroken: 0,
  uptime: Date.now(),
  latencies: [], // sliding window of last 1000 latencies
};

function recordLatency(ms) {
  metrics.latencies.push(ms);
  if (metrics.latencies.length > 1000) metrics.latencies.shift();
}

function computeLatencyStats() {
  const lats = [...metrics.latencies].sort((a, b) => a - b);
  if (lats.length === 0) return { p50: 0, p95: 0, p99: 0, mean: 0 };
  const p = (pct) => lats[Math.floor(lats.length * pct / 100)];
  const mean = lats.reduce((s, v) => s + v, 0) / lats.length;
  return { p50: p(50), p95: p(95), p99: p(99), mean: Math.round(mean) };
}

// ─── Proxy Request ────────────────────────────────────────────────────────────

function forwardRequest(method, path, headers, body, apiKey) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, CONFIG.targetApiBaseUrl);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const outHeaders = {
      ...headers,
      'x-api-key': apiKey,
      'authorization': `Bearer ${apiKey}`,
      'host': url.hostname,
      'x-forwarded-for': undefined,
    };
    // Remove hop-by-hop headers
    for (const h of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
      'te', 'trailers', 'transfer-encoding', 'upgrade', 'x-forwarded-for']) {
      delete outHeaders[h];
    }

    const bodyData = body && method !== 'GET' && method !== 'HEAD'
      ? (typeof body === 'string' ? body : JSON.stringify(body))
      : null;

    if (bodyData) {
      outHeaders['content-length'] = Buffer.byteLength(bodyData);
    }

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: outHeaders,
      timeout: 15000,
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('UPSTREAM_TIMEOUT'));
    });

    req.on('error', reject);

    if (bodyData) req.write(bodyData);
    req.end();
  });
}

// ─── Express App ──────────────────────────────────────────────────────────────

const app = express();

// Security middleware (order matters)
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
}));

// Global express rate limiter (fallback)
app.use(rateLimit({
  windowMs: 60000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests', code: 'RATE_LIMITED' },
}));

app.use(express.json({ limit: MAX_BODY_SIZE }));
app.use(express.urlencoded({ extended: false, limit: MAX_BODY_SIZE }));

// Request tracing middleware
app.use((req, _res, next) => {
  req.requestId = crypto.randomUUID();
  req.startedAt = Date.now();
  metrics.requestsTotal++;
  next();
});

// ─── Observability Endpoints ──────────────────────────────────────────────────

app.get('/health', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  if (!limiters.health.isAllowed(clientIp)) {
    return res.status(429).json({ error: 'Rate limit exceeded', requestId: req.requestId });
  }
  res.json({
    status: 'ok',
    requestId: req.requestId,
    uptime: Math.floor((Date.now() - metrics.uptime) / 1000),
    circuitBreaker: circuitBreaker.state,
    timestamp: new Date().toISOString(),
  });
});

app.get('/metrics', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  if (!limiters.admin.isAllowed(clientIp)) {
    return res.status(429).json({ error: 'Rate limit exceeded', requestId: req.requestId });
  }
  res.json({
    requestId: req.requestId,
    metrics: {
      ...metrics,
      latencies: undefined,
      latencyStats: computeLatencyStats(),
    },
    cache: cache.stats(),
    circuitBreaker: circuitBreaker.stats(),
    keyRotator: keyRotator.stats(),
    uptime: Math.floor((Date.now() - metrics.uptime) / 1000),
    timestamp: new Date().toISOString(),
  });
});

app.delete('/cache', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  if (!limiters.admin.isAllowed(clientIp)) {
    return res.status(429).json({ error: 'Rate limit exceeded', requestId: req.requestId });
  }
  const adminKey = req.headers['x-admin-key'];
  if (!process.env.ADMIN_KEY || adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: 'Forbidden', requestId: req.requestId });
  }
  cache.clear();
  res.json({ message: 'Cache cleared', requestId: req.requestId });
});

// ─── Proxy Route ──────────────────────────────────────────────────────────────

app.all('/proxy/*', async (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  const requestId = req.requestId;

  // Input validation
  if (!ALLOWED_METHODS.has(req.method)) {
    return res.status(405).json({ error: 'Method not allowed', requestId });
  }

  const proxyPath = req.path.replace(/^\/proxy/, '') || '/';
  if (!PATH_REGEX.test(proxyPath) || proxyPath.length > MAX_PATH_LENGTH) {
    return res.status(400).json({ error: 'Invalid path', requestId });
  }

  // Sliding window rate limit
  if (!limiters.proxy.isAllowed(clientIp)) {
    metrics.requestsRateLimited++;
    return res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: 60,
      requestId,
    });
  }

  // Circuit breaker check
  if (!circuitBreaker.canRequest()) {
    metrics.requestsCircuitBroken++;
    return res.status(503).json({
      error: 'Service temporarily unavailable (circuit open)',
      requestId,
      retryAfter: Math.ceil(CONFIG.cbResetTimeoutMs / 1000),
    });
  }

  // Cache check (GET only)
  const cacheKey = req.method === 'GET'
    ? `${req.method}:${proxyPath}:${new URLSearchParams(req.query).toString()}`
    : null;

  if (cacheKey) {
    const cached = cache.get(cacheKey);
    if (cached) {
      metrics.requestsCachedServed++;
      res.set('X-Cache', 'HIT');
      res.set('X-Request-Id', requestId);
      res.set('X-Remaining-Limit', String(limiters.proxy.remaining(clientIp)));
      return res.status(cached.status).json(cached.body);
    }
  }

  res.set('X-Cache', 'MISS');
  res.set('X-Request-Id', requestId);

  // Forward with retry on 401
  let attempt = 0;
  const maxAttempts = Math.min(CONFIG.apiKeys.length, 3);
  let lastError = null;
  let lastStatus = null;

  while (attempt < maxAttempts) {
    const apiKey = keyRotator.current();
    try {
      const result = await forwardRequest(
        req.method,
        proxyPath + (Object.keys(req.query).length
          ? '?' + new URLSearchParams(req.query).toString()
          : ''),
        req.headers,
        req.body,
        apiKey
      );

      lastStatus = result.status;

      if (result.status === 401) {
        console.log(`[Proxy] 401 on attempt ${attempt + 1}, rotating key`);
        keyRotator.rotate();
        attempt++;
        lastError = new Error('AUTH_FAILED');
        continue;
      }

      // Success or non-retryable error
      const isSuccess = result.status >= 200 && result.status < 300;
      if (isSuccess) {
        circuitBreaker.recordSuccess();
        metrics.requestsSucceeded++;
      } else if (result.status >= 500) {
        circuitBreaker.recordFailure();
        metrics.requestsFailed++;
      } else {
        // 4xx (non-401) — don't trip circuit breaker
        metrics.requestsSucceeded++;
      }

      recordLatency(Date.now() - req.startedAt);

      let parsedBody;
      try {
        parsedBody = JSON.parse(result.body);
      } catch {
        parsedBody = result.body;
      }

      // Cache successful GET responses
      if (cacheKey && isSuccess) {
        cache.set(cacheKey, { status: result.status, body: parsedBody });
      }

      // Forward select response headers
      const forwardHeaders = ['content-type', 'x-ratelimit-remaining', 'x-ratelimit-reset'];
      for (const h of forwardHeaders) {
        if (result.headers[h]) res.set(h, result.headers[h]);
      }
      res.set('X-Remaining-Limit', String(limiters.proxy.remaining(clientIp)));

      return res.status(result.status).json(parsedBody);

    } catch (err) {
      lastError = err;
      if (err.message === 'UPSTREAM_TIMEOUT') {
        circuitBreaker.recordFailure();
        metrics.requestsFailed++;
        recordLatency(Date.now() - req.startedAt);
        return res.status(504).json({ error: 'Upstream timeout', requestId });
      }
      circuitBreaker.recordFailure();
      metrics.requestsFailed++;
      attempt++;
    }
  }

  recordLatency(Date.now() - req.startedAt);

  if (lastStatus === 401) {
    return res.status(502).json({
      error: 'All API keys rejected (401)',
      requestId,
    });
  }

  return res.status(502).json({
    error: 'Upstream error after retries',
    detail: lastError?.message,
    requestId,
  });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────

app.use((err, req, res, _next) => {
  const requestId = req.requestId || crypto.randomUUID();

  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: 'Invalid JSON in request body',
      requestId,
    });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Request body too large',
      limit: MAX_BODY_SIZE,
      requestId,
    });
  }

  console.error(`[Error] ${requestId}:`, err.message);
  metrics.requestsFailed++;

  res.status(500).json({
    error: 'Internal server error',
    requestId,
  });
});

// 404 catch-all
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    requestId: req.requestId,
  });
});

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

const server = app.listen(CONFIG.port, () => {
  console.log(`[Server] Rate-limited API proxy running on port ${CONFIG.port}`);
  console.log(`[Server] Target API: ${CONFIG.targetApiBaseUrl}`);
  console.log(`[Server] API keys loaded: ${CONFIG.apiKeys.length}`);
  console.log(`[Server] Cache TTL: ${CONFIG.cacheTtlMs}ms, max: ${CONFIG.cacheMaxSize}`);
  console.log(`[Server] Circuit breaker: threshold=${CONFIG.cbFailureThreshold}, reset=${CONFIG.cbResetTimeoutMs}ms`);
});

const activeConnections = new Set();
server.on('connection', (socket) => {
  activeConnections.add(socket);
  socket.on('close', () => activeConnections.delete(socket));
});

// Periodic cache cleanup
const cacheCleanupInterval = setInterval(() => {
  cache.purgeExpired();
  limiters.proxy.purge();
  limiters.admin.purge();
  limiters.health.purge();
}, 60000);

function gracefulShutdown(signal) {
  console.log(`[Server] Received ${signal}, initiating graceful shutdown`);

  // Notify active connections
  for (const socket of activeConnections) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
    socket.destroy();
  }

  clearInterval(cacheCleanupInterval);

  server.close((err) => {
    if (err) {
      console.error('[Server] Error during shutdown:', err.message);
      process.exit(1);
    }
    console.log('[Server] Graceful shutdown complete');
    process.exit(0);
  });

  // Force exit after 10s
  setTimeout(() => {
    console.error('[Server] Forced shutdown after timeout');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

export default app;
