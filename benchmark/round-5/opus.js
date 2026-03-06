import express from "express";
import helmet from "helmet";
import cors from "cors";
import crypto from "crypto";

// =============================================================================
// ENV VALIDATION — fail fast at startup
// =============================================================================

const REQUIRED_ENV = [
  "API_KEYS",           // comma-separated list of third-party API keys
  "TARGET_BASE_URL",    // e.g. https://api.example.com
  "PORT",
];

const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`FATAL: missing required env vars: ${missing.join(", ")}`);
  process.exit(1);
}

const API_KEYS = process.env.API_KEYS.split(",").map((k) => k.trim()).filter(Boolean);
if (API_KEYS.length === 0) {
  console.error("FATAL: API_KEYS must contain at least one key");
  process.exit(1);
}

const TARGET_BASE_URL = process.env.TARGET_BASE_URL.replace(/\/+$/, "");
const PORT = parseInt(process.env.PORT, 10) || 3000;
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS, 10) || 60_000;
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60_000;
const RATE_LIMIT_MAX_DEFAULT = parseInt(process.env.RATE_LIMIT_MAX_DEFAULT, 10) || 100;
const RATE_LIMIT_MAX_SENSITIVE = parseInt(process.env.RATE_LIMIT_MAX_SENSITIVE, 10) || 20;
const CIRCUIT_FAILURE_THRESHOLD = parseInt(process.env.CIRCUIT_FAILURE_THRESHOLD, 10) || 5;
const CIRCUIT_RESET_TIMEOUT_MS = parseInt(process.env.CIRCUIT_RESET_TIMEOUT_MS, 10) || 30_000;
const MAX_BODY_SIZE = process.env.MAX_BODY_SIZE || "100kb";

// =============================================================================
// VALIDATION CONSTANTS — reuse across routes
// =============================================================================

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PATH_RE = /^\/[a-zA-Z0-9\-_\/.\?&=%+:@,;~]*$/;
const MAX_PATH_LENGTH = 2048;

function isValidUUID(v) {
  return typeof v === "string" && UUID_RE.test(v);
}

function sanitizePath(p) {
  if (typeof p !== "string") return null;
  if (p.length > MAX_PATH_LENGTH) return null;
  if (!PATH_RE.test(p)) return null;
  return p;
}

// =============================================================================
// API KEY ROTATION
// =============================================================================

class KeyRotator {
  constructor(keys) {
    this._keys = [...keys];
    this._index = 0;
    this._exhausted = new Set();
  }

  current() {
    return this._keys[this._index];
  }

  rotate() {
    this._exhausted.add(this._index);
    if (this._exhausted.size >= this._keys.length) {
      // all keys exhausted — reset and return null to signal total failure
      this._exhausted.clear();
      return null;
    }
    // advance to next non-exhausted key
    do {
      this._index = (this._index + 1) % this._keys.length;
    } while (this._exhausted.has(this._index));
    return this.current();
  }

  resetExhausted() {
    this._exhausted.clear();
  }

  get totalKeys() {
    return this._keys.length;
  }

  get exhaustedCount() {
    return this._exhausted.size;
  }
}

const keyRotator = new KeyRotator(API_KEYS);

// =============================================================================
// CIRCUIT BREAKER
// =============================================================================

const CircuitState = Object.freeze({
  CLOSED: "CLOSED",
  OPEN: "OPEN",
  HALF_OPEN: "HALF_OPEN",
});

class CircuitBreaker {
  constructor({ failureThreshold, resetTimeout }) {
    this.failureThreshold = failureThreshold;
    this.resetTimeout = resetTimeout;
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.successCount = 0;
  }

  canPass() {
    if (this.state === CircuitState.CLOSED) return true;

    if (this.state === CircuitState.OPEN) {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.resetTimeout) {
        this.state = CircuitState.HALF_OPEN;
        return true;
      }
      return false;
    }

    // HALF_OPEN — allow a single probe
    return true;
  }

  recordSuccess() {
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount += 1;
      // require 2 consecutive successes to fully close
      if (this.successCount >= 2) {
        this.state = CircuitState.CLOSED;
        this.failureCount = 0;
        this.successCount = 0;
        keyRotator.resetExhausted();
      }
    } else {
      this.failureCount = 0;
    }
  }

  recordFailure() {
    this.failureCount += 1;
    this.lastFailureTime = Date.now();
    this.successCount = 0;

    if (this.failureCount >= this.failureThreshold) {
      this.state = CircuitState.OPEN;
    }
  }

  toJSON() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      failureThreshold: this.failureThreshold,
      lastFailureTime: this.lastFailureTime,
      resetTimeoutMs: this.resetTimeout,
    };
  }
}

const circuitBreaker = new CircuitBreaker({
  failureThreshold: CIRCUIT_FAILURE_THRESHOLD,
  resetTimeout: CIRCUIT_RESET_TIMEOUT_MS,
});

// =============================================================================
// IN-MEMORY CACHE (Map) with TTL
// =============================================================================

class TTLCache {
  constructor(defaultTTL) {
    this._store = new Map();           // key → { value, expiresAt, createdAt }
    this._defaultTTL = defaultTTL;
    this._sweepInterval = setInterval(() => this._sweep(), defaultTTL * 2);
    this._sweepInterval.unref?.();
  }

  get(key) {
    const entry = this._store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this._store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key, value, ttl) {
    const now = Date.now();
    this._store.set(key, {
      value,
      createdAt: now,
      expiresAt: now + (ttl ?? this._defaultTTL),
    });
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  delete(key) {
    this._store.delete(key);
  }

  clear() {
    this._store.clear();
  }

  get size() {
    return this._store.size;
  }

  entries() {
    const now = Date.now();
    const result = [];
    for (const [k, v] of this._store) {
      if (now <= v.expiresAt) {
        result.push({ key: k, createdAt: v.createdAt, expiresAt: v.expiresAt });
      }
    }
    return result.sort((a, b) => a.createdAt - b.createdAt);
  }

  _sweep() {
    const now = Date.now();
    for (const [key, entry] of this._store) {
      if (now > entry.expiresAt) this._store.delete(key);
    }
  }

  destroy() {
    clearInterval(this._sweepInterval);
    this._store.clear();
  }
}

const cache = new TTLCache(CACHE_TTL_MS);

// =============================================================================
// SLIDING WINDOW RATE LIMITER (per-IP, Map-based)
// =============================================================================

class SlidingWindowRateLimiter {
  constructor() {
    this._windows = new Map(); // key → timestamp[]
    this._cleanupInterval = setInterval(() => this._cleanup(), 120_000);
    this._cleanupInterval.unref?.();
  }

  /**
   * Returns { allowed, remaining, resetMs } for the given key.
   */
  check(key, windowMs, maxRequests) {
    const now = Date.now();
    const cutoff = now - windowMs;

    let timestamps = this._windows.get(key);
    if (!timestamps) {
      timestamps = [];
      this._windows.set(key, timestamps);
    }

    // prune old entries (sliding window)
    while (timestamps.length > 0 && timestamps[0] <= cutoff) {
      timestamps.shift();
    }

    if (timestamps.length >= maxRequests) {
      const oldestInWindow = timestamps[0];
      const resetMs = oldestInWindow + windowMs - now;
      return { allowed: false, remaining: 0, resetMs: Math.max(resetMs, 0) };
    }

    timestamps.push(now);
    return {
      allowed: true,
      remaining: maxRequests - timestamps.length,
      resetMs: windowMs,
    };
  }

  _cleanup() {
    const now = Date.now();
    for (const [key, timestamps] of this._windows) {
      // remove keys that have no recent entries (2x max window)
      if (timestamps.length === 0 || now - timestamps[timestamps.length - 1] > 300_000) {
        this._windows.delete(key);
      }
    }
  }

  destroy() {
    clearInterval(this._cleanupInterval);
    this._windows.clear();
  }
}

const rateLimiter = new SlidingWindowRateLimiter();

// =============================================================================
// REQUEST DEDUPLICATION / TRACING
// =============================================================================

const recentRequestIds = new Map(); // requestId → timestamp
setInterval(() => {
  const cutoff = Date.now() - 300_000;
  for (const [id, ts] of recentRequestIds) {
    if (ts < cutoff) recentRequestIds.delete(id);
  }
}, 60_000).unref?.();

// =============================================================================
// METRICS COLLECTOR
// =============================================================================

const metrics = {
  startedAt: new Date().toISOString(),
  totalRequests: 0,
  totalProxied: 0,
  cacheHits: 0,
  cacheMisses: 0,
  rateLimited: 0,
  circuitBroken: 0,
  keyRotations: 0,
  upstreamErrors: 0,
  statusCodes: new Map(),

  recordStatus(code) {
    this.statusCodes.set(code, (this.statusCodes.get(code) || 0) + 1);
  },

  toJSON() {
    return {
      startedAt: this.startedAt,
      uptimeSeconds: Math.floor((Date.now() - new Date(this.startedAt).getTime()) / 1000),
      totalRequests: this.totalRequests,
      totalProxied: this.totalProxied,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      cacheSize: cache.size,
      rateLimited: this.rateLimited,
      circuitBroken: this.circuitBroken,
      keyRotations: this.keyRotations,
      upstreamErrors: this.upstreamErrors,
      circuitBreaker: circuitBreaker.toJSON(),
      apiKeys: {
        total: keyRotator.totalKeys,
        exhausted: keyRotator.exhaustedCount,
      },
      statusCodes: Object.fromEntries(metrics.statusCodes),
    };
  },
};

// =============================================================================
// EXPRESS APP
// =============================================================================

const app = express();

// --- Security middleware (helmet → cors → body parsing) ---
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: MAX_BODY_SIZE }));

// --- Attach request ID + tracing ---
app.use((req, res, next) => {
  const clientId = req.headers["x-request-id"];
  const requestId = clientId && isValidUUID(clientId) ? clientId : crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);
  metrics.totalRequests += 1;
  next();
});

// --- Deduplication check ---
app.use((req, res, next) => {
  const clientId = req.headers["x-idempotency-key"];
  if (clientId && typeof clientId === "string" && clientId.length <= 128) {
    if (recentRequestIds.has(clientId)) {
      return res.status(409).json({
        error: "Duplicate request",
        requestId: req.requestId,
        idempotencyKey: clientId,
      });
    }
    recentRequestIds.set(clientId, Date.now());
  }
  next();
});

// =============================================================================
// RATE LIMITING MIDDLEWARE FACTORY (differentiated by sensitivity)
// =============================================================================

function createRateLimitMiddleware(maxRequests, label) {
  return (req, res, next) => {
    const ip = req.ip || req.socket?.remoteAddress || "unknown";
    const key = `${label}:${ip}`;
    const result = rateLimiter.check(key, RATE_LIMIT_WINDOW_MS, maxRequests);

    res.setHeader("X-RateLimit-Limit", maxRequests);
    res.setHeader("X-RateLimit-Remaining", result.remaining);
    res.setHeader("X-RateLimit-Reset", Math.ceil(result.resetMs / 1000));

    if (!result.allowed) {
      metrics.rateLimited += 1;
      metrics.recordStatus(429);
      return res.status(429).json({
        error: "Too many requests",
        retryAfterMs: result.resetMs,
        requestId: req.requestId,
      });
    }
    next();
  };
}

const defaultRateLimit = createRateLimitMiddleware(RATE_LIMIT_MAX_DEFAULT, "default");
const sensitiveRateLimit = createRateLimitMiddleware(RATE_LIMIT_MAX_SENSITIVE, "sensitive");

// =============================================================================
// OBSERVABILITY ENDPOINTS — health + metrics (sensitive rate limit)
// =============================================================================

app.get("/health", (req, res) => {
  const healthy = circuitBreaker.state !== CircuitState.OPEN;
  res.status(healthy ? 200 : 503).json({
    status: healthy ? "healthy" : "degraded",
    circuitBreaker: circuitBreaker.state,
    uptime: Math.floor((Date.now() - new Date(metrics.startedAt).getTime()) / 1000),
    requestId: req.requestId,
  });
});

app.get("/metrics", sensitiveRateLimit, (req, res) => {
  res.json({ ...metrics.toJSON(), requestId: req.requestId });
});

app.get("/cache", sensitiveRateLimit, (req, res) => {
  const entries = cache.entries();
  res.json({
    size: cache.size,
    entries: entries.slice(0, 100), // paginated, sorted by createdAt
    requestId: req.requestId,
  });
});

// =============================================================================
// HANDLER DISPATCH MAP — route-specific behaviors
// =============================================================================

const routeHandlers = new Map();

// Register a custom handler for a specific upstream path prefix
// (extensible — add entries for special proxy logic per route)
routeHandlers.set("/v1/models", {
  cacheable: true,
  ttl: 300_000, // models list cached 5 min
  sensitive: false,
});

routeHandlers.set("/v1/completions", {
  cacheable: false,
  sensitive: true,
});

function getRouteConfig(path) {
  for (const [prefix, config] of routeHandlers) {
    if (path.startsWith(prefix)) return config;
  }
  return { cacheable: true, ttl: null, sensitive: false };
}

// =============================================================================
// PROXY ENDPOINT — the main proxy route
// =============================================================================

app.all("/proxy/*", defaultRateLimit, async (req, res) => {
  // Extract and validate upstream path
  const rawPath = "/" + req.params[0] + (req.url.includes("?") ? "?" + req.url.split("?")[1] : "");
  const upstreamPath = sanitizePath(rawPath);

  if (!upstreamPath) {
    metrics.recordStatus(400);
    return res.status(400).json({
      error: "Invalid upstream path",
      requestId: req.requestId,
    });
  }

  const routeConfig = getRouteConfig(upstreamPath);

  // Apply sensitive rate-limit if route demands it
  if (routeConfig.sensitive) {
    const ip = req.ip || req.socket?.remoteAddress || "unknown";
    const check = rateLimiter.check(`sensitive:${ip}`, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_SENSITIVE);
    if (!check.allowed) {
      metrics.rateLimited += 1;
      metrics.recordStatus(429);
      return res.status(429).json({
        error: "Too many requests (sensitive endpoint)",
        retryAfterMs: check.resetMs,
        requestId: req.requestId,
      });
    }
  }

  // --- Cache check (only GET requests with cacheable routes) ---
  const cacheKey = `${req.method}:${upstreamPath}`;
  if (req.method === "GET" && routeConfig.cacheable) {
    const cached = cache.get(cacheKey);
    if (cached) {
      metrics.cacheHits += 1;
      res.setHeader("X-Cache", "HIT");
      res.setHeader("X-Request-Id", req.requestId);
      metrics.recordStatus(cached.status);
      return res.status(cached.status).json(cached.body);
    }
    metrics.cacheMisses += 1;
  }

  // --- Circuit breaker check ---
  if (!circuitBreaker.canPass()) {
    metrics.circuitBroken += 1;
    metrics.recordStatus(503);
    return res.status(503).json({
      error: "Service temporarily unavailable (circuit open)",
      circuitBreaker: circuitBreaker.toJSON(),
      requestId: req.requestId,
    });
  }

  // --- Forward request to upstream, with key rotation on 401 ---
  const maxAttempts = keyRotator.totalKeys;
  let lastError = null;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const apiKey = keyRotator.current();
    if (!apiKey) break;

    const targetUrl = `${TARGET_BASE_URL}${upstreamPath}`;
    const headers = {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      "X-Request-Id": req.requestId,
      "X-Forwarded-For": req.ip || req.socket?.remoteAddress || "unknown",
    };

    // Forward relevant headers from client
    if (req.headers["accept"]) headers["Accept"] = req.headers["accept"];
    if (req.headers["accept-language"]) headers["Accept-Language"] = req.headers["accept-language"];

    const fetchOptions = {
      method: req.method,
      headers,
      signal: AbortSignal.timeout(30_000),
    };

    if (req.method !== "GET" && req.method !== "HEAD" && req.body && Object.keys(req.body).length > 0) {
      fetchOptions.body = JSON.stringify(req.body);
    }

    try {
      const upstream = await fetch(targetUrl, fetchOptions);

      if (upstream.status === 401) {
        // Key rejected — rotate to next key
        metrics.keyRotations += 1;
        const nextKey = keyRotator.rotate();
        if (!nextKey) {
          // All keys exhausted
          circuitBreaker.recordFailure();
          metrics.upstreamErrors += 1;
          metrics.recordStatus(502);
          return res.status(502).json({
            error: "All API keys exhausted (401 on all keys)",
            requestId: req.requestId,
          });
        }
        continue;
      }

      let body;
      const contentType = upstream.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        body = await upstream.json();
      } else {
        body = await upstream.text();
      }

      if (upstream.ok) {
        circuitBreaker.recordSuccess();
      } else if (upstream.status >= 500) {
        circuitBreaker.recordFailure();
        metrics.upstreamErrors += 1;
      }

      // Cache successful GET responses
      if (req.method === "GET" && routeConfig.cacheable && upstream.ok) {
        cache.set(cacheKey, { status: upstream.status, body }, routeConfig.ttl);
      }

      metrics.totalProxied += 1;
      metrics.recordStatus(upstream.status);
      res.setHeader("X-Cache", "MISS");
      res.setHeader("X-Upstream-Status", upstream.status);
      return res.status(upstream.status).json(typeof body === "string" ? { data: body } : body);

    } catch (err) {
      lastError = err;
      circuitBreaker.recordFailure();
      metrics.upstreamErrors += 1;

      if (err.name === "TimeoutError" || err.name === "AbortError") {
        metrics.recordStatus(504);
        return res.status(504).json({
          error: "Upstream request timed out",
          requestId: req.requestId,
        });
      }

      // Network error — don't retry with a different key, just fail
      break;
    }
  }

  // If we fell through, something went wrong
  metrics.recordStatus(502);
  return res.status(502).json({
    error: "Failed to proxy request to upstream",
    detail: lastError?.message || "Unknown error",
    requestId: req.requestId,
  });
});

// =============================================================================
// CACHE MANAGEMENT ENDPOINTS
// =============================================================================

app.delete("/cache", sensitiveRateLimit, (req, res) => {
  cache.clear();
  res.json({ message: "Cache cleared", requestId: req.requestId });
});

app.delete("/cache/:key", sensitiveRateLimit, (req, res) => {
  const key = req.params.key;
  if (cache.has(key)) {
    cache.delete(key);
    return res.json({ message: `Cache entry '${key}' deleted`, requestId: req.requestId });
  }
  res.status(404).json({ error: "Cache key not found", requestId: req.requestId });
});

// =============================================================================
// 404 HANDLER
// =============================================================================

app.use((req, res) => {
  metrics.recordStatus(404);
  res.status(404).json({
    error: "Not found",
    path: req.path,
    requestId: req.requestId,
  });
});

// =============================================================================
// GLOBAL ERROR HANDLER — differentiated by error type
// =============================================================================

app.use((err, req, res, _next) => {
  const requestId = req.requestId || crypto.randomUUID();

  // Express body-parser specific errors
  if (err.type === "entity.parse.failed") {
    metrics.recordStatus(400);
    return res.status(400).json({
      error: "Malformed JSON in request body",
      requestId,
    });
  }

  if (err.type === "entity.too.large") {
    metrics.recordStatus(413);
    return res.status(413).json({
      error: `Request body exceeds maximum size (${MAX_BODY_SIZE})`,
      requestId,
    });
  }

  if (err.status === 415) {
    metrics.recordStatus(415);
    return res.status(415).json({
      error: "Unsupported media type",
      requestId,
    });
  }

  // SyntaxError from JSON parsing
  if (err instanceof SyntaxError && err.message.includes("JSON")) {
    metrics.recordStatus(400);
    return res.status(400).json({
      error: "Invalid JSON",
      requestId,
    });
  }

  // URIError from malformed URIs
  if (err instanceof URIError) {
    metrics.recordStatus(400);
    return res.status(400).json({
      error: "Malformed URI",
      requestId,
    });
  }

  // Default 500
  console.error(`[${requestId}] Unhandled error:`, err);
  metrics.recordStatus(500);
  res.status(500).json({
    error: "Internal server error",
    requestId,
  });
});

// =============================================================================
// SERVER START + GRACEFUL SHUTDOWN
// =============================================================================

const server = app.listen(PORT, () => {
  console.log(`API proxy listening on port ${PORT}`);
  console.log(`Target: ${TARGET_BASE_URL}`);
  console.log(`API keys loaded: ${API_KEYS.length}`);
  console.log(`Cache TTL: ${CACHE_TTL_MS}ms`);
  console.log(`Circuit breaker threshold: ${CIRCUIT_FAILURE_THRESHOLD} failures`);
});

// Track active connections for graceful shutdown
const activeConnections = new Set();
server.on("connection", (conn) => {
  activeConnections.add(conn);
  conn.on("close", () => activeConnections.delete(conn));
});

let isShuttingDown = false;

function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\n[${signal}] Graceful shutdown initiated...`);

  // Stop accepting new connections
  server.close(() => {
    console.log("HTTP server closed");
    cache.destroy();
    rateLimiter.destroy();
    console.log("Cleanup complete. Exiting.");
    process.exit(0);
  });

  // Notify existing connections and set timeout
  for (const conn of activeConnections) {
    // Close idle keep-alive connections
    conn.end();
  }

  // Force shutdown after 10s
  setTimeout(() => {
    console.error("Forced shutdown after timeout");
    for (const conn of activeConnections) {
      conn.destroy();
    }
    process.exit(1);
  }, 10_000).unref?.();
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Reject new requests during shutdown
app.use((req, res, next) => {
  if (isShuttingDown) {
    res.setHeader("Connection", "close");
    return res.status(503).json({
      error: "Server is shutting down",
      requestId: req.requestId || crypto.randomUUID(),
    });
  }
  next();
});

export default app;
