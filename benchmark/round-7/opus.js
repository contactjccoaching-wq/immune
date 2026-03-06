import http from "node:http";
import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// 1. Environment validation — fail fast at startup
// ---------------------------------------------------------------------------
const REQUIRED_ENV = ["WEBHOOK_SECRET", "PORT"];
const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missing.length) {
  process.stderr.write(
    JSON.stringify({
      level: "fatal",
      ts: new Date().toISOString(),
      msg: "Missing required environment variables",
      missing,
    }) + "\n"
  );
  process.exit(1);
}

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const PORT = Number(process.env.PORT) || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES) || 1_048_576; // 1 MB
const IDEMPOTENCY_TTL_MS =
  Number(process.env.IDEMPOTENCY_TTL_MS) || 24 * 60 * 60 * 1000; // 24 h
const IDEMPOTENCY_MAX_SIZE =
  Number(process.env.IDEMPOTENCY_MAX_SIZE) || 100_000;
const CLEANUP_INTERVAL_MS =
  Number(process.env.CLEANUP_INTERVAL_MS) || 60 * 60 * 1000; // 1 h

// ---------------------------------------------------------------------------
// 2. Structured JSON logger
// ---------------------------------------------------------------------------
class Logger {
  #write(level, msg, extra = {}) {
    const entry = {
      level,
      ts: new Date().toISOString(),
      msg,
      ...extra,
    };
    const stream = level === "error" || level === "fatal" ? process.stderr : process.stdout;
    stream.write(JSON.stringify(entry) + "\n");
  }
  info(msg, extra) {
    this.#write("info", msg, extra);
  }
  warn(msg, extra) {
    this.#write("warn", msg, extra);
  }
  error(msg, extra) {
    this.#write("error", msg, extra);
  }
  fatal(msg, extra) {
    this.#write("fatal", msg, extra);
  }
}

const log = new Logger();

// ---------------------------------------------------------------------------
// 3. Bounded Map with TTL for idempotency / rate-limiting
// ---------------------------------------------------------------------------
class BoundedTTLMap {
  #map = new Map();
  #maxSize;
  #ttlMs;

  constructor(maxSize, ttlMs) {
    this.#maxSize = maxSize;
    this.#ttlMs = ttlMs;
  }

  set(key, value) {
    // Evict oldest entry when at capacity
    if (this.#map.size >= this.#maxSize && !this.#map.has(key)) {
      const oldest = this.#map.keys().next().value;
      this.#map.delete(oldest);
    }
    this.#map.set(key, { value, expiresAt: Date.now() + this.#ttlMs });
  }

  get(key) {
    const entry = this.#map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.#map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  delete(key) {
    return this.#map.delete(key);
  }

  /** Remove all expired entries */
  prune() {
    const now = Date.now();
    let pruned = 0;
    for (const [k, v] of this.#map) {
      if (now > v.expiresAt) {
        this.#map.delete(k);
        pruned++;
      }
    }
    return pruned;
  }

  get size() {
    return this.#map.size;
  }
}

// ---------------------------------------------------------------------------
// 4. Idempotency store (event ID -> processing status)
// ---------------------------------------------------------------------------
const idempotencyStore = new BoundedTTLMap(IDEMPOTENCY_MAX_SIZE, IDEMPOTENCY_TTL_MS);

// Periodic cleanup
const cleanupTimer = setInterval(() => {
  const pruned = idempotencyStore.prune();
  if (pruned > 0) {
    log.info("Idempotency store pruned", { pruned, remaining: idempotencyStore.size });
  }
}, CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

// ---------------------------------------------------------------------------
// 5. Retry logic with exponential backoff (class-based)
// ---------------------------------------------------------------------------
class RetryExecutor {
  #maxAttempts;
  #baseDelayMs;
  #maxDelayMs;
  #jitter;

  constructor({ maxAttempts = 5, baseDelayMs = 500, maxDelayMs = 30_000, jitter = true } = {}) {
    this.#maxAttempts = maxAttempts;
    this.#baseDelayMs = baseDelayMs;
    this.#maxDelayMs = maxDelayMs;
    this.#jitter = jitter;
  }

  async execute(fn, context = {}) {
    let lastError;
    for (let attempt = 1; attempt <= this.#maxAttempts; attempt++) {
      try {
        return await fn(attempt);
      } catch (err) {
        lastError = err;

        // Do not retry non-retryable errors
        if (err.retryable === false) throw err;

        if (attempt < this.#maxAttempts) {
          const delay = this.#computeDelay(attempt);
          log.warn("Handler failed, retrying", {
            attempt,
            maxAttempts: this.#maxAttempts,
            nextRetryMs: delay,
            error: err.message,
            ...context,
          });
          await sleep(delay);
        }
      }
    }
    throw lastError;
  }

  #computeDelay(attempt) {
    let delay = this.#baseDelayMs * Math.pow(2, attempt - 1);
    if (this.#jitter) {
      delay *= 0.5 + Math.random(); // 50-150 % of calculated delay
    }
    return Math.min(delay, this.#maxDelayMs);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const retrier = new RetryExecutor({
  maxAttempts: 5,
  baseDelayMs: 500,
  maxDelayMs: 30_000,
});

// ---------------------------------------------------------------------------
// 6. Rate limiters (differentiated by endpoint)
// ---------------------------------------------------------------------------
class RateLimiter {
  #store;
  #windowMs;
  #maxRequests;

  constructor(windowMs, maxRequests, maxSize = 50_000) {
    this.#store = new BoundedTTLMap(maxSize, windowMs);
    this.#windowMs = windowMs;
    this.#maxRequests = maxRequests;
  }

  /** Returns true if request is allowed */
  allow(key) {
    const record = this.#store.get(key);
    if (!record) {
      this.#store.set(key, { count: 1, windowStart: Date.now() });
      return true;
    }
    if (record.count >= this.#maxRequests) return false;
    record.count++;
    this.#store.set(key, record);
    return true;
  }

  get windowMs() {
    return this.#windowMs;
  }

  get maxRequests() {
    return this.#maxRequests;
  }
}

const webhookLimiter = new RateLimiter(60_000, 120); // 120 req/min for webhook
const healthLimiter = new RateLimiter(60_000, 300); // 300 req/min for health

// ---------------------------------------------------------------------------
// 7. HMAC signature validation
// ---------------------------------------------------------------------------
function verifySignature(payload, signatureHeader) {
  if (!signatureHeader) return false;

  // Support "sha256=<hex>" format (GitHub-style) or raw hex
  const parts = signatureHeader.split("=");
  const algo = parts.length === 2 ? parts[0] : "sha256";
  const receivedSig = parts.length === 2 ? parts[1] : parts[0];

  const computed = crypto.createHmac(algo, WEBHOOK_SECRET).update(payload).digest("hex");

  // Constant-time comparison
  try {
    return crypto.timingSafeEqual(Buffer.from(computed, "hex"), Buffer.from(receivedSig, "hex"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 8. Event handlers registry
// ---------------------------------------------------------------------------
const eventHandlers = new Map();

function registerHandler(eventType, handler) {
  if (!eventHandlers.has(eventType)) {
    eventHandlers.set(eventType, []);
  }
  eventHandlers.get(eventType).push(handler);
}

// Example handlers — replace with real business logic
registerHandler("order.created", async (event, attempt) => {
  log.info("Processing order.created", { eventId: event.id, attempt });
  // ... business logic ...
});

registerHandler("user.updated", async (event, attempt) => {
  log.info("Processing user.updated", { eventId: event.id, attempt });
  // ... business logic ...
});

registerHandler("payment.completed", async (event, attempt) => {
  log.info("Processing payment.completed", { eventId: event.id, attempt });
  // ... business logic ...
});

// ---------------------------------------------------------------------------
// 9. Core webhook processing (idempotent + retries)
// ---------------------------------------------------------------------------
async function processWebhookEvent(event) {
  const eventId = event.id;
  const eventType = event.type;
  const requestId = crypto.randomUUID();

  // Idempotency check
  const existing = idempotencyStore.get(eventId);
  if (existing) {
    if (existing.status === "completed") {
      log.info("Duplicate event, already processed", { eventId, requestId });
      return { status: "duplicate", eventId };
    }
    if (existing.status === "processing") {
      log.info("Duplicate event, currently processing", { eventId, requestId });
      return { status: "duplicate", eventId };
    }
    // status === "failed" — allow retry
  }

  // Mark as processing
  idempotencyStore.set(eventId, { status: "processing", requestId });

  const handlers = eventHandlers.get(eventType) || [];
  if (handlers.length === 0) {
    log.warn("No handler registered for event type", { eventType, eventId, requestId });
    idempotencyStore.set(eventId, { status: "completed", requestId, note: "no_handler" });
    return { status: "no_handler", eventId };
  }

  const results = [];
  let allSucceeded = true;

  for (const handler of handlers) {
    try {
      await retrier.execute(
        (attempt) => handler(event, attempt),
        { eventId, eventType, requestId }
      );
      results.push({ handler: handler.name || "anonymous", status: "ok" });
    } catch (err) {
      allSucceeded = false;
      results.push({ handler: handler.name || "anonymous", status: "failed", error: err.message });
      log.error("Handler exhausted all retries", {
        eventId,
        eventType,
        requestId,
        error: err.message,
        stack: err.stack,
      });
    }
  }

  const finalStatus = allSucceeded ? "completed" : "partial_failure";
  idempotencyStore.set(eventId, { status: finalStatus, requestId, results });

  log.info("Event processing finished", { eventId, eventType, requestId, finalStatus });
  return { status: finalStatus, eventId, requestId, results };
}

// ---------------------------------------------------------------------------
// 10. Input validation
// ---------------------------------------------------------------------------
class ValidationError extends Error {
  constructor(message, details) {
    super(message);
    this.name = "ValidationError";
    this.statusCode = 400;
    this.retryable = false;
    this.details = details;
  }
}

class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthError";
    this.statusCode = 401;
    this.retryable = false;
  }
}

class RateLimitError extends Error {
  constructor(retryAfterMs) {
    super("Rate limit exceeded");
    this.name = "RateLimitError";
    this.statusCode = 429;
    this.retryable = false;
    this.retryAfterMs = retryAfterMs;
  }
}

function validateWebhookPayload(body) {
  if (!body || typeof body !== "object") {
    throw new ValidationError("Body must be a JSON object");
  }
  if (typeof body.id !== "string" || body.id.length === 0 || body.id.length > 256) {
    throw new ValidationError("Event 'id' must be a non-empty string (max 256 chars)", {
      field: "id",
    });
  }
  if (typeof body.type !== "string" || body.type.length === 0 || body.type.length > 128) {
    throw new ValidationError("Event 'type' must be a non-empty string (max 128 chars)", {
      field: "type",
    });
  }
  // Reject prototype pollution keys
  if ("__proto__" in body || "constructor" in body || "prototype" in body) {
    throw new ValidationError("Payload contains forbidden keys");
  }
  return body;
}

// ---------------------------------------------------------------------------
// 11. Body parser helper
// ---------------------------------------------------------------------------
function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    req.on("data", (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        req.destroy();
        reject(new ValidationError(`Request body exceeds ${maxBytes} bytes limit`));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// 12. HTTP helpers
// ---------------------------------------------------------------------------
function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    // Security headers (helmet-equivalent)
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Cache-Control": "no-store",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  res.end(body);
}

function clientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

// ---------------------------------------------------------------------------
// 13. Request handler / router
// ---------------------------------------------------------------------------
async function handleRequest(req, res) {
  const ip = clientIP(req);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const path = url.pathname;
  const method = req.method;

  // CORS preflight
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": CORS_ORIGIN,
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Signature-256, X-Webhook-Id",
      "Access-Control-Max-Age": "86400",
    });
    res.end();
    return;
  }

  // Add CORS header to all responses
  res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);

  // ---- Health endpoint ----
  if (path === "/health" && method === "GET") {
    if (!healthLimiter.allow(ip)) {
      throw new RateLimitError(healthLimiter.windowMs);
    }
    sendJSON(res, 200, {
      status: "ok",
      uptime: process.uptime(),
      idempotencyStoreSize: idempotencyStore.size,
    });
    return;
  }

  // ---- Webhook endpoint ----
  if (path === "/webhook" && method === "POST") {
    if (!webhookLimiter.allow(ip)) {
      throw new RateLimitError(webhookLimiter.windowMs);
    }

    // Read raw body for HMAC verification
    const rawBody = await readBody(req, MAX_BODY_BYTES);

    // Verify HMAC signature
    const signature =
      req.headers["x-signature-256"] ||
      req.headers["x-hub-signature-256"] ||
      req.headers["x-signature"];
    if (!verifySignature(rawBody, signature)) {
      throw new AuthError("Invalid HMAC signature");
    }

    // Parse JSON
    let parsed;
    try {
      parsed = JSON.parse(rawBody.toString("utf-8"));
    } catch {
      throw new ValidationError("Malformed JSON body");
    }

    // Validate payload
    const event = validateWebhookPayload(parsed);

    log.info("Webhook received", {
      eventId: event.id,
      eventType: event.type,
      ip,
    });

    // Process asynchronously but respond after processing so the caller knows the result
    const result = await processWebhookEvent(event);

    const statusCode = result.status === "duplicate" ? 200 : result.status === "completed" || result.status === "no_handler" ? 200 : 207;
    sendJSON(res, statusCode, result);
    return;
  }

  // ---- 404 ----
  sendJSON(res, 404, { error: "Not found", path });
}

// ---------------------------------------------------------------------------
// 14. Global error handler
// ---------------------------------------------------------------------------
function handleError(err, req, res) {
  if (res.headersSent) return;

  if (err instanceof ValidationError) {
    log.warn("Validation error", { error: err.message, details: err.details });
    sendJSON(res, err.statusCode, {
      error: err.message,
      details: err.details || undefined,
    });
  } else if (err instanceof AuthError) {
    log.warn("Auth error", { error: err.message, ip: clientIP(req) });
    sendJSON(res, err.statusCode, { error: err.message });
  } else if (err instanceof RateLimitError) {
    log.warn("Rate limited", { ip: clientIP(req) });
    res.setHeader("Retry-After", Math.ceil(err.retryAfterMs / 1000));
    sendJSON(res, err.statusCode, { error: err.message });
  } else {
    // Unexpected error — do not leak internals
    log.error("Unhandled error", {
      error: err.message,
      stack: err.stack,
      ip: clientIP(req),
    });
    sendJSON(res, 500, { error: "Internal server error" });
  }
}

// ---------------------------------------------------------------------------
// 15. Server creation with active connection tracking + graceful shutdown
// ---------------------------------------------------------------------------
const activeConnections = new Set();

const server = http.createServer(async (req, res) => {
  activeConnections.add(res);
  res.on("close", () => activeConnections.delete(res));

  try {
    await handleRequest(req, res);
  } catch (err) {
    handleError(err, req, res);
  }
});

server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;

server.listen(PORT, () => {
  log.info("Webhook receiver started", { port: PORT });
});

// ---------------------------------------------------------------------------
// 16. Graceful shutdown
// ---------------------------------------------------------------------------
let isShuttingDown = false;

async function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  log.info("Graceful shutdown initiated", { signal, activeConnections: activeConnections.size });

  // Stop accepting new connections
  server.close(() => {
    log.info("Server closed, no more connections");
    clearInterval(cleanupTimer);
    process.exit(0);
  });

  // Give active connections time to finish (10s)
  const forceTimeout = setTimeout(() => {
    log.warn("Force shutdown — killing remaining connections", {
      remaining: activeConnections.size,
    });
    for (const res of activeConnections) {
      try {
        res.destroy();
      } catch {
        // ignore
      }
    }
    process.exit(1);
  }, 10_000);
  forceTimeout.unref();
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Catch unhandled rejections/exceptions
process.on("unhandledRejection", (reason) => {
  log.error("Unhandled rejection", {
    error: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});

process.on("uncaughtException", (err) => {
  log.fatal("Uncaught exception — shutting down", { error: err.message, stack: err.stack });
  gracefulShutdown("uncaughtException");
});
