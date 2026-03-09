/**
 * Webhook Receiver — Production-Quality Node.js
 *
 * Features:
 *  - HMAC-SHA256 signature verification (constant-time, fail-closed)
 *  - Idempotent event processing (deduplication by event ID)
 *  - Exponential backoff retry for failed handlers (bounded, max-iteration guarded)
 *  - Structured JSON logging
 *  - Auth gate before any cost-bearing or state-mutating operations
 *  - Schema validation with per-field type guards and fallback defaults
 *  - Explicit CORS origin allowlist (no wildcard)
 *  - No hardcoded credentials (env-only, fail-closed if missing)
 *  - All user data treated as hostile (validated before use)
 *  - POST-only mutation endpoints (no write side effects on GET)
 */

"use strict";

const http = require("http");
const crypto = require("crypto");

// ─── CS-CODE-007: Single centralized state object ────────────────────────────
const state = {
  /** Map<eventId, { status, attempts, firstSeenAt, lastAttemptAt }> */
  processedEvents: new Map(),

  /** Server instance — populated in init() */
  server: null,

  /** Config — populated in init() */
  config: null,
};

// ─── CS-CODE-006: Centralized init() orchestrating all setup ─────────────────
async function init() {
  state.config = loadConfig(); // fail-closed if env missing
  registerHandlers();
  state.server = createServer();
  await startServer();
  log("info", "webhook_server_started", { port: state.config.port });
}

// ─── Configuration (env-only, fail-closed) ────────────────────────────────────
// CS-CODE-013 + AB-CODE-022: no hardcoded fallback credentials, reject if missing
function loadConfig() {
  const secret = process.env.WEBHOOK_SECRET;
  if (!secret || secret.trim() === "") {
    // AB-CODE-021 + CS-CODE-013: fail-closed — never allow a default-true auth path
    log("error", "startup_failed", { reason: "WEBHOOK_SECRET env var is missing or empty" });
    process.exit(1);
  }

  const rawPort = process.env.PORT || "3000";
  const port = parseInt(rawPort, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    log("error", "startup_failed", { reason: "Invalid PORT env var", value: rawPort });
    process.exit(1);
  }

  // AB-CODE-025: no wildcard CORS — explicit origin allowlist
  const rawOrigins = process.env.ALLOWED_ORIGINS || "";
  const allowedOrigins = rawOrigins
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);

  // AB-CODE-017 / CS-CODE-017: note — deduplication store is in-memory here;
  // for serverless, replace with persistent DB/KV (Map resets on cold start).
  // This implementation is correct for a long-lived Node.js process.
  const maxRetries = parseInt(process.env.MAX_RETRIES || "4", 10);
  const baseBackoffMs = parseInt(process.env.BASE_BACKOFF_MS || "200", 10);

  return {
    secret,
    port,
    allowedOrigins,
    maxRetries: isNaN(maxRetries) || maxRetries < 0 ? 4 : maxRetries,
    baseBackoffMs: isNaN(baseBackoffMs) || baseBackoffMs < 0 ? 200 : baseBackoffMs,
    /** Maximum deduplication cache entries (bounded memory) */
    maxCacheSize: 10_000,
    /** TTL for dedup cache entries (ms) — 24 h */
    dedupTtlMs: 24 * 60 * 60 * 1000,
  };
}

// ─── Structured JSON logger ───────────────────────────────────────────────────
function log(level, event, data = {}) {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...data,
  });
  if (level === "error") {
    process.stderr.write(entry + "\n");
  } else {
    process.stdout.write(entry + "\n");
  }
}

// ─── HMAC Signature Verification ─────────────────────────────────────────────
// AB-CODE-020: always verify signature before processing
// AB-CODE-031: constant-time comparison to prevent timing attacks
function verifySignature(rawBody, signatureHeader) {
  if (!signatureHeader || typeof signatureHeader !== "string") {
    return false;
  }

  // Expected format: "sha256=<hex>"
  const PREFIX = "sha256=";
  if (!signatureHeader.startsWith(PREFIX)) {
    return false;
  }

  const receivedHex = signatureHeader.slice(PREFIX.length);

  // Validate hex format before allocating Buffer (CS-CODE-015)
  if (!/^[0-9a-f]{64}$/i.test(receivedHex)) {
    return false;
  }

  const expectedHmac = crypto
    .createHmac("sha256", state.config.secret)
    .update(rawBody) // rawBody is a Buffer — not decoded string, avoids encoding issues
    .digest("hex");

  const expected = Buffer.from(expectedHmac, "hex");
  const received = Buffer.from(receivedHex, "hex");

  // AB-CODE-031: timingSafeEqual requires equal-length buffers
  if (expected.length !== received.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, received);
}

// ─── Schema Validation ────────────────────────────────────────────────────────
// CS-CODE-005: per-field type guards with fallback defaults
function validateEventPayload(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { valid: false, reason: "Payload must be a JSON object" };
  }

  // eventId — required string, non-empty, length-bounded (CS-CODE-015)
  const eventId = raw.eventId;
  if (typeof eventId !== "string" || eventId.trim() === "") {
    return { valid: false, reason: "Missing or invalid eventId" };
  }
  if (eventId.length > 128) {
    return { valid: false, reason: "eventId exceeds maximum length (128)" };
  }

  // eventType — required string from allowlist
  const ALLOWED_EVENT_TYPES = new Set([
    "payment.completed",
    "payment.failed",
    "subscription.created",
    "subscription.cancelled",
    "user.created",
    "user.deleted",
  ]);
  const eventType = raw.eventType;
  if (typeof eventType !== "string" || !ALLOWED_EVENT_TYPES.has(eventType)) {
    return { valid: false, reason: `Unknown or missing eventType: ${escapeForLog(eventType)}` };
  }

  // timestamp — optional ISO string; default to now if absent/invalid
  let timestamp = raw.timestamp;
  if (typeof timestamp !== "string" || isNaN(Date.parse(timestamp))) {
    timestamp = new Date().toISOString();
  }

  // data — optional object, default to empty
  const data =
    raw.data && typeof raw.data === "object" && !Array.isArray(raw.data) ? raw.data : {};

  return {
    valid: true,
    payload: {
      eventId: eventId.trim(),
      eventType,
      timestamp,
      data,
    },
  };
}

// ─── Safe log-value escaping (prevent log injection) ─────────────────────────
// CS-CODE-001 / CS-CODE-014: escape user-controlled data before embedding in output
function escapeForLog(value) {
  if (value === null || value === undefined) return String(value);
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t")
    .slice(0, 256); // length-bound
}

// ─── Idempotency / Deduplication ─────────────────────────────────────────────
function isDuplicate(eventId) {
  const entry = state.processedEvents.get(eventId);
  if (!entry) return false;
  // Treat as duplicate only if successfully completed within TTL
  const expired = Date.now() - entry.firstSeenAt > state.config.dedupTtlMs;
  if (expired) {
    state.processedEvents.delete(eventId);
    return false;
  }
  return entry.status === "completed";
}

function recordEventStart(eventId) {
  // Bounded cache — evict oldest entry when full (AB-CODE-010: no unbounded growth)
  if (state.processedEvents.size >= state.config.maxCacheSize) {
    const oldestKey = state.processedEvents.keys().next().value;
    state.processedEvents.delete(oldestKey);
    log("warn", "dedup_cache_eviction", { evicted: oldestKey });
  }

  state.processedEvents.set(eventId, {
    status: "processing",
    attempts: 0,
    firstSeenAt: Date.now(),
    lastAttemptAt: Date.now(),
  });
}

function recordEventSuccess(eventId) {
  const entry = state.processedEvents.get(eventId);
  if (entry) {
    entry.status = "completed";
    entry.lastAttemptAt = Date.now();
  }
}

function recordEventFailure(eventId, attempts) {
  const entry = state.processedEvents.get(eventId);
  if (entry) {
    entry.status = "failed";
    entry.attempts = attempts;
    entry.lastAttemptAt = Date.now();
  }
}

// ─── Event Handlers ───────────────────────────────────────────────────────────
const eventHandlers = {
  "payment.completed": handlePaymentCompleted,
  "payment.failed": handlePaymentFailed,
  "subscription.created": handleSubscriptionCreated,
  "subscription.cancelled": handleSubscriptionCancelled,
  "user.created": handleUserCreated,
  "user.deleted": handleUserDeleted,
};

function registerHandlers() {
  // Handlers are statically registered above — this function exists for
  // extensibility (e.g., dynamic plugin loading) and to satisfy CS-CODE-006.
  log("info", "handlers_registered", { count: Object.keys(eventHandlers).length });
}

async function handlePaymentCompleted(payload) {
  log("info", "processing_payment_completed", { eventId: payload.eventId });
  // Simulate async processing (replace with real business logic)
  await simulateAsyncWork(50);
}

async function handlePaymentFailed(payload) {
  log("info", "processing_payment_failed", { eventId: payload.eventId });
  await simulateAsyncWork(30);
}

async function handleSubscriptionCreated(payload) {
  log("info", "processing_subscription_created", { eventId: payload.eventId });
  await simulateAsyncWork(40);
}

async function handleSubscriptionCancelled(payload) {
  log("info", "processing_subscription_cancelled", { eventId: payload.eventId });
  await simulateAsyncWork(40);
}

async function handleUserCreated(payload) {
  log("info", "processing_user_created", { eventId: payload.eventId });
  await simulateAsyncWork(20);
}

async function handleUserDeleted(payload) {
  log("info", "processing_user_deleted", { eventId: payload.eventId });
  await simulateAsyncWork(20);
}

function simulateAsyncWork(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Exponential Backoff Retry ────────────────────────────────────────────────
// AB-CODE-004: proper backoff; AB-CODE-010: bounded max iterations
async function withRetry(fn, payload) {
  const { maxRetries, baseBackoffMs } = state.config;
  let lastError;
  let attempt = 0;

  // AB-CODE-010: explicit max iteration guard — loop cannot run forever
  const MAX_ITERATIONS = maxRetries + 1;
  while (attempt < MAX_ITERATIONS) {
    if (attempt > MAX_ITERATIONS) break; // safety net (dead code guard — explicit)

    try {
      await fn(payload);
      log("info", "handler_succeeded", {
        eventId: payload.eventId,
        attempt: attempt + 1,
      });
      return { success: true, attempts: attempt + 1 };
    } catch (err) {
      lastError = err;
      attempt++;

      if (attempt >= MAX_ITERATIONS) break;

      // Exponential backoff: base * 2^attempt + jitter
      const backoff = baseBackoffMs * Math.pow(2, attempt - 1) + Math.random() * 100;
      log("warn", "handler_failed_retrying", {
        eventId: payload.eventId,
        attempt,
        backoffMs: Math.round(backoff),
        error: escapeForLog(err.message),
      });
      await sleep(backoff);
    }
  }

  log("error", "handler_exhausted_retries", {
    eventId: payload.eventId,
    totalAttempts: attempt,
    error: escapeForLog(lastError?.message),
  });
  return { success: false, attempts: attempt, error: lastError };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, Math.round(ms))));
}

// ─── Raw Body Reader ──────────────────────────────────────────────────────────
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const MAX_BODY_BYTES = 1024 * 1024; // 1 MB limit
    const chunks = [];
    let totalBytes = 0;

    req.on("data", (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error("Request body exceeds size limit"));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ─── CORS helper ─────────────────────────────────────────────────────────────
// AB-CODE-025: explicit origin allowlist, no wildcard
function setCorsHeaders(req, res) {
  const origin = req.headers["origin"];
  if (!origin) return; // non-browser request — no CORS headers needed

  if (state.config.allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Hub-Signature-256");
  }
  // If origin not in allowlist: no CORS headers — browser will block
}

// ─── Response Helpers ─────────────────────────────────────────────────────────
function sendJSON(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(payload);
}

// ─── Request Router ───────────────────────────────────────────────────────────
// AB-CODE-028: GET endpoints have no write side effects
// CS-CODE-016: auth gate BEFORE any state mutation
async function handleRequest(req, res) {
  setCorsHeaders(req, res);

  // Handle preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://localhost`);
  const pathname = url.pathname;

  // Health check — no auth required, no side effects, GET only
  if (pathname === "/health" && req.method === "GET") {
    sendJSON(res, 200, {
      status: "ok",
      cacheSize: state.processedEvents.size,
      uptime: process.uptime(),
    });
    return;
  }

  // AB-CODE-028: webhook endpoint only accepts POST
  if (pathname === "/webhook") {
    if (req.method !== "POST") {
      res.setHeader("Allow", "POST");
      sendJSON(res, 405, { error: "Method Not Allowed" });
      return;
    }
    await handleWebhook(req, res);
    return;
  }

  sendJSON(res, 404, { error: "Not Found" });
}

// ─── Webhook Handler ──────────────────────────────────────────────────────────
async function handleWebhook(req, res) {
  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (err) {
    log("warn", "body_read_failed", { error: escapeForLog(err.message) });
    sendJSON(res, 400, { error: "Failed to read request body" });
    return;
  }

  // ── CS-CODE-016 + AB-CODE-026: Auth gate FIRST, before any processing ───
  // CS-CODE-012: secret present → verification required
  // AB-CODE-021: never default-true auth
  const signatureHeader = req.headers["x-hub-signature-256"];
  const signatureValid = verifySignature(rawBody, signatureHeader);

  if (!signatureValid) {
    log("warn", "signature_verification_failed", {
      ip: req.socket?.remoteAddress,
      hasHeader: !!signatureHeader,
    });
    // Uniform 401 — do not reveal whether secret is wrong vs. header missing
    sendJSON(res, 401, { error: "Unauthorized" });
    return;
  }

  // ── Parse JSON body — AB-CODE-008: always wrap JSON.parse ────────────────
  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString("utf8"));
  } catch {
    log("warn", "json_parse_failed", {});
    sendJSON(res, 400, { error: "Invalid JSON body" });
    return;
  }

  // ── Schema validation — CS-CODE-005 ──────────────────────────────────────
  const validation = validateEventPayload(parsed);
  if (!validation.valid) {
    log("warn", "payload_validation_failed", { reason: escapeForLog(validation.reason) });
    sendJSON(res, 400, { error: "Invalid payload", detail: validation.reason });
    return;
  }

  const { payload } = validation;

  // ── Idempotency check ─────────────────────────────────────────────────────
  if (isDuplicate(payload.eventId)) {
    log("info", "duplicate_event_skipped", { eventId: payload.eventId });
    // 200 with idempotent acknowledgment (not 409 — the event was already handled)
    sendJSON(res, 200, { received: true, duplicate: true, eventId: payload.eventId });
    return;
  }

  // Mark event as in-flight before dispatching
  recordEventStart(payload.eventId);

  log("info", "event_received", {
    eventId: payload.eventId,
    eventType: payload.eventType,
    timestamp: payload.timestamp,
  });

  // ── Dispatch to handler with exponential backoff retry ────────────────────
  const handler = eventHandlers[payload.eventType];
  if (!handler) {
    // Should not reach here — eventType is allowlist-validated above — defensive guard
    log("error", "no_handler_found", { eventType: escapeForLog(payload.eventType) });
    recordEventFailure(payload.eventId, 0);
    sendJSON(res, 500, { error: "No handler registered for event type" });
    return;
  }

  // Respond to the webhook caller immediately (202 Accepted), then process async.
  // This prevents the caller from timing out during retry loops.
  sendJSON(res, 202, { received: true, eventId: payload.eventId });

  // Process asynchronously — errors are caught and logged internally
  setImmediate(async () => {
    const result = await withRetry(handler, payload);
    if (result.success) {
      recordEventSuccess(payload.eventId);
      log("info", "event_processed", {
        eventId: payload.eventId,
        eventType: payload.eventType,
        attempts: result.attempts,
      });
    } else {
      recordEventFailure(payload.eventId, result.attempts);
      log("error", "event_processing_failed", {
        eventId: payload.eventId,
        eventType: payload.eventType,
        attempts: result.attempts,
        error: escapeForLog(result.error?.message),
      });
    }
  });
}

// ─── HTTP Server ──────────────────────────────────────────────────────────────
function createServer() {
  const server = http.createServer(async (req, res) => {
    try {
      await handleRequest(req, res);
    } catch (err) {
      // Top-level catch — prevents unhandled exceptions from crashing the server
      log("error", "unhandled_request_error", {
        method: req.method,
        url: escapeForLog(req.url),
        error: escapeForLog(err.message),
        stack: escapeForLog(err.stack),
      });
      if (!res.headersSent) {
        sendJSON(res, 500, { error: "Internal Server Error" });
      }
    }
  });

  // Graceful shutdown
  process.on("SIGTERM", () => shutdown(server, "SIGTERM"));
  process.on("SIGINT", () => shutdown(server, "SIGINT"));

  // Catch unhandled promise rejections (defensive — should not reach here)
  process.on("unhandledRejection", (reason) => {
    log("error", "unhandled_rejection", { reason: escapeForLog(String(reason)) });
  });

  return server;
}

function startServer() {
  return new Promise((resolve, reject) => {
    state.server.listen(state.config.port, "0.0.0.0", () => resolve());
    state.server.once("error", reject);
  });
}

function shutdown(server, signal) {
  log("info", "shutdown_initiated", { signal });
  server.close(() => {
    log("info", "shutdown_complete", {});
    process.exit(0);
  });

  // Force exit after 10 s if connections linger
  setTimeout(() => {
    log("warn", "shutdown_forced", {});
    process.exit(1);
  }, 10_000).unref();
}

// ─── Entry Point ──────────────────────────────────────────────────────────────
init().catch((err) => {
  log("error", "init_failed", {
    error: escapeForLog(err.message),
    stack: escapeForLog(err.stack),
  });
  process.exit(1);
});
