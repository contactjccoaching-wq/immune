"use strict";

/**
 * Webhook Receiver
 *
 * Features:
 * - HMAC-SHA256 signature validation
 * - Idempotent event processing (deduplication by event ID)
 * - Retry with exponential backoff for failed handlers
 * - Structured JSON logging
 */

const http = require("http");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CONFIG = {
  port: parseInt(process.env.PORT || "3000", 10),
  hmacSecret: process.env.WEBHOOK_SECRET || "",
  hmacHeader: process.env.HMAC_HEADER || "x-hub-signature-256",
  hmacAlgorithm: "sha256",
  maxBodyBytes: 1 * 1024 * 1024, // 1 MB
  dedup: {
    ttlMs: 24 * 60 * 60 * 1000, // 24 hours
    maxSize: 100_000,            // max entries before eviction
  },
  retry: {
    maxAttempts: 4,
    baseDelayMs: 250,
    maxDelayMs: 30_000,
    jitterFactor: 0.2,
  },
};

// ---------------------------------------------------------------------------
// Structured JSON Logger
// ---------------------------------------------------------------------------

const LOG_LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL] ?? LOG_LEVELS.info;

function log(level, message, fields = {}) {
  if ((LOG_LEVELS[level] ?? 0) < MIN_LEVEL) return;

  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...fields,
  };

  const output = JSON.stringify(entry);

  if (level === "error" || level === "warn") {
    process.stderr.write(output + "\n");
  } else {
    process.stdout.write(output + "\n");
  }
}

const logger = {
  debug: (msg, fields) => log("debug", msg, fields),
  info:  (msg, fields) => log("info",  msg, fields),
  warn:  (msg, fields) => log("warn",  msg, fields),
  error: (msg, fields) => log("error", msg, fields),
};

// ---------------------------------------------------------------------------
// Deduplication Store
// ---------------------------------------------------------------------------

/**
 * In-memory store that maps eventId → processedAtMs.
 * Expired entries are lazily evicted on each check.
 * If the store grows beyond maxSize, all expired entries are purged eagerly.
 */
class DeduplicationStore {
  constructor({ ttlMs, maxSize }) {
    this._ttlMs = ttlMs;
    this._maxSize = maxSize;
    this._store = new Map();
  }

  /**
   * Returns true if the event ID has already been processed and is not expired.
   * Also marks the event as processed when returning false (first-time seen).
   */
  checkAndMark(eventId) {
    this._evictExpiredIfNeeded();

    const now = Date.now();
    const existing = this._store.get(eventId);

    if (existing !== undefined) {
      if (now - existing < this._ttlMs) {
        return true; // duplicate
      }
      // Entry is expired — fall through and refresh it
    }

    this._store.set(eventId, now);
    return false; // first time seen (or expired and refreshed)
  }

  _evictExpiredIfNeeded() {
    if (this._store.size < this._maxSize) return;

    const cutoff = Date.now() - this._ttlMs;
    for (const [id, ts] of this._store) {
      if (ts < cutoff) this._store.delete(id);
    }

    logger.warn("dedup_store_eviction", { remainingEntries: this._store.size });
  }

  get size() {
    return this._store.size;
  }
}

// ---------------------------------------------------------------------------
// HMAC Signature Validation
// ---------------------------------------------------------------------------

/**
 * Validates the HMAC-SHA256 signature of the raw request body.
 *
 * The expected header value format is either:
 *   sha256=<hex>   (GitHub style)
 *   <hex>          (raw hex)
 *
 * @param {Buffer} rawBody
 * @param {string} signatureHeader - value from the HTTP header
 * @returns {boolean}
 */
function validateHmacSignature(rawBody, signatureHeader) {
  if (!CONFIG.hmacSecret) {
    logger.warn("hmac_secret_not_configured");
    return false;
  }

  if (!signatureHeader || typeof signatureHeader !== "string") {
    return false;
  }

  const rawSignature = signatureHeader.startsWith(`${CONFIG.hmacAlgorithm}=`)
    ? signatureHeader.slice(CONFIG.hmacAlgorithm.length + 1)
    : signatureHeader;

  if (!rawSignature) return false;

  const expected = crypto
    .createHmac(CONFIG.hmacAlgorithm, CONFIG.hmacSecret)
    .update(rawBody)
    .digest("hex");

  // Constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(rawSignature, "hex"),
      Buffer.from(expected, "hex")
    );
  } catch {
    // timingSafeEqual throws if buffers have different lengths
    return false;
  }
}

// ---------------------------------------------------------------------------
// Retry with Exponential Backoff
// ---------------------------------------------------------------------------

/**
 * Sleeps for `ms` milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Calculates the delay for a given attempt using exponential backoff with jitter.
 *
 * @param {number} attempt - 0-indexed attempt number
 * @returns {number} delay in milliseconds
 */
function computeBackoffDelay(attempt) {
  const base = Math.min(
    CONFIG.retry.baseDelayMs * Math.pow(2, attempt),
    CONFIG.retry.maxDelayMs
  );
  const jitter = base * CONFIG.retry.jitterFactor * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(base + jitter));
}

/**
 * Calls `fn` up to maxAttempts times, retrying on thrown errors with
 * exponential backoff.
 *
 * @param {() => Promise<void>} fn
 * @param {string} eventId - used for logging
 * @param {string} eventType - used for logging
 * @returns {Promise<{ success: boolean, attempts: number, error?: Error }>}
 */
async function retryWithBackoff(fn, eventId, eventType) {
  let lastError;

  for (let attempt = 0; attempt < CONFIG.retry.maxAttempts; attempt++) {
    try {
      await fn();
      return { success: true, attempts: attempt + 1 };
    } catch (err) {
      lastError = err;

      const isLastAttempt = attempt === CONFIG.retry.maxAttempts - 1;
      const delay = isLastAttempt ? 0 : computeBackoffDelay(attempt);

      logger.warn("handler_attempt_failed", {
        eventId,
        eventType,
        attempt: attempt + 1,
        maxAttempts: CONFIG.retry.maxAttempts,
        errorMessage: err instanceof Error ? err.message : String(err),
        nextRetryMs: delay,
      });

      if (!isLastAttempt) {
        await sleep(delay);
      }
    }
  }

  return { success: false, attempts: CONFIG.retry.maxAttempts, error: lastError };
}

// ---------------------------------------------------------------------------
// Event Handler Registry
// ---------------------------------------------------------------------------

/**
 * Registry of event type → async handler function.
 * Each handler receives the parsed event payload.
 *
 * @type {Map<string, (payload: object) => Promise<void>>}
 */
const eventHandlers = new Map();

/**
 * Registers a handler for a specific event type.
 *
 * @param {string} eventType
 * @param {(payload: object) => Promise<void>} handler
 */
function registerHandler(eventType, handler) {
  if (typeof eventType !== "string" || !eventType) {
    throw new TypeError("eventType must be a non-empty string");
  }
  if (typeof handler !== "function") {
    throw new TypeError("handler must be a function");
  }
  eventHandlers.set(eventType, handler);
  logger.info("handler_registered", { eventType });
}

// ---------------------------------------------------------------------------
// Request Body Reading
// ---------------------------------------------------------------------------

/**
 * Reads and buffers the full request body up to maxBodyBytes.
 *
 * @param {http.IncomingMessage} req
 * @returns {Promise<Buffer>}
 */
function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;

    req.on("data", (chunk) => {
      totalBytes += chunk.length;

      if (totalBytes > CONFIG.maxBodyBytes) {
        req.destroy();
        reject(new Error(`Request body exceeds ${CONFIG.maxBodyBytes} bytes`));
        return;
      }

      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// HTTP Response Helpers
// ---------------------------------------------------------------------------

/**
 * Sends a JSON HTTP response.
 *
 * @param {http.ServerResponse} res
 * @param {number} statusCode
 * @param {object} body
 */
function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

// ---------------------------------------------------------------------------
// Input Validation
// ---------------------------------------------------------------------------

/**
 * Validates the parsed webhook payload structure.
 * Returns an error message string, or null if valid.
 *
 * @param {unknown} payload
 * @returns {string|null}
 */
function validatePayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return "Payload must be a JSON object";
  }

  const { id, type } = payload;

  if (typeof id !== "string" || !id.trim()) {
    return "Payload must have a non-empty string 'id' field";
  }

  if (typeof type !== "string" || !type.trim()) {
    return "Payload must have a non-empty string 'type' field";
  }

  return null;
}

// ---------------------------------------------------------------------------
// Core Request Handler
// ---------------------------------------------------------------------------

const dedupStore = new DeduplicationStore(CONFIG.dedup);

/**
 * Handles an incoming HTTP POST /webhook request.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
async function handleWebhookRequest(req, res) {
  const requestId = crypto.randomUUID();

  logger.info("request_received", {
    requestId,
    method: req.method,
    url: req.url,
    remoteAddress: req.socket?.remoteAddress,
  });

  // -- Read body -----------------------------------------------------------

  let rawBody;
  try {
    rawBody = await readRequestBody(req);
  } catch (err) {
    logger.warn("body_read_failed", {
      requestId,
      errorMessage: err instanceof Error ? err.message : String(err),
    });
    sendJson(res, 413, { error: "Payload too large or read error" });
    return;
  }

  // -- Validate HMAC signature ---------------------------------------------

  const signatureHeader = req.headers[CONFIG.hmacHeader];
  const signatureValid = validateHmacSignature(rawBody, signatureHeader);

  if (!signatureValid) {
    logger.warn("invalid_signature", {
      requestId,
      headerPresent: !!signatureHeader,
    });
    sendJson(res, 401, { error: "Invalid signature" });
    return;
  }

  // -- Parse JSON body ------------------------------------------------------

  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch (err) {
    logger.warn("json_parse_failed", {
      requestId,
      errorMessage: err instanceof Error ? err.message : String(err),
    });
    sendJson(res, 400, { error: "Invalid JSON body" });
    return;
  }

  // -- Validate payload structure -------------------------------------------

  const validationError = validatePayload(payload);
  if (validationError) {
    logger.warn("payload_validation_failed", { requestId, reason: validationError });
    sendJson(res, 400, { error: validationError });
    return;
  }

  const { id: eventId, type: eventType } = payload;

  logger.info("event_parsed", { requestId, eventId, eventType });

  // -- Idempotency check (deduplication) ------------------------------------

  const isDuplicate = dedupStore.checkAndMark(eventId);
  if (isDuplicate) {
    logger.info("duplicate_event_skipped", { requestId, eventId, eventType });
    sendJson(res, 200, { status: "duplicate", eventId });
    return;
  }

  // -- Dispatch to handler with retry ---------------------------------------

  const handler = eventHandlers.get(eventType);

  if (!handler) {
    logger.warn("no_handler_registered", { requestId, eventId, eventType });
    // Acknowledge receipt; unknown event types are not errors in the transport layer
    sendJson(res, 200, { status: "unhandled", eventId, eventType });
    return;
  }

  const { success, attempts, error } = await retryWithBackoff(
    () => handler(payload),
    eventId,
    eventType
  );

  if (success) {
    logger.info("event_processed", { requestId, eventId, eventType, attempts });
    sendJson(res, 200, { status: "ok", eventId, attempts });
  } else {
    logger.error("event_processing_failed", {
      requestId,
      eventId,
      eventType,
      attempts,
      errorMessage: error instanceof Error ? error.message : String(error),
      errorStack: error instanceof Error ? error.stack : undefined,
    });
    // Return 500 so the caller knows to retry at the webhook level
    sendJson(res, 500, { error: "Handler failed after retries", eventId });
  }
}

// ---------------------------------------------------------------------------
// HTTP Server
// ---------------------------------------------------------------------------

/**
 * Creates and starts the HTTP server.
 * Only accepts POST /webhook; all other routes return 404.
 *
 * @returns {http.Server}
 */
function createServer() {
  const server = http.createServer(async (req, res) => {
    // Route guard
    if (req.method !== "POST" || req.url !== "/webhook") {
      sendJson(res, 404, { error: "Not found" });
      return;
    }

    try {
      await handleWebhookRequest(req, res);
    } catch (err) {
      // Safety net: should not be reached under normal operation
      logger.error("unhandled_exception", {
        errorMessage: err instanceof Error ? err.message : String(err),
        errorStack: err instanceof Error ? err.stack : undefined,
      });
      if (!res.headersSent) {
        sendJson(res, 500, { error: "Internal server error" });
      }
    }
  });

  return server;
}

// ---------------------------------------------------------------------------
// Graceful Shutdown
// ---------------------------------------------------------------------------

/**
 * Registers SIGTERM / SIGINT handlers for graceful shutdown.
 *
 * @param {http.Server} server
 */
function registerShutdownHandlers(server) {
  let shuttingDown = false;

  function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;

    logger.info("shutdown_initiated", { signal });

    server.close((err) => {
      if (err) {
        logger.error("server_close_error", {
          errorMessage: err.message,
        });
        process.exit(1);
      }
      logger.info("server_closed");
      process.exit(0);
    });

    // Force-exit after 10 s if connections haven't drained
    setTimeout(() => {
      logger.warn("shutdown_timeout_forcing_exit");
      process.exit(1);
    }, 10_000).unref();
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT",  () => shutdown("SIGINT"));
}

// ---------------------------------------------------------------------------
// Example Handlers (illustrative)
// ---------------------------------------------------------------------------

registerHandler("order.created", async (payload) => {
  logger.info("processing_order_created", { eventId: payload.id });
  // Simulate async work
  await sleep(10);
  logger.info("order_created_handled", { eventId: payload.id });
});

registerHandler("payment.completed", async (payload) => {
  logger.info("processing_payment_completed", { eventId: payload.id });
  await sleep(10);
  logger.info("payment_completed_handled", { eventId: payload.id });
});

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

function main() {
  if (!CONFIG.hmacSecret) {
    logger.warn("startup_warning", {
      message: "WEBHOOK_SECRET is not set — all requests will be rejected",
    });
  }

  const server = createServer();
  registerShutdownHandlers(server);

  server.listen(CONFIG.port, () => {
    logger.info("server_started", { port: CONFIG.port, endpoint: "/webhook" });
  });

  return server;
}

// Run only when executed directly (not when required as a module)
if (require.main === module) {
  main();
}

// ---------------------------------------------------------------------------
// Exports (for testing)
// ---------------------------------------------------------------------------

module.exports = {
  validateHmacSignature,
  DeduplicationStore,
  computeBackoffDelay,
  retryWithBackoff,
  validatePayload,
  registerHandler,
  createServer,
  CONFIG,
};
