const http = require('http');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// Configuration & env validation
const CONFIG = {
  WEBHOOK_SECRET: process.env.WEBHOOK_SECRET || (() => {
    throw new Error('WEBHOOK_SECRET env var is required');
  })(),
  LOG_DIR: process.env.LOG_DIR || path.join(__dirname, 'logs'),
  MAX_RETRY_ATTEMPTS: parseInt(process.env.MAX_RETRY_ATTEMPTS || '3', 10),
  INITIAL_BACKOFF_MS: parseInt(process.env.INITIAL_BACKOFF_MS || '100', 10),
  MAX_BACKOFF_MS: parseInt(process.env.MAX_BACKOFF_MS || '5000', 10),
  DEDUP_TTL_MS: parseInt(process.env.DEDUP_TTL_MS || '3600000', 10),
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  PORT: parseInt(process.env.PORT || '3000', 10),
  CLEANUP_INTERVAL_MS: parseInt(process.env.CLEANUP_INTERVAL_MS || '300000', 10),
};

if (!CONFIG.WEBHOOK_SECRET || CONFIG.WEBHOOK_SECRET.length < 16) {
  throw new Error('WEBHOOK_SECRET must be at least 16 characters');
}

if (!fs.existsSync(CONFIG.LOG_DIR)) {
  fs.mkdirSync(CONFIG.LOG_DIR, { recursive: true });
}

// Structured logging
class StructuredLogger {
  constructor(logDir) {
    this.logDir = logDir;
    this.currentDate = new Date().toISOString().split('T')[0];
  }

  log(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp, level, message,
      ...data,
      requestId: data.requestId || 'N/A',
      pid: process.pid,
    };
    const logLine = JSON.stringify(logEntry);
    console.log(logLine);
    const logFile = path.join(this.logDir, `${this.currentDate}.jsonl`);
    fs.appendFileSync(logFile, logLine + '\n');
  }

  info(message, data) { this.log('INFO', message, data); }
  error(message, data) { this.log('ERROR', message, data); }
  warn(message, data) { this.log('WARN', message, data); }
  debug(message, data) { this.log('DEBUG', message, data); }
}

const logger = new StructuredLogger(CONFIG.LOG_DIR);

// Deduplication cache
class DeduplicationCache {
  constructor(ttlMs) {
    this.ttlMs = ttlMs;
    this.cache = new Map();
    this.cleanup();
  }

  has(eventId) {
    if (!this.cache.has(eventId)) return false;
    const entry = this.cache.get(eventId);
    if (Date.now() - entry.processedAt > this.ttlMs) {
      this.cache.delete(eventId);
      return false;
    }
    return true;
  }

  get(eventId) {
    if (this.has(eventId)) return this.cache.get(eventId).result;
    return null;
  }

  set(eventId, result) {
    this.cache.set(eventId, { processedAt: Date.now(), result });
  }

  cleanup() {
    const now = Date.now();
    for (const [eventId, entry] of this.cache.entries()) {
      if (now - entry.processedAt > this.ttlMs) this.cache.delete(eventId);
    }
    setTimeout(() => this.cleanup(), CONFIG.CLEANUP_INTERVAL_MS);
  }

  stats() { return { size: this.cache.size }; }
}

const dedupCache = new DeduplicationCache(CONFIG.DEDUP_TTL_MS);

// Rate limiter
class RateLimiter {
  constructor(windowMs, maxRequests) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.requests = new Map();
  }

  isAllowed(ip) {
    const now = Date.now();
    if (!this.requests.has(ip)) {
      this.requests.set(ip, [now]);
      return true;
    }
    const timestamps = this.requests.get(ip);
    const validTimestamps = timestamps.filter(t => t > now - this.windowMs);
    if (validTimestamps.length < this.maxRequests) {
      validTimestamps.push(now);
      this.requests.set(ip, validTimestamps);
      return true;
    }
    return false;
  }
}

const globalRateLimiter = new RateLimiter(CONFIG.RATE_LIMIT_WINDOW_MS, CONFIG.RATE_LIMIT_MAX_REQUESTS);

// HMAC signature validation
function validateHmacSignature(payload, signature, secret) {
  if (!signature) throw new Error('Missing X-Webhook-Signature header');
  const hash = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(signature));
}

// Exponential backoff retry
class RetryEngine {
  constructor(maxAttempts, initialBackoffMs, maxBackoffMs) {
    this.maxAttempts = maxAttempts;
    this.initialBackoffMs = initialBackoffMs;
    this.maxBackoffMs = maxBackoffMs;
  }

  async execute(handler, eventId, event) {
    let lastError;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        const result = await handler(event);
        logger.debug('Handler succeeded', { eventId, attempt, handler: handler.name || 'anonymous' });
        return result;
      } catch (error) {
        lastError = error;
        logger.warn('Handler failed', { eventId, attempt, maxAttempts: this.maxAttempts, error: error.message });
        if (attempt < this.maxAttempts) {
          const backoffMs = this.calculateBackoff(attempt);
          await this.sleep(backoffMs);
        }
      }
    }
    throw new Error(`Handler failed after ${this.maxAttempts} attempts: ${lastError.message}`);
  }

  calculateBackoff(attempt) {
    const exponential = this.initialBackoffMs * Math.pow(2, attempt - 1);
    const capped = Math.min(exponential, this.maxBackoffMs);
    const jitter = capped * (Math.random() * 0.1);
    return Math.floor(capped + jitter);
  }

  sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
}

const retryEngine = new RetryEngine(CONFIG.MAX_RETRY_ATTEMPTS, CONFIG.INITIAL_BACKOFF_MS, CONFIG.MAX_BACKOFF_MS);

// Event handlers
async function handleUserCreated(event) {
  if (!event.userId) throw new Error('Missing userId in user.created event');
  logger.info('Processing user.created event', { eventId: event.id, userId: event.userId });
  await new Promise(resolve => setTimeout(resolve, 50));
  return { success: true };
}

async function handleOrderPlaced(event) {
  if (!event.orderId) throw new Error('Missing orderId in order.placed event');
  logger.info('Processing order.placed event', { eventId: event.id, orderId: event.orderId });
  await new Promise(resolve => setTimeout(resolve, 50));
  return { success: true };
}

async function handlePaymentProcessed(event) {
  if (!event.transactionId) throw new Error('Missing transactionId in payment.processed event');
  logger.info('Processing payment.processed event', { eventId: event.id, transactionId: event.transactionId });
  await new Promise(resolve => setTimeout(resolve, 50));
  return { success: true };
}

const eventHandlers = {
  'user.created': handleUserCreated,
  'order.placed': handleOrderPlaced,
  'payment.processed': handlePaymentProcessed,
};

// Webhook processor
async function processWebhookEvent(event, requestId) {
  const { id: eventId, type, data } = event;
  if (!eventId || !type || !data) throw new Error('Invalid event structure: missing id, type, or data');

  if (dedupCache.has(eventId)) {
    logger.info('Event already processed (idempotent)', { eventId, type });
    return dedupCache.get(eventId);
  }

  const handler = eventHandlers[type];
  if (!handler) throw new Error(`No handler registered for event type: ${type}`);

  const result = await retryEngine.execute(handler, eventId, { id: eventId, type, ...data });
  dedupCache.set(eventId, result);
  logger.info('Event processed successfully', { eventId, type, requestId });
  return result;
}

// HTTP request handler
async function handleWebhookRequest(req, res) {
  const requestId = crypto.randomUUID();
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  logger.debug('Incoming request', { requestId, method: req.method, path: req.url, clientIp });

  if (!globalRateLimiter.isAllowed(clientIp)) {
    logger.warn('Rate limit exceeded', { clientIp, requestId });
    res.writeHead(429, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Too many requests' }));
    return;
  }

  if (req.method !== 'POST' || req.url !== '/webhooks') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
    return;
  }

  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
    if (body.length > 1048576) {
      req.destroy();
      logger.error('Payload too large', { requestId });
    }
  });

  req.on('end', async () => {
    try {
      const signature = req.headers['x-webhook-signature'];
      if (!validateHmacSignature(body, signature, CONFIG.WEBHOOK_SECRET)) {
        logger.warn('Signature validation failed', { requestId });
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      let event;
      try {
        event = JSON.parse(body);
      } catch (parseError) {
        logger.error('JSON parse error', { requestId, error: parseError.message });
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
        return;
      }

      const result = await processWebhookEvent(event, requestId);
      logger.info('Request completed', { requestId, status: 200 });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, result }));
    } catch (error) {
      logger.error('Request failed', { requestId, error: error.message, stack: error.stack });
      const statusCode = error.message.includes('Unauthorized') ? 401 : 400;
      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
  });

  req.on('error', error => {
    logger.error('Request stream error', { requestId, error: error.message });
  });
}

// Health check
function handleHealth(req, res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    dedupCache: dedupCache.stats(),
    timestamp: new Date().toISOString(),
  }));
}

// HTTP server
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Webhook-Signature');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.url === '/health' && req.method === 'GET') {
    handleHealth(req, res);
  } else if (req.url === '/webhooks' && req.method === 'POST') {
    await handleWebhookRequest(req, res);
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }
});

// Graceful shutdown
let activeConnections = 0;
server.on('connection', socket => {
  activeConnections++;
  socket.on('close', () => { activeConnections--; });
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received', { activeConnections });
  server.close(() => { logger.info('Server closed'); process.exit(0); });
  setTimeout(() => { logger.error('Forced shutdown'); process.exit(1); }, 30000);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received', { activeConnections });
  server.close(() => { logger.info('Server closed'); process.exit(0); });
  setTimeout(() => { logger.error('Forced shutdown'); process.exit(1); }, 30000);
});

server.listen(CONFIG.PORT, () => {
  logger.info('Webhook receiver started', {
    port: CONFIG.PORT, logDir: CONFIG.LOG_DIR,
    maxRetries: CONFIG.MAX_RETRY_ATTEMPTS, dedupTtlMs: CONFIG.DEDUP_TTL_MS,
  });
});

process.on('uncaughtException', error => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', reason => {
  logger.error('Unhandled rejection', { reason: reason instanceof Error ? reason.message : String(reason) });
  process.exit(1);
});

module.exports = { server, logger, dedupCache, retryEngine };
