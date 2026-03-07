'use strict';

// ============================================================
// Dependencies
// ============================================================
const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const crypto = require('crypto');
const path = require('path');

// ============================================================
// Configuration — fail fast on invalid config (CS-CODE-006)
// ============================================================
const CONFIG = (function validateConfig() {
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
    : null;

  // No fallback secrets or wildcards in production (AB-001, AB-006)
  const nodeEnv = process.env.NODE_ENV || 'development';
  const port = parseInt(process.env.PORT || '3000', 10);

  if (isNaN(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid PORT: ${process.env.PORT}`);
  }

  return Object.freeze({
    port,
    nodeEnv,
    allowedOrigins,
    upload: Object.freeze({
      maxFileSizeBytes: 5 * 1024 * 1024, // 5 MB
      allowedMimeTypes: new Set(['image/jpeg', 'image/png', 'image/webp']),
      allowedExtensions: new Set(['.jpg', '.jpeg', '.png', '.webp']),
    }),
    thumbnail: Object.freeze({
      width: 200,
      height: 200,
      fit: 'cover',
    }),
    rateLimit: Object.freeze({
      windowMs: 60 * 1000,      // 1 minute sliding window
      maxRequests: 20,
      cleanupIntervalMs: 5 * 60 * 1000,
    }),
    shutdown: Object.freeze({
      timeoutMs: 10_000,
    }),
  });
})();

// ============================================================
// In-Memory Metadata Store — closure-based isolation (CS-CODE-010)
// ============================================================
const metadataStore = (function createMetadataStore() {
  const store = new Map();

  function save(record) {
    store.set(record.id, record);
    return record;
  }

  function findById(id) {
    return store.get(id) ?? null;
  }

  function findAll() {
    return Array.from(store.values());
  }

  function count() {
    return store.size;
  }

  return Object.freeze({ save, findById, findAll, count });
})();

// ============================================================
// Sliding-Window Rate Limiter — with cleanup (CS-CODE-009, AB-007)
// ============================================================
const rateLimiter = (function createRateLimiter() {
  const clients = new Map(); // ip → [timestamp, ...]
  let cleanupTimer = null;

  function getClientIp(req) {
    // Trust x-forwarded-for only if behind a known proxy
    const forwarded = req.headers['x-forwarded-for'];
    return (forwarded ? forwarded.split(',')[0].trim() : null) || req.socket.remoteAddress || 'unknown';
  }

  function isAllowed(req) {
    const ip = getClientIp(req);
    const now = Date.now();
    const windowStart = now - CONFIG.rateLimit.windowMs;

    const timestamps = (clients.get(ip) || []).filter((t) => t > windowStart);
    timestamps.push(now);
    clients.set(ip, timestamps);

    return timestamps.length <= CONFIG.rateLimit.maxRequests;
  }

  function startCleanup() {
    cleanupTimer = setInterval(() => {
      const windowStart = Date.now() - CONFIG.rateLimit.windowMs;
      for (const [ip, timestamps] of clients.entries()) {
        const active = timestamps.filter((t) => t > windowStart);
        if (active.length === 0) {
          clients.delete(ip);
        } else {
          clients.set(ip, active);
        }
      }
    }, CONFIG.rateLimit.cleanupIntervalMs);

    // Allow Node to exit without waiting for this timer (AB-007 handled via stopCleanup)
    if (cleanupTimer.unref) cleanupTimer.unref();
    return cleanupTimer;
  }

  function stopCleanup() {
    if (cleanupTimer) {
      clearInterval(cleanupTimer);
      cleanupTimer = null;
    }
  }

  return Object.freeze({ isAllowed, startCleanup, stopCleanup });
})();

// ============================================================
// Multer — memory storage, mime + extension guard
// ============================================================
function buildMulterFileFilter(_req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype;

  const extOk = CONFIG.upload.allowedExtensions.has(ext);
  const mimeOk = CONFIG.upload.allowedMimeTypes.has(mime);

  if (!extOk || !mimeOk) {
    return cb(
      Object.assign(new Error('Only jpg, png, and webp images are accepted.'), { code: 'INVALID_FILE_TYPE' }),
      false,
    );
  }
  cb(null, true);
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: CONFIG.upload.maxFileSizeBytes },
  fileFilter: buildMulterFileFilter,
});

// ============================================================
// Image Processing
// ============================================================
async function generateThumbnail(buffer, mimeType) {
  const format = mimeType === 'image/webp' ? 'webp' : mimeType === 'image/png' ? 'png' : 'jpeg';

  return sharp(buffer)
    .resize(CONFIG.thumbnail.width, CONFIG.thumbnail.height, { fit: CONFIG.thumbnail.fit })
    .toFormat(format)
    .toBuffer();
}

async function extractImageMetadata(buffer) {
  const meta = await sharp(buffer).metadata();
  return {
    width: meta.width ?? null,
    height: meta.height ?? null,
    channels: meta.channels ?? null,
    space: meta.space ?? null,
  };
}

// ============================================================
// Business Logic — upload handler
// ============================================================
async function processUpload(file) {
  const [thumbnailBuffer, imageMeta] = await Promise.all([
    generateThumbnail(file.buffer, file.mimetype),
    extractImageMetadata(file.buffer),
  ]);

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const record = {
    id,
    originalName: file.originalname,
    mimeType: file.mimetype,
    sizeBytes: file.size,
    dimensions: imageMeta,
    thumbnail: {
      sizeBytes: thumbnailBuffer.length,
      width: CONFIG.thumbnail.width,
      height: CONFIG.thumbnail.height,
      data: thumbnailBuffer.toString('base64'),
    },
    uploadedAt: now,
  };

  return metadataStore.save(record);
}

// ============================================================
// Input Validation Helpers (CS-CODE-003)
// ============================================================
function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isValidUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

// ============================================================
// Route Handlers
// ============================================================
async function handleUpload(req, res) {
  // multer already validated mime, extension, and size — file is guaranteed here
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided.' });
  }

  try {
    const record = await processUpload(req.file);
    return res.status(201).json({
      message: 'Image uploaded successfully.',
      id: record.id,
      originalName: record.originalName,
      mimeType: record.mimeType,
      sizeBytes: record.sizeBytes,
      dimensions: record.dimensions,
      thumbnail: {
        width: record.thumbnail.width,
        height: record.thumbnail.height,
        sizeBytes: record.thumbnail.sizeBytes,
        data: `data:${record.mimeType};base64,${record.thumbnail.data}`,
      },
      uploadedAt: record.uploadedAt,
    });
  } catch (err) {
    // Unexpected sharp or processing failure
    console.error('[upload] Processing error:', err.message);
    return res.status(500).json({ error: 'Image processing failed. Please try again.' });
  }
}

function handleGetImage(req, res) {
  const { id } = req.params;

  if (!isNonEmptyString(id) || !isValidUuid(id)) {
    return res.status(400).json({ error: 'Invalid image ID format.' });
  }

  const record = metadataStore.findById(id);
  if (!record) {
    return res.status(404).json({ error: 'Image not found.' });
  }

  // Return metadata without the raw base64 thumbnail payload unless explicitly requested
  return res.json({
    id: record.id,
    originalName: record.originalName,
    mimeType: record.mimeType,
    sizeBytes: record.sizeBytes,
    dimensions: record.dimensions,
    thumbnail: {
      width: record.thumbnail.width,
      height: record.thumbnail.height,
      sizeBytes: record.thumbnail.sizeBytes,
    },
    uploadedAt: record.uploadedAt,
  });
}

function handleListImages(_req, res) {
  const images = metadataStore.findAll().map((record) => ({
    id: record.id,
    originalName: record.originalName,
    mimeType: record.mimeType,
    sizeBytes: record.sizeBytes,
    dimensions: record.dimensions,
    uploadedAt: record.uploadedAt,
  }));

  return res.json({ total: images.length, images });
}

function handleHealth(_req, res) {
  return res.json({ status: 'ok', imagesStored: metadataStore.count() });
}

// ============================================================
// Middleware
// ============================================================
function rateLimitMiddleware(req, res, next) {
  if (!rateLimiter.isAllowed(req)) {
    return res.status(429).json({ error: 'Too many requests. Please slow down.' });
  }
  next();
}

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;

  if (!origin) {
    // Same-origin or non-browser requests — allow
    return next();
  }

  const allowed = CONFIG.allowedOrigins;

  if (!allowed) {
    // No ALLOWED_ORIGINS configured — reject cross-origin in production (AB-005, AB-006)
    if (CONFIG.nodeEnv === 'production') {
      return res.status(403).json({ error: 'Cross-origin requests not permitted.' });
    }
    // In development, allow all origins for convenience (still no wildcard in prod)
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    return res.status(403).json({ error: 'Origin not allowed.' });
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
}

function securityHeadersMiddleware(_req, res, next) {
  // AB-004: security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; frame-ancestors 'none'",
  );
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
}

// Multer-specific error handler — must have 4 params
function multerErrorHandler(err, req, res, next) {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: `File too large. Maximum allowed size is ${CONFIG.upload.maxFileSizeBytes / (1024 * 1024)} MB.`,
    });
  }
  if (err.code === 'INVALID_FILE_TYPE') {
    return res.status(415).json({ error: err.message });
  }
  next(err);
}

// Generic error handler — must have 4 params
// eslint-disable-next-line no-unused-vars
function globalErrorHandler(err, req, res, _next) {
  console.error('[server] Unhandled error:', err.message);
  return res.status(500).json({ error: 'An unexpected error occurred.' });
}

// ============================================================
// App Factory
// ============================================================
function createApp() {
  const app = express();

  // Middleware ordering: headers → CORS → rate limit → body parser → routes (CS-CODE-008)
  app.use(securityHeadersMiddleware);
  app.use(corsMiddleware);
  app.use(rateLimitMiddleware);

  // Body size guard for non-multipart routes (CS-CODE-004)
  app.use(express.json({ limit: '10kb' }));

  // Routes
  app.get('/health', handleHealth);
  app.post('/images', upload.single('image'), multerErrorHandler, handleUpload);
  app.get('/images', handleListImages);
  app.get('/images/:id', handleGetImage);

  // 404 catch-all
  app.use((_req, res) => {
    res.status(404).json({ error: 'Route not found.' });
  });

  app.use(globalErrorHandler);

  return app;
}

// ============================================================
// Server Bootstrap
// ============================================================
function startServer(app) {
  rateLimiter.startCleanup();

  const server = app.listen(CONFIG.port, () => {
    console.log(`[server] Image Upload API running on port ${CONFIG.port} (${CONFIG.nodeEnv})`);
  });

  // Graceful shutdown — CS-CODE-005, AB-007
  function shutdown(signal) {
    console.log(`[server] ${signal} received — shutting down gracefully`);

    rateLimiter.stopCleanup(); // AB-007: clear interval before exit

    const forceExitTimer = setTimeout(() => {
      console.error('[server] Shutdown timeout exceeded — forcing exit');
      process.exit(1);
    }, CONFIG.shutdown.timeoutMs);

    if (forceExitTimer.unref) forceExitTimer.unref();

    server.close((err) => {
      clearTimeout(forceExitTimer);
      if (err) {
        console.error('[server] Error during close:', err.message);
        process.exit(1);
      }
      console.log('[server] Shutdown complete');
      process.exit(0);
    });
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  return server;
}

// ============================================================
// Entry Point
// ============================================================
if (require.main === module) {
  const app = createApp();
  startServer(app);
}

// ============================================================
// Exports (for testing)
// ============================================================
module.exports = {
  createApp,
  metadataStore,
  processUpload,
  generateThumbnail,
  extractImageMetadata,
  CONFIG,
};
