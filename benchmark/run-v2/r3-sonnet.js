/**
 * File Upload Endpoint — Production-Quality
 * Express.js + Multer image upload with thumbnail generation and metadata storage
 *
 * Cheatsheet strategies applied:
 *   CS-CODE-005: Schema validation with per-field type guards and fallback defaults
 *   CS-CODE-006: Centralized init() orchestrating all setup from single entry point
 *   CS-CODE-007: Single centralized state object instead of scattered globals
 *   CS-CODE-012: Credential-present implies validation-required
 *   CS-CODE-013: Fail-closed pattern for secrets
 *   CS-CODE-014: All stored text fields require escapeHtml() before rendering
 *   CS-CODE-015: Query params and path segments treated as hostile
 *   CS-CODE-016: Auth gate BEFORE cost-bearing operations
 *   CS-CODE-017: Persistent rate limiting via file/DB (no in-memory counters)
 *
 * Pitfalls avoided:
 *   AB-CODE-003: No sequential API calls in loops (Promise.all used)
 *   AB-CODE-006: No innerHTML / template literals with raw user data
 *   AB-CODE-008: All JSON.parse wrapped with try/catch + fallback
 *   AB-CODE-020: HMAC signature verification on upload webhook
 *   AB-CODE-021: No always-true auth path
 *   AB-CODE-022: No hardcoded fallback credentials
 *   AB-CODE-023: No server-side template XSS
 *   AB-CODE-025: No wildcard CORS — explicit origin allowlist
 *   AB-CODE-026: Auth gate before cost-bearing thumbnail generation
 *   AB-CODE-027: API key read from Authorization header, not query param
 *   AB-CODE-028: Mutations use POST only
 *   AB-CODE-029: Rate limiting persisted to disk (no in-memory reset risk)
 *   AB-CODE-031: Constant-time comparison for secrets
 */

'use strict';

const express       = require('express');
const multer        = require('multer');
const sharp         = require('sharp');
const crypto        = require('crypto');
const fs            = require('fs');
const fsp           = require('fs').promises;
const path          = require('path');

// ─────────────────────────────────────────────
// CS-CODE-007: Single centralized state object
// ─────────────────────────────────────────────
const CONFIG = {
  port:              parseInt(process.env.PORT, 10)           || 3000,
  uploadDir:         process.env.UPLOAD_DIR                   || path.join(__dirname, 'uploads', 'originals'),
  thumbDir:          process.env.THUMB_DIR                    || path.join(__dirname, 'uploads', 'thumbnails'),
  metaDir:           process.env.META_DIR                     || path.join(__dirname, 'uploads', 'metadata'),
  rateLimitDir:      process.env.RATE_LIMIT_DIR               || path.join(__dirname, 'uploads', 'ratelimit'),
  // CS-CODE-013: fail-closed — these will be validated in init()
  apiKey:            process.env.API_KEY                      || null,
  webhookSecret:     process.env.WEBHOOK_SECRET               || null,
  allowedOrigins:    (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
  maxFileSizeBytes:  5 * 1024 * 1024,   // 5 MB
  allowedMimeTypes:  new Set(['image/jpeg', 'image/png', 'image/webp']),
  allowedExtensions: new Set(['.jpg', '.jpeg', '.png', '.webp']),
  thumbWidth:        320,
  thumbHeight:       320,
  // CS-CODE-017: rate limit window config
  rateLimit: {
    windowMs:  60 * 1000,  // 1 minute
    maxPerWindow: 10,
  },
};

// ─────────────────────────────────────────────
// Utility: HTML escaping (CS-CODE-014, AB-CODE-006, AB-CODE-023)
// ─────────────────────────────────────────────
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
}

// ─────────────────────────────────────────────
// Utility: constant-time comparison (AB-CODE-031)
// ─────────────────────────────────────────────
function safeCompare(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    // Still run timingSafeEqual against itself to avoid timing leak
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// ─────────────────────────────────────────────
// Utility: safe JSON parse (AB-CODE-008)
// ─────────────────────────────────────────────
function safeJsonParse(str, fallback = {}) {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

// ─────────────────────────────────────────────
// Auth middleware — CS-CODE-012/013/016, AB-CODE-021/022/027
// API key must be in Authorization header as "Bearer <key>"
// ─────────────────────────────────────────────
function requireApiKey(req, res, next) {
  const header = req.headers['authorization'] || '';
  const match  = header.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  // AB-CODE-031: constant-time comparison — no === or ==
  if (!safeCompare(match[1], CONFIG.apiKey)) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  next();
}

// ─────────────────────────────────────────────
// CS-CODE-017 + AB-CODE-029: Persistent rate limiting via filesystem
// (In-memory counters reset on cold start in serverless environments)
// ─────────────────────────────────────────────
async function checkRateLimit(identifier) {
  // Sanitize identifier to be safe as a filename (AB-CODE-015)
  const safeId   = crypto.createHash('sha256').update(String(identifier)).digest('hex');
  const filePath = path.join(CONFIG.rateLimitDir, `${safeId}.json`);
  const now      = Date.now();

  let record = { count: 0, windowStart: now };

  try {
    const raw = await fsp.readFile(filePath, 'utf8');
    // AB-CODE-008: safe JSON parse with fallback
    const parsed = safeJsonParse(raw, null);
    // CS-CODE-005: per-field type guards
    if (
      parsed &&
      typeof parsed.count       === 'number' &&
      typeof parsed.windowStart === 'number'
    ) {
      record = parsed;
    }
  } catch {
    // File doesn't exist yet — start fresh
  }

  // Reset window if expired
  if (now - record.windowStart > CONFIG.rateLimit.windowMs) {
    record = { count: 0, windowStart: now };
  }

  if (record.count >= CONFIG.rateLimit.maxPerWindow) {
    const retryAfterSec = Math.ceil(
      (CONFIG.rateLimit.windowMs - (now - record.windowStart)) / 1000
    );
    return { allowed: false, retryAfterSec };
  }

  record.count += 1;
  await fsp.writeFile(filePath, JSON.stringify(record), 'utf8');
  return { allowed: true, retryAfterSec: 0 };
}

// ─────────────────────────────────────────────
// CORS middleware — AB-CODE-025: explicit origin allowlist, no wildcard
// ─────────────────────────────────────────────
function corsMiddleware(req, res, next) {
  const origin = req.headers['origin'];
  if (origin && CONFIG.allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',  origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
}

// ─────────────────────────────────────────────
// Multer storage: store to disk with sanitized filename
// ─────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, CONFIG.uploadDir),
  filename:    (_req, file, cb) => {
    const ext     = path.extname(file.originalname).toLowerCase();
    const safeName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`;
    cb(null, safeName);
  },
});

// ─────────────────────────────────────────────
// Multer file filter — validate MIME type at upload time
// ─────────────────────────────────────────────
function multerFileFilter(_req, file, cb) {
  if (!CONFIG.allowedMimeTypes.has(file.mimetype)) {
    return cb(
      Object.assign(new Error('Invalid file type. Only jpg, png, webp allowed.'), { code: 'INVALID_MIME' }),
      false
    );
  }
  cb(null, true);
}

const upload = multer({
  storage,
  fileFilter: multerFileFilter,
  limits: {
    fileSize: CONFIG.maxFileSizeBytes,
    files:    1,
  },
});

// ─────────────────────────────────────────────
// Deep validation of uploaded file (CS-CODE-005, CS-CODE-015)
// Defense-in-depth: re-validate extension and MIME after multer accepts
// ─────────────────────────────────────────────
function validateUploadedFile(file) {
  if (!file) {
    return { valid: false, reason: 'No file received' };
  }

  const ext = path.extname(file.originalname || '').toLowerCase();
  if (!CONFIG.allowedExtensions.has(ext)) {
    return { valid: false, reason: `File extension not allowed: ${escapeHtml(ext)}` };
  }

  if (!CONFIG.allowedMimeTypes.has(file.mimetype)) {
    return { valid: false, reason: `MIME type not allowed: ${escapeHtml(file.mimetype)}` };
  }

  if (file.size > CONFIG.maxFileSizeBytes) {
    return { valid: false, reason: `File too large: ${file.size} bytes (max ${CONFIG.maxFileSizeBytes})` };
  }

  return { valid: true };
}

// ─────────────────────────────────────────────
// Thumbnail generation with sharp
// ─────────────────────────────────────────────
async function generateThumbnail(sourcePath, thumbFilename) {
  const thumbPath = path.join(CONFIG.thumbDir, thumbFilename);

  await sharp(sourcePath)
    .resize(CONFIG.thumbWidth, CONFIG.thumbHeight, {
      fit:      'cover',
      position: 'centre',
    })
    .toFormat('webp', { quality: 80 })
    .toFile(thumbPath);

  return thumbPath;
}

// ─────────────────────────────────────────────
// Metadata storage — persist to JSON file
// CS-CODE-014: all string fields escaped before storage in human-readable form
// ─────────────────────────────────────────────
async function storeMetadata(meta) {
  const filename = `${meta.id}.json`;
  const filePath = path.join(CONFIG.metaDir, filename);

  // CS-CODE-005: schema validation — ensure all required fields present
  const record = {
    id:            String(meta.id            || ''),
    originalName:  escapeHtml(String(meta.originalName || '')),
    storedName:    String(meta.storedName    || ''),
    thumbName:     String(meta.thumbName     || ''),
    mimeType:      escapeHtml(String(meta.mimeType     || '')),
    sizeBytes:     Number(meta.sizeBytes)     || 0,
    width:         Number(meta.width)         || 0,
    height:        Number(meta.height)        || 0,
    uploadedAt:    String(meta.uploadedAt    || new Date().toISOString()),
    uploader:      escapeHtml(String(meta.uploader     || 'anonymous')),
  };

  await fsp.writeFile(filePath, JSON.stringify(record, null, 2), 'utf8');
  return record;
}

// ─────────────────────────────────────────────
// Cleanup helper — remove orphaned file on error
// ─────────────────────────────────────────────
async function safeUnlink(filePath) {
  try {
    await fsp.unlink(filePath);
  } catch {
    // Ignore — file may not exist
  }
}

// ─────────────────────────────────────────────
// CS-CODE-006: Centralized init() orchestrating all setup
// ─────────────────────────────────────────────
async function init() {
  // CS-CODE-013: Fail-closed for secrets — reject startup if missing
  if (!CONFIG.apiKey) {
    console.error('FATAL: API_KEY environment variable is required. Set it and restart.');
    process.exit(1);
  }

  if (!CONFIG.webhookSecret) {
    console.error('FATAL: WEBHOOK_SECRET environment variable is required. Set it and restart.');
    process.exit(1);
  }

  // CS-CODE-012: Validate key length (minimum security bar)
  if (CONFIG.apiKey.length < 32) {
    console.error('FATAL: API_KEY must be at least 32 characters.');
    process.exit(1);
  }

  // Ensure upload directories exist
  await Promise.all([
    fsp.mkdir(CONFIG.uploadDir,   { recursive: true }),
    fsp.mkdir(CONFIG.thumbDir,    { recursive: true }),
    fsp.mkdir(CONFIG.metaDir,     { recursive: true }),
    fsp.mkdir(CONFIG.rateLimitDir, { recursive: true }),
  ]);

  const app = buildApp();

  app.listen(CONFIG.port, () => {
    console.log(`Upload server listening on port ${CONFIG.port}`);
  });
}

// ─────────────────────────────────────────────
// App factory — separated from listen() for testability
// ─────────────────────────────────────────────
function buildApp() {
  const app = express();

  // Security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=()');
    next();
  });

  // AB-CODE-025: explicit CORS — no wildcard
  app.use(corsMiddleware);

  // Body size limit for JSON (non-file) routes
  app.use(express.json({ limit: '16kb' }));

  // ─── POST /upload ─────────────────────────
  // AB-CODE-028: mutation → POST only
  // CS-CODE-016: auth gate BEFORE cost-bearing thumbnail generation
  app.post(
    '/upload',

    // 1. Auth — must pass before we even receive the file
    requireApiKey,

    // 2. Rate limit — persistent, not in-memory (AB-CODE-029, CS-CODE-017)
    async (req, res, next) => {
      // CS-CODE-015: treat IP as hostile input — sanitize before use as key
      const rawIp = req.ip || req.socket?.remoteAddress || 'unknown';
      const ip    = String(rawIp).slice(0, 128);  // bound length

      const { allowed, retryAfterSec } = await checkRateLimit(ip);
      if (!allowed) {
        // AB-CODE-004: always return 429 with Retry-After
        res.setHeader('Retry-After', String(retryAfterSec));
        return res.status(429).json({
          error:      'Rate limit exceeded',
          retryAfter: retryAfterSec,
        });
      }
      next();
    },

    // 3. Multer — accept file only after auth + rate limit pass
    (req, res, next) => {
      upload.single('image')(req, res, (err) => {
        if (!err) return next();

        if (err instanceof multer.MulterError) {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: 'File exceeds 5 MB limit' });
          }
          return res.status(400).json({ error: `Upload error: ${escapeHtml(err.message)}` });
        }

        if (err && err.code === 'INVALID_MIME') {
          return res.status(415).json({ error: escapeHtml(err.message) });
        }

        if (err) {
          return res.status(500).json({ error: 'Upload failed' });
        }

        next();
      });
    },

    // 4. Deep validation + thumbnail + metadata
    async (req, res) => {
      const file = req.file;

      // Defense-in-depth re-validation (CS-CODE-005)
      const validation = validateUploadedFile(file);
      if (!validation.valid) {
        if (file?.path) await safeUnlink(file.path);
        return res.status(422).json({ error: validation.reason });
      }

      let imageInfo;
      try {
        // Read image dimensions for metadata
        imageInfo = await sharp(file.path).metadata();
      } catch {
        await safeUnlink(file.path);
        return res.status(422).json({ error: 'Could not process image — file may be corrupt' });
      }

      const id        = crypto.randomUUID();
      const thumbName = `thumb-${id}.webp`;
      let   thumbPath;

      try {
        thumbPath = await generateThumbnail(file.path, thumbName);
      } catch (err) {
        await safeUnlink(file.path);
        console.error('Thumbnail generation failed:', err);
        return res.status(500).json({ error: 'Thumbnail generation failed' });
      }

      let record;
      try {
        record = await storeMetadata({
          id,
          originalName: file.originalname,
          storedName:   file.filename,
          thumbName,
          mimeType:     file.mimetype,
          sizeBytes:    file.size,
          width:        imageInfo.width  || 0,
          height:       imageInfo.height || 0,
          uploadedAt:   new Date().toISOString(),
          uploader:     req.ip || 'anonymous',
        });
      } catch (err) {
        await Promise.all([safeUnlink(file.path), safeUnlink(thumbPath)]);
        console.error('Metadata storage failed:', err);
        return res.status(500).json({ error: 'Metadata storage failed' });
      }

      return res.status(201).json({
        id:          record.id,
        originalName: record.originalName,
        storedName:  record.storedName,
        thumbName:   record.thumbName,
        mimeType:    record.mimeType,
        sizeBytes:   record.sizeBytes,
        dimensions:  { width: record.width, height: record.height },
        uploadedAt:  record.uploadedAt,
      });
    }
  );

  // ─── POST /webhook/upload-event ───────────
  // AB-CODE-020: HMAC signature verification before processing
  app.post('/webhook/upload-event', express.raw({ type: '*/*', limit: '64kb' }), (req, res) => {
    const signature = req.headers['x-signature-sha256'] || '';
    const payload   = req.body;

    if (!Buffer.isBuffer(payload) || payload.length === 0) {
      return res.status(400).json({ error: 'Empty payload' });
    }

    // Compute expected HMAC
    const expected = crypto
      .createHmac('sha256', CONFIG.webhookSecret)
      .update(payload)
      .digest('hex');

    const sigHeader = signature.replace(/^sha256=/, '');

    // AB-CODE-031: constant-time comparison for HMAC
    if (!safeCompare(sigHeader, expected)) {
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    // AB-CODE-008: safe JSON parse with fallback
    const event = safeJsonParse(payload.toString('utf8'), null);

    if (!event || typeof event !== 'object') {
      return res.status(400).json({ error: 'Invalid event payload' });
    }

    // CS-CODE-005: per-field type guards
    const eventType = typeof event.type === 'string' ? event.type : '';
    const eventId   = typeof event.id   === 'string' ? event.id   : '';

    console.log(`Webhook received: type=${escapeHtml(eventType)} id=${escapeHtml(eventId)}`);

    return res.status(200).json({ received: true });
  });

  // ─── GET /metadata/:id ────────────────────
  // CS-CODE-015: path segment treated as hostile — validate format before use
  app.get('/metadata/:id', requireApiKey, async (req, res) => {
    const rawId = req.params.id || '';

    // Validate UUID format — prevent path traversal or injection
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(rawId)) {
      return res.status(400).json({ error: 'Invalid ID format' });
    }

    const filePath = path.join(CONFIG.metaDir, `${rawId}.json`);

    let raw;
    try {
      raw = await fsp.readFile(filePath, 'utf8');
    } catch {
      return res.status(404).json({ error: 'Metadata not found' });
    }

    // AB-CODE-008: safe JSON parse
    const record = safeJsonParse(raw, null);
    if (!record) {
      return res.status(500).json({ error: 'Corrupt metadata' });
    }

    return res.status(200).json(record);
  });

  // ─── Global error handler ─────────────────
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

// ─────────────────────────────────────────────
// Entry point — CS-CODE-006
// ─────────────────────────────────────────────
init().catch((err) => {
  console.error('Startup failed:', err);
  process.exit(1);
});

module.exports = { buildApp, safeCompare, escapeHtml, safeJsonParse };
