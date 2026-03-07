'use strict';

/**
 * File Upload Endpoint
 * Accepts images (jpg/png/webp), validates type and size (max 5MB),
 * generates thumbnails, and stores metadata.
 *
 * Architecture:
 *   - Validation layer  : MIME type + extension + size checks
 *   - Business logic    : thumbnail generation (sharp)
 *   - Data layer        : in-memory metadata store
 *   - Routing/handlers  : Express + multer
 */

const express = require('express');
const multer  = require('multer');
const sharp   = require('sharp');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
]);

const ALLOWED_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp']);

const UPLOAD_DIR    = path.join(__dirname, 'uploads');
const THUMBNAIL_DIR = path.join(__dirname, 'thumbnails');

const THUMBNAIL_WIDTH  = 200;
const THUMBNAIL_HEIGHT = 200;

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Data layer — in-memory metadata store
// ---------------------------------------------------------------------------

/** @type {Map<string, Object>} id → metadata record */
const metadataStore = new Map();

/**
 * Persists a metadata record and returns the stored object.
 * @param {Object} record
 * @returns {Object}
 */
function storeMetadata(record) {
  if (!record || typeof record.id !== 'string') {
    throw new Error('storeMetadata: record must have a string id');
  }
  metadataStore.set(record.id, record);
  return record;
}

/**
 * Retrieves a metadata record by id.
 * @param {string} id
 * @returns {Object|null}
 */
function getMetadata(id) {
  return metadataStore.get(id) ?? null;
}

/**
 * Returns all stored metadata records as an array.
 * @returns {Object[]}
 */
function listMetadata() {
  return Array.from(metadataStore.values());
}

// ---------------------------------------------------------------------------
// Validation layer
// ---------------------------------------------------------------------------

/**
 * Checks whether a MIME type is permitted.
 * @param {string} mimeType
 * @returns {boolean}
 */
function isAllowedMimeType(mimeType) {
  return typeof mimeType === 'string' && ALLOWED_MIME_TYPES.has(mimeType);
}

/**
 * Checks whether a file extension is permitted.
 * @param {string} filename
 * @returns {boolean}
 */
function isAllowedExtension(filename) {
  if (typeof filename !== 'string' || filename.trim() === '') return false;
  const ext = path.extname(filename).toLowerCase();
  return ALLOWED_EXTENSIONS.has(ext);
}

/**
 * Checks whether a file size is within the allowed limit.
 * @param {number} sizeBytes
 * @returns {boolean}
 */
function isAllowedSize(sizeBytes) {
  return typeof sizeBytes === 'number' && sizeBytes > 0 && sizeBytes <= MAX_FILE_SIZE_BYTES;
}

/**
 * Validates a multer file object against all rules.
 * Returns null on success or an error message string on failure.
 * @param {Express.Multer.File} file
 * @returns {string|null}
 */
function validateUploadedFile(file) {
  if (!file) {
    return 'No file provided.';
  }

  if (!isAllowedMimeType(file.mimetype)) {
    return `Invalid file type "${file.mimetype}". Allowed: jpg, png, webp.`;
  }

  if (!isAllowedExtension(file.originalname)) {
    return `Invalid file extension for "${file.originalname}". Allowed: .jpg, .jpeg, .png, .webp.`;
  }

  if (!isAllowedSize(file.size)) {
    return `File size ${file.size} bytes exceeds maximum of ${MAX_FILE_SIZE_BYTES} bytes (5 MB).`;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Business logic — thumbnail generation
// ---------------------------------------------------------------------------

/**
 * Generates a thumbnail for the given source file and writes it to the
 * thumbnail directory.
 * @param {string} sourcePath  Absolute path to the uploaded image.
 * @param {string} thumbnailFilename  Filename for the output thumbnail.
 * @returns {Promise<string>}  Absolute path to the generated thumbnail.
 */
async function generateThumbnail(sourcePath, thumbnailFilename) {
  if (typeof sourcePath !== 'string' || sourcePath.trim() === '') {
    throw new Error('generateThumbnail: sourcePath must be a non-empty string');
  }
  if (typeof thumbnailFilename !== 'string' || thumbnailFilename.trim() === '') {
    throw new Error('generateThumbnail: thumbnailFilename must be a non-empty string');
  }

  const thumbnailPath = path.join(THUMBNAIL_DIR, thumbnailFilename);

  await sharp(sourcePath)
    .resize(THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT, { fit: 'cover', position: 'centre' })
    .toFile(thumbnailPath);

  return thumbnailPath;
}

/**
 * Builds a metadata record from upload information.
 * @param {Express.Multer.File} file
 * @param {string} thumbnailPath
 * @returns {Object}
 */
function buildMetadataRecord(file, thumbnailPath) {
  return {
    id:               crypto.randomUUID(),
    originalName:     file.originalname,
    storedFilename:   file.filename,
    mimeType:         file.mimetype,
    sizeBytes:        file.size,
    uploadPath:       file.path,
    thumbnailPath:    thumbnailPath,
    uploadedAt:       new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Multer configuration
// ---------------------------------------------------------------------------

/**
 * Multer filter — rejects files that do not pass MIME/extension validation
 * before they are written to disk. Size is enforced by multer's limits option.
 * @type {multer.Options['fileFilter']}
 */
function multerFileFilter(_req, file, cb) {
  if (!isAllowedMimeType(file.mimetype)) {
    return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname));
  }
  if (!isAllowedExtension(file.originalname)) {
    return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname));
  }
  cb(null, true);
}

const storage = multer.diskStorage({
  destination(_req, _file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename(_req, file, cb) {
    const uniqueSuffix = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `upload-${uniqueSuffix}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE_BYTES },
  fileFilter: multerFileFilter,
});

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/**
 * POST /upload
 * Accepts a single image file under the field name "image".
 */
async function handleUpload(req, res) {
  // multer places the file on req.file after its middleware runs.
  const file = req.file;

  // Secondary validation (defence in depth — multer filter may pass edge cases)
  const validationError = validateUploadedFile(file);
  if (validationError) {
    return res.status(400).json({ success: false, error: validationError });
  }

  let record;

  try {
    const thumbnailFilename = `thumb-${file.filename}`;
    const thumbnailPath = await generateThumbnail(file.path, thumbnailFilename);

    record = buildMetadataRecord(file, thumbnailPath);
    storeMetadata(record);
  } catch (err) {
    // Clean up the uploaded file if post-processing fails
    cleanupFile(file.path);
    console.error('[handleUpload] Processing error:', err);
    return res.status(500).json({ success: false, error: 'Failed to process uploaded file.' });
  }

  return res.status(201).json({
    success:  true,
    metadata: record,
  });
}

/**
 * GET /uploads
 * Returns all stored metadata records.
 */
function handleListUploads(_req, res) {
  return res.status(200).json({ success: true, uploads: listMetadata() });
}

/**
 * GET /uploads/:id
 * Returns a single metadata record by id.
 */
function handleGetUpload(req, res) {
  const { id } = req.params;

  if (typeof id !== 'string' || id.trim() === '') {
    return res.status(400).json({ success: false, error: 'Missing or invalid id parameter.' });
  }

  const record = getMetadata(id.trim());

  if (!record) {
    return res.status(404).json({ success: false, error: `No upload found with id "${id}".` });
  }

  return res.status(200).json({ success: true, metadata: record });
}

// ---------------------------------------------------------------------------
// Error handlers
// ---------------------------------------------------------------------------

/**
 * Express error-handling middleware for multer errors and generic errors.
 * @type {express.ErrorRequestHandler}
 */
function errorHandler(err, _req, res, _next) {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        success: false,
        error: `File too large. Maximum allowed size is ${MAX_FILE_SIZE_BYTES / (1024 * 1024)} MB.`,
      });
    }
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        error: 'Invalid file type. Allowed types: jpg, png, webp.',
      });
    }
    return res.status(400).json({ success: false, error: err.message });
  }

  console.error('[errorHandler] Unhandled error:', err);
  return res.status(500).json({ success: false, error: 'Internal server error.' });
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * Silently deletes a file, ignoring errors (e.g. file already removed).
 * @param {string} filePath
 */
function cleanupFile(filePath) {
  try {
    fs.unlinkSync(filePath);
  } catch (_) {
    // Intentionally swallowed — best-effort cleanup
  }
}

/**
 * Ensures a directory exists, creating it recursively if necessary.
 * @param {string} dirPath
 */
function ensureDirectoryExists(dirPath) {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch (err) {
    console.error(`[ensureDirectoryExists] Failed to create directory "${dirPath}":`, err);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Application bootstrap
// ---------------------------------------------------------------------------

/**
 * Initialises required directories, wires up routes, and starts the server.
 * @returns {import('http').Server}
 */
function createApp() {
  ensureDirectoryExists(UPLOAD_DIR);
  ensureDirectoryExists(THUMBNAIL_DIR);

  const app = express();

  app.use(express.json());

  // Routes
  app.post('/upload', upload.single('image'), handleUpload);
  app.get('/uploads',     handleListUploads);
  app.get('/uploads/:id', handleGetUpload);

  // Error handler must be registered last
  app.use(errorHandler);

  return app;
}

function startServer() {
  const app    = createApp();
  const server = app.listen(PORT, () => {
    console.log(`[server] Listening on http://localhost:${PORT}`);
    console.log(`[server] Upload dir    : ${UPLOAD_DIR}`);
    console.log(`[server] Thumbnail dir : ${THUMBNAIL_DIR}`);
  });

  // Resource management: graceful shutdown
  process.on('SIGTERM', () => {
    console.log('[server] SIGTERM received — shutting down gracefully.');
    server.close(() => {
      console.log('[server] HTTP server closed.');
      process.exit(0);
    });
  });

  process.on('SIGINT', () => {
    console.log('[server] SIGINT received — shutting down gracefully.');
    server.close(() => {
      console.log('[server] HTTP server closed.');
      process.exit(0);
    });
  });

  return server;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

startServer();
