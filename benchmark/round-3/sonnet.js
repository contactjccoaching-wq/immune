'use strict';

const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

// --- Mandatory env validation at startup ---
const REQUIRED_ENV = ['ALLOWED_ORIGIN', 'PORT'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const PORT = parseInt(process.env.PORT, 10);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp'];
const THUMBNAIL_WIDTH = 200;
const THUMBNAIL_HEIGHT = 200;

// --- In-memory storage using Map for O(1) lookups ---
const fileMetadataStore = new Map();

// --- Validation rule constants ---
const FILE_VALIDATION_RULES = {
  maxSize: MAX_FILE_SIZE,
  allowedMimeTypes: ALLOWED_MIME_TYPES,
  allowedExtensions: ALLOWED_EXTENSIONS,
};

const PAGINATION_RULES = {
  defaultPage: 1,
  defaultLimit: 20,
  maxLimit: 100,
};

// --- Multer configuration ---
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (
    !FILE_VALIDATION_RULES.allowedMimeTypes.includes(file.mimetype) ||
    !FILE_VALIDATION_RULES.allowedExtensions.includes(ext)
  ) {
    return cb(
      Object.assign(new Error('Invalid file type. Only jpg, png, and webp are allowed.'), {
        code: 'INVALID_FILE_TYPE',
        status: 400,
      }),
      false
    );
  }
  cb(null, true);
};

const upload = multer({
  storage,
  limits: { fileSize: FILE_VALIDATION_RULES.maxSize },
  fileFilter,
});

// --- App setup ---
const app = express();

// Security middleware layers in order
app.use(helmet());

app.use(
  cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
  })
);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// --- Input validation middleware ---
const validateUploadInput = (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const ext = path.extname(req.file.originalname).toLowerCase();
  if (!FILE_VALIDATION_RULES.allowedExtensions.includes(ext)) {
    return res.status(400).json({ error: 'Invalid file extension.' });
  }

  if (!FILE_VALIDATION_RULES.allowedMimeTypes.includes(req.file.mimetype)) {
    return res.status(400).json({ error: 'Invalid MIME type.' });
  }

  if (req.file.size > FILE_VALIDATION_RULES.maxSize) {
    return res.status(413).json({ error: 'File too large. Maximum size is 5MB.' });
  }

  next();
};

const validatePaginationInput = (req, res, next) => {
  let { page, limit } = req.query;

  page = parseInt(page, 10) || PAGINATION_RULES.defaultPage;
  limit = parseInt(limit, 10) || PAGINATION_RULES.defaultLimit;

  if (page < 1) page = PAGINATION_RULES.defaultPage;
  if (limit < 1 || limit > PAGINATION_RULES.maxLimit) limit = PAGINATION_RULES.defaultLimit;

  req.pagination = { page, limit };
  next();
};

// --- Routes ---

// POST /upload - file upload endpoint
app.post('/upload', upload.single('image'), validateUploadInput, async (req, res, next) => {
  try {
    const fileId = crypto.randomUUID();
    const originalName = path.basename(req.file.originalname);
    const ext = path.extname(originalName).toLowerCase();
    const mimeType = req.file.mimetype;
    const size = req.file.size;

    // Generate thumbnail using sharp
    const thumbnailBuffer = await sharp(req.file.buffer)
      .resize(THUMBNAIL_WIDTH, THUMBNAIL_HEIGHT, { fit: 'cover', position: 'centre' })
      .toFormat('webp', { quality: 80 })
      .toBuffer();

    const thumbnailBase64 = thumbnailBuffer.toString('base64');
    const thumbnailDataUrl = `data:image/webp;base64,${thumbnailBase64}`;

    // Get image dimensions from original
    const metadata = await sharp(req.file.buffer).metadata();

    const fileRecord = {
      id: fileId,
      originalName,
      mimeType,
      extension: ext,
      size,
      width: metadata.width || null,
      height: metadata.height || null,
      thumbnailDataUrl,
      thumbnailWidth: THUMBNAIL_WIDTH,
      thumbnailHeight: THUMBNAIL_HEIGHT,
      createdAt: new Date().toISOString(),
    };

    // Store in Map for O(1) lookup
    fileMetadataStore.set(fileId, fileRecord);

    return res.status(201).json({
      id: fileRecord.id,
      originalName: fileRecord.originalName,
      mimeType: fileRecord.mimeType,
      size: fileRecord.size,
      width: fileRecord.width,
      height: fileRecord.height,
      thumbnailWidth: fileRecord.thumbnailWidth,
      thumbnailHeight: fileRecord.thumbnailHeight,
      thumbnailDataUrl: fileRecord.thumbnailDataUrl,
      createdAt: fileRecord.createdAt,
    });
  } catch (err) {
    next(err);
  }
});

// GET /files - list uploaded files with pagination
app.get('/files', validatePaginationInput, (req, res) => {
  const { page, limit } = req.pagination;

  // Sort by createdAt for stable pagination
  const allFiles = Array.from(fileMetadataStore.values()).sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  );

  const total = allFiles.length;
  const offset = (page - 1) * limit;
  const items = allFiles.slice(offset, offset + limit).map((f) => ({
    id: f.id,
    originalName: f.originalName,
    mimeType: f.mimeType,
    size: f.size,
    width: f.width,
    height: f.height,
    thumbnailWidth: f.thumbnailWidth,
    thumbnailHeight: f.thumbnailHeight,
    createdAt: f.createdAt,
  }));

  return res.json({
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
    items,
  });
});

// GET /files/:id - retrieve single file metadata
app.get('/files/:id', (req, res) => {
  const { id } = req.params;

  if (!id || typeof id !== 'string' || id.trim() === '') {
    return res.status(400).json({ error: 'Invalid file ID.' });
  }

  const record = fileMetadataStore.get(id.trim());
  if (!record) {
    return res.status(404).json({ error: 'File not found.' });
  }

  return res.json(record);
});

// --- Global error handler ---
app.use((err, req, res, next) => {
  // Multer-specific errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large. Maximum size is 5MB.' });
  }

  if (err.code === 'INVALID_FILE_TYPE') {
    return res.status(400).json({ error: err.message });
  }

  // Body-parser specific errors
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON body.' });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large.' });
  }

  // Sharp/image processing errors
  if (err.message && err.message.includes('Input buffer contains unsupported image format')) {
    return res.status(400).json({ error: 'Unsupported image format.' });
  }

  console.error('Unhandled error:', err);
  return res.status(500).json({ error: 'Internal server error.' });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`File upload server running on port ${PORT}`);
  console.log(`Allowed origin: ${ALLOWED_ORIGIN}`);
  console.log(`Max file size: ${MAX_FILE_SIZE / (1024 * 1024)}MB`);
  console.log(`Allowed types: ${ALLOWED_MIME_TYPES.join(', ')}`);
});

module.exports = app;
