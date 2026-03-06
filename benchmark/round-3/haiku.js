const express = require('express');
const multer = require('multer');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const sharp = require('sharp');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

// Environment validation at startup
const requiredEnvVars = ['NODE_ENV', 'UPLOAD_DIR', 'MAX_FILE_SIZE', 'ALLOWED_TYPES'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) {
    throw new Error(`Missing required environment variable: ${varName}`);
  }
});

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR;
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE, 10);
const ALLOWED_TYPES = process.env.ALLOWED_TYPES.split(',');

// Create upload directories if they don't exist
[UPLOAD_DIR, `${UPLOAD_DIR}/originals`, `${UPLOAD_DIR}/thumbnails`].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Validation constants
const FILE_VALIDATION_RULES = [
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description must be 500 characters or less'),
];

// In-memory storage using Map for O(1) lookups
const fileMetadata = new Map();

// Multer storage configuration
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const mimeType = file.mimetype;

  if (!ALLOWED_TYPES.includes(ext.substring(1)) || !mimeType.startsWith('image/')) {
    return cb(new Error('Invalid file type. Only JPG, PNG, and WebP are allowed.'));
  }

  cb(null, true);
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
  },
});

// Security middleware layers in order
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use(limiter);

// Body parser with error handling
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ limit: '10kb', extended: false }));

// Custom body-parser error handling
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON format' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request payload too large' });
  }
  next(err);
});

// Upload endpoint
app.post('/upload', upload.single('image'), FILE_VALIDATION_RULES, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    if (req.file.size > MAX_FILE_SIZE) {
      return res.status(413).json({ error: `File size exceeds maximum limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB` });
    }

    const fileId = crypto.randomUUID();
    const ext = path.extname(req.file.originalname).toLowerCase();
    const fileName = `${fileId}${ext}`;

    const originalPath = path.join(UPLOAD_DIR, 'originals', fileName);
    const thumbnailPath = path.join(UPLOAD_DIR, 'thumbnails', `thumb_${fileName}`);

    await fs.promises.writeFile(originalPath, req.file.buffer);

    await sharp(req.file.buffer)
      .resize(200, 200, {
        fit: 'cover',
        position: 'center',
      })
      .webp({ quality: 80 })
      .toFile(thumbnailPath.replace(/\.[^.]+$/, '.webp'));

    const metadata = {
      id: fileId,
      originalFileName: req.file.originalname,
      fileName: fileName,
      fileSize: req.file.size,
      mimeType: req.file.mimetype,
      description: req.body.description || '',
      uploadedAt: new Date().toISOString(),
      originalPath: originalPath,
      thumbnailPath: thumbnailPath.replace(/\.[^.]+$/, '.webp'),
    };

    fileMetadata.set(fileId, metadata);

    res.status(201).json({
      success: true,
      file: {
        id: fileId,
        originalFileName: req.file.originalname,
        fileSize: req.file.size,
        mimeType: req.file.mimetype,
        uploadedAt: metadata.uploadedAt,
        description: req.body.description || '',
      },
    });
  } catch (error) {
    next(error);
  }
});

// Get file metadata
app.get('/files/:id', (req, res) => {
  const fileId = req.params.id;

  if (!fileMetadata.has(fileId)) {
    return res.status(404).json({ error: 'File not found' });
  }

  const metadata = fileMetadata.get(fileId);
  res.json({
    success: true,
    file: {
      id: metadata.id,
      originalFileName: metadata.originalFileName,
      fileSize: metadata.fileSize,
      mimeType: metadata.mimeType,
      uploadedAt: metadata.uploadedAt,
      description: metadata.description,
    },
  });
});

// List files with pagination
app.get('/files', (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;

  if (page < 1 || limit < 1 || limit > 100) {
    return res.status(400).json({ error: 'Invalid pagination parameters' });
  }

  const files = Array.from(fileMetadata.values())
    .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt))
    .slice((page - 1) * limit, page * limit)
    .map(file => ({
      id: file.id,
      originalFileName: file.originalFileName,
      fileSize: file.fileSize,
      mimeType: file.mimeType,
      uploadedAt: file.uploadedAt,
      description: file.description,
    }));

  const total = fileMetadata.size;

  res.json({
    success: true,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
    },
    files,
  });
});

// Delete file
app.delete('/files/:id', async (req, res) => {
  const fileId = req.params.id;

  if (!fileMetadata.has(fileId)) {
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    const metadata = fileMetadata.get(fileId);

    if (fs.existsSync(metadata.originalPath)) {
      await fs.promises.unlink(metadata.originalPath);
    }
    if (fs.existsSync(metadata.thumbnailPath)) {
      await fs.promises.unlink(metadata.thumbnailPath);
    }

    fileMetadata.delete(fileId);

    res.json({
      success: true,
      message: 'File deleted successfully',
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Serve files
app.get('/serve/:type/:id', (req, res) => {
  const { type, id } = req.params;

  if (!fileMetadata.has(id)) {
    return res.status(404).json({ error: 'File not found' });
  }

  const metadata = fileMetadata.get(id);
  const filePath = type === 'thumbnail' ? metadata.thumbnailPath : metadata.originalPath;

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found on disk' });
  }

  res.sendFile(filePath);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);

  if (err.message === 'Invalid file type. Only JPG, PNG, and WebP are allowed.') {
    return res.status(400).json({ error: err.message });
  }

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: `File size exceeds maximum limit of ${MAX_FILE_SIZE / (1024 * 1024)}MB` });
  }

  if (err.code === 'LIMIT_PART_COUNT') {
    return res.status(400).json({ error: 'Too many parts' });
  }

  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`File upload server running on port ${PORT}`);
});

module.exports = app;
