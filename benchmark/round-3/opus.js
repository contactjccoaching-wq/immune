const express = require("express");
const multer = require("multer");
const sharp = require("sharp");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// 1. Environment variable validation at startup
// ---------------------------------------------------------------------------
const REQUIRED_ENV = ["PORT", "UPLOAD_DIR", "THUMBNAIL_DIR", "CORS_ORIGIN"];

const missing = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missing.length > 0) {
  console.error(`Missing required environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

const PORT = parseInt(process.env.PORT, 10);
const UPLOAD_DIR = process.env.UPLOAD_DIR;
const THUMBNAIL_DIR = process.env.THUMBNAIL_DIR;
const CORS_ORIGIN = process.env.CORS_ORIGIN;
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || "5242880", 10); // 5 MB
const THUMB_WIDTH = parseInt(process.env.THUMB_WIDTH || "200", 10);
const THUMB_HEIGHT = parseInt(process.env.THUMB_HEIGHT || "200", 10);

// Ensure upload directories exist
[UPLOAD_DIR, THUMBNAIL_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// 2. In-memory metadata store — Map for O(1) lookups
// ---------------------------------------------------------------------------
const imageStore = new Map();

// ---------------------------------------------------------------------------
// 3. Validation constants (reusable)
// ---------------------------------------------------------------------------
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp"];

const PAGINATION_DEFAULTS = { page: 1, limit: 20, maxLimit: 100 };

// ---------------------------------------------------------------------------
// 4. Multer configuration
// ---------------------------------------------------------------------------
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const id = crypto.randomUUID();
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${id}${ext}`);
  },
});

const fileFilter = (_req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (
    !ALLOWED_MIME_TYPES.includes(file.mimetype) ||
    !ALLOWED_EXTENSIONS.includes(ext)
  ) {
    return cb(
      Object.assign(new Error("Invalid file type. Allowed: jpg, png, webp."), {
        status: 400,
      }),
      false
    );
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE },
});

// ---------------------------------------------------------------------------
// 5. Express app setup
// ---------------------------------------------------------------------------
const app = express();

// --- Security middleware layers (in order) ---

// a) Helmet — secure HTTP headers
app.use(helmet());

// b) CORS — origin restriction
app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ["GET", "POST", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// c) Rate limiting — abuse prevention
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many upload requests. Please try again later." },
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." },
});

app.use(generalLimiter);

// d) JSON body parser (for non-multipart routes)
app.use(express.json({ limit: "1mb" }));

// ---------------------------------------------------------------------------
// 6. Thumbnail generator
// ---------------------------------------------------------------------------
async function generateThumbnail(sourcePath, filename) {
  const thumbPath = path.join(THUMBNAIL_DIR, `thumb_${filename}`);
  await sharp(sourcePath)
    .resize(THUMB_WIDTH, THUMB_HEIGHT, { fit: "cover", position: "center" })
    .toFile(thumbPath);
  return thumbPath;
}

// ---------------------------------------------------------------------------
// 7. Validation helpers
// ---------------------------------------------------------------------------
function validatePagination(query) {
  let page = parseInt(query.page, 10);
  let limit = parseInt(query.limit, 10);

  if (isNaN(page) || page < 1) page = PAGINATION_DEFAULTS.page;
  if (isNaN(limit) || limit < 1) limit = PAGINATION_DEFAULTS.limit;
  if (limit > PAGINATION_DEFAULTS.maxLimit) limit = PAGINATION_DEFAULTS.maxLimit;

  return { page, limit };
}

function validateUUID(id) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    id
  );
}

// ---------------------------------------------------------------------------
// 8. Routes
// ---------------------------------------------------------------------------

// POST /upload — upload a single image
app.post("/upload", uploadLimiter, upload.single("image"), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image file provided." });
    }

    const { filename, originalname, mimetype, size, path: filePath } = req.file;
    const id = path.parse(filename).name;

    // Generate thumbnail
    const thumbnailPath = await generateThumbnail(filePath, filename);

    // Build metadata
    const metadata = {
      id,
      originalName: originalname,
      filename,
      mimeType: mimetype,
      size,
      filePath,
      thumbnailPath,
      thumbnailFilename: `thumb_${filename}`,
      createdAt: new Date().toISOString(),
    };

    // Store in Map (O(1) insertion)
    imageStore.set(id, metadata);

    return res.status(201).json({
      message: "Image uploaded successfully.",
      data: {
        id: metadata.id,
        originalName: metadata.originalName,
        filename: metadata.filename,
        mimeType: metadata.mimeType,
        size: metadata.size,
        thumbnailFilename: metadata.thumbnailFilename,
        createdAt: metadata.createdAt,
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /images — list all images with pagination
app.get("/images", (req, res) => {
  const { page, limit } = validatePagination(req.query);

  // Sort by createdAt descending before slicing for stable pagination
  const allImages = Array.from(imageStore.values()).sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
  );

  const total = allImages.length;
  const totalPages = Math.ceil(total / limit) || 1;
  const startIndex = (page - 1) * limit;
  const results = allImages.slice(startIndex, startIndex + limit);

  return res.json({
    data: results.map((img) => ({
      id: img.id,
      originalName: img.originalName,
      filename: img.filename,
      mimeType: img.mimeType,
      size: img.size,
      thumbnailFilename: img.thumbnailFilename,
      createdAt: img.createdAt,
    })),
    pagination: {
      page,
      limit,
      total,
      totalPages,
    },
  });
});

// GET /images/:id — get single image metadata
app.get("/images/:id", (req, res) => {
  const { id } = req.params;

  if (!validateUUID(id)) {
    return res.status(400).json({ error: "Invalid image ID format." });
  }

  const metadata = imageStore.get(id);
  if (!metadata) {
    return res.status(404).json({ error: "Image not found." });
  }

  return res.json({
    data: {
      id: metadata.id,
      originalName: metadata.originalName,
      filename: metadata.filename,
      mimeType: metadata.mimeType,
      size: metadata.size,
      thumbnailFilename: metadata.thumbnailFilename,
      createdAt: metadata.createdAt,
    },
  });
});

// GET /images/:id/file — serve original image file
app.get("/images/:id/file", (req, res) => {
  const { id } = req.params;

  if (!validateUUID(id)) {
    return res.status(400).json({ error: "Invalid image ID format." });
  }

  const metadata = imageStore.get(id);
  if (!metadata) {
    return res.status(404).json({ error: "Image not found." });
  }

  return res.sendFile(path.resolve(metadata.filePath));
});

// GET /images/:id/thumbnail — serve thumbnail
app.get("/images/:id/thumbnail", (req, res) => {
  const { id } = req.params;

  if (!validateUUID(id)) {
    return res.status(400).json({ error: "Invalid image ID format." });
  }

  const metadata = imageStore.get(id);
  if (!metadata) {
    return res.status(404).json({ error: "Image not found." });
  }

  return res.sendFile(path.resolve(metadata.thumbnailPath));
});

// DELETE /images/:id — delete an image and its thumbnail
app.delete("/images/:id", (req, res) => {
  const { id } = req.params;

  if (!validateUUID(id)) {
    return res.status(400).json({ error: "Invalid image ID format." });
  }

  const metadata = imageStore.get(id);
  if (!metadata) {
    return res.status(404).json({ error: "Image not found." });
  }

  // Remove files from disk
  try {
    if (fs.existsSync(metadata.filePath)) fs.unlinkSync(metadata.filePath);
  } catch (_) {
    /* best effort */
  }
  try {
    if (fs.existsSync(metadata.thumbnailPath)) fs.unlinkSync(metadata.thumbnailPath);
  } catch (_) {
    /* best effort */
  }

  // Remove from store
  imageStore.delete(id);

  return res.json({ message: "Image deleted successfully.", id });
});

// ---------------------------------------------------------------------------
// 9. Global error handler
// ---------------------------------------------------------------------------
app.use((err, _req, res, _next) => {
  // Multer file-size error
  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({
      error: `File too large. Maximum allowed size is ${MAX_FILE_SIZE} bytes (${(MAX_FILE_SIZE / 1024 / 1024).toFixed(1)} MB).`,
    });
  }

  // Multer unexpected field
  if (err.code === "LIMIT_UNEXPECTED_FILE") {
    return res.status(400).json({
      error: 'Unexpected field. Use "image" as the form field name.',
    });
  }

  // Custom file-type validation error
  if (err.status === 400) {
    return res.status(400).json({ error: err.message });
  }

  // Body-parser specific error types
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Malformed JSON in request body." });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body too large." });
  }

  // Catch-all
  console.error("Unhandled error:", err);
  return res.status(500).json({ error: "Internal server error." });
});

// ---------------------------------------------------------------------------
// 10. Start server
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Image upload server running on port ${PORT}`);
  console.log(`Upload directory: ${UPLOAD_DIR}`);
  console.log(`Thumbnail directory: ${THUMBNAIL_DIR}`);
  console.log(`Max file size: ${(MAX_FILE_SIZE / 1024 / 1024).toFixed(1)} MB`);
  console.log(`Allowed types: ${ALLOWED_MIME_TYPES.join(", ")}`);
});

module.exports = app;
