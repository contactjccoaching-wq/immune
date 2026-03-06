const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { body, query, param, validationResult } = require("express-validator");
const crypto = require("crypto");

// --- Mandatory environment variable validation at startup ---
const REQUIRED_ENV = ["PORT", "CORS_ORIGIN", "RATE_LIMIT_WINDOW_MS", "RATE_LIMIT_MAX"];

const missing = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missing.length > 0) {
  console.error(`FATAL: Missing required environment variables: ${missing.join(", ")}`);
  process.exit(1);
}

const PORT = parseInt(process.env.PORT, 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN;
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX, 10);

if (isNaN(PORT) || isNaN(RATE_LIMIT_WINDOW_MS) || isNaN(RATE_LIMIT_MAX)) {
  console.error("FATAL: PORT, RATE_LIMIT_WINDOW_MS, and RATE_LIMIT_MAX must be valid integers.");
  process.exit(1);
}

// --- App setup ---
const app = express();

// --- Security middleware layers (order matters) ---

// 1. Helmet: secure HTTP headers
app.use(helmet());

// 2. CORS: restrict origins
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? "*" : CORS_ORIGIN.split(","),
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// 3. Rate limiting: abuse prevention
app.use(
  rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max: RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests, please try again later." },
  })
);

// 4. Body parsing with size limit
app.use(express.json({ limit: "10kb" }));

// --- In-memory storage ---
const todos = new Map();

// --- Validation helpers ---
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: "Validation failed",
      details: errors.array().map((e) => ({
        field: e.path,
        message: e.msg,
      })),
    });
  }
  next();
};

const sanitizeString = (value) => {
  if (typeof value !== "string") return value;
  return value.replace(/[<>]/g, "").trim();
};

// --- Validation schemas ---
const createTodoValidation = [
  body("title")
    .exists({ checkFalsy: true })
    .withMessage("title is required")
    .isString()
    .withMessage("title must be a string")
    .isLength({ min: 1, max: 255 })
    .withMessage("title must be between 1 and 255 characters")
    .customSanitizer(sanitizeString),
  body("description")
    .optional()
    .isString()
    .withMessage("description must be a string")
    .isLength({ max: 1024 })
    .withMessage("description must be at most 1024 characters")
    .customSanitizer(sanitizeString),
  handleValidationErrors,
];

const updateTodoValidation = [
  param("id").isUUID(4).withMessage("id must be a valid UUID"),
  body("title")
    .optional()
    .isString()
    .withMessage("title must be a string")
    .isLength({ min: 1, max: 255 })
    .withMessage("title must be between 1 and 255 characters")
    .customSanitizer(sanitizeString),
  body("description")
    .optional()
    .isString()
    .withMessage("description must be a string")
    .isLength({ max: 1024 })
    .withMessage("description must be at most 1024 characters")
    .customSanitizer(sanitizeString),
  body("status")
    .optional()
    .isIn(["done", "pending"])
    .withMessage("status must be 'done' or 'pending'"),
  handleValidationErrors,
];

const getTodoValidation = [
  param("id").isUUID(4).withMessage("id must be a valid UUID"),
  handleValidationErrors,
];

const deleteTodoValidation = [
  param("id").isUUID(4).withMessage("id must be a valid UUID"),
  handleValidationErrors,
];

const listTodosValidation = [
  query("status")
    .optional()
    .isIn(["done", "pending"])
    .withMessage("status must be 'done' or 'pending'"),
  query("limit")
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage("limit must be an integer between 1 and 100")
    .toInt(),
  query("offset")
    .optional()
    .isInt({ min: 0 })
    .withMessage("offset must be a non-negative integer")
    .toInt(),
  handleValidationErrors,
];

// --- Routes ---

// GET /todos - List todos with optional filtering and pagination
app.get("/todos", listTodosValidation, (req, res) => {
  const { status, limit = 20, offset = 0 } = req.query;

  let items = Array.from(todos.values());

  // Filter by status
  if (status) {
    items = items.filter((todo) => todo.status === status);
  }

  // Sort by creation date (newest first)
  items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const total = items.length;
  const paginatedItems = items.slice(offset, offset + limit);

  res.json({
    data: paginatedItems,
    pagination: {
      total,
      limit,
      offset,
      hasMore: offset + limit < total,
    },
  });
});

// GET /todos/:id - Get a single todo
app.get("/todos/:id", getTodoValidation, (req, res) => {
  const todo = todos.get(req.params.id);

  if (!todo) {
    return res.status(404).json({ error: "Todo not found" });
  }

  res.json({ data: todo });
});

// POST /todos - Create a new todo
app.post("/todos", createTodoValidation, (req, res) => {
  const { title, description } = req.body;
  const now = new Date().toISOString();

  const todo = {
    id: crypto.randomUUID(),
    title,
    description: description || null,
    status: "pending",
    createdAt: now,
    updatedAt: now,
  };

  todos.set(todo.id, todo);

  res.status(201).json({ data: todo });
});

// PUT /todos/:id - Full update of a todo
app.put(
  "/todos/:id",
  [
    param("id").isUUID(4).withMessage("id must be a valid UUID"),
    body("title")
      .exists({ checkFalsy: true })
      .withMessage("title is required")
      .isString()
      .withMessage("title must be a string")
      .isLength({ min: 1, max: 255 })
      .withMessage("title must be between 1 and 255 characters")
      .customSanitizer(sanitizeString),
    body("description")
      .optional()
      .isString()
      .withMessage("description must be a string")
      .isLength({ max: 1024 })
      .withMessage("description must be at most 1024 characters")
      .customSanitizer(sanitizeString),
    body("status")
      .exists({ checkFalsy: true })
      .withMessage("status is required")
      .isIn(["done", "pending"])
      .withMessage("status must be 'done' or 'pending'"),
    handleValidationErrors,
  ],
  (req, res) => {
    const existing = todos.get(req.params.id);

    if (!existing) {
      return res.status(404).json({ error: "Todo not found" });
    }

    const { title, description, status } = req.body;

    const updated = {
      ...existing,
      title,
      description: description || null,
      status,
      updatedAt: new Date().toISOString(),
    };

    todos.set(req.params.id, updated);

    res.json({ data: updated });
  }
);

// PATCH /todos/:id - Partial update of a todo
app.patch("/todos/:id", updateTodoValidation, (req, res) => {
  const existing = todos.get(req.params.id);

  if (!existing) {
    return res.status(404).json({ error: "Todo not found" });
  }

  const { title, description, status } = req.body;

  if (title === undefined && description === undefined && status === undefined) {
    return res.status(400).json({
      error: "Validation failed",
      details: [{ field: "body", message: "At least one field (title, description, status) must be provided" }],
    });
  }

  const updated = {
    ...existing,
    ...(title !== undefined && { title }),
    ...(description !== undefined && { description }),
    ...(status !== undefined && { status }),
    updatedAt: new Date().toISOString(),
  };

  todos.set(req.params.id, updated);

  res.json({ data: updated });
});

// DELETE /todos/:id - Delete a todo
app.delete("/todos/:id", deleteTodoValidation, (req, res) => {
  const existing = todos.get(req.params.id);

  if (!existing) {
    return res.status(404).json({ error: "Todo not found" });
  }

  todos.delete(req.params.id);

  res.status(204).send();
});

// --- 404 handler ---
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// --- Global error handler ---
app.use((err, req, res, _next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON in request body" });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body too large" });
  }

  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Todo API server running on port ${PORT}`);
});

module.exports = app;
