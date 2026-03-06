const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, query, param, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');

// Environment variables validation at startup
const REQUIRED_ENV = ['PORT', 'ALLOWED_ORIGIN'];
const missingEnv = REQUIRED_ENV.filter(key => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const PORT = parseInt(process.env.PORT, 10);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);

const app = express();

// In-memory storage
let todos = [];

// Security middleware layers in order
app.use(helmet());

app.use(cors({
  origin: ALLOWED_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
}));

app.use(express.json({ limit: '10kb' }));

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(e => ({ field: e.path, message: e.msg })),
    });
  }
  next();
};

// GET /todos - List todos with optional filtering and pagination
app.get(
  '/todos',
  [
    query('status')
      .optional()
      .isIn(['done', 'pending'])
      .withMessage('status must be "done" or "pending"'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('limit must be an integer between 1 and 100')
      .toInt(),
    query('offset')
      .optional()
      .isInt({ min: 0 })
      .withMessage('offset must be a non-negative integer')
      .toInt(),
  ],
  handleValidationErrors,
  (req, res) => {
    const { status, limit = 20, offset = 0 } = req.query;

    let filtered = todos;
    if (status) {
      filtered = todos.filter(t => t.status === status);
    }

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    res.json({
      data: paginated,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total,
      },
    });
  }
);

// GET /todos/:id - Get a single todo
app.get(
  '/todos/:id',
  [
    param('id').isUUID().withMessage('id must be a valid UUID'),
  ],
  handleValidationErrors,
  (req, res) => {
    const todo = todos.find(t => t.id === req.params.id);
    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }
    res.json({ data: todo });
  }
);

// POST /todos - Create a new todo
app.post(
  '/todos',
  [
    body('title')
      .exists({ checkFalsy: true })
      .withMessage('title is required')
      .isString()
      .withMessage('title must be a string')
      .trim()
      .isLength({ min: 1, max: 255 })
      .withMessage('title must be between 1 and 255 characters')
      .escape(),
    body('description')
      .optional()
      .isString()
      .withMessage('description must be a string')
      .trim()
      .isLength({ max: 1000 })
      .withMessage('description must be at most 1000 characters')
      .escape(),
  ],
  handleValidationErrors,
  (req, res) => {
    const { title, description = '' } = req.body;

    const todo = {
      id: uuidv4(),
      title,
      description,
      status: 'pending',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    todos.push(todo);
    res.status(201).json({ data: todo });
  }
);

// PUT /todos/:id - Replace a todo
app.put(
  '/todos/:id',
  [
    param('id').isUUID().withMessage('id must be a valid UUID'),
    body('title')
      .exists({ checkFalsy: true })
      .withMessage('title is required')
      .isString()
      .withMessage('title must be a string')
      .trim()
      .isLength({ min: 1, max: 255 })
      .withMessage('title must be between 1 and 255 characters')
      .escape(),
    body('description')
      .optional()
      .isString()
      .withMessage('description must be a string')
      .trim()
      .isLength({ max: 1000 })
      .withMessage('description must be at most 1000 characters')
      .escape(),
    body('status')
      .optional()
      .isIn(['done', 'pending'])
      .withMessage('status must be "done" or "pending"'),
  ],
  handleValidationErrors,
  (req, res) => {
    const index = todos.findIndex(t => t.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    const { title, description = '', status = 'pending' } = req.body;

    todos[index] = {
      ...todos[index],
      title,
      description,
      status,
      updatedAt: new Date().toISOString(),
    };

    res.json({ data: todos[index] });
  }
);

// PATCH /todos/:id - Partially update a todo
app.patch(
  '/todos/:id',
  [
    param('id').isUUID().withMessage('id must be a valid UUID'),
    body('title')
      .optional()
      .isString()
      .withMessage('title must be a string')
      .trim()
      .isLength({ min: 1, max: 255 })
      .withMessage('title must be between 1 and 255 characters')
      .escape(),
    body('description')
      .optional()
      .isString()
      .withMessage('description must be a string')
      .trim()
      .isLength({ max: 1000 })
      .withMessage('description must be at most 1000 characters')
      .escape(),
    body('status')
      .optional()
      .isIn(['done', 'pending'])
      .withMessage('status must be "done" or "pending"'),
  ],
  handleValidationErrors,
  (req, res) => {
    const index = todos.findIndex(t => t.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    const allowedFields = ['title', 'description', 'status'];
    const updates = {};
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No valid fields provided for update' });
    }

    todos[index] = {
      ...todos[index],
      ...updates,
      updatedAt: new Date().toISOString(),
    };

    res.json({ data: todos[index] });
  }
);

// DELETE /todos/:id - Delete a todo
app.delete(
  '/todos/:id',
  [
    param('id').isUUID().withMessage('id must be a valid UUID'),
  ],
  handleValidationErrors,
  (req, res) => {
    const index = todos.findIndex(t => t.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    todos.splice(index, 1);
    res.status(204).send();
  }
);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Todo API listening on port ${PORT}`);
});

module.exports = app;
