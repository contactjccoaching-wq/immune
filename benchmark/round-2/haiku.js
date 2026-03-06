const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');

// Configuration and environment validation
const validateEnvironment = () => {
  const requiredEnvVars = ['NODE_ENV', 'PORT'];
  const missingVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
  if (missingVars.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }
};

validateEnvironment();

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// In-memory storage
let todos = [
  { id: 1, title: 'Learn Express', description: 'Build APIs with Express.js', status: 'done', createdAt: new Date('2026-01-01') },
  { id: 2, title: 'Setup database', description: 'Configure PostgreSQL', status: 'pending', createdAt: new Date('2026-01-02') },
  { id: 3, title: 'Write tests', description: 'Add unit tests', status: 'pending', createdAt: new Date('2026-01-03') }
];
let nextId = 4;

// Security middleware layers (in order)
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX || 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10kb' }));

// Validation middleware
const validateInputErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array().map(err => ({ field: err.param, message: err.msg }))
    });
  }
  next();
};

// Helper function to find todo by ID
const findTodoById = (id) => todos.find(todo => todo.id === parseInt(id));

// GET /api/todos - Retrieve all todos with filtering and pagination
app.get('/api/todos',
  query('status').optional().isIn(['done', 'pending']).withMessage('Status must be "done" or "pending"'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be 0 or greater'),
  validateInputErrors,
  (req, res) => {
    try {
      const { status, limit = 10, offset = 0 } = req.query;

      let filtered = todos;
      if (status) {
        filtered = todos.filter(todo => todo.status === status);
      }

      const total = filtered.length;
      const paginated = filtered.slice(parseInt(offset), parseInt(offset) + parseInt(limit));

      res.json({
        success: true,
        data: paginated,
        pagination: {
          total,
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: parseInt(offset) + parseInt(limit) < total
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// GET /api/todos/:id - Retrieve a single todo
app.get('/api/todos/:id',
  (req, res) => {
    try {
      const { id } = req.params;

      if (!Number.isInteger(parseInt(id))) {
        return res.status(400).json({
          success: false,
          error: 'Invalid ID format'
        });
      }

      const todo = findTodoById(id);
      if (!todo) {
        return res.status(404).json({
          success: false,
          error: 'Todo not found'
        });
      }

      res.json({
        success: true,
        data: todo
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// POST /api/todos - Create a new todo
app.post('/api/todos',
  body('title').trim().notEmpty().withMessage('Title is required').isLength({ max: 255 }).withMessage('Title must be 255 characters or less'),
  body('description').optional().trim().isLength({ max: 1000 }).withMessage('Description must be 1000 characters or less'),
  body('status').optional().isIn(['done', 'pending']).withMessage('Status must be "done" or "pending"'),
  validateInputErrors,
  (req, res) => {
    try {
      const { title, description = '', status = 'pending' } = req.body;

      const newTodo = {
        id: nextId++,
        title,
        description,
        status,
        createdAt: new Date()
      };

      todos.push(newTodo);

      res.status(201).json({
        success: true,
        data: newTodo,
        message: 'Todo created successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// PUT /api/todos/:id - Update a todo
app.put('/api/todos/:id',
  body('title').optional().trim().notEmpty().withMessage('Title cannot be empty').isLength({ max: 255 }).withMessage('Title must be 255 characters or less'),
  body('description').optional().trim().isLength({ max: 1000 }).withMessage('Description must be 1000 characters or less'),
  body('status').optional().isIn(['done', 'pending']).withMessage('Status must be "done" or "pending"'),
  validateInputErrors,
  (req, res) => {
    try {
      const { id } = req.params;

      if (!Number.isInteger(parseInt(id))) {
        return res.status(400).json({
          success: false,
          error: 'Invalid ID format'
        });
      }

      const todo = findTodoById(id);
      if (!todo) {
        return res.status(404).json({
          success: false,
          error: 'Todo not found'
        });
      }

      const { title, description, status } = req.body;

      if (title !== undefined) todo.title = title;
      if (description !== undefined) todo.description = description;
      if (status !== undefined) todo.status = status;

      res.json({
        success: true,
        data: todo,
        message: 'Todo updated successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// DELETE /api/todos/:id - Delete a todo
app.delete('/api/todos/:id',
  (req, res) => {
    try {
      const { id } = req.params;

      if (!Number.isInteger(parseInt(id))) {
        return res.status(400).json({
          success: false,
          error: 'Invalid ID format'
        });
      }

      const index = todos.findIndex(todo => todo.id === parseInt(id));
      if (index === -1) {
        return res.status(404).json({
          success: false,
          error: 'Todo not found'
        });
      }

      const deletedTodo = todos.splice(index, 1)[0];

      res.json({
        success: true,
        data: deletedTodo,
        message: 'Todo deleted successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? error.message : undefined
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Todo API running on port ${PORT} (${NODE_ENV} mode)`);
});

module.exports = app;
