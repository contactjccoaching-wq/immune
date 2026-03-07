/**
 * Todo List REST API
 * Express.js, in-memory storage
 * Features: CRUD, status filtering (done/pending), pagination (limit/offset)
 */

'use strict';

const express = require('express');

// ─── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const VALID_STATUSES = new Set(['done', 'pending']);

// ─── In-Memory Storage Layer ─────────────────────────────────────────────────

const store = {
  todos: new Map(),
  nextId: 1,

  create(data) {
    const id = String(this.nextId++);
    const todo = {
      id,
      title: data.title,
      description: data.description ?? '',
      status: data.status ?? 'pending',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.todos.set(id, todo);
    return todo;
  },

  findById(id) {
    return this.todos.get(id) ?? null;
  },

  findAll({ status, limit, offset }) {
    let items = Array.from(this.todos.values());

    if (status !== undefined) {
      items = items.filter((todo) => todo.status === status);
    }

    const total = items.length;
    const page = items.slice(offset, offset + limit);

    return { items: page, total, limit, offset };
  },

  update(id, data) {
    const todo = this.todos.get(id);
    if (!todo) return null;

    const updated = {
      ...todo,
      ...(data.title !== undefined && { title: data.title }),
      ...(data.description !== undefined && { description: data.description }),
      ...(data.status !== undefined && { status: data.status }),
      updatedAt: new Date().toISOString(),
    };

    this.todos.set(id, updated);
    return updated;
  },

  delete(id) {
    if (!this.todos.has(id)) return false;
    this.todos.delete(id);
    return true;
  },
};

// ─── Validation Helpers ───────────────────────────────────────────────────────

function validateCreateBody(body) {
  const errors = [];

  if (!body || typeof body !== 'object') {
    return ['Request body must be a JSON object'];
  }

  if (body.title === undefined || body.title === null) {
    errors.push('title is required');
  } else if (typeof body.title !== 'string') {
    errors.push('title must be a string');
  } else if (body.title.trim().length === 0) {
    errors.push('title must not be empty');
  } else if (body.title.length > 255) {
    errors.push('title must be 255 characters or fewer');
  }

  if (body.description !== undefined) {
    if (typeof body.description !== 'string') {
      errors.push('description must be a string');
    } else if (body.description.length > 1000) {
      errors.push('description must be 1000 characters or fewer');
    }
  }

  if (body.status !== undefined) {
    if (!VALID_STATUSES.has(body.status)) {
      errors.push(`status must be one of: ${[...VALID_STATUSES].join(', ')}`);
    }
  }

  return errors;
}

function validateUpdateBody(body) {
  const errors = [];

  if (!body || typeof body !== 'object') {
    return ['Request body must be a JSON object'];
  }

  const hasAnyField = ['title', 'description', 'status'].some(
    (k) => k in body
  );
  if (!hasAnyField) {
    errors.push('At least one field must be provided: title, description, status');
  }

  if ('title' in body) {
    if (typeof body.title !== 'string') {
      errors.push('title must be a string');
    } else if (body.title.trim().length === 0) {
      errors.push('title must not be empty');
    } else if (body.title.length > 255) {
      errors.push('title must be 255 characters or fewer');
    }
  }

  if ('description' in body) {
    if (typeof body.description !== 'string') {
      errors.push('description must be a string');
    } else if (body.description.length > 1000) {
      errors.push('description must be 1000 characters or fewer');
    }
  }

  if ('status' in body) {
    if (!VALID_STATUSES.has(body.status)) {
      errors.push(`status must be one of: ${[...VALID_STATUSES].join(', ')}`);
    }
  }

  return errors;
}

function parseQueryPagination(query) {
  const errors = [];

  let limit = DEFAULT_LIMIT;
  let offset = 0;

  if (query.limit !== undefined) {
    const parsed = Number(query.limit);
    if (!Number.isInteger(parsed) || parsed < 1) {
      errors.push('limit must be a positive integer');
    } else if (parsed > MAX_LIMIT) {
      errors.push(`limit must not exceed ${MAX_LIMIT}`);
    } else {
      limit = parsed;
    }
  }

  if (query.offset !== undefined) {
    const parsed = Number(query.offset);
    if (!Number.isInteger(parsed) || parsed < 0) {
      errors.push('offset must be a non-negative integer');
    } else {
      offset = parsed;
    }
  }

  return { limit, offset, errors };
}

function parseQueryStatus(query) {
  if (query.status === undefined) return { status: undefined, error: null };
  if (!VALID_STATUSES.has(query.status)) {
    return {
      status: undefined,
      error: `status filter must be one of: ${[...VALID_STATUSES].join(', ')}`,
    };
  }
  return { status: query.status, error: null };
}

// ─── Response Helpers ─────────────────────────────────────────────────────────

function sendSuccess(res, data, statusCode = 200) {
  return res.status(statusCode).json({ success: true, data });
}

function sendError(res, message, statusCode = 400, details = null) {
  const body = { success: false, error: { message } };
  if (details) body.error.details = details;
  return res.status(statusCode).json(body);
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

function listTodos(req, res) {
  const { status, error: statusError } = parseQueryStatus(req.query);
  if (statusError) {
    return sendError(res, statusError, 400);
  }

  const { limit, offset, errors: paginationErrors } = parseQueryPagination(req.query);
  if (paginationErrors.length > 0) {
    return sendError(res, 'Invalid pagination parameters', 400, paginationErrors);
  }

  const result = store.findAll({ status, limit, offset });

  return sendSuccess(res, {
    todos: result.items,
    pagination: {
      total: result.total,
      limit: result.limit,
      offset: result.offset,
      hasMore: result.offset + result.items.length < result.total,
    },
  });
}

function createTodo(req, res) {
  const errors = validateCreateBody(req.body);
  if (errors.length > 0) {
    return sendError(res, 'Validation failed', 400, errors);
  }

  const todo = store.create({
    title: req.body.title.trim(),
    description: typeof req.body.description === 'string'
      ? req.body.description.trim()
      : '',
    status: req.body.status,
  });

  return sendSuccess(res, { todo }, 201);
}

function getTodo(req, res) {
  const todo = store.findById(req.params.id);
  if (!todo) {
    return sendError(res, `Todo with id '${req.params.id}' not found`, 404);
  }
  return sendSuccess(res, { todo });
}

function updateTodo(req, res) {
  const errors = validateUpdateBody(req.body);
  if (errors.length > 0) {
    return sendError(res, 'Validation failed', 400, errors);
  }

  const existing = store.findById(req.params.id);
  if (!existing) {
    return sendError(res, `Todo with id '${req.params.id}' not found`, 404);
  }

  const updated = store.update(req.params.id, {
    ...(req.body.title !== undefined && { title: req.body.title.trim() }),
    ...(req.body.description !== undefined && { description: req.body.description.trim() }),
    ...(req.body.status !== undefined && { status: req.body.status }),
  });

  return sendSuccess(res, { todo: updated });
}

function deleteTodo(req, res) {
  const deleted = store.delete(req.params.id);
  if (!deleted) {
    return sendError(res, `Todo with id '${req.params.id}' not found`, 404);
  }
  return sendSuccess(res, { message: 'Todo deleted successfully' });
}

// ─── App Setup ────────────────────────────────────────────────────────────────

function buildApp() {
  const app = express();

  app.use(express.json());

  // Handle malformed JSON bodies
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
      return sendError(res, 'Invalid JSON in request body', 400);
    }
    return next(err);
  });

  // Routes
  app.get('/todos', listTodos);
  app.post('/todos', createTodo);
  app.get('/todos/:id', getTodo);
  app.put('/todos/:id', updateTodo);
  app.delete('/todos/:id', deleteTodo);

  // 404 for unknown routes
  app.use((req, res) => {
    return sendError(res, `Route '${req.method} ${req.path}' not found`, 404);
  });

  // Global error handler (catch unexpected throws)
  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    return sendError(res, 'Internal server error', 500);
  });

  return app;
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const app = buildApp();

const server = app.listen(PORT, () => {
  console.log(`Todo API listening on port ${PORT}`);
});

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

function shutdown(signal) {
  console.log(`\nReceived ${signal}. Shutting down gracefully...`);
  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });

  // Force shutdown if server hasn't closed within 10 seconds
  setTimeout(() => {
    console.error('Forced shutdown after timeout.');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = { app, store };
