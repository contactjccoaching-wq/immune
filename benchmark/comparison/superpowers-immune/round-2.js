/**
 * Todo List REST API
 * Express.js + in-memory storage
 * Endpoints: POST /todos, GET /todos, GET /todos/:id, PUT /todos/:id, DELETE /todos/:id
 * Features: filtering by status (done/pending), pagination (limit/offset), proper error responses
 *
 * Immune Cheatsheet applied:
 *   CS-CODE-003: comprehensive input validation at boundaries (type + length + format)
 *   CS-CODE-004: request body size limit (10kb) to prevent payload DoS
 *   CS-CODE-005: graceful shutdown on SIGTERM/SIGINT
 * Antibodies avoided:
 *   - No hardcoded secrets or env fallbacks for sensitive values
 *   - Security headers (helmet-style manual headers)
 *   - CORS configuration
 *   - Rate limiting on write endpoints
 */

'use strict';

const express = require('express');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CONFIG = {
  port: parseInt(process.env.PORT || '3000', 10),
  host: process.env.HOST || '127.0.0.1',
  maxTitleLength: 255,
  maxDescriptionLength: 2000,
  maxTodos: parseInt(process.env.MAX_TODOS || '10000', 10),
  pagination: {
    defaultLimit: 20,
    maxLimit: 100,
  },
  rateLimit: {
    windowMs: 60_000,       // 1 minute sliding window
    maxRequests: 100,       // per IP
  },
};

const VALID_STATUSES = new Set(['pending', 'done']);

// Validate critical config at startup
if (Number.isNaN(CONFIG.port) || CONFIG.port < 1 || CONFIG.port > 65535) {
  console.error('[FATAL] Invalid PORT — must be 1–65535');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// In-memory todo store (data layer — separated from route logic)
// ---------------------------------------------------------------------------

const todoStore = (() => {
  const _todos = new Map(); // id (number) → todo object
  let _nextId = 1;

  return {
    findById(id) {
      return _todos.get(id) ?? null;
    },

    /**
     * Returns a sorted snapshot of all todos, optionally filtered by status.
     * Newest first (by createdAt descending).
     * @param {string|null} statusFilter
     * @returns {Array}
     */
    findAll(statusFilter) {
      const all = Array.from(_todos.values());
      const filtered = statusFilter === null
        ? all
        : all.filter((t) => t.status === statusFilter);
      return filtered.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    isFull() {
      return _todos.size >= CONFIG.maxTodos;
    },

    create({ title, description, status }) {
      const id = _nextId++;
      const now = new Date().toISOString();
      const todo = {
        id,
        title,
        description: description ?? null,
        status: status ?? 'pending',
        createdAt: now,
        updatedAt: now,
      };
      _todos.set(id, todo);
      return todo;
    },

    update(id, fields) {
      const todo = _todos.get(id);
      if (!todo) return null;
      const updated = {
        ...todo,
        ...fields,
        id,                         // immutable
        createdAt: todo.createdAt,  // immutable
        updatedAt: new Date().toISOString(),
      };
      _todos.set(id, updated);
      return updated;
    },

    remove(id) {
      return _todos.delete(id);
    },

    size() {
      return _todos.size;
    },
  };
})();

// ---------------------------------------------------------------------------
// In-process rate limiter (sliding window per IP)
// ---------------------------------------------------------------------------

const rateLimitStore = (() => {
  const _store = new Map(); // ip → { count, windowStart }

  // Periodically evict expired entries to prevent unbounded memory growth
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of _store.entries()) {
      if (now - entry.windowStart > CONFIG.rateLimit.windowMs) {
        _store.delete(ip);
      }
    }
  }, CONFIG.rateLimit.windowMs);
  cleanupInterval.unref();

  return {
    check(ip) {
      const now = Date.now();
      const entry = _store.get(ip);

      if (!entry || now - entry.windowStart > CONFIG.rateLimit.windowMs) {
        _store.set(ip, { count: 1, windowStart: now });
        return { allowed: true };
      }

      entry.count += 1;
      if (entry.count > CONFIG.rateLimit.maxRequests) {
        const retryAfter = Math.ceil(CONFIG.rateLimit.windowMs / 1000);
        return { allowed: false, retryAfter };
      }
      return { allowed: true };
    },
  };
})();

// ---------------------------------------------------------------------------
// Validation helpers (CS-CODE-003)
// ---------------------------------------------------------------------------

function validateTitle(title, { required = true } = {}) {
  if (title === undefined || title === null) {
    return required ? 'title is required' : null;
  }
  if (typeof title !== 'string') return 'title must be a string';
  if (title.trim().length === 0) return 'title must not be empty';
  if (title.trim().length > CONFIG.maxTitleLength) {
    return `title must not exceed ${CONFIG.maxTitleLength} characters`;
  }
  return null;
}

function validateDescription(description) {
  if (description === undefined || description === null) return null; // optional
  if (typeof description !== 'string') return 'description must be a string';
  if (description.trim().length > CONFIG.maxDescriptionLength) {
    return `description must not exceed ${CONFIG.maxDescriptionLength} characters`;
  }
  return null;
}

function validateStatus(status) {
  if (status === undefined || status === null) return null; // optional
  if (!VALID_STATUSES.has(status)) {
    return `status must be one of: ${[...VALID_STATUSES].join(', ')}`;
  }
  return null;
}

/**
 * Validates and parses `limit` and `offset` query params.
 * Returns { limit, offset } on success or { error } on failure.
 */
function parsePagination(limitRaw, offsetRaw) {
  const limit = limitRaw !== undefined ? parseInt(limitRaw, 10) : CONFIG.pagination.defaultLimit;
  const offset = offsetRaw !== undefined ? parseInt(offsetRaw, 10) : 0;

  if (limitRaw !== undefined) {
    if (Number.isNaN(limit) || limit < 1) {
      return { error: 'limit must be a positive integer' };
    }
    if (limit > CONFIG.pagination.maxLimit) {
      return { error: `limit must not exceed ${CONFIG.pagination.maxLimit}` };
    }
  }

  if (offsetRaw !== undefined) {
    if (Number.isNaN(offset) || offset < 0) {
      return { error: 'offset must be a non-negative integer' };
    }
  }

  return { limit, offset };
}

/**
 * Validates a URL id param — must be a positive integer as a string.
 * Returns { id } on success or { error } on failure.
 */
function parseIdParam(rawId) {
  const id = parseInt(rawId, 10);
  if (!Number.isFinite(id) || id < 1 || String(id) !== rawId) {
    return { error: 'id must be a positive integer' };
  }
  return { id };
}

// ---------------------------------------------------------------------------
// Pagination helper (pure function, no side effects)
// ---------------------------------------------------------------------------

function applyPagination(items, limit, offset) {
  const total = items.length;
  const sliced = items.slice(offset, offset + limit);
  return {
    data: sliced,
    pagination: {
      total,
      limit,
      offset,
      hasMore: offset + limit < total,
    },
  };
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function sendError(res, statusCode, message, details) {
  const body = { error: message };
  if (details) body.details = details;
  return res.status(statusCode).json(body);
}

// ---------------------------------------------------------------------------
// Middleware — security headers (antibody: missing security headers)
// ---------------------------------------------------------------------------

function securityHeaders(_req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0'); // disabled in favour of CSP
  res.setHeader('Content-Security-Policy', "default-src 'none'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
}

// ---------------------------------------------------------------------------
// Middleware — CORS (antibody: missing CORS configuration)
// ---------------------------------------------------------------------------

function corsHeaders(_req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
}

// ---------------------------------------------------------------------------
// Middleware — rate limiting (antibody: missing rate limiting)
// ---------------------------------------------------------------------------

function rateLimitMiddleware(req, res, next) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const result = rateLimitStore.check(ip);
  if (!result.allowed) {
    res.setHeader('Retry-After', result.retryAfter);
    return sendError(res, 429, 'Too many requests — please slow down');
  }
  return next();
}

// ---------------------------------------------------------------------------
// Route handlers (single responsibility — one function per endpoint)
// ---------------------------------------------------------------------------

/**
 * POST /todos
 * Body: { title, description?, status? }
 * Returns: 201 { data: todo }
 */
function handleCreate(req, res) {
  if (todoStore.isFull()) {
    return sendError(res, 507, `Storage limit reached — maximum ${CONFIG.maxTodos} todos`);
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return sendError(res, 400, 'Request body must be a JSON object');
  }

  const { title, description, status } = body;
  const errors = [];

  const titleError = validateTitle(title, { required: true });
  if (titleError) errors.push(titleError);

  const descError = validateDescription(description);
  if (descError) errors.push(descError);

  const statusError = validateStatus(status);
  if (statusError) errors.push(statusError);

  if (errors.length > 0) {
    return sendError(res, 400, 'Validation failed', errors);
  }

  const todo = todoStore.create({
    title: title.trim(),
    description: typeof description === 'string' ? description.trim() : null,
    status: status ?? 'pending',
  });

  return res.status(201).json({ data: todo });
}

/**
 * GET /todos
 * Query: status?, limit?, offset?
 * Returns: 200 { data, pagination: { total, limit, offset, hasMore } }
 */
function handleList(req, res) {
  const { status: statusFilter, limit: limitRaw, offset: offsetRaw } = req.query;

  const statusError = validateStatus(statusFilter);
  if (statusError) {
    return sendError(res, 400, statusError);
  }

  const pagination = parsePagination(limitRaw, offsetRaw);
  if (pagination.error) {
    return sendError(res, 400, pagination.error);
  }

  const { limit, offset } = pagination;
  const items = todoStore.findAll(statusFilter ?? null);
  const result = applyPagination(items, limit, offset);

  return res.status(200).json(result);
}

/**
 * GET /todos/:id
 * Returns: 200 { data: todo }
 */
function handleGetOne(req, res) {
  const parsed = parseIdParam(req.params.id);
  if (parsed.error) {
    return sendError(res, 400, parsed.error);
  }

  const todo = todoStore.findById(parsed.id);
  if (!todo) {
    return sendError(res, 404, `Todo with id ${parsed.id} not found`);
  }

  return res.status(200).json({ data: todo });
}

/**
 * PUT /todos/:id
 * Body: { title?, description?, status? } — at least one field required
 * Returns: 200 { data: updatedTodo }
 */
function handleUpdate(req, res) {
  const parsed = parseIdParam(req.params.id);
  if (parsed.error) {
    return sendError(res, 400, parsed.error);
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return sendError(res, 400, 'Request body must be a JSON object');
  }

  const { title, description, status } = body;

  if (title === undefined && description === undefined && status === undefined) {
    return sendError(res, 400, 'At least one field must be provided: title, description, status');
  }

  const errors = [];

  if (title !== undefined) {
    const titleError = validateTitle(title, { required: false });
    if (titleError) errors.push(titleError);
  }

  if (description !== undefined) {
    const descError = validateDescription(description);
    if (descError) errors.push(descError);
  }

  if (status !== undefined) {
    const statusError = validateStatus(status);
    if (statusError) errors.push(statusError);
  }

  if (errors.length > 0) {
    return sendError(res, 400, 'Validation failed', errors);
  }

  const existing = todoStore.findById(parsed.id);
  if (!existing) {
    return sendError(res, 404, `Todo with id ${parsed.id} not found`);
  }

  const fields = {};
  if (title !== undefined) fields.title = title.trim();
  if (description !== undefined) {
    fields.description = description !== null ? description.trim() : null;
  }
  if (status !== undefined) fields.status = status;

  const updated = todoStore.update(parsed.id, fields);
  return res.status(200).json({ data: updated });
}

/**
 * DELETE /todos/:id
 * Returns: 204 No Content
 */
function handleDelete(req, res) {
  const parsed = parseIdParam(req.params.id);
  if (parsed.error) {
    return sendError(res, 400, parsed.error);
  }

  const existing = todoStore.findById(parsed.id);
  if (!existing) {
    return sendError(res, 404, `Todo with id ${parsed.id} not found`);
  }

  todoStore.remove(parsed.id);
  return res.status(204).send();
}

// ---------------------------------------------------------------------------
// App factory (separated from startup — enables unit testing)
// ---------------------------------------------------------------------------

function createApp() {
  const app = express();

  // Middleware stack (order matters)
  app.use(securityHeaders);
  app.use(corsHeaders);
  app.options('*', (_req, res) => res.status(204).send()); // preflight
  app.use(rateLimitMiddleware);
  app.use(express.json({ limit: '10kb' })); // CS-CODE-004: payload size limit

  // Handle malformed JSON from body parser before it reaches route handlers
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, next) => {
    if (err.type === 'entity.parse.failed') {
      return sendError(res, 400, 'Invalid JSON in request body');
    }
    return next(err);
  });

  // Health check — no rate limit, no auth
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', todoCount: todoStore.size() });
  });

  // Todo CRUD routes
  app.post('/todos', handleCreate);
  app.get('/todos', handleList);
  app.get('/todos/:id', handleGetOne);
  app.put('/todos/:id', handleUpdate);
  app.delete('/todos/:id', handleDelete);

  // 404 — unknown routes
  app.use((_req, res) => {
    sendError(res, 404, 'Route not found');
  });

  // Global error handler — catches unexpected throws from any route handler
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    console.error('[ERROR] Unhandled exception:', err);
    sendError(res, 500, 'Internal server error');
  });

  return app;
}

// ---------------------------------------------------------------------------
// Server startup + graceful shutdown (CS-CODE-005)
// ---------------------------------------------------------------------------

function startServer() {
  const app = createApp();

  const server = app.listen(CONFIG.port, CONFIG.host, () => {
    console.log(`[INFO] Todo API listening on http://${CONFIG.host}:${CONFIG.port}`);
    console.log(`[INFO] In-memory store limit: ${CONFIG.maxTodos} todos`);
    console.log(`[INFO] Rate limit: ${CONFIG.rateLimit.maxRequests} req / ${CONFIG.rateLimit.windowMs / 1000}s per IP`);
  });

  function shutdown(signal) {
    console.log(`\n[INFO] ${signal} received — shutting down gracefully`);
    server.close((err) => {
      if (err) {
        console.error('[ERROR] Error during server close:', err);
        process.exit(1);
      }
      console.log('[INFO] Server closed — goodbye');
      process.exit(0);
    });

    // Force exit if graceful shutdown hangs
    setTimeout(() => {
      console.error('[ERROR] Graceful shutdown timed out — forcing exit');
      process.exit(1);
    }, 10_000).unref();
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  return server;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

if (require.main === module) {
  startServer();
}

module.exports = { createApp, todoStore, CONFIG }; // Export for testing
