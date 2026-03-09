'use strict';

/**
 * Todo List REST API
 * Production-quality, single-file Express.js server
 * In-memory storage with CRUD + filtering by status + pagination
 *
 * Cheatsheet strategies applied:
 *   CS-CODE-005: Schema validation with per-field type guards and fallback defaults
 *   CS-CODE-006: Centralized init() function
 *   CS-CODE-007: Single centralized state object
 *   CS-CODE-012: Credential-present implies validation-required (optional API_KEY gate)
 *   CS-CODE-013: Fail-closed pattern for secrets
 *   CS-CODE-014: escapeHtml() before any HTML-context rendering
 *   CS-CODE-015: Query params and path segments validated before use
 *   CS-CODE-016: Auth gate BEFORE dangerous operations
 *
 * Known pitfalls avoided:
 *   AB-CODE-008: JSON.parse wrapped in try/catch
 *   AB-CODE-021: No default-true auth path
 *   AB-CODE-022: No hardcoded fallback credentials
 *   AB-CODE-023: No template XSS (only JSON responses)
 *   AB-CODE-025: No wildcard CORS on sensitive endpoints
 *   AB-CODE-027: Auth via Authorization header, not URL query param
 *   AB-CODE-028: GET endpoints are read-only; mutations use POST/PUT/DELETE
 *   AB-CODE-030: No dynamic SQL / identifier injection (in-memory, all keys validated)
 *   AB-CODE-031: Constant-time secret comparison (crypto.timingSafeEqual)
 */

const express = require('express');
const crypto  = require('crypto');

// ─────────────────────────────────────────────
// CS-CODE-007 — Single centralized state object
// ─────────────────────────────────────────────
const state = {
  todos:   new Map(),   // id → todo object
  nextId:  1,
  app:     null,
  server:  null,
  config:  {},
};

// ─────────────────────────────────────────────
// Utility — HTML escaping (CS-CODE-014)
// Not strictly needed for JSON-only API, but
// included per CS-CODE-001/014 for completeness
// ─────────────────────────────────────────────
function escapeHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
}

// ─────────────────────────────────────────────
// Constant-time secret comparison (AB-CODE-031)
// ─────────────────────────────────────────────
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) {
    // Still run comparison on equal-length buffers to prevent length-timing leak
    crypto.timingSafeEqual(aBuf, aBuf);
    return false;
  }
  return crypto.timingSafeEqual(aBuf, bBuf);
}

// ─────────────────────────────────────────────
// Schema validation helpers (CS-CODE-005)
// ─────────────────────────────────────────────
const VALID_STATUSES = new Set(['pending', 'done']);

/**
 * Validate and sanitize a todo input body.
 * Returns { valid: true, data } or { valid: false, error }
 */
function validateTodoBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, error: 'Request body must be a JSON object.' };
  }

  const title = body.title;
  if (typeof title !== 'string' || title.trim().length === 0) {
    return { valid: false, error: '"title" is required and must be a non-empty string.' };
  }
  if (title.trim().length > 500) {
    return { valid: false, error: '"title" must not exceed 500 characters.' };
  }

  // status: optional on create (defaults to 'pending'), required valid value if present
  let status = 'pending';
  if (body.status !== undefined) {
    if (!VALID_STATUSES.has(body.status)) {
      return { valid: false, error: `"status" must be one of: ${[...VALID_STATUSES].join(', ')}.` };
    }
    status = body.status;
  }

  // description: optional, string, max 2000 chars
  let description = '';
  if (body.description !== undefined) {
    if (typeof body.description !== 'string') {
      return { valid: false, error: '"description" must be a string.' };
    }
    if (body.description.length > 2000) {
      return { valid: false, error: '"description" must not exceed 2000 characters.' };
    }
    description = body.description;
  }

  return {
    valid: true,
    data: {
      title:       title.trim(),
      description: description.trim(),
      status,
    },
  };
}

/**
 * Validate and parse pagination + filter query params (CS-CODE-015)
 * Returns { valid: true, params } or { valid: false, error }
 */
function validateListParams(query) {
  // limit: integer 1–100, default 20
  let limit = 20;
  if (query.limit !== undefined) {
    const parsed = parseInt(query.limit, 10);
    if (isNaN(parsed) || parsed < 1 || parsed > 100) {
      return { valid: false, error: '"limit" must be an integer between 1 and 100.' };
    }
    limit = parsed;
  }

  // offset: non-negative integer, default 0
  let offset = 0;
  if (query.offset !== undefined) {
    const parsed = parseInt(query.offset, 10);
    if (isNaN(parsed) || parsed < 0) {
      return { valid: false, error: '"offset" must be a non-negative integer.' };
    }
    offset = parsed;
  }

  // status filter: optional, must be valid value if present
  let statusFilter = null;
  if (query.status !== undefined) {
    if (!VALID_STATUSES.has(query.status)) {
      return { valid: false, error: `"status" filter must be one of: ${[...VALID_STATUSES].join(', ')}.` };
    }
    statusFilter = query.status;
  }

  return { valid: true, params: { limit, offset, statusFilter } };
}

/**
 * Parse a numeric ID from a path parameter (CS-CODE-015)
 * Returns { valid: true, id } or { valid: false, error }
 */
function validateIdParam(raw) {
  const parsed = parseInt(raw, 10);
  if (isNaN(parsed) || parsed < 1 || String(parsed) !== String(raw)) {
    return { valid: false, error: 'Todo ID must be a positive integer.' };
  }
  return { valid: true, id: parsed };
}

// ─────────────────────────────────────────────
// Standard response helpers
// ─────────────────────────────────────────────
function sendSuccess(res, data, statusCode = 200) {
  return res.status(statusCode).json({ success: true, ...data });
}

function sendError(res, statusCode, message) {
  return res.status(statusCode).json({ success: false, error: message });
}

// ─────────────────────────────────────────────
// Auth middleware (CS-CODE-012, CS-CODE-013,
//   CS-CODE-016, AB-CODE-021, AB-CODE-022,
//   AB-CODE-027, AB-CODE-031)
//
// If API_KEY is set in environment, ALL requests
// MUST present it via "Authorization: Bearer <key>".
// Fail-closed: if key is configured but missing/wrong
// → 401. No hardcoded fallback.
// ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const requiredKey = state.config.apiKey;

  // No key configured → open API (no auth required)
  if (!requiredKey) {
    return next();
  }

  // Key is configured → validation is required (CS-CODE-012)
  const authHeader = req.headers['authorization'] || '';
  if (!authHeader.startsWith('Bearer ')) {
    return sendError(res, 401, 'Authorization header with Bearer token required.');
  }

  const provided = authHeader.slice('Bearer '.length);

  // Constant-time comparison to prevent timing attacks (AB-CODE-031)
  if (!timingSafeEqual(provided, requiredKey)) {
    return sendError(res, 401, 'Invalid API key.');
  }

  return next();
}

// ─────────────────────────────────────────────
// CORS middleware (AB-CODE-025)
// Restrict to explicit allowed origins only.
// No wildcard on the main API.
// ─────────────────────────────────────────────
function corsMiddleware(req, res, next) {
  const allowedOrigins = state.config.allowedOrigins;
  const origin = req.headers['origin'];

  if (origin && allowedOrigins.length > 0) {
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
    // Unknown origin → do not set CORS header (browser will block it)
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  return next();
}

// ─────────────────────────────────────────────
// Route handlers
// ─────────────────────────────────────────────

// GET /todos — list with filtering + pagination (AB-CODE-028: read-only GET)
function handleListTodos(req, res) {
  const validation = validateListParams(req.query);
  if (!validation.valid) {
    return sendError(res, 400, validation.error);
  }

  const { limit, offset, statusFilter } = validation.params;

  // Filter
  let items = [...state.todos.values()];
  if (statusFilter !== null) {
    items = items.filter(t => t.status === statusFilter);
  }

  // Sort by creation time (ascending) for deterministic pagination
  items.sort((a, b) => a.createdAt - b.createdAt);

  const total  = items.length;
  const paged  = items.slice(offset, offset + limit);

  return sendSuccess(res, {
    data: paged,
    pagination: {
      total,
      limit,
      offset,
      count:    paged.length,
      hasMore:  offset + paged.length < total,
    },
  });
}

// GET /todos/:id — get single todo (AB-CODE-028: read-only GET)
function handleGetTodo(req, res) {
  const validation = validateIdParam(req.params.id);
  if (!validation.valid) {
    return sendError(res, 400, validation.error);
  }

  const todo = state.todos.get(validation.id);
  if (!todo) {
    return sendError(res, 404, `Todo with ID ${validation.id} not found.`);
  }

  return sendSuccess(res, { data: todo });
}

// POST /todos — create (AB-CODE-028: mutation uses POST)
function handleCreateTodo(req, res) {
  const validation = validateTodoBody(req.body);
  if (!validation.valid) {
    return sendError(res, 400, validation.error);
  }

  const { title, description, status } = validation.data;
  const id   = state.nextId++;
  const now  = Date.now();

  const todo = {
    id,
    title,
    description,
    status,
    createdAt:  now,
    updatedAt:  now,
  };

  state.todos.set(id, todo);
  return sendSuccess(res, { data: todo }, 201);
}

// PUT /todos/:id — full update (AB-CODE-028: mutation uses PUT)
function handleUpdateTodo(req, res) {
  const idValidation = validateIdParam(req.params.id);
  if (!idValidation.valid) {
    return sendError(res, 400, idValidation.error);
  }

  const existing = state.todos.get(idValidation.id);
  if (!existing) {
    return sendError(res, 404, `Todo with ID ${idValidation.id} not found.`);
  }

  const bodyValidation = validateTodoBody(req.body);
  if (!bodyValidation.valid) {
    return sendError(res, 400, bodyValidation.error);
  }

  const { title, description, status } = bodyValidation.data;
  const updated = {
    ...existing,
    title,
    description,
    status,
    updatedAt: Date.now(),
  };

  state.todos.set(idValidation.id, updated);
  return sendSuccess(res, { data: updated });
}

// PATCH /todos/:id — partial update (status only or title+description)
function handlePatchTodo(req, res) {
  const idValidation = validateIdParam(req.params.id);
  if (!idValidation.valid) {
    return sendError(res, 400, idValidation.error);
  }

  const existing = state.todos.get(idValidation.id);
  if (!existing) {
    return sendError(res, 404, `Todo with ID ${idValidation.id} not found.`);
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return sendError(res, 400, 'Request body must be a JSON object.');
  }

  // Only known fields are accepted; unknown fields are silently ignored
  let title       = existing.title;
  let description = existing.description;
  let status      = existing.status;

  if (body.title !== undefined) {
    if (typeof body.title !== 'string' || body.title.trim().length === 0) {
      return sendError(res, 400, '"title" must be a non-empty string.');
    }
    if (body.title.trim().length > 500) {
      return sendError(res, 400, '"title" must not exceed 500 characters.');
    }
    title = body.title.trim();
  }

  if (body.description !== undefined) {
    if (typeof body.description !== 'string') {
      return sendError(res, 400, '"description" must be a string.');
    }
    if (body.description.length > 2000) {
      return sendError(res, 400, '"description" must not exceed 2000 characters.');
    }
    description = body.description.trim();
  }

  if (body.status !== undefined) {
    if (!VALID_STATUSES.has(body.status)) {
      return sendError(res, 400, `"status" must be one of: ${[...VALID_STATUSES].join(', ')}.`);
    }
    status = body.status;
  }

  const updated = { ...existing, title, description, status, updatedAt: Date.now() };
  state.todos.set(idValidation.id, updated);
  return sendSuccess(res, { data: updated });
}

// DELETE /todos/:id — delete (AB-CODE-028: mutation uses DELETE)
function handleDeleteTodo(req, res) {
  const idValidation = validateIdParam(req.params.id);
  if (!idValidation.valid) {
    return sendError(res, 400, idValidation.error);
  }

  if (!state.todos.has(idValidation.id)) {
    return sendError(res, 404, `Todo with ID ${idValidation.id} not found.`);
  }

  state.todos.delete(idValidation.id);
  return sendSuccess(res, { message: `Todo ${idValidation.id} deleted.` });
}

// GET /health — lightweight health check (public, no auth)
function handleHealth(req, res) {
  return res.status(200).json({
    status: 'ok',
    todos:  state.todos.size,
    uptime: process.uptime(),
  });
}

// ─────────────────────────────────────────────
// CS-CODE-006 — Centralized init()
// ─────────────────────────────────────────────
function init() {
  // ── Config from environment (CS-CODE-013: fail-closed) ──────────────────
  const port = parseInt(process.env.PORT || '3000', 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error('[FATAL] PORT env var is invalid. Aborting.');
    process.exit(1);
  }

  // API_KEY: optional. If set, ALL routes require it.
  // No hardcoded fallback (AB-CODE-022).
  const apiKey = process.env.API_KEY || null;
  if (apiKey !== null && apiKey.trim().length === 0) {
    console.error('[FATAL] API_KEY env var is set but empty. Aborting (fail-closed, CS-CODE-013).');
    process.exit(1);
  }

  // Allowed CORS origins: comma-separated list in ALLOWED_ORIGINS env var
  // Default: empty (no CORS headers set → same-origin only) (AB-CODE-025)
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
    : [];

  state.config = { port, apiKey, allowedOrigins };

  // ── Express setup ────────────────────────────────────────────────────────
  const app = express();
  state.app = app;

  // Parse JSON bodies; AB-CODE-008 guard: Express handles parse errors via
  // the verify/reviver, but we also catch them in the error handler below.
  app.use(express.json({ limit: '16kb' }));

  // Global middleware
  app.use(corsMiddleware);

  // ── Public routes (no auth) ──────────────────────────────────────────────
  app.get('/health', handleHealth);

  // ── Auth gate BEFORE all /todos routes (CS-CODE-016, AB-CODE-026) ────────
  app.use('/todos', authMiddleware);

  // ── Todo routes ──────────────────────────────────────────────────────────
  app.get   ('/todos',      handleListTodos);
  app.get   ('/todos/:id',  handleGetTodo);
  app.post  ('/todos',      handleCreateTodo);
  app.put   ('/todos/:id',  handleUpdateTodo);
  app.patch ('/todos/:id',  handlePatchTodo);
  app.delete('/todos/:id',  handleDeleteTodo);

  // ── 404 for unknown routes ───────────────────────────────────────────────
  app.use((req, res) => {
    sendError(res, 404, `Route ${req.method} ${escapeHtml(req.path)} not found.`);
  });

  // ── Centralized error handler (AB-CODE-008: catches JSON parse errors) ───
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    // Express sets err.type = 'entity.parse.failed' for bad JSON bodies
    if (err.type === 'entity.parse.failed') {
      return sendError(res, 400, 'Request body contains invalid JSON.');
    }
    console.error('[ERROR]', err);
    return sendError(res, 500, 'Internal server error.');
  });

  // ── Start server ─────────────────────────────────────────────────────────
  state.server = app.listen(port, () => {
    console.log(`[INFO] Todo API listening on port ${port}`);
    if (apiKey) {
      console.log('[INFO] API key authentication: ENABLED');
    } else {
      console.log('[INFO] API key authentication: DISABLED (set API_KEY env var to enable)');
    }
    if (allowedOrigins.length > 0) {
      console.log(`[INFO] CORS allowed origins: ${allowedOrigins.join(', ')}`);
    } else {
      console.log('[INFO] CORS: no origins configured (same-origin only)');
    }
  });

  // ── Graceful shutdown ────────────────────────────────────────────────────
  function shutdown(signal) {
    console.log(`[INFO] Received ${signal}. Shutting down gracefully...`);
    state.server.close(() => {
      console.log('[INFO] Server closed.');
      process.exit(0);
    });
    // Force exit if graceful shutdown takes too long
    setTimeout(() => {
      console.error('[WARN] Graceful shutdown timed out. Forcing exit.');
      process.exit(1);
    }, 10_000).unref();
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  // Catch unexpected errors — log and continue (don't crash on transient issues)
  process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught exception:', err);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled promise rejection:', reason);
    process.exit(1);
  });
}

// ─────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────
init();
