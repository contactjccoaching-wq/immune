'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ─── Constants ────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_EXPIRES_IN = '24h';
const BCRYPT_SALT_ROUNDS = 12;

const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  CONFLICT: 409,
  INTERNAL_SERVER_ERROR: 500,
};

// ─── In-Memory Store ──────────────────────────────────────────────────────────

/** @type {Map<string, { id: string, email: string, passwordHash: string, createdAt: string }>} */
const users = new Map(); // keyed by email

let nextId = 1;

// ─── Input Validation ─────────────────────────────────────────────────────────

/**
 * Validates that a value is a non-empty string.
 * @param {unknown} value
 * @returns {boolean}
 */
function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Validates email format using a basic RFC-compliant pattern.
 * @param {string} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return pattern.test(email);
}

/**
 * Validates password meets minimum requirements.
 * @param {string} password
 * @returns {{ valid: boolean, reason?: string }}
 */
function validatePassword(password) {
  if (!isNonEmptyString(password)) {
    return { valid: false, reason: 'Password is required' };
  }
  if (password.length < 8) {
    return { valid: false, reason: 'Password must be at least 8 characters' };
  }
  if (password.length > 128) {
    return { valid: false, reason: 'Password must not exceed 128 characters' };
  }
  return { valid: true };
}

/**
 * Validates register/login request body.
 * @param {unknown} body
 * @returns {{ valid: boolean, reason?: string, email?: string, password?: string }}
 */
function validateAuthBody(body) {
  if (!body || typeof body !== 'object') {
    return { valid: false, reason: 'Request body is required' };
  }

  const { email, password } = body;

  if (!isNonEmptyString(email)) {
    return { valid: false, reason: 'Email is required' };
  }
  if (!isValidEmail(email)) {
    return { valid: false, reason: 'Email format is invalid' };
  }

  const passwordCheck = validatePassword(password);
  if (!passwordCheck.valid) {
    return { valid: false, reason: passwordCheck.reason };
  }

  return { valid: true, email: email.toLowerCase().trim(), password };
}

// ─── Token Helpers ────────────────────────────────────────────────────────────

/**
 * Signs a JWT token for a given user id.
 * @param {string} userId
 * @returns {string}
 */
function signToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

/**
 * Verifies a JWT token and returns the decoded payload.
 * @param {string} token
 * @returns {{ sub: string } | null}
 */
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

/**
 * Extracts Bearer token from Authorization header.
 * @param {string | undefined} authHeader
 * @returns {string | null}
 */
function extractBearerToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.slice(7).trim();
  return token.length > 0 ? token : null;
}

// ─── Password Helpers ─────────────────────────────────────────────────────────

/**
 * Hashes a plain-text password.
 * @param {string} plainPassword
 * @returns {Promise<string>}
 */
async function hashPassword(plainPassword) {
  return bcrypt.hash(plainPassword, BCRYPT_SALT_ROUNDS);
}

/**
 * Compares a plain-text password against a stored hash.
 * @param {string} plainPassword
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plainPassword, hash) {
  return bcrypt.compare(plainPassword, hash);
}

// ─── User Store Helpers ───────────────────────────────────────────────────────

/**
 * Creates and persists a new user.
 * @param {string} email
 * @param {string} passwordHash
 * @returns {{ id: string, email: string, createdAt: string }}
 */
function createUser(email, passwordHash) {
  const id = String(nextId++);
  const createdAt = new Date().toISOString();
  const user = { id, email, passwordHash, createdAt };
  users.set(email, user);
  return user;
}

/**
 * Finds a user by email.
 * @param {string} email
 * @returns {{ id: string, email: string, passwordHash: string, createdAt: string } | undefined}
 */
function findUserByEmail(email) {
  return users.get(email);
}

/**
 * Finds a user by id.
 * @param {string} id
 * @returns {{ id: string, email: string, passwordHash: string, createdAt: string } | undefined}
 */
function findUserById(id) {
  for (const user of users.values()) {
    if (user.id === id) return user;
  }
  return undefined;
}

/**
 * Returns a safe public view of a user (no password hash).
 * @param {{ id: string, email: string, createdAt: string }} user
 * @returns {{ id: string, email: string, createdAt: string }}
 */
function toPublicUser(user) {
  return { id: user.id, email: user.email, createdAt: user.createdAt };
}

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * Authenticates requests via Bearer JWT.
 * Attaches the user to req.user on success.
 */
function requireAuth(req, res, next) {
  const token = extractBearerToken(req.headers.authorization);

  if (!token) {
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      error: 'Authorization token is required',
    });
  }

  const payload = verifyToken(token);
  if (!payload) {
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      error: 'Token is invalid or expired',
    });
  }

  const user = findUserById(payload.sub);
  if (!user) {
    return res.status(HTTP_STATUS.UNAUTHORIZED).json({
      error: 'User not found',
    });
  }

  req.user = user;
  return next();
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

/**
 * POST /register
 * Creates a new user account and returns a JWT.
 */
async function handleRegister(req, res) {
  const validation = validateAuthBody(req.body);
  if (!validation.valid) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: validation.reason });
  }

  const { email, password } = validation;

  if (findUserByEmail(email)) {
    return res.status(HTTP_STATUS.CONFLICT).json({ error: 'Email is already registered' });
  }

  try {
    const passwordHash = await hashPassword(password);
    const user = createUser(email, passwordHash);
    const token = signToken(user.id);

    return res.status(HTTP_STATUS.CREATED).json({
      user: toPublicUser(user),
      token,
    });
  } catch (err) {
    console.error('[register] Unexpected error:', err);
    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Registration failed' });
  }
}

/**
 * POST /login
 * Authenticates existing credentials and returns a JWT.
 */
async function handleLogin(req, res) {
  const validation = validateAuthBody(req.body);
  if (!validation.valid) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({ error: validation.reason });
  }

  const { email, password } = validation;

  try {
    const user = findUserByEmail(email);

    // Use constant-time comparison path to avoid timing attacks on user enumeration.
    const dummyHash = '$2b$12$invalidhashfortimingprotection000000000000000000000000';
    const hash = user ? user.passwordHash : dummyHash;

    const passwordMatches = await verifyPassword(password, hash);

    if (!user || !passwordMatches) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: 'Invalid email or password' });
    }

    const token = signToken(user.id);

    return res.status(HTTP_STATUS.OK).json({
      user: toPublicUser(user),
      token,
    });
  } catch (err) {
    console.error('[login] Unexpected error:', err);
    return res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Login failed' });
  }
}

/**
 * GET /me
 * Returns the authenticated user's profile.
 */
function handleMe(req, res) {
  return res.status(HTTP_STATUS.OK).json({ user: toPublicUser(req.user) });
}

// ─── App Setup ────────────────────────────────────────────────────────────────

function createApp() {
  const app = express();

  app.use(express.json({ limit: '16kb' }));

  // Routes
  app.post('/register', handleRegister);
  app.post('/login', handleLogin);
  app.get('/me', requireAuth, handleMe);

  // 404 fallback
  app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
  });

  // Global error handler
  app.use((err, req, res, _next) => {
    console.error('[unhandled]', err);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Internal server error' });
  });

  return app;
}

// ─── Server Lifecycle ─────────────────────────────────────────────────────────

function startServer() {
  const app = createApp();

  const server = app.listen(PORT, () => {
    console.log(`Auth API running on port ${PORT}`);
  });

  function shutdown(signal) {
    console.log(`${signal} received — shutting down gracefully`);
    server.close(() => {
      console.log('Server closed');
      process.exit(0);
    });
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  return server;
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

if (require.main === module) {
  startServer();
}

module.exports = { createApp };
