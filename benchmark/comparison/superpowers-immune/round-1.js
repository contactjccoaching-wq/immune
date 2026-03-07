/**
 * User Authentication API
 * Express.js + bcrypt + JWT
 * In-memory user store
 * Endpoints: POST /register, POST /login, GET /me
 */

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CONFIG = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-in-production',
  jwtExpiresIn: '1h',
  bcryptSaltRounds: 10,
  maxEmailLength: 254,
  maxPasswordLength: 128,
  minPasswordLength: 8,
};

// ---------------------------------------------------------------------------
// In-memory user store
// ---------------------------------------------------------------------------

const userStore = {
  _users: new Map(), // email → { id, email, passwordHash, createdAt }
  _nextId: 1,

  findByEmail(email) {
    return this._users.get(email.toLowerCase()) || null;
  },

  findById(id) {
    for (const user of this._users.values()) {
      if (user.id === id) return user;
    }
    return null;
  },

  create(email, passwordHash) {
    const user = {
      id: this._nextId++,
      email: email.toLowerCase(),
      passwordHash,
      createdAt: new Date().toISOString(),
    };
    this._users.set(user.email, user);
    return user;
  },
};

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateEmail(email) {
  if (typeof email !== 'string') return 'Email must be a string';
  const trimmed = email.trim();
  if (!trimmed) return 'Email is required';
  if (trimmed.length > CONFIG.maxEmailLength) return 'Email is too long';
  if (!EMAIL_RE.test(trimmed)) return 'Email format is invalid';
  return null;
}

function validatePassword(password) {
  if (typeof password !== 'string') return 'Password must be a string';
  if (!password) return 'Password is required';
  if (password.length < CONFIG.minPasswordLength)
    return `Password must be at least ${CONFIG.minPasswordLength} characters`;
  if (password.length > CONFIG.maxPasswordLength) return 'Password is too long';
  return null;
}

function validateCredentials(body) {
  const errors = [];
  const emailError = validateEmail(body?.email);
  if (emailError) errors.push(emailError);
  const passwordError = validatePassword(body?.password);
  if (passwordError) errors.push(passwordError);
  return errors;
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

function signToken(userId) {
  return jwt.sign({ sub: userId }, CONFIG.jwtSecret, {
    expiresIn: CONFIG.jwtExpiresIn,
  });
}

function verifyToken(token) {
  return jwt.verify(token, CONFIG.jwtSecret); // throws on invalid/expired
}

function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') return null;
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return null;
  return parts[1] || null;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

function authenticate(req, res, next) {
  const token = extractBearerToken(req.headers.authorization);
  if (!token) {
    return res.status(401).json({ error: 'Authorization token is required' });
  }

  let payload;
  try {
    payload = verifyToken(token);
  } catch (err) {
    const message = err.name === 'TokenExpiredError'
      ? 'Token has expired'
      : 'Token is invalid';
    return res.status(401).json({ error: message });
  }

  const user = userStore.findById(payload.sub);
  if (!user) {
    return res.status(401).json({ error: 'User no longer exists' });
  }

  req.currentUser = user;
  next();
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/**
 * POST /register
 * Body: { email, password }
 * Returns: 201 { message, token, user: { id, email, createdAt } }
 */
async function handleRegister(req, res) {
  const validationErrors = validateCredentials(req.body);
  if (validationErrors.length > 0) {
    return res.status(400).json({ error: 'Validation failed', details: validationErrors });
  }

  const email = req.body.email.trim().toLowerCase();

  if (userStore.findByEmail(email)) {
    return res.status(409).json({ error: 'Email is already registered' });
  }

  let passwordHash;
  try {
    passwordHash = await bcrypt.hash(req.body.password, CONFIG.bcryptSaltRounds);
  } catch (err) {
    console.error('[register] bcrypt error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }

  const user = userStore.create(email, passwordHash);
  const token = signToken(user.id);

  return res.status(201).json({
    message: 'Account created successfully',
    token,
    user: {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    },
  });
}

/**
 * POST /login
 * Body: { email, password }
 * Returns: 200 { token, user: { id, email, createdAt } }
 */
async function handleLogin(req, res) {
  const validationErrors = validateCredentials(req.body);
  if (validationErrors.length > 0) {
    return res.status(400).json({ error: 'Validation failed', details: validationErrors });
  }

  const email = req.body.email.trim().toLowerCase();
  const user = userStore.findByEmail(email);

  // Use constant-time comparison to avoid timing attacks — always call bcrypt
  const dummyHash = '$2b$10$invalidhashfortimingprotection000000000000000000000000000';
  const hashToCompare = user ? user.passwordHash : dummyHash;

  let passwordMatch;
  try {
    passwordMatch = await bcrypt.compare(req.body.password, hashToCompare);
  } catch (err) {
    console.error('[login] bcrypt error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }

  if (!user || !passwordMatch) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = signToken(user.id);

  return res.status(200).json({
    token,
    user: {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    },
  });
}

/**
 * GET /me
 * Header: Authorization: Bearer <token>
 * Returns: 200 { user: { id, email, createdAt } }
 */
function handleMe(req, res) {
  const { currentUser } = req;
  return res.status(200).json({
    user: {
      id: currentUser.id,
      email: currentUser.email,
      createdAt: currentUser.createdAt,
    },
  });
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

function createApp() {
  const app = express();

  app.use(express.json({ limit: '10kb' })); // guard against oversized payloads

  // Routes
  app.post('/register', handleRegister);
  app.post('/login', handleLogin);
  app.get('/me', authenticate, handleMe);

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
  });

  // Global error handler
  app.use((err, req, res, _next) => {
    console.error('[unhandled]', err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

function startServer() {
  const app = createApp();

  const server = app.listen(CONFIG.port, () => {
    console.log(`Auth API running on port ${CONFIG.port}`);
  });

  // Graceful shutdown
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

if (require.main === module) {
  startServer();
}

module.exports = { createApp, userStore, CONFIG };
