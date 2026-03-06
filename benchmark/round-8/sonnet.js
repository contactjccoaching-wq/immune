'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

// ─── Environment validation ───────────────────────────────────────────────────
const REQUIRED_ENV = [
  'SESSION_SECRET',
  'CSRF_SECRET',
  'PASSWORD_RESET_SECRET',
  'ALLOWED_ORIGIN',
];

for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[FATAL] Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const SESSION_SECRET = process.env.SESSION_SECRET;
const CSRF_SECRET = process.env.CSRF_SECRET;
const PASSWORD_RESET_SECRET = process.env.PASSWORD_RESET_SECRET;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;
const PORT = parseInt(process.env.PORT || '3000', 10);

// ─── Constants ────────────────────────────────────────────────────────────────
const SESSION_TTL_MS = 30 * 60 * 1000;          // 30 minutes
const SESSION_RENEW_THRESHOLD_MS = 5 * 60 * 1000; // renew if < 5 min left
const SESSION_COOKIE_NAME = 'sid';
const CSRF_COOKIE_NAME = 'csrf_token';
const MAX_SESSIONS = 10_000;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;     // 15 minutes
const PASSWORD_RESET_TTL_MS = 60 * 60 * 1000;   // 1 hour
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;       // cleanup every 5 minutes

// ─── In-memory stores (bounded, TTL-aware) ───────────────────────────────────
/** @type {Map<string, {userId: string, expiresAt: number, csrfToken: string}>} */
const sessions = new Map();

/**
 * @type {Map<string, {
 *   passwordHash: string,
 *   salt: string,
 *   failedAttempts: number,
 *   lockedUntil: number|null,
 *   email: string
 * }>}
 */
const users = new Map([
  // Seed demo user: username=demo, password=Password1!
  // Generated via: hashPassword('Password1!') — pre-computed for demo
  ['demo', (() => {
    const salt = crypto.randomBytes(32).toString('hex');
    const hash = hashPasswordSync('Password1!', salt);
    return { passwordHash: hash, salt, failedAttempts: 0, lockedUntil: null, email: 'demo@example.com' };
  })()],
]);

/** @type {Map<string, {userId: string, expiresAt: number, used: boolean}>} */
const passwordResetTokens = new Map();

// ─── Metrics ─────────────────────────────────────────────────────────────────
const metrics = {
  login: { attempts: 0, successes: 0, failures: 0, lockouts: 0 },
  logout: { calls: 0 },
  csrf: { violations: 0 },
  passwordReset: { requests: 0, completions: 0, failures: 0 },
  sessions: { created: 0, renewed: 0, expired: 0 },
};

// ─── Crypto helpers ───────────────────────────────────────────────────────────
function hashPasswordSync(password, salt) {
  return crypto
    .pbkdf2Sync(password, salt + SESSION_SECRET, 310_000, 64, 'sha512')
    .toString('hex');
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const hash = await new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt + SESSION_SECRET, 310_000, 64, 'sha512', (err, key) => {
      if (err) reject(err);
      else resolve(key.toString('hex'));
    });
  });
  return { hash, salt };
}

async function verifyPassword(password, hash, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt + SESSION_SECRET, 310_000, 64, 'sha512', (err, key) => {
      if (err) return reject(err);
      resolve(crypto.timingSafeEqual(Buffer.from(key.toString('hex')), Buffer.from(hash)));
    });
  });
}

function generateCsrfToken(sessionId) {
  const data = `${sessionId}:${Date.now()}:${CSRF_SECRET}`;
  return crypto.createHmac('sha256', CSRF_SECRET).update(data).digest('hex');
}

function generateResetToken() {
  return crypto.randomBytes(48).toString('hex');
}

// ─── Session helpers ──────────────────────────────────────────────────────────
function createSession(userId) {
  // Evict oldest if at capacity
  if (sessions.size >= MAX_SESSIONS) {
    const oldest = [...sessions.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt)[0];
    if (oldest) sessions.delete(oldest[0]);
  }

  const sessionId = crypto.randomUUID();
  const csrfToken = generateCsrfToken(sessionId);

  sessions.set(sessionId, {
    userId,
    expiresAt: Date.now() + SESSION_TTL_MS,
    csrfToken,
  });

  metrics.sessions.created++;
  return { sessionId, csrfToken };
}

function getSession(sessionId) {
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    metrics.sessions.expired++;
    return null;
  }

  // Renew if close to expiry
  const timeLeft = session.expiresAt - Date.now();
  if (timeLeft < SESSION_RENEW_THRESHOLD_MS) {
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    metrics.sessions.renewed++;
  }

  return session;
}

function destroySession(sessionId) {
  sessions.delete(sessionId);
}

// ─── Middleware: session authentication ───────────────────────────────────────
function requireAuth(req, res, next) {
  const sessionId = req.cookies[SESSION_COOKIE_NAME];
  const session = getSession(sessionId);

  if (!session) {
    return res.status(401).json({ error: 'Unauthorized', code: 'SESSION_INVALID' });
  }

  req.session = session;
  req.sessionId = sessionId;
  req.userId = session.userId;
  next();
}

// ─── Middleware: CSRF protection ──────────────────────────────────────────────
const CSRF_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function csrfProtection(req, res, next) {
  if (CSRF_SAFE_METHODS.has(req.method)) return next();

  const sessionId = req.cookies[SESSION_COOKIE_NAME];
  const session = getSession(sessionId);

  if (!session) {
    return res.status(401).json({ error: 'Unauthorized', code: 'SESSION_INVALID' });
  }

  const tokenFromHeader = req.headers['x-csrf-token'];
  const tokenFromBody = req.body?.csrfToken;
  const clientToken = tokenFromHeader || tokenFromBody;

  if (!clientToken) {
    metrics.csrf.violations++;
    return res.status(403).json({ error: 'Forbidden', code: 'CSRF_TOKEN_MISSING' });
  }

  const expectedToken = session.csrfToken;
  let valid = false;
  try {
    valid =
      clientToken.length === expectedToken.length &&
      crypto.timingSafeEqual(Buffer.from(clientToken), Buffer.from(expectedToken));
  } catch {
    valid = false;
  }

  if (!valid) {
    metrics.csrf.violations++;
    return res.status(403).json({ error: 'Forbidden', code: 'CSRF_TOKEN_INVALID' });
  }

  req.session = session;
  req.sessionId = sessionId;
  req.userId = session.userId;
  next();
}

// ─── Input validation helpers ─────────────────────────────────────────────────
function sanitizeString(value, maxLength = 256) {
  if (typeof value !== 'string') return null;
  return value.trim().slice(0, maxLength);
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;
  return /^[a-zA-Z0-9_.-]{3,64}$/.test(username);
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;
  return password.length >= 8 && password.length <= 128;
}

function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

// ─── Brute-force: lockout helpers ─────────────────────────────────────────────
function isAccountLocked(user) {
  if (!user.lockedUntil) return false;
  if (Date.now() < user.lockedUntil) return true;
  // Lockout expired — reset
  user.lockedUntil = null;
  user.failedAttempts = 0;
  return false;
}

function recordFailedAttempt(user) {
  user.failedAttempts = (user.failedAttempts || 0) + 1;
  if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
    user.lockedUntil = Date.now() + LOCKOUT_DURATION_MS;
    metrics.login.lockouts++;
  }
}

function resetFailedAttempts(user) {
  user.failedAttempts = 0;
  user.lockedUntil = null;
}

// ─── Rate limiters ─────────────────────────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests', code: 'RATE_LIMIT_GENERAL' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts', code: 'RATE_LIMIT_AUTH' },
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password reset requests', code: 'RATE_LIMIT_RESET' },
});

// ─── App setup ────────────────────────────────────────────────────────────────
const app = express();

// Security middleware (in order: helmet → cors → rate-limit)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

app.use(cors({
  origin: ALLOWED_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
}));

app.use(generalLimiter);
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(cookieParser());

// ─── Cookie helper ────────────────────────────────────────────────────────────
function setSessionCookie(res, sessionId) {
  res.cookie(SESSION_COOKIE_NAME, sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: SESSION_TTL_MS,
    path: '/',
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' });
  res.clearCookie(CSRF_COOKIE_NAME, { httpOnly: false, secure: true, sameSite: 'strict', path: '/' });
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /auth/login
app.post('/auth/login', authLimiter, async (req, res, next) => {
  try {
    metrics.login.attempts++;

    const username = sanitizeString(req.body?.username);
    const password = sanitizeString(req.body?.password);

    if (!validateUsername(username) || !validatePassword(password)) {
      metrics.login.failures++;
      return res.status(400).json({ error: 'Invalid credentials format', code: 'INVALID_INPUT' });
    }

    const user = users.get(username);
    if (!user) {
      // Constant-time fake verify to prevent username enumeration timing
      await new Promise(resolve => setTimeout(resolve, 200 + Math.random() * 100));
      metrics.login.failures++;
      return res.status(401).json({ error: 'Invalid credentials', code: 'AUTH_FAILED' });
    }

    if (isAccountLocked(user)) {
      return res.status(423).json({ error: 'Account temporarily locked', code: 'ACCOUNT_LOCKED' });
    }

    const valid = await verifyPassword(password, user.passwordHash, user.salt);
    if (!valid) {
      recordFailedAttempt(user);
      metrics.login.failures++;
      const remaining = MAX_FAILED_ATTEMPTS - user.failedAttempts;
      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'AUTH_FAILED',
        attemptsRemaining: Math.max(0, remaining),
      });
    }

    resetFailedAttempts(user);
    metrics.login.successes++;

    const { sessionId, csrfToken } = createSession(username);
    setSessionCookie(res, sessionId);

    // CSRF token goes in non-httpOnly cookie so JS can read it
    res.cookie(CSRF_COOKIE_NAME, csrfToken, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: SESSION_TTL_MS,
      path: '/',
    });

    res.status(200).json({ message: 'Authenticated', csrfToken });
  } catch (err) {
    next(err);
  }
});

// POST /auth/logout
app.post('/auth/logout', requireAuth, csrfProtection, (req, res) => {
  metrics.logout.calls++;
  destroySession(req.sessionId);
  clearSessionCookie(res);
  res.status(200).json({ message: 'Logged out' });
});

// GET /auth/session — check current session
app.get('/auth/session', requireAuth, (req, res) => {
  res.status(200).json({
    userId: req.userId,
    expiresAt: req.session.expiresAt,
  });
});

// POST /auth/password-reset/request — request a password reset token
app.post('/auth/password-reset/request', passwordResetLimiter, (req, res) => {
  metrics.passwordReset.requests++;

  const email = sanitizeString(req.body?.email);
  if (!validateEmail(email)) {
    // Return 200 always to prevent email enumeration
    return res.status(200).json({ message: 'If that email exists, a reset link has been sent.' });
  }

  // Find user by email
  let foundUsername = null;
  for (const [username, user] of users.entries()) {
    if (user.email === email) {
      foundUsername = username;
      break;
    }
  }

  if (foundUsername) {
    const token = generateResetToken();
    passwordResetTokens.set(token, {
      userId: foundUsername,
      expiresAt: Date.now() + PASSWORD_RESET_TTL_MS,
      used: false,
    });

    // In production, send email. Here we log for demo.
    console.log(`[PASSWORD_RESET] Token for ${email}: ${token}`);
  }

  // Always return same response
  res.status(200).json({ message: 'If that email exists, a reset link has been sent.' });
});

// POST /auth/password-reset/confirm — use token to set new password
app.post('/auth/password-reset/confirm', authLimiter, async (req, res, next) => {
  try {
    const token = sanitizeString(req.body?.token);
    const newPassword = sanitizeString(req.body?.password);

    if (!token || !newPassword || !validatePassword(newPassword)) {
      metrics.passwordReset.failures++;
      return res.status(400).json({ error: 'Invalid request', code: 'INVALID_INPUT' });
    }

    const resetEntry = passwordResetTokens.get(token);
    if (!resetEntry) {
      metrics.passwordReset.failures++;
      return res.status(400).json({ error: 'Invalid or expired token', code: 'TOKEN_INVALID' });
    }

    if (resetEntry.used || Date.now() > resetEntry.expiresAt) {
      passwordResetTokens.delete(token);
      metrics.passwordReset.failures++;
      return res.status(400).json({ error: 'Invalid or expired token', code: 'TOKEN_EXPIRED' });
    }

    const user = users.get(resetEntry.userId);
    if (!user) {
      metrics.passwordReset.failures++;
      return res.status(400).json({ error: 'Invalid or expired token', code: 'TOKEN_INVALID' });
    }

    const { hash, salt } = await hashPassword(newPassword);
    user.passwordHash = hash;
    user.salt = salt;

    // Mark token as used and schedule deletion
    resetEntry.used = true;
    setTimeout(() => passwordResetTokens.delete(token), 1000);

    // Reset lockout on successful password reset
    resetFailedAttempts(user);

    // Invalidate all sessions for this user
    for (const [sessionId, session] of sessions.entries()) {
      if (session.userId === resetEntry.userId) {
        sessions.delete(sessionId);
      }
    }

    metrics.passwordReset.completions++;
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    next(err);
  }
});

// GET /metrics — observability endpoint (internal use)
app.get('/metrics', requireAuth, (req, res) => {
  res.status(200).json({
    metrics,
    sessions: { active: sessions.size, maxCapacity: MAX_SESSIONS },
    passwordResetTokens: { pending: passwordResetTokens.size },
    users: { registered: users.size },
    uptime: process.uptime(),
  });
});

// ─── Protected example route ──────────────────────────────────────────────────
app.get('/protected', requireAuth, (req, res) => {
  res.status(200).json({ message: 'Protected resource', userId: req.userId });
});

// ─── Global error handler ─────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large', code: 'PAYLOAD_TOO_LARGE' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON', code: 'PARSE_ERROR' });
  }
  if (err.code === 'EBADCSRFTOKEN') {
    metrics.csrf.violations++;
    return res.status(403).json({ error: 'Invalid CSRF token', code: 'CSRF_TOKEN_INVALID' });
  }
  if (err.status === 429) {
    return res.status(429).json({ error: 'Rate limit exceeded', code: 'RATE_LIMITED' });
  }

  console.error('[ERROR]', err.message, err.stack);
  res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
});

// ─── Periodic cleanup ─────────────────────────────────────────────────────────
const cleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [id, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(id);
      metrics.sessions.expired++;
    }
  }

  for (const [token, entry] of passwordResetTokens.entries()) {
    if (now > entry.expiresAt || entry.used) {
      passwordResetTokens.delete(token);
    }
  }
}, CLEANUP_INTERVAL_MS);

cleanupTimer.unref();

// ─── Graceful shutdown ────────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`[SHUTDOWN] Received ${signal}`);
  clearInterval(cleanupTimer);
  server.close(() => {
    console.log('[SHUTDOWN] HTTP server closed');
    sessions.clear();
    passwordResetTokens.clear();
    process.exit(0);
  });

  // Force exit after 10s
  setTimeout(() => {
    console.error('[SHUTDOWN] Forced exit after timeout');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT_EXCEPTION]', err);
  shutdown('uncaughtException');
});
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED_REJECTION]', reason);
});

// ─── Start ────────────────────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`[SERVER] Listening on port ${PORT} (env: ${process.env.NODE_ENV || 'development'})`);
});

module.exports = { app, server };
