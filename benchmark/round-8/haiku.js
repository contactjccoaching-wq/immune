const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Startup validation
const requiredEnvVars = ['SESSION_SECRET', 'BCRYPT_ROUNDS', 'SESSION_TTL_MS', 'TOKEN_EXPIRY_MS', 'MAX_LOGIN_ATTEMPTS', 'LOCKOUT_DURATION_MS'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required env var: ${envVar}`);
    process.exit(1);
  }
}

const config = {
  sessionSecret: process.env.SESSION_SECRET,
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10),
  sessionTtlMs: parseInt(process.env.SESSION_TTL_MS, 10),
  tokenExpiryMs: parseInt(process.env.TOKEN_EXPIRY_MS, 10),
  maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10),
  lockoutDurationMs: parseInt(process.env.LOCKOUT_DURATION_MS, 10),
  secureCookie: process.env.NODE_ENV === 'production',
  cookieName: 'session_id',
};

// Bounded Maps with TTL
class BoundedMap {
  constructor(maxSize = 10000, ttlMs = 3600000) {
    this.data = new Map();
    this.ttl = new Map();
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
  }

  set(key, value) {
    if (this.data.size >= this.maxSize) {
      const firstKey = this.data.keys().next().value;
      this.data.delete(firstKey);
      this.ttl.delete(firstKey);
    }
    this.data.set(key, value);
    this.ttl.set(key, Date.now() + this.ttlMs);
  }

  get(key) {
    const expiryTime = this.ttl.get(key);
    if (expiryTime && Date.now() > expiryTime) {
      this.data.delete(key);
      this.ttl.delete(key);
      return undefined;
    }
    return this.data.get(key);
  }

  has(key) { return this.get(key) !== undefined; }
  delete(key) { this.data.delete(key); this.ttl.delete(key); }

  cleanup() {
    const now = Date.now();
    for (const [key, expiryTime] of this.ttl) {
      if (now > expiryTime) { this.data.delete(key); this.ttl.delete(key); }
    }
  }
}

// Data stores
const sessions = new BoundedMap(10000, config.sessionTtlMs);
const users = new Map();
const loginAttempts = new BoundedMap(10000, config.lockoutDurationMs);
const passwordResetTokens = new BoundedMap(1000, config.tokenExpiryMs);
const metrics = new Map();

// Rate limiters
class SlidingWindowLimiter {
  constructor(windowMs, maxRequests) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
    this.requests = new Map();
  }

  isAllowed(identifier) {
    const now = Date.now();
    if (!this.requests.has(identifier)) { this.requests.set(identifier, []); }
    const timestamps = this.requests.get(identifier).filter(t => now - t < this.windowMs);
    if (timestamps.length >= this.maxRequests) { this.requests.set(identifier, timestamps); return false; }
    timestamps.push(now);
    this.requests.set(identifier, timestamps);
    return true;
  }

  cleanup() {
    const now = Date.now();
    for (const [key, timestamps] of this.requests) {
      const filtered = timestamps.filter(t => now - t < this.windowMs);
      if (filtered.length === 0) this.requests.delete(key);
      else this.requests.set(key, filtered);
    }
  }
}

const authRateLimiter = new SlidingWindowLimiter(900000, 10);
const resetRateLimiter = new SlidingWindowLimiter(3600000, 5);

// Utilities
function generateSessionId() { return crypto.randomUUID(); }
function generateResetToken() { return crypto.randomBytes(32).toString('hex'); }
function generateCsrfToken() { return crypto.randomBytes(32).toString('hex'); }

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.trim().substring(0, 255);
}

function validateEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function validatePassword(password) { return password && password.length >= 8 && password.length <= 128; }

function recordMetric(endpoint, success, durationMs) {
  if (!metrics.has(endpoint)) {
    metrics.set(endpoint, { total: 0, success: 0, failure: 0, totalDuration: 0 });
  }
  const m = metrics.get(endpoint);
  m.total++; success ? m.success++ : m.failure++; m.totalDuration += durationMs;
}

// Session management
function createSession(userId) {
  const sessionId = generateSessionId();
  const csrfToken = generateCsrfToken();
  sessions.set(sessionId, {
    userId, csrfToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + config.sessionTtlMs,
    lastActivity: Date.now(),
  });
  return { sessionId, csrfToken };
}

function renewSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  session.expiresAt = Date.now() + config.sessionTtlMs;
  session.lastActivity = Date.now();
  sessions.set(sessionId, session);
  return session;
}

// Brute-force protection
function recordLoginAttempt(email, success) {
  const key = `login:${email}`;
  if (success) { loginAttempts.delete(key); return; }
  const data = loginAttempts.get(key) || { attempts: 0, lockedUntil: 0 };
  data.attempts++;
  if (data.attempts >= config.maxLoginAttempts) {
    data.lockedUntil = Date.now() + config.lockoutDurationMs;
  }
  loginAttempts.set(key, data);
}

function isAccountLocked(email) {
  const key = `login:${email}`;
  const data = loginAttempts.get(key);
  if (!data) return false;
  if (data.lockedUntil && Date.now() < data.lockedUntil) return true;
  if (data.lockedUntil && Date.now() >= data.lockedUntil) { loginAttempts.delete(key); }
  return false;
}

// Password reset
function createPasswordResetToken(userId) {
  const token = generateResetToken();
  passwordResetTokens.set(token, {
    userId, createdAt: Date.now(),
    expiresAt: Date.now() + config.tokenExpiryMs, used: false,
  });
  return token;
}

function redeemPasswordResetToken(token, newPassword) {
  const resetToken = passwordResetTokens.get(token);
  if (!resetToken) return { success: false, error: 'Invalid or expired token' };
  if (resetToken.used) return { success: false, error: 'Token already used' };
  if (Date.now() > resetToken.expiresAt) {
    passwordResetTokens.delete(token);
    return { success: false, error: 'Token expired' };
  }
  const user = Array.from(users.values()).find(u => u.id === resetToken.userId);
  if (!user) return { success: false, error: 'User not found' };
  user.passwordHash = bcrypt.hashSync(newPassword, config.bcryptRounds);
  resetToken.used = true;
  passwordResetTokens.set(token, resetToken);
  return { success: true };
}

// Express app
const app = express();

// Security middleware in order
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: true,
}));

const globalLimiter = rateLimit({
  windowMs: 900000, max: 300,
  message: { error: 'Too many requests' },
  standardHeaders: true, legacyHeaders: false,
});
app.use(globalLimiter);
app.use(express.json({ limit: '10kb' }));

// Cookie parser (simple)
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) req.cookies[name] = value;
    });
  }
  next();
});

// CSRF middleware for mutating requests
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  // Skip CSRF for login and register
  if (req.path === '/auth/login' || req.path === '/auth/register' || req.path === '/auth/forgot-password' || req.path === '/auth/reset-password') {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'];
  const sessionId = req.cookies[config.cookieName];

  if (!sessionId || !csrfToken) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }

  const session = sessions.get(sessionId);
  if (!session) return res.status(403).json({ error: 'Invalid session' });

  const expected = Buffer.from(session.csrfToken);
  const received = Buffer.from(csrfToken);
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  next();
});

// Routes
app.post('/auth/register', async (req, res) => {
  const start = Date.now();
  try {
    if (!authRateLimiter.isAllowed(req.ip)) {
      recordMetric('/auth/register', false, Date.now() - start);
      return res.status(429).json({ error: 'Too many attempts' });
    }

    const email = sanitizeInput(req.body.email).toLowerCase();
    const password = sanitizeInput(req.body.password);

    if (!validateEmail(email)) {
      recordMetric('/auth/register', false, Date.now() - start);
      return res.status(400).json({ error: 'Invalid email' });
    }
    if (!validatePassword(password)) {
      recordMetric('/auth/register', false, Date.now() - start);
      return res.status(400).json({ error: 'Password must be 8-128 chars' });
    }
    if (users.has(email)) {
      recordMetric('/auth/register', false, Date.now() - start);
      return res.status(409).json({ error: 'Email already registered' });
    }

    const userId = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, config.bcryptRounds);
    users.set(email, { id: userId, email, passwordHash, createdAt: Date.now() });

    recordMetric('/auth/register', true, Date.now() - start);
    return res.status(201).json({ success: true, userId });
  } catch (error) {
    recordMetric('/auth/register', false, Date.now() - start);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  const start = Date.now();
  try {
    if (!authRateLimiter.isAllowed(req.ip)) {
      recordMetric('/auth/login', false, Date.now() - start);
      return res.status(429).json({ error: 'Too many login attempts' });
    }

    const email = sanitizeInput(req.body.email).toLowerCase();
    const password = sanitizeInput(req.body.password);

    if (isAccountLocked(email)) {
      recordMetric('/auth/login', false, Date.now() - start);
      return res.status(429).json({ error: 'Account locked' });
    }

    const user = users.get(email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      recordLoginAttempt(email, false);
      recordMetric('/auth/login', false, Date.now() - start);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    recordLoginAttempt(email, true);
    const { sessionId, csrfToken } = createSession(user.id);

    res.setHeader('Set-Cookie',
      `${config.cookieName}=${sessionId}; HttpOnly; ${config.secureCookie ? 'Secure; ' : ''}SameSite=Strict; Max-Age=${Math.floor(config.sessionTtlMs / 1000)}; Path=/`
    );

    recordMetric('/auth/login', true, Date.now() - start);
    return res.json({ success: true, csrfToken });
  } catch (error) {
    recordMetric('/auth/login', false, Date.now() - start);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/logout', (req, res) => {
  const sessionId = req.cookies[config.cookieName];
  if (sessionId) sessions.delete(sessionId);
  res.setHeader('Set-Cookie', `${config.cookieName}=; HttpOnly; Max-Age=0; Path=/`);
  return res.json({ success: true });
});

app.get('/auth/session', (req, res) => {
  const sessionId = req.cookies[config.cookieName];
  if (!sessionId) return res.status(401).json({ error: 'No session' });

  const session = sessions.get(sessionId);
  if (!session) return res.status(401).json({ error: 'Session expired' });

  renewSession(sessionId);
  const user = Array.from(users.values()).find(u => u.id === session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  return res.json({ success: true, userId: user.id, email: user.email, expiresAt: session.expiresAt });
});

app.post('/auth/forgot-password', (req, res) => {
  const start = Date.now();
  if (!resetRateLimiter.isAllowed(req.ip)) {
    recordMetric('/auth/forgot-password', false, Date.now() - start);
    return res.status(429).json({ error: 'Too many requests' });
  }

  const email = sanitizeInput(req.body.email).toLowerCase();
  if (!validateEmail(email)) {
    recordMetric('/auth/forgot-password', false, Date.now() - start);
    return res.status(400).json({ error: 'Invalid email' });
  }

  const user = users.get(email);
  if (user) {
    const token = createPasswordResetToken(user.id);
    console.log(`Password reset token for ${email}: ${token}`);
  }

  // Always return same response to prevent email enumeration
  recordMetric('/auth/forgot-password', true, Date.now() - start);
  return res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
});

app.post('/auth/reset-password', (req, res) => {
  const start = Date.now();
  const token = sanitizeInput(req.body.token);
  const newPassword = sanitizeInput(req.body.newPassword);

  if (!validatePassword(newPassword)) {
    recordMetric('/auth/reset-password', false, Date.now() - start);
    return res.status(400).json({ error: 'Password must be 8-128 chars' });
  }

  const result = redeemPasswordResetToken(token, newPassword);
  if (!result.success) {
    recordMetric('/auth/reset-password', false, Date.now() - start);
    return res.status(400).json({ error: result.error });
  }

  recordMetric('/auth/reset-password', true, Date.now() - start);
  return res.json({ success: true });
});

app.get('/metrics', (req, res) => {
  const data = {};
  for (const [endpoint, m] of metrics) {
    data[endpoint] = { ...m, avgDuration: m.totalDuration / m.total };
  }
  return res.json(data);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.message);
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  return res.status(500).json({ error: 'Internal server error' });
});

// Periodic cleanup
const cleanupInterval = setInterval(() => {
  sessions.cleanup();
  loginAttempts.cleanup();
  passwordResetTokens.cleanup();
  authRateLimiter.cleanup();
  resetRateLimiter.cleanup();
}, 60000);

// Graceful shutdown
const server = app.listen(parseInt(process.env.PORT || '3000', 10), () => {
  console.log(`Server listening on port ${process.env.PORT || 3000}`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received');
  clearInterval(cleanupInterval);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000);
});

process.on('SIGINT', () => {
  console.log('SIGINT received');
  clearInterval(cleanupInterval);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000);
});

module.exports = app;
