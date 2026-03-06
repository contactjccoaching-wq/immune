"use strict";

const http = require("http");
const crypto = require("crypto");
const { URL } = require("url");

// ---------------------------------------------------------------------------
// 1. Environment validation — fail fast if any secret is missing
// ---------------------------------------------------------------------------
const REQUIRED_ENV = [
  "SESSION_SECRET",
  "COOKIE_DOMAIN",
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_USER",
  "SMTP_PASS",
  "APP_ORIGIN",
];

const env = {};
for (const key of REQUIRED_ENV) {
  const val = process.env[key];
  if (!val) {
    console.error(`FATAL: Missing required env var ${key}`);
    process.exit(1);
  }
  env[key] = val;
}

env.PORT = parseInt(process.env.PORT || "3000", 10);
env.SESSION_TTL_MS = parseInt(process.env.SESSION_TTL_MS || String(30 * 60 * 1000), 10); // 30 min
env.SESSION_RENEW_MS = parseInt(process.env.SESSION_RENEW_MS || String(10 * 60 * 1000), 10); // 10 min
env.RESET_TOKEN_TTL_MS = parseInt(process.env.RESET_TOKEN_TTL_MS || String(15 * 60 * 1000), 10); // 15 min
env.LOCKOUT_WINDOW_MS = parseInt(process.env.LOCKOUT_WINDOW_MS || String(15 * 60 * 1000), 10); // 15 min
env.MAX_FAILED_ATTEMPTS = parseInt(process.env.MAX_FAILED_ATTEMPTS || "5", 10);
env.CLEANUP_INTERVAL_MS = parseInt(process.env.CLEANUP_INTERVAL_MS || String(60 * 1000), 10); // 1 min
env.MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || "10000", 10);
env.MAX_RESET_TOKENS = parseInt(process.env.MAX_RESET_TOKENS || "5000", 10);

// ---------------------------------------------------------------------------
// 2. In-memory stores (bounded Maps with TTL)
// ---------------------------------------------------------------------------

/** @type {Map<string, {userId:string, csrfToken:string, createdAt:number, lastActivity:number, ip:string, ua:string}>} */
const sessions = new Map();

/** @type {Map<string, {email:string, createdAt:number}>} */
const resetTokens = new Map();

/** @type {Map<string, {count:number, firstAttempt:number, lockedUntil:number|null}>} */
const loginAttempts = new Map();

/** @type {Map<string, {passwordHash:string, salt:string, email:string, locked:boolean}>} */
const users = new Map();

// Seed a demo user for testing
const demoSalt = crypto.randomBytes(32).toString("hex");
const demoHash = crypto.scryptSync("P@ssw0rd123", demoSalt, 64).toString("hex");
users.set("demo", {
  passwordHash: demoHash,
  salt: demoSalt,
  email: "demo@example.com",
  locked: false,
});

// ---------------------------------------------------------------------------
// 3. Metrics
// ---------------------------------------------------------------------------
const metrics = {
  requests: new Map(),       // endpoint -> count
  errors: new Map(),         // endpoint -> count
  activeSessions: () => sessions.size,
  pendingResets: () => resetTokens.size,
  lockedAccounts: () => {
    let n = 0;
    const now = Date.now();
    for (const v of loginAttempts.values()) {
      if (v.lockedUntil && v.lockedUntil > now) n++;
    }
    return n;
  },
};

function trackRequest(endpoint) {
  metrics.requests.set(endpoint, (metrics.requests.get(endpoint) || 0) + 1);
}

function trackError(endpoint) {
  metrics.errors.set(endpoint, (metrics.errors.get(endpoint) || 0) + 1);
}

// ---------------------------------------------------------------------------
// 4. Periodic cleanup (TTL enforcement + bounded eviction)
// ---------------------------------------------------------------------------
function cleanupSessions() {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastActivity > env.SESSION_TTL_MS) {
      sessions.delete(id);
    }
  }
  // Hard cap — evict oldest if over limit
  if (sessions.size > env.MAX_SESSIONS) {
    const sorted = [...sessions.entries()].sort((a, b) => a[1].lastActivity - b[1].lastActivity);
    const excess = sessions.size - env.MAX_SESSIONS;
    for (let i = 0; i < excess; i++) {
      sessions.delete(sorted[i][0]);
    }
  }
}

function cleanupResetTokens() {
  const now = Date.now();
  for (const [token, data] of resetTokens) {
    if (now - data.createdAt > env.RESET_TOKEN_TTL_MS) {
      resetTokens.delete(token);
    }
  }
  if (resetTokens.size > env.MAX_RESET_TOKENS) {
    const sorted = [...resetTokens.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt);
    const excess = resetTokens.size - env.MAX_RESET_TOKENS;
    for (let i = 0; i < excess; i++) {
      resetTokens.delete(sorted[i][0]);
    }
  }
}

function cleanupLoginAttempts() {
  const now = Date.now();
  for (const [key, data] of loginAttempts) {
    if (
      (!data.lockedUntil || data.lockedUntil <= now) &&
      now - data.firstAttempt > env.LOCKOUT_WINDOW_MS
    ) {
      loginAttempts.delete(key);
    }
  }
}

const cleanupTimer = setInterval(() => {
  cleanupSessions();
  cleanupResetTokens();
  cleanupLoginAttempts();
}, env.CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

// ---------------------------------------------------------------------------
// 5. Utility helpers
// ---------------------------------------------------------------------------
function generateId() {
  return crypto.randomUUID();
}

function generateSecureToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hmacSign(data) {
  return crypto.createHmac("sha256", env.SESSION_SECRET).update(data).digest("hex");
}

function parseCookies(header) {
  const map = {};
  if (!header) return map;
  header.split(";").forEach((pair) => {
    const [k, ...rest] = pair.trim().split("=");
    if (k) map[k.trim()] = decodeURIComponent(rest.join("="));
  });
  return map;
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Domain=${env.COOKIE_DOMAIN}`);
  parts.push("Path=/");
  parts.push("HttpOnly");
  parts.push("Secure");
  parts.push("SameSite=Strict");
  if (options.maxAge != null) parts.push(`Max-Age=${options.maxAge}`);
  const existing = res.getHeader("Set-Cookie") || [];
  const arr = Array.isArray(existing) ? existing : existing ? [existing] : [];
  arr.push(parts.join("; "));
  res.setHeader("Set-Cookie", arr);
}

function clearCookie(res, name) {
  setCookie(res, name, "", { maxAge: 0 });
}

function json(res, statusCode, data) {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const MAX_BODY = 1024 * 64; // 64KB
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new InputError("Request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new InputError("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// 6. Custom error types
// ---------------------------------------------------------------------------
class InputError extends Error {
  constructor(msg) {
    super(msg);
    this.name = "InputError";
    this.statusCode = 400;
  }
}

class AuthError extends Error {
  constructor(msg) {
    super(msg);
    this.name = "AuthError";
    this.statusCode = 401;
  }
}

class ForbiddenError extends Error {
  constructor(msg) {
    super(msg);
    this.name = "ForbiddenError";
    this.statusCode = 403;
  }
}

class NotFoundError extends Error {
  constructor(msg) {
    super(msg);
    this.name = "NotFoundError";
    this.statusCode = 404;
  }
}

class RateLimitError extends Error {
  constructor(msg, retryAfter) {
    super(msg);
    this.name = "RateLimitError";
    this.statusCode = 429;
    this.retryAfter = retryAfter;
  }
}

// ---------------------------------------------------------------------------
// 7. Input validation / sanitisation
// ---------------------------------------------------------------------------
function sanitize(str) {
  if (typeof str !== "string") return "";
  return str.replace(/[<>&"']/g, "").trim().slice(0, 256);
}

function validateUsername(u) {
  if (typeof u !== "string" || u.length < 3 || u.length > 64) {
    throw new InputError("Username must be 3-64 characters");
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(u)) {
    throw new InputError("Username contains invalid characters");
  }
  return u;
}

function validatePassword(p) {
  if (typeof p !== "string" || p.length < 8 || p.length > 128) {
    throw new InputError("Password must be 8-128 characters");
  }
  return p;
}

function validateEmail(e) {
  if (typeof e !== "string") throw new InputError("Email required");
  const cleaned = e.trim().toLowerCase().slice(0, 256);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleaned)) {
    throw new InputError("Invalid email format");
  }
  return cleaned;
}

function validateToken(t) {
  if (typeof t !== "string" || !/^[a-f0-9]{64}$/.test(t)) {
    throw new InputError("Invalid token format");
  }
  return t;
}

// ---------------------------------------------------------------------------
// 8. Rate limiting (differentiated)
// ---------------------------------------------------------------------------

/**
 * Simple sliding-window rate limiter backed by a Map.
 * @param {number} windowMs
 * @param {number} maxHits
 */
function createRateLimiter(windowMs, maxHits) {
  /** @type {Map<string, {count:number, resetAt:number}>} */
  const store = new Map();

  // Periodic cleanup
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of store) {
      if (v.resetAt <= now) store.delete(k);
    }
  }, windowMs);
  timer.unref();

  return function check(key) {
    const now = Date.now();
    let entry = store.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 1, resetAt: now + windowMs };
      store.set(key, entry);
      return; // allowed
    }
    entry.count++;
    if (entry.count > maxHits) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      throw new RateLimitError("Too many requests", retryAfter);
    }
  };
}

const globalLimiter = createRateLimiter(60_000, 100);    // 100 req/min per IP
const authLimiter = createRateLimiter(60_000, 10);       // 10 req/min per IP on auth endpoints
const resetLimiter = createRateLimiter(3600_000, 5);     // 5 reset requests/hour per IP

// ---------------------------------------------------------------------------
// 9. Middleware pipeline
// ---------------------------------------------------------------------------

/** Security headers (helmet-like) */
function helmetMiddleware(_req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "0");
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

/** CORS */
function corsMiddleware(req, res) {
  const origin = req.headers.origin;
  if (origin === env.APP_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,X-CSRF-Token");
    res.setHeader("Access-Control-Max-Age", "86400");
  }
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return true; // signal: response already sent
  }
  return false;
}

/** Global rate limit */
function rateLimitMiddleware(req) {
  const ip = req.socket.remoteAddress || "unknown";
  globalLimiter(ip);
}

/** Session resolution (non-blocking — attaches session to req if valid) */
function sessionMiddleware(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies["sid"];
  const sig = cookies["sid.sig"];
  if (!sessionId || !sig) {
    req.session = null;
    return;
  }
  // Verify HMAC signature
  const expected = hmacSign(sessionId);
  if (!crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"))) {
    req.session = null;
    return;
  }
  const session = sessions.get(sessionId);
  if (!session) {
    req.session = null;
    return;
  }
  const now = Date.now();
  // Check expiry
  if (now - session.lastActivity > env.SESSION_TTL_MS) {
    sessions.delete(sessionId);
    req.session = null;
    return;
  }
  // Session renewal — slide the window
  if (now - session.lastActivity > env.SESSION_RENEW_MS) {
    session.lastActivity = now;
  }
  req.session = session;
  req.sessionId = sessionId;
}

/** CSRF verification for state-changing methods */
function csrfMiddleware(req) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return;
  if (!req.session) return; // no session = no CSRF needed (login uses brute-force protection instead)
  const headerToken = req.headers["x-csrf-token"];
  if (!headerToken || headerToken !== req.session.csrfToken) {
    throw new ForbiddenError("CSRF token mismatch");
  }
}

/** Require authentication */
function requireAuth(req) {
  if (!req.session) {
    throw new AuthError("Authentication required");
  }
}

// ---------------------------------------------------------------------------
// 10. Brute-force protection
// ---------------------------------------------------------------------------
function checkBruteForce(username) {
  const key = username.toLowerCase();
  const entry = loginAttempts.get(key);
  if (!entry) return;
  const now = Date.now();
  // Check if currently locked out
  if (entry.lockedUntil && entry.lockedUntil > now) {
    const retryAfter = Math.ceil((entry.lockedUntil - now) / 1000);
    throw new RateLimitError(
      `Account locked due to too many failed attempts. Try again in ${retryAfter}s`,
      retryAfter
    );
  }
  // Reset window if expired
  if (now - entry.firstAttempt > env.LOCKOUT_WINDOW_MS) {
    loginAttempts.delete(key);
  }
}

function recordFailedAttempt(username) {
  const key = username.toLowerCase();
  const now = Date.now();
  let entry = loginAttempts.get(key);
  if (!entry || now - entry.firstAttempt > env.LOCKOUT_WINDOW_MS) {
    entry = { count: 0, firstAttempt: now, lockedUntil: null };
  }
  entry.count++;
  if (entry.count >= env.MAX_FAILED_ATTEMPTS) {
    entry.lockedUntil = now + env.LOCKOUT_WINDOW_MS;
  }
  loginAttempts.set(key, entry);
}

function clearFailedAttempts(username) {
  loginAttempts.delete(username.toLowerCase());
}

// ---------------------------------------------------------------------------
// 11. Password hashing
// ---------------------------------------------------------------------------
function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derived) => {
      if (err) return reject(err);
      resolve(derived.toString("hex"));
    });
  });
}

async function verifyPassword(password, salt, storedHash) {
  const hash = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(storedHash, "hex"));
}

// ---------------------------------------------------------------------------
// 12. Session management helpers
// ---------------------------------------------------------------------------
function createSession(res, userId, req) {
  const sessionId = generateId();
  const csrfToken = generateSecureToken();
  const now = Date.now();

  sessions.set(sessionId, {
    userId,
    csrfToken,
    createdAt: now,
    lastActivity: now,
    ip: req.socket.remoteAddress || "unknown",
    ua: sanitize(req.headers["user-agent"] || ""),
  });

  const sig = hmacSign(sessionId);
  const maxAge = Math.floor(env.SESSION_TTL_MS / 1000);
  setCookie(res, "sid", sessionId, { maxAge });
  setCookie(res, "sid.sig", sig, { maxAge });

  return { sessionId, csrfToken };
}

function destroySession(res, sessionId) {
  sessions.delete(sessionId);
  clearCookie(res, "sid");
  clearCookie(res, "sid.sig");
}

// ---------------------------------------------------------------------------
// 13. Route handlers
// ---------------------------------------------------------------------------

async function handleRegister(req, res) {
  const ip = req.socket.remoteAddress || "unknown";
  authLimiter(ip);

  const body = await readBody(req);
  const username = validateUsername(sanitize(body.username));
  const password = validatePassword(body.password);
  const email = validateEmail(body.email);

  if (users.has(username)) {
    throw new InputError("Username already taken");
  }

  const salt = crypto.randomBytes(32).toString("hex");
  const passwordHash = await hashPassword(password, salt);
  users.set(username, { passwordHash, salt, email, locked: false });

  const { csrfToken } = createSession(res, username, req);
  json(res, 201, {
    message: "Account created",
    csrfToken,
    user: { username, email },
  });
}

async function handleLogin(req, res) {
  const ip = req.socket.remoteAddress || "unknown";
  authLimiter(ip);

  const body = await readBody(req);
  const username = validateUsername(sanitize(body.username));
  const password = validatePassword(body.password);

  // Check brute-force lockout BEFORE password verification
  checkBruteForce(username);

  const user = users.get(username);
  if (!user) {
    recordFailedAttempt(username);
    // Constant-time delay to prevent user enumeration
    await hashPassword(password, crypto.randomBytes(32).toString("hex"));
    throw new AuthError("Invalid credentials");
  }

  if (user.locked) {
    throw new ForbiddenError("Account is permanently locked. Contact support.");
  }

  const valid = await verifyPassword(password, user.salt, user.passwordHash);
  if (!valid) {
    recordFailedAttempt(username);
    throw new AuthError("Invalid credentials");
  }

  clearFailedAttempts(username);
  const { csrfToken } = createSession(res, username, req);
  json(res, 200, {
    message: "Logged in",
    csrfToken,
    user: { username, email: user.email },
  });
}

function handleLogout(req, res) {
  requireAuth(req);
  destroySession(res, req.sessionId);
  json(res, 200, { message: "Logged out" });
}

function handleMe(req, res) {
  requireAuth(req);
  const user = users.get(req.session.userId);
  json(res, 200, {
    user: {
      username: req.session.userId,
      email: user ? user.email : null,
    },
    session: {
      createdAt: req.session.createdAt,
      lastActivity: req.session.lastActivity,
    },
  });
}

function handleCsrf(req, res) {
  requireAuth(req);
  json(res, 200, { csrfToken: req.session.csrfToken });
}

async function handlePasswordResetRequest(req, res) {
  const ip = req.socket.remoteAddress || "unknown";
  resetLimiter(ip);

  const body = await readBody(req);
  const email = validateEmail(body.email);

  // Always respond 200 to prevent email enumeration
  // But only create token if user exists
  let found = false;
  for (const [, user] of users) {
    if (user.email === email) {
      found = true;
      break;
    }
  }

  if (found) {
    const token = generateSecureToken();
    resetTokens.set(token, { email, createdAt: Date.now() });

    // In production, send email via SMTP. Here we log it.
    console.log(
      `[PASSWORD RESET] Token for ${email}: ${token} (valid ${env.RESET_TOKEN_TTL_MS / 60000} min)`
    );
    console.log(`  Reset link: ${env.APP_ORIGIN}/reset-password?token=${token}`);
  }

  json(res, 200, {
    message: "If that email exists, a reset link has been sent.",
  });
}

async function handlePasswordReset(req, res) {
  const ip = req.socket.remoteAddress || "unknown";
  authLimiter(ip);

  const body = await readBody(req);
  const token = validateToken(body.token);
  const newPassword = validatePassword(body.newPassword);

  const tokenData = resetTokens.get(token);
  if (!tokenData) {
    throw new AuthError("Invalid or expired reset token");
  }

  // Check expiry
  if (Date.now() - tokenData.createdAt > env.RESET_TOKEN_TTL_MS) {
    resetTokens.delete(token);
    throw new AuthError("Reset token has expired");
  }

  // Find user by email and update password
  let targetUsername = null;
  for (const [username, user] of users) {
    if (user.email === tokenData.email) {
      targetUsername = username;
      break;
    }
  }

  if (!targetUsername) {
    resetTokens.delete(token);
    throw new AuthError("User no longer exists");
  }

  const salt = crypto.randomBytes(32).toString("hex");
  const passwordHash = await hashPassword(newPassword, salt);
  const user = users.get(targetUsername);
  user.passwordHash = passwordHash;
  user.salt = salt;

  // Invalidate ALL existing sessions for this user
  for (const [sid, sess] of sessions) {
    if (sess.userId === targetUsername) {
      sessions.delete(sid);
    }
  }

  // Clear lockouts and consume the token
  clearFailedAttempts(targetUsername);
  resetTokens.delete(token);

  // Also invalidate all other reset tokens for this email
  for (const [t, d] of resetTokens) {
    if (d.email === tokenData.email) {
      resetTokens.delete(t);
    }
  }

  json(res, 200, { message: "Password has been reset. Please log in." });
}

async function handleChangePassword(req, res) {
  requireAuth(req);

  const body = await readBody(req);
  const currentPassword = validatePassword(body.currentPassword);
  const newPassword = validatePassword(body.newPassword);

  if (currentPassword === newPassword) {
    throw new InputError("New password must be different from current password");
  }

  const user = users.get(req.session.userId);
  if (!user) throw new AuthError("User not found");

  const valid = await verifyPassword(currentPassword, user.salt, user.passwordHash);
  if (!valid) {
    throw new AuthError("Current password is incorrect");
  }

  const salt = crypto.randomBytes(32).toString("hex");
  const passwordHash = await hashPassword(newPassword, salt);
  user.passwordHash = passwordHash;
  user.salt = salt;

  // Invalidate all OTHER sessions (keep current)
  for (const [sid, sess] of sessions) {
    if (sess.userId === req.session.userId && sid !== req.sessionId) {
      sessions.delete(sid);
    }
  }

  json(res, 200, { message: "Password changed successfully" });
}

function handleMetrics(_req, res) {
  json(res, 200, {
    activeSessions: metrics.activeSessions(),
    pendingResets: metrics.pendingResets(),
    lockedAccounts: metrics.lockedAccounts(),
    totalUsers: users.size,
    requestsByEndpoint: Object.fromEntries(metrics.requests),
    errorsByEndpoint: Object.fromEntries(metrics.errors),
  });
}

function handleHealthCheck(_req, res) {
  json(res, 200, { status: "ok", uptime: process.uptime() });
}

// ---------------------------------------------------------------------------
// 14. Router
// ---------------------------------------------------------------------------
const routes = {
  "POST /api/auth/register": handleRegister,
  "POST /api/auth/login": handleLogin,
  "POST /api/auth/logout": handleLogout,
  "GET /api/auth/me": handleMe,
  "GET /api/auth/csrf": handleCsrf,
  "POST /api/auth/password-reset/request": handlePasswordResetRequest,
  "POST /api/auth/password-reset/confirm": handlePasswordReset,
  "POST /api/auth/change-password": handleChangePassword,
  "GET /api/metrics": handleMetrics,
  "GET /health": handleHealthCheck,
};

// ---------------------------------------------------------------------------
// 15. Main request handler
// ---------------------------------------------------------------------------
async function handleRequest(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const routeKey = `${req.method} ${parsedUrl.pathname}`;
  const endpoint = parsedUrl.pathname;

  trackRequest(endpoint);

  try {
    // Middleware pipeline (order matters: helmet → CORS → rate-limit → session → CSRF)
    helmetMiddleware(req, res);

    const corsDone = corsMiddleware(req, res);
    if (corsDone) return; // OPTIONS preflight handled

    rateLimitMiddleware(req);
    sessionMiddleware(req);
    csrfMiddleware(req);

    const handler = routes[routeKey];
    if (!handler) {
      throw new NotFoundError(`Route ${routeKey} not found`);
    }

    await handler(req, res);
  } catch (err) {
    trackError(endpoint);

    // Differentiated error handling
    if (err instanceof RateLimitError) {
      if (err.retryAfter) res.setHeader("Retry-After", String(err.retryAfter));
      json(res, 429, { error: err.message });
    } else if (err instanceof InputError) {
      json(res, 400, { error: err.message });
    } else if (err instanceof AuthError) {
      json(res, 401, { error: err.message });
    } else if (err instanceof ForbiddenError) {
      json(res, 403, { error: err.message });
    } else if (err instanceof NotFoundError) {
      json(res, 404, { error: err.message });
    } else {
      // Unexpected error — log full stack, return generic message
      console.error(`[UNHANDLED ERROR] ${endpoint}:`, err);
      json(res, 500, { error: "Internal server error" });
    }
  }
}

// ---------------------------------------------------------------------------
// 16. Server creation + graceful shutdown
// ---------------------------------------------------------------------------
const server = http.createServer(handleRequest);

server.listen(env.PORT, () => {
  console.log(`Auth server listening on port ${env.PORT}`);
  console.log(`CORS origin: ${env.APP_ORIGIN}`);
  console.log(`Session TTL: ${env.SESSION_TTL_MS / 60000} min`);
  console.log(`Reset token TTL: ${env.RESET_TOKEN_TTL_MS / 60000} min`);
  console.log(`Max failed attempts: ${env.MAX_FAILED_ATTEMPTS}`);
  console.log(`Demo user: demo / P@ssw0rd123`);
});

function gracefulShutdown(signal) {
  console.log(`\n[${signal}] Shutting down gracefully...`);

  // Stop accepting new connections
  server.close(() => {
    console.log("HTTP server closed.");

    // Clear all intervals
    clearInterval(cleanupTimer);

    // Flush session data (in production, persist to store)
    console.log(`Sessions cleared: ${sessions.size}`);
    sessions.clear();
    resetTokens.clear();
    loginAttempts.clear();

    console.log("Cleanup complete. Exiting.");
    process.exit(0);
  });

  // Force shutdown after 10s
  setTimeout(() => {
    console.error("Forced shutdown after timeout.");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Catch unhandled rejections
process.on("unhandledRejection", (reason) => {
  console.error("[UNHANDLED REJECTION]", reason);
});

process.on("uncaughtException", (err) => {
  console.error("[UNCAUGHT EXCEPTION]", err);
  gracefulShutdown("uncaughtException");
});

module.exports = { server, sessions, users, resetTokens, loginAttempts, metrics };
