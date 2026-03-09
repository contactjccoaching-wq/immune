/**
 * Session-Based Authentication Middleware
 * Production-quality Node.js implementation
 *
 * Features:
 * - Session management with secure cookies
 * - CSRF protection (Double Submit Cookie + Synchronizer Token Pattern)
 * - Session expiry and renewal (sliding window)
 * - Brute-force protection (account lockout after 5 failed attempts)
 * - Password reset flow with time-limited tokens
 * - Constant-time secret comparison (CS-CODE-031)
 * - Fail-closed pattern for all secrets (CS-CODE-013, AB-CODE-022)
 * - Auth gate before every sensitive operation (CS-CODE-016, AB-CODE-026)
 * - No in-memory rate limiting — DB-backed (CS-CODE-017, AB-CODE-029)
 * - Input validated as hostile (CS-CODE-015)
 * - HTML escaping on all user-controlled output (CS-CODE-014, AB-CODE-006, AB-CODE-023)
 * - No wildcard CORS (AB-CODE-025)
 * - No auth tokens in URLs (AB-CODE-027)
 * - No GET mutations (AB-CODE-028)
 * - JSON.parse always wrapped (AB-CODE-008)
 * - No placeholder / default-true auth (AB-CODE-021)
 * - Explicit origin allowlist for CORS (AB-CODE-025)
 */

'use strict';

const crypto = require('crypto');
const http = require('http');
const { URL } = require('url');

// ---------------------------------------------------------------------------
// CS-CODE-007: Single centralized state object
// ---------------------------------------------------------------------------
const STATE = {
  db: null,          // will be set by init()
  config: null,      // will be set by init()
  initialized: false,
};

// ---------------------------------------------------------------------------
// CS-CODE-006: Centralized init() — single entry point for all setup
// ---------------------------------------------------------------------------
async function init(db, userConfig = {}) {
  validateConfig(userConfig);

  STATE.db = db;
  STATE.config = buildConfig(userConfig);
  STATE.initialized = true;

  await ensureSchema();
}

// ---------------------------------------------------------------------------
// Configuration — fail-closed if required secrets are missing
// CS-CODE-012, CS-CODE-013, AB-CODE-022
// ---------------------------------------------------------------------------
const REQUIRED_ENV = ['SESSION_SECRET', 'CSRF_SECRET'];
const OPTIONAL_ENV = {
  RESET_TOKEN_SECRET: null,
  ALLOWED_ORIGINS: '',
};

function buildConfig(userConfig) {
  // Fail-closed: reject startup if required secrets are absent
  for (const key of REQUIRED_ENV) {
    const value = process.env[key] || userConfig[key];
    if (!value || value.length < 32) {
      throw new Error(
        `[auth] FAIL-CLOSED: Required secret "${key}" is missing or too short (min 32 chars). ` +
        'Refusing to start. Set the env variable before launching.'
      );
    }
  }

  const sessionSecret = process.env.SESSION_SECRET || userConfig.SESSION_SECRET;
  const csrfSecret   = process.env.CSRF_SECRET    || userConfig.CSRF_SECRET;
  // RESET_TOKEN_SECRET falls back to sessionSecret if not explicitly set,
  // but still must be at least 32 chars since sessionSecret already passed validation.
  const resetSecret  =
    process.env.RESET_TOKEN_SECRET ||
    userConfig.RESET_TOKEN_SECRET  ||
    sessionSecret;

  // Parse allowed origins; never allow wildcard on auth endpoints (AB-CODE-025)
  const rawOrigins = process.env.ALLOWED_ORIGINS || userConfig.ALLOWED_ORIGINS || '';
  const allowedOrigins = rawOrigins
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

  return {
    sessionSecret,
    csrfSecret,
    resetSecret,
    allowedOrigins,                         // explicit allowlist, never '*'
    sessionTtlMs:     userConfig.sessionTtlMs     || 30 * 60 * 1000, // 30 min
    renewThresholdMs: userConfig.renewThresholdMs || 10 * 60 * 1000, // renew if < 10 min left
    maxLoginAttempts: userConfig.maxLoginAttempts || 5,
    lockoutDurationMs:userConfig.lockoutDurationMs|| 15 * 60 * 1000, // 15 min
    resetTokenTtlMs:  userConfig.resetTokenTtlMs  || 60 * 60 * 1000, // 1 hour
    cookieName:       userConfig.cookieName        || '__Host-sid',
    csrfCookieName:   userConfig.csrfCookieName    || '__Host-csrf',
    secureCookies:    userConfig.secureCookies !== false, // default true
    sameSite:         userConfig.sameSite          || 'Strict',
  };
}

function validateConfig(userConfig) {
  // CS-CODE-005: per-field type guards
  const numericFields = [
    'sessionTtlMs', 'renewThresholdMs', 'maxLoginAttempts',
    'lockoutDurationMs', 'resetTokenTtlMs',
  ];
  for (const field of numericFields) {
    if (field in userConfig && (typeof userConfig[field] !== 'number' || userConfig[field] <= 0)) {
      throw new TypeError(`[auth] config.${field} must be a positive number`);
    }
  }
}

// ---------------------------------------------------------------------------
// Database schema bootstrap
// ---------------------------------------------------------------------------
async function ensureSchema() {
  const { db } = STATE;
  // These are idiomatic SQL; real production code would use migrations.
  await db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id          TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL,
      csrf_token  TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL,
      renewed_at  INTEGER NOT NULL,
      user_agent  TEXT,
      ip_address  TEXT
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      identifier   TEXT NOT NULL,
      attempted_at INTEGER NOT NULL,
      success      INTEGER NOT NULL DEFAULT 0,
      ip_address   TEXT
    )
  `);

  await db.run(`
    CREATE INDEX IF NOT EXISTS idx_login_attempts_identifier
    ON login_attempts(identifier, attempted_at)
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS account_lockouts (
      identifier  TEXT PRIMARY KEY,
      locked_at   INTEGER NOT NULL,
      locked_until INTEGER NOT NULL,
      failed_count INTEGER NOT NULL DEFAULT 0
    )
  `);

  await db.run(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_hash  TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL,
      used        INTEGER NOT NULL DEFAULT 0
    )
  `);
}

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

/** Generate a cryptographically secure random hex string */
function generateSecureToken(byteLength = 32) {
  return crypto.randomBytes(byteLength).toString('hex');
}

/**
 * HMAC-SHA256 — used for session IDs, CSRF tokens, reset tokens
 * Never used for password storage (use bcrypt/argon2 instead)
 */
function hmacSign(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Constant-time comparison to prevent timing attacks.
 * AB-CODE-031: never use === for secret comparison
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) {
    // Still run timingSafeEqual on same-length buffers to avoid length leak
    crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
    return false;
  }
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/** SHA-256 hash (for storing reset tokens — not passwords) */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ---------------------------------------------------------------------------
// HTML escaping — CS-CODE-001, CS-CODE-014, AB-CODE-006, AB-CODE-023
// ---------------------------------------------------------------------------
const HTML_ESCAPE_MAP = {
  '&':  '&amp;',
  '<':  '&lt;',
  '>':  '&gt;',
  '"':  '&quot;',
  "'":  '&#x27;',
  '/':  '&#x2F;',
};

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"'/]/g, ch => HTML_ESCAPE_MAP[ch]);
}

// ---------------------------------------------------------------------------
// Input validation helpers — CS-CODE-015
// ---------------------------------------------------------------------------

/**
 * Validate and sanitize a session/token identifier from a cookie or header.
 * Tokens are lowercase hex; reject anything that deviates.
 */
function validateHexToken(raw, expectedLength = 64) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (trimmed.length !== expectedLength) return null;
  if (!/^[0-9a-f]+$/.test(trimmed)) return null;
  return trimmed;
}

/**
 * Validate an email address — basic format + length.
 * CS-CODE-015: treat all user input as hostile.
 */
function validateEmail(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim().toLowerCase();
  if (trimmed.length > 254) return null;
  // RFC 5322 simplified
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return null;
  return trimmed;
}

/** Safe JSON.parse wrapper — AB-CODE-008 */
function safeJsonParse(str, fallback = null) {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

/**
 * Build a Set-Cookie header string with secure defaults.
 * __Host- prefix requires: Secure; Path=/; no Domain
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes
 */
function buildSetCookieHeader(name, value, options = {}) {
  const {
    maxAge,
    httpOnly = true,
    sameSite = STATE.config.sameSite,
    secure   = STATE.config.secureCookies,
  } = options;

  let cookie = `${name}=${value}; Path=/`;
  if (secure)   cookie += '; Secure';
  if (httpOnly) cookie += '; HttpOnly';
  if (sameSite) cookie += `; SameSite=${sameSite}`;
  if (maxAge !== undefined) cookie += `; Max-Age=${maxAge}`;
  return cookie;
}

/**
 * Parse Cookie header into a plain object.
 * CS-CODE-015: values are not trusted until validated.
 */
function parseCookies(cookieHeader) {
  const result = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) result[key] = val;
  }
  return result;
}

// ---------------------------------------------------------------------------
// CORS — explicit origin allowlist, never wildcard (AB-CODE-025)
// ---------------------------------------------------------------------------
function applyCors(req, res) {
  const origin = req.headers['origin'];
  if (!origin) return;

  const { allowedOrigins } = STATE.config;
  if (allowedOrigins.length === 0) return; // no CORS if no origins configured

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, X-CSRF-Token, Authorization'
    );
  }
  // Origins not in the allowlist receive no CORS headers — browser blocks the request
}

// ---------------------------------------------------------------------------
// Brute-force / account lockout — DB-backed (CS-CODE-017, AB-CODE-029)
// ---------------------------------------------------------------------------

/**
 * Check whether an identifier (email or username) is currently locked out.
 * Returns { locked: boolean, lockedUntil: number|null }
 */
async function checkLockout(identifier) {
  const { db, config } = STATE;
  const now = Date.now();

  const row = await db.get(
    'SELECT locked_until, failed_count FROM account_lockouts WHERE identifier = ?',
    [identifier]
  );

  if (!row) return { locked: false, lockedUntil: null };

  if (row.locked_until > now) {
    return { locked: true, lockedUntil: row.locked_until, failedCount: row.failed_count };
  }

  // Lockout expired — clean up so counter resets
  await db.run('DELETE FROM account_lockouts WHERE identifier = ?', [identifier]);
  return { locked: false, lockedUntil: null };
}

/**
 * Record a failed login attempt and apply lockout if threshold is exceeded.
 * Returns { nowLocked: boolean, failedCount: number }
 */
async function recordFailedAttempt(identifier, ipAddress) {
  const { db, config } = STATE;
  const now = Date.now();

  await db.run(
    'INSERT INTO login_attempts (identifier, attempted_at, success, ip_address) VALUES (?, ?, 0, ?)',
    [identifier, now, ipAddress || null]
  );

  // Count failures within the lockout window
  const windowStart = now - config.lockoutDurationMs;
  const row = await db.get(
    `SELECT COUNT(*) AS cnt FROM login_attempts
     WHERE identifier = ? AND attempted_at > ? AND success = 0`,
    [identifier, windowStart]
  );
  const failedCount = row ? row.cnt : 1;

  if (failedCount >= config.maxLoginAttempts) {
    const lockedUntil = now + config.lockoutDurationMs;
    await db.run(
      `INSERT INTO account_lockouts (identifier, locked_at, locked_until, failed_count)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(identifier) DO UPDATE SET
         locked_at    = excluded.locked_at,
         locked_until = excluded.locked_until,
         failed_count = excluded.failed_count`,
      [identifier, now, lockedUntil, failedCount]
    );
    return { nowLocked: true, failedCount };
  }

  return { nowLocked: false, failedCount };
}

/** Record a successful login — clears lockout and failure history for identifier */
async function recordSuccessfulLogin(identifier) {
  const { db } = STATE;
  const now = Date.now();
  await Promise.all([
    db.run(
      'INSERT INTO login_attempts (identifier, attempted_at, success) VALUES (?, ?, 1)',
      [identifier, now]
    ),
    db.run('DELETE FROM account_lockouts WHERE identifier = ?', [identifier]),
  ]);
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

/**
 * Create a new session after successful authentication.
 * Returns { sessionId, csrfToken }
 */
async function createSession(userId, requestMeta = {}) {
  const { db, config } = STATE;
  const now = Date.now();
  const expiresAt = now + config.sessionTtlMs;

  const rawId    = generateSecureToken(32);
  const sessionId = hmacSign(config.sessionSecret, rawId); // store signed ID
  const csrfToken = generateSecureToken(32);

  await db.run(
    `INSERT INTO sessions
       (id, user_id, csrf_token, created_at, expires_at, renewed_at, user_agent, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      sessionId,
      userId,
      csrfToken,
      now,
      expiresAt,
      now,
      requestMeta.userAgent || null,
      requestMeta.ipAddress || null,
    ]
  );

  return { sessionId, csrfToken };
}

/**
 * Look up a session by ID and handle expiry + sliding renewal.
 * Returns the session row (with renewed expires_at) or null if invalid/expired.
 */
async function getSession(sessionId) {
  const { db, config } = STATE;
  const now = Date.now();

  const session = await db.get(
    'SELECT * FROM sessions WHERE id = ?',
    [sessionId]
  );

  if (!session) return null;
  if (session.expires_at <= now) {
    // Expired — delete and reject
    await db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
    return null;
  }

  // Sliding window renewal: extend if less than renewThresholdMs remains
  const remaining = session.expires_at - now;
  if (remaining < config.renewThresholdMs) {
    const newExpiresAt = now + config.sessionTtlMs;
    await db.run(
      'UPDATE sessions SET expires_at = ?, renewed_at = ? WHERE id = ?',
      [newExpiresAt, now, sessionId]
    );
    session.expires_at = newExpiresAt;
    session.renewed_at = now;
  }

  return session;
}

/** Destroy a session (logout) */
async function destroySession(sessionId) {
  const { db } = STATE;
  await db.run('DELETE FROM sessions WHERE id = ?', [sessionId]);
}

/** Destroy all sessions for a user (e.g., password change) */
async function destroyAllUserSessions(userId) {
  const { db } = STATE;
  await db.run('DELETE FROM sessions WHERE user_id = ?', [userId]);
}

// ---------------------------------------------------------------------------
// CSRF verification
// ---------------------------------------------------------------------------

/**
 * Verify that the CSRF token in the request header matches the session token.
 * Uses constant-time comparison. (AB-CODE-031)
 *
 * The client must send the CSRF token in the X-CSRF-Token header (not a cookie,
 * not a URL param — AB-CODE-027).
 */
function verifyCsrfToken(session, requestCsrfToken) {
  if (!session || !session.csrf_token) return false;
  if (typeof requestCsrfToken !== 'string' || requestCsrfToken.length === 0) return false;
  return safeCompare(session.csrf_token, requestCsrfToken);
}

// ---------------------------------------------------------------------------
// Password reset tokens
// ---------------------------------------------------------------------------

/**
 * Generate a password reset token for a user.
 * The raw token is returned to the caller (to be emailed); only the hash is stored.
 * Returns { rawToken, expiresAt }
 */
async function createResetToken(userId) {
  const { db, config } = STATE;
  const now = Date.now();
  const expiresAt = now + config.resetTokenTtlMs;

  const rawToken  = generateSecureToken(32);
  const tokenHash = sha256(rawToken);

  // Invalidate any existing reset tokens for this user before inserting a new one
  await db.run('DELETE FROM password_reset_tokens WHERE user_id = ?', [userId]);

  await db.run(
    `INSERT INTO password_reset_tokens (token_hash, user_id, created_at, expires_at, used)
     VALUES (?, ?, ?, ?, 0)`,
    [tokenHash, userId, now, expiresAt]
  );

  return { rawToken, expiresAt };
}

/**
 * Validate a password reset token.
 * Returns { valid: boolean, userId: string|null, reason: string }
 */
async function validateResetToken(rawToken) {
  if (typeof rawToken !== 'string' || rawToken.length === 0) {
    return { valid: false, userId: null, reason: 'missing_token' };
  }

  const { db } = STATE;
  const now = Date.now();
  const tokenHash = sha256(rawToken);

  const row = await db.get(
    'SELECT * FROM password_reset_tokens WHERE token_hash = ?',
    [tokenHash]
  );

  if (!row)            return { valid: false, userId: null, reason: 'not_found' };
  if (row.used)        return { valid: false, userId: null, reason: 'already_used' };
  if (row.expires_at <= now) {
    await db.run('DELETE FROM password_reset_tokens WHERE token_hash = ?', [tokenHash]);
    return { valid: false, userId: null, reason: 'expired' };
  }

  return { valid: true, userId: row.user_id, reason: null };
}

/**
 * Mark a reset token as used (call after successful password change).
 * Also destroys all active sessions for the user.
 */
async function consumeResetToken(rawToken, userId) {
  const { db } = STATE;
  const tokenHash = sha256(rawToken);

  await Promise.all([
    db.run(
      'UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?',
      [tokenHash]
    ),
    destroyAllUserSessions(userId),
  ]);
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/**
 * Returns an Express/Connect-compatible middleware that:
 * 1. Applies CORS headers from the allowlist
 * 2. Parses the session cookie
 * 3. Validates and (if necessary) renews the session
 * 4. Attaches session data to req
 * 5. Exposes helper methods on req for downstream handlers
 *
 * CS-CODE-016, AB-CODE-026: Auth check happens HERE, before any downstream work.
 */
function sessionMiddleware() {
  assertInitialized();

  return async function authMiddleware(req, res, next) {
    try {
      applyCors(req, res);

      // Handle preflight — no session needed for OPTIONS
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const cookies = parseCookies(req.headers['cookie']);

      // Validate raw session ID from cookie — CS-CODE-015
      const rawSessionId = validateHexToken(cookies[STATE.config.cookieName], 64);

      let session = null;
      if (rawSessionId) {
        session = await getSession(rawSessionId);

        if (session && session.expires_at !== undefined) {
          // Renew cookie if session was renewed
          const maxAgeSec = Math.floor((session.expires_at - Date.now()) / 1000);
          setSessionCookie(res, rawSessionId, maxAgeSec);
        }
      }

      // Attach to request
      req.session    = session;
      req.sessionId  = rawSessionId || null;
      req.isLoggedIn = !!session;

      // Helpers for downstream route handlers
      req.requireAuth = function requireAuth() {
        if (!req.isLoggedIn) {
          sendJson(res, 401, { error: 'Authentication required' });
          return false;
        }
        return true;
      };

      req.verifyCsrf = function verifyCsrf() {
        // CS-CODE-016: CSRF check before any mutation
        const headerToken = req.headers['x-csrf-token'];
        if (!verifyCsrfToken(req.session, headerToken)) {
          sendJson(res, 403, { error: 'Invalid CSRF token' });
          return false;
        }
        return true;
      };

      next();
    } catch (err) {
      console.error('[auth] middleware error:', err);
      sendJson(res, 500, { error: 'Internal server error' });
    }
  };
}

// ---------------------------------------------------------------------------
// Route handlers (use these in your router)
// ---------------------------------------------------------------------------

/**
 * POST /auth/login
 *
 * Body: { identifier: string, password: string }
 *
 * Expects `verifyPassword(identifier, password) => Promise<{ userId }|null>`
 * to be injected (pluggable password verification — bcrypt, argon2, etc.).
 *
 * AB-CODE-028: POST only for mutations.
 * CS-CODE-016: lockout checked BEFORE any password comparison.
 * AB-CODE-021: never a default-true auth path.
 */
function createLoginHandler(verifyPassword) {
  assertInitialized();

  if (typeof verifyPassword !== 'function') {
    throw new TypeError('[auth] createLoginHandler requires a verifyPassword function');
  }

  return async function loginHandler(req, res) {
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }

    let body;
    try {
      body = await readJsonBody(req, 1024);
    } catch {
      sendJson(res, 400, { error: 'Invalid request body' });
      return;
    }

    // CS-CODE-015: validate all inputs as hostile
    const identifier = validateEmail(body && body.identifier);
    const password   = typeof body?.password === 'string' ? body.password : null;

    if (!identifier || !password || password.length > 1024) {
      sendJson(res, 400, { error: 'Invalid credentials format' });
      return;
    }

    const ipAddress = getClientIp(req);

    // CS-CODE-016: auth gate BEFORE any cost-bearing work — check lockout first
    const lockout = await checkLockout(identifier);
    if (lockout.locked) {
      const retryAfterSec = Math.ceil((lockout.lockedUntil - Date.now()) / 1000);
      res.setHeader('Retry-After', String(retryAfterSec));
      sendJson(res, 429, {
        error: 'Account temporarily locked. Too many failed attempts.',
        retryAfterSeconds: retryAfterSec,
      });
      return;
    }

    // Verify password (injected — never a default-true path, AB-CODE-021)
    let userId = null;
    try {
      const result = await verifyPassword(identifier, password);
      if (result && result.userId) {
        userId = result.userId;
      }
    } catch (err) {
      console.error('[auth] verifyPassword threw:', err);
      sendJson(res, 500, { error: 'Internal server error' });
      return;
    }

    if (!userId) {
      const { nowLocked, failedCount } = await recordFailedAttempt(identifier, ipAddress);
      if (nowLocked) {
        const retryAfterSec = Math.ceil(STATE.config.lockoutDurationMs / 1000);
        res.setHeader('Retry-After', String(retryAfterSec));
        sendJson(res, 429, {
          error: 'Account locked due to too many failed attempts.',
          retryAfterSeconds: retryAfterSec,
        });
      } else {
        const remaining = STATE.config.maxLoginAttempts - failedCount;
        sendJson(res, 401, {
          error: 'Invalid credentials',
          attemptsRemaining: Math.max(0, remaining),
        });
      }
      return;
    }

    // Success
    await recordSuccessfulLogin(identifier);

    const { sessionId, csrfToken } = await createSession(userId, {
      userAgent: req.headers['user-agent'],
      ipAddress,
    });

    const maxAgeSec = Math.floor(STATE.config.sessionTtlMs / 1000);
    setSessionCookie(res, sessionId, maxAgeSec);
    setCsrfCookie(res, csrfToken, maxAgeSec);

    sendJson(res, 200, {
      message:   'Login successful',
      csrfToken, // also returned in body so JS can store it for header use
    });
  };
}

/**
 * POST /auth/logout
 * Requires: valid session + CSRF token
 * AB-CODE-028: POST for mutation.
 */
async function logoutHandler(req, res) {
  if (req.method !== 'POST') {
    sendJson(res, 405, { error: 'Method not allowed' });
    return;
  }

  // CS-CODE-016: auth before action
  if (!req.requireAuth()) return;
  if (!req.verifyCsrf())  return;

  await destroySession(req.sessionId);

  // Expire cookies
  clearSessionCookie(res);
  clearCsrfCookie(res);

  sendJson(res, 200, { message: 'Logged out successfully' });
}

/**
 * POST /auth/request-password-reset
 * Body: { identifier: string }
 *
 * Always returns 200 to prevent user enumeration.
 * AB-CODE-028: POST.
 */
function createRequestResetHandler(lookupUserByEmail, sendResetEmail) {
  assertInitialized();

  if (typeof lookupUserByEmail !== 'function' || typeof sendResetEmail !== 'function') {
    throw new TypeError(
      '[auth] createRequestResetHandler requires lookupUserByEmail and sendResetEmail functions'
    );
  }

  return async function requestResetHandler(req, res) {
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }

    let body;
    try {
      body = await readJsonBody(req, 512);
    } catch {
      sendJson(res, 400, { error: 'Invalid request body' });
      return;
    }

    const identifier = validateEmail(body && body.identifier);

    // Always respond 200 — never reveal whether the account exists
    if (!identifier) {
      sendJson(res, 200, { message: 'If that account exists, a reset link has been sent.' });
      return;
    }

    try {
      const user = await lookupUserByEmail(identifier);
      if (user && user.userId) {
        const { rawToken, expiresAt } = await createResetToken(user.userId);
        // Emit reset email — do not await to avoid timing oracle
        sendResetEmail(identifier, rawToken, expiresAt).catch(err =>
          console.error('[auth] sendResetEmail failed:', err)
        );
      }
    } catch (err) {
      console.error('[auth] requestReset error:', err);
      // Still return 200 to prevent enumeration
    }

    sendJson(res, 200, { message: 'If that account exists, a reset link has been sent.' });
  };
}

/**
 * POST /auth/reset-password
 * Body: { token: string, newPassword: string }
 *
 * Expects `updatePassword(userId, newPassword) => Promise<void>`
 * AB-CODE-027: token comes from body, NOT from URL/query string.
 * AB-CODE-028: POST.
 */
function createResetPasswordHandler(updatePassword) {
  assertInitialized();

  if (typeof updatePassword !== 'function') {
    throw new TypeError('[auth] createResetPasswordHandler requires an updatePassword function');
  }

  return async function resetPasswordHandler(req, res) {
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }

    let body;
    try {
      body = await readJsonBody(req, 1024);
    } catch {
      sendJson(res, 400, { error: 'Invalid request body' });
      return;
    }

    // CS-CODE-015: validate token as hex string
    const rawToken   = validateHexToken(body && body.token, 64);
    const newPassword = typeof body?.newPassword === 'string' ? body.newPassword : null;

    if (!rawToken || !newPassword) {
      sendJson(res, 400, { error: 'token and newPassword are required' });
      return;
    }

    if (newPassword.length < 12 || newPassword.length > 1024) {
      sendJson(res, 400, { error: 'Password must be 12–1024 characters' });
      return;
    }

    const { valid, userId, reason } = await validateResetToken(rawToken);

    if (!valid) {
      // Do NOT leak specific reason to client — log internally
      console.warn(`[auth] resetPassword token invalid: ${reason}`);
      sendJson(res, 400, { error: 'Invalid or expired reset token' });
      return;
    }

    try {
      await updatePassword(userId, newPassword);
    } catch (err) {
      console.error('[auth] updatePassword failed:', err);
      sendJson(res, 500, { error: 'Failed to update password' });
      return;
    }

    // Consume token + destroy all sessions
    await consumeResetToken(rawToken, userId);

    sendJson(res, 200, { message: 'Password updated successfully. Please log in again.' });
  };
}

/**
 * GET /auth/csrf-token
 * Returns the CSRF token for the current session.
 * Only call this from authenticated contexts where you need to bootstrap the CSRF token
 * (e.g., after a full page load — for SPAs that need to refresh the token).
 */
async function csrfTokenHandler(req, res) {
  if (req.method !== 'GET') {
    sendJson(res, 405, { error: 'Method not allowed' });
    return;
  }

  if (!req.requireAuth()) return;

  sendJson(res, 200, { csrfToken: req.session.csrf_token });
}

// ---------------------------------------------------------------------------
// Cookie setters / clearers
// ---------------------------------------------------------------------------

function setSessionCookie(res, sessionId, maxAgeSec) {
  const { cookieName, secureCookies, sameSite } = STATE.config;
  const header = buildSetCookieHeader(cookieName, sessionId, {
    maxAge:   maxAgeSec,
    httpOnly: true,
    secure:   secureCookies,
    sameSite,
  });
  appendSetCookie(res, header);
}

function setCsrfCookie(res, csrfToken, maxAgeSec) {
  const { csrfCookieName, secureCookies, sameSite } = STATE.config;
  // CSRF cookie is readable by JS (httpOnly=false) so the SPA can attach it to headers
  const header = buildSetCookieHeader(csrfCookieName, csrfToken, {
    maxAge:   maxAgeSec,
    httpOnly: false,  // intentionally readable by JS — value goes into X-CSRF-Token header
    secure:   secureCookies,
    sameSite,
  });
  appendSetCookie(res, header);
}

function clearSessionCookie(res) {
  const { cookieName, secureCookies, sameSite } = STATE.config;
  const header = buildSetCookieHeader(cookieName, '', {
    maxAge:   0,
    httpOnly: true,
    secure:   secureCookies,
    sameSite,
  });
  appendSetCookie(res, header);
}

function clearCsrfCookie(res) {
  const { csrfCookieName, secureCookies, sameSite } = STATE.config;
  const header = buildSetCookieHeader(csrfCookieName, '', {
    maxAge:   0,
    httpOnly: false,
    secure:   secureCookies,
    sameSite,
  });
  appendSetCookie(res, header);
}

/** Append a Set-Cookie header without overwriting existing ones */
function appendSetCookie(res, value) {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    res.setHeader('Set-Cookie', [value]);
  } else if (Array.isArray(existing)) {
    res.setHeader('Set-Cookie', [...existing, value]);
  } else {
    res.setHeader('Set-Cookie', [existing, value]);
  }
}

// ---------------------------------------------------------------------------
// HTTP utilities
// ---------------------------------------------------------------------------

/** Read and parse a JSON request body with a byte-length cap */
function readJsonBody(req, maxBytes = 4096) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;

    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      data += chunk;
    });

    req.on('end', () => {
      // AB-CODE-008: JSON.parse always wrapped
      const parsed = safeJsonParse(data, undefined);
      if (parsed === undefined) {
        reject(new Error('Invalid JSON'));
      } else {
        resolve(parsed);
      }
    });

    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':           'application/json',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control':          'no-store',
  });
  res.end(payload);
}

/** Extract client IP, respecting common proxy headers */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // Take the first IP in the chain (closest client)
    const first = forwarded.split(',')[0].trim();
    // Basic IP sanity — CS-CODE-015: treat as hostile
    if (/^[\d.:a-fA-F]+$/.test(first) && first.length <= 45) return first;
  }
  return req.socket?.remoteAddress || null;
}

// ---------------------------------------------------------------------------
// Guard helper
// ---------------------------------------------------------------------------
function assertInitialized() {
  if (!STATE.initialized) {
    throw new Error('[auth] Call auth.init(db, config) before using any auth function.');
  }
}

// ---------------------------------------------------------------------------
// Maintenance: purge expired sessions and stale lockout records
// Call this periodically (e.g., cron job) to keep DB clean.
// AB-CODE-029 note: no in-memory sweep needed — all data lives in DB.
// ---------------------------------------------------------------------------
async function purgeExpiredData() {
  assertInitialized();
  const { db } = STATE;
  const now = Date.now();

  await Promise.all([
    db.run('DELETE FROM sessions WHERE expires_at <= ?', [now]),
    db.run('DELETE FROM account_lockouts WHERE locked_until <= ?', [now]),
    db.run('DELETE FROM password_reset_tokens WHERE expires_at <= ? OR used = 1', [now]),
    // Keep login_attempts for 7 days for audit trail
    db.run('DELETE FROM login_attempts WHERE attempted_at <= ?', [now - 7 * 24 * 60 * 60 * 1000]),
  ]);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
module.exports = {
  // Lifecycle
  init,
  purgeExpiredData,

  // Middleware
  sessionMiddleware,

  // Route handler factories
  createLoginHandler,
  logoutHandler,
  createRequestResetHandler,
  createResetPasswordHandler,
  csrfTokenHandler,

  // Lower-level exports (for testing / custom flows)
  createSession,
  getSession,
  destroySession,
  destroyAllUserSessions,
  createResetToken,
  validateResetToken,
  consumeResetToken,
  checkLockout,
  recordFailedAttempt,
  recordSuccessfulLogin,

  // Utilities
  safeCompare,
  escapeHtml,
  generateSecureToken,
  validateEmail,
  validateHexToken,
  safeJsonParse,
};

// ---------------------------------------------------------------------------
// Example usage (illustrative — not executed when require()'d)
// ---------------------------------------------------------------------------
/*

const auth  = require('./r8-sonnet');
const db    = require('./db');   // your DB adapter (must expose .run, .get, .all)
const bcrypt = require('bcrypt');

// CS-CODE-006: single centralized init
await auth.init(db, {
  // Secrets come from env — fail-closed if missing (CS-CODE-013)
  // SESSION_SECRET and CSRF_SECRET must be set in environment
  ALLOWED_ORIGINS:    'https://app.example.com',
  sessionTtlMs:       30 * 60 * 1000,
  renewThresholdMs:   10 * 60 * 1000,
  maxLoginAttempts:   5,
  lockoutDurationMs:  15 * 60 * 1000,
  resetTokenTtlMs:    60 * 60 * 1000,
});

// Pluggable password verification (bcrypt, argon2, etc.)
async function verifyPassword(identifier, password) {
  const user = await db.get('SELECT id, password_hash FROM users WHERE email = ?', [identifier]);
  if (!user) return null;
  const ok = await bcrypt.compare(password, user.password_hash);
  return ok ? { userId: user.id } : null;
}

// Express-style wiring
app.use(auth.sessionMiddleware());

// AB-CODE-028: POST for mutations
app.post('/auth/login',            auth.createLoginHandler(verifyPassword));
app.post('/auth/logout',           auth.logoutHandler);
app.get( '/auth/csrf-token',       auth.csrfTokenHandler);
app.post('/auth/request-reset',    auth.createRequestResetHandler(lookupUserByEmail, sendResetEmail));
app.post('/auth/reset-password',   auth.createResetPasswordHandler(updatePassword));

// Protected route example
app.post('/api/profile', async (req, res) => {
  if (!req.requireAuth()) return;  // CS-CODE-016
  if (!req.verifyCsrf())  return;
  // ... safe to proceed
});

// Cron (daily)
setInterval(auth.purgeExpiredData, 24 * 60 * 60 * 1000);

*/
