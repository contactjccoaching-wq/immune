/**
 * Session-Based Authentication Middleware
 * Features: CSRF protection, secure cookies, session expiry/renewal,
 *           brute-force protection (lockout after 5 attempts),
 *           password reset with time-limited tokens.
 *
 * Architecture:
 *   CryptoUtils          → token generation, hashing, HMAC signing
 *   SessionStore         → in-memory session storage with TTL
 *   RateLimiter          → per-account failed attempt tracking + lockout
 *   CSRFProtection       → per-session CSRF token lifecycle
 *   PasswordResetManager → time-limited reset token lifecycle
 *   CookieUtils          → secure cookie serialization / parsing
 *   AuthMiddleware       → Express-compatible middleware (session, CSRF gate)
 *   AuthRouter           → Route handlers: login, logout, reset-request, reset-confirm
 */

"use strict";

const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CONSTANTS = Object.freeze({
  SESSION_TTL_MS: 30 * 60 * 1000,          // 30 minutes idle timeout
  SESSION_RENEWAL_THRESHOLD_MS: 5 * 60 * 1000, // Renew if < 5 min remaining
  SESSION_ABSOLUTE_TTL_MS: 8 * 60 * 60 * 1000, // 8-hour hard cap
  CSRF_TTL_MS: 30 * 60 * 1000,             // Matches session TTL
  RESET_TOKEN_TTL_MS: 60 * 60 * 1000,      // 1-hour password reset window
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION_MS: 15 * 60 * 1000,     // 15-minute lockout
  TOKEN_BYTES: 32,
  SESSION_ID_BYTES: 32,
  HMAC_ALGORITHM: "sha256",
  COOKIE_NAME: "sid",
  CSRF_HEADER: "x-csrf-token",
  CSRF_FIELD: "_csrf",
  SAFE_METHODS: new Set(["GET", "HEAD", "OPTIONS"]),
});

// ---------------------------------------------------------------------------
// CryptoUtils — pure utility functions, no state
// ---------------------------------------------------------------------------

const CryptoUtils = {
  /**
   * Generate a cryptographically random hex string.
   * @param {number} bytes - number of random bytes
   * @returns {string} hex-encoded token
   */
  generateToken(bytes = CONSTANTS.TOKEN_BYTES) {
    if (typeof bytes !== "number" || bytes < 1 || bytes > 512) {
      throw new RangeError(`bytes must be between 1 and 512, got ${bytes}`);
    }
    return crypto.randomBytes(bytes).toString("hex");
  },

  /**
   * Hash a value with SHA-256, returning hex digest.
   * @param {string} value
   * @returns {string}
   */
  sha256(value) {
    if (typeof value !== "string") throw new TypeError("value must be a string");
    return crypto.createHash("sha256").update(value).digest("hex");
  },

  /**
   * HMAC-SHA256 sign a message with a secret key.
   * @param {string} message
   * @param {string} secret
   * @returns {string} hex digest
   */
  hmacSign(message, secret) {
    if (typeof message !== "string") throw new TypeError("message must be a string");
    if (typeof secret !== "string" || secret.length === 0) {
      throw new TypeError("secret must be a non-empty string");
    }
    return crypto.createHmac(CONSTANTS.HMAC_ALGORITHM, secret).update(message).digest("hex");
  },

  /**
   * Constant-time comparison to prevent timing attacks.
   * @param {string} a
   * @param {string} b
   * @returns {boolean}
   */
  timingSafeEqual(a, b) {
    if (typeof a !== "string" || typeof b !== "string") return false;
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) {
      // Still run comparison to avoid timing leak on length
      crypto.timingSafeEqual(bufA, Buffer.alloc(bufA.length));
      return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  },

  /**
   * Hash a password using scrypt (async, returns hex string).
   * @param {string} password
   * @param {string} [salt] - hex salt; generated if omitted
   * @returns {Promise<{hash: string, salt: string}>}
   */
  async hashPassword(password, salt) {
    if (typeof password !== "string" || password.length === 0) {
      throw new TypeError("password must be a non-empty string");
    }
    const saltBuf = salt
      ? Buffer.from(salt, "hex")
      : crypto.randomBytes(16);
    return new Promise((resolve, reject) => {
      crypto.scrypt(password, saltBuf, 64, (err, derivedKey) => {
        if (err) return reject(err);
        resolve({ hash: derivedKey.toString("hex"), salt: saltBuf.toString("hex") });
      });
    });
  },

  /**
   * Verify a plaintext password against a stored hash+salt.
   * @param {string} password
   * @param {string} hash
   * @param {string} salt
   * @returns {Promise<boolean>}
   */
  async verifyPassword(password, hash, salt) {
    try {
      const { hash: derived } = await CryptoUtils.hashPassword(password, salt);
      return CryptoUtils.timingSafeEqual(derived, hash);
    } catch {
      return false;
    }
  },
};

// ---------------------------------------------------------------------------
// SessionStore — in-memory store with TTL enforcement
// ---------------------------------------------------------------------------

class SessionStore {
  /**
   * @param {object} options
   * @param {number} [options.ttlMs]
   * @param {number} [options.absoluteTtlMs]
   * @param {number} [options.cleanupIntervalMs]
   */
  constructor({
    ttlMs = CONSTANTS.SESSION_TTL_MS,
    absoluteTtlMs = CONSTANTS.SESSION_ABSOLUTE_TTL_MS,
    cleanupIntervalMs = 60_000,
  } = {}) {
    /** @type {Map<string, {data: object, expiresAt: number, createdAt: number, absoluteExpiresAt: number}>} */
    this._sessions = new Map();
    this._ttlMs = ttlMs;
    this._absoluteTtlMs = absoluteTtlMs;
    this._cleanupTimer = setInterval(() => this._evictExpired(), cleanupIntervalMs);
    // Allow the process to exit even if this timer is active
    if (this._cleanupTimer.unref) this._cleanupTimer.unref();
  }

  /**
   * Create a new session and return its ID.
   * @param {object} data - session payload (userId, etc.)
   * @returns {string} sessionId
   */
  create(data) {
    this._validateData(data);
    const sessionId = CryptoUtils.generateToken(CONSTANTS.SESSION_ID_BYTES);
    const now = Date.now();
    this._sessions.set(sessionId, {
      data: { ...data },
      expiresAt: now + this._ttlMs,
      createdAt: now,
      absoluteExpiresAt: now + this._absoluteTtlMs,
    });
    return sessionId;
  }

  /**
   * Retrieve a session by ID. Returns null if missing or expired.
   * @param {string} sessionId
   * @returns {{data: object, expiresAt: number, createdAt: number} | null}
   */
  get(sessionId) {
    if (!this._isValidId(sessionId)) return null;
    const session = this._sessions.get(sessionId);
    if (!session) return null;
    const now = Date.now();
    if (now > session.expiresAt || now > session.absoluteExpiresAt) {
      this._sessions.delete(sessionId);
      return null;
    }
    return session;
  }

  /**
   * Renew the idle TTL of an existing session.
   * @param {string} sessionId
   * @returns {boolean} true if renewed, false if session not found/expired
   */
  renew(sessionId) {
    const session = this.get(sessionId);
    if (!session) return false;
    const now = Date.now();
    const maxExtend = session.absoluteExpiresAt - now;
    session.expiresAt = now + Math.min(this._ttlMs, maxExtend);
    return true;
  }

  /**
   * Destroy a session by ID.
   * @param {string} sessionId
   */
  destroy(sessionId) {
    if (this._isValidId(sessionId)) {
      this._sessions.delete(sessionId);
    }
  }

  /**
   * Update session data fields (shallow merge).
   * @param {string} sessionId
   * @param {object} patch
   * @returns {boolean}
   */
  update(sessionId, patch) {
    const session = this.get(sessionId);
    if (!session) return false;
    this._validateData(patch);
    Object.assign(session.data, patch);
    return true;
  }

  /** Remove all expired sessions (background task). */
  _evictExpired() {
    const now = Date.now();
    for (const [id, session] of this._sessions) {
      if (now > session.expiresAt || now > session.absoluteExpiresAt) {
        this._sessions.delete(id);
      }
    }
  }

  /** Stop the background cleanup timer. */
  shutdown() {
    clearInterval(this._cleanupTimer);
  }

  _isValidId(id) {
    return typeof id === "string" && id.length > 0;
  }

  _validateData(data) {
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new TypeError("Session data must be a plain object");
    }
  }
}

// ---------------------------------------------------------------------------
// RateLimiter — per-account brute-force protection with lockout
// ---------------------------------------------------------------------------

class RateLimiter {
  /**
   * @param {object} options
   * @param {number} [options.maxAttempts]
   * @param {number} [options.lockoutDurationMs]
   * @param {number} [options.cleanupIntervalMs]
   */
  constructor({
    maxAttempts = CONSTANTS.MAX_FAILED_ATTEMPTS,
    lockoutDurationMs = CONSTANTS.LOCKOUT_DURATION_MS,
    cleanupIntervalMs = 60_000,
  } = {}) {
    /** @type {Map<string, {count: number, lockedUntil: number | null, lastAttempt: number}>} */
    this._records = new Map();
    this._maxAttempts = maxAttempts;
    this._lockoutDurationMs = lockoutDurationMs;
    this._cleanupTimer = setInterval(() => this._evictStale(), cleanupIntervalMs);
    if (this._cleanupTimer.unref) this._cleanupTimer.unref();
  }

  /**
   * Record a failed login attempt for an account key.
   * @param {string} key - typically username or userId
   * @returns {{locked: boolean, attemptsRemaining: number, lockedUntil: number | null}}
   */
  recordFailure(key) {
    this._validateKey(key);
    const now = Date.now();
    const record = this._getOrCreate(key, now);

    // If currently locked, just update timestamp and return
    if (record.lockedUntil && now < record.lockedUntil) {
      record.lastAttempt = now;
      return { locked: true, attemptsRemaining: 0, lockedUntil: record.lockedUntil };
    }

    // Reset count if lockout has expired
    if (record.lockedUntil && now >= record.lockedUntil) {
      record.count = 0;
      record.lockedUntil = null;
    }

    record.count += 1;
    record.lastAttempt = now;

    if (record.count >= this._maxAttempts) {
      record.lockedUntil = now + this._lockoutDurationMs;
      return { locked: true, attemptsRemaining: 0, lockedUntil: record.lockedUntil };
    }

    return {
      locked: false,
      attemptsRemaining: this._maxAttempts - record.count,
      lockedUntil: null,
    };
  }

  /**
   * Check whether an account key is currently locked out.
   * @param {string} key
   * @returns {{locked: boolean, lockedUntil: number | null, attemptsRemaining: number}}
   */
  checkLockout(key) {
    this._validateKey(key);
    const record = this._records.get(key);
    if (!record) {
      return { locked: false, lockedUntil: null, attemptsRemaining: this._maxAttempts };
    }
    const now = Date.now();
    if (record.lockedUntil && now < record.lockedUntil) {
      return { locked: true, lockedUntil: record.lockedUntil, attemptsRemaining: 0 };
    }
    const remaining = Math.max(0, this._maxAttempts - record.count);
    return { locked: false, lockedUntil: null, attemptsRemaining: remaining };
  }

  /**
   * Reset the failure record for an account key (called on successful login).
   * @param {string} key
   */
  reset(key) {
    this._validateKey(key);
    this._records.delete(key);
  }

  _getOrCreate(key, now) {
    if (!this._records.has(key)) {
      this._records.set(key, { count: 0, lockedUntil: null, lastAttempt: now });
    }
    return this._records.get(key);
  }

  _evictStale() {
    const cutoff = Date.now() - this._lockoutDurationMs * 2;
    for (const [key, record] of this._records) {
      if (record.lastAttempt < cutoff && !record.lockedUntil) {
        this._records.delete(key);
      }
    }
  }

  _validateKey(key) {
    if (typeof key !== "string" || key.trim().length === 0) {
      throw new TypeError("Rate limiter key must be a non-empty string");
    }
  }

  shutdown() {
    clearInterval(this._cleanupTimer);
  }
}

// ---------------------------------------------------------------------------
// CSRFProtection — per-session CSRF token with HMAC binding
// ---------------------------------------------------------------------------

class CSRFProtection {
  /**
   * @param {string} secret - server-side signing secret
   * @param {number} [ttlMs]
   */
  constructor(secret, ttlMs = CONSTANTS.CSRF_TTL_MS) {
    if (typeof secret !== "string" || secret.length < 16) {
      throw new TypeError("CSRF secret must be a string of at least 16 characters");
    }
    this._secret = secret;
    this._ttlMs = ttlMs;
  }

  /**
   * Generate a CSRF token bound to a session ID.
   * Format: <randomHex>.<expiresAt>.<hmac>
   * @param {string} sessionId
   * @returns {string}
   */
  generateToken(sessionId) {
    this._validateSessionId(sessionId);
    const random = CryptoUtils.generateToken(16);
    const expiresAt = Date.now() + this._ttlMs;
    const payload = `${random}.${expiresAt}.${sessionId}`;
    const mac = CryptoUtils.hmacSign(payload, this._secret);
    return `${random}.${expiresAt}.${mac}`;
  }

  /**
   * Validate a CSRF token against the session ID.
   * @param {string} token
   * @param {string} sessionId
   * @returns {boolean}
   */
  validateToken(token, sessionId) {
    if (!token || !sessionId) return false;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return false;
      const [random, expiresAtStr, mac] = parts;
      const expiresAt = parseInt(expiresAtStr, 10);
      if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return false;
      const payload = `${random}.${expiresAt}.${sessionId}`;
      const expectedMac = CryptoUtils.hmacSign(payload, this._secret);
      return CryptoUtils.timingSafeEqual(mac, expectedMac);
    } catch {
      return false;
    }
  }

  /**
   * Extract CSRF token from request (header takes precedence over body field).
   * @param {object} req - Express-like request object
   * @returns {string | null}
   */
  extractFromRequest(req) {
    if (!req) return null;
    return (
      req.headers?.[CONSTANTS.CSRF_HEADER] ||
      req.body?.[CONSTANTS.CSRF_FIELD] ||
      null
    );
  }

  _validateSessionId(sessionId) {
    if (typeof sessionId !== "string" || sessionId.length === 0) {
      throw new TypeError("sessionId must be a non-empty string");
    }
  }
}

// ---------------------------------------------------------------------------
// PasswordResetManager — time-limited, single-use reset tokens
// ---------------------------------------------------------------------------

class PasswordResetManager {
  /**
   * @param {string} secret - HMAC signing secret
   * @param {number} [ttlMs]
   */
  constructor(secret, ttlMs = CONSTANTS.RESET_TOKEN_TTL_MS) {
    if (typeof secret !== "string" || secret.length < 16) {
      throw new TypeError("Reset token secret must be at least 16 characters");
    }
    this._secret = secret;
    this._ttlMs = ttlMs;
    /** @type {Set<string>} consumed tokens (single-use enforcement) */
    this._used = new Set();
    /** @type {Map<string, number>} token -> expiresAt for cleanup */
    this._tokenExpiry = new Map();
    this._cleanupTimer = setInterval(() => this._evictExpired(), 5 * 60_000);
    if (this._cleanupTimer.unref) this._cleanupTimer.unref();
  }

  /**
   * Generate a signed, time-limited reset token for a user.
   * @param {string} userId
   * @param {string} currentPasswordHash - binds token to current password state
   * @returns {{token: string, expiresAt: number}}
   */
  generateToken(userId, currentPasswordHash) {
    this._validateUserId(userId);
    if (typeof currentPasswordHash !== "string" || currentPasswordHash.length === 0) {
      throw new TypeError("currentPasswordHash must be a non-empty string");
    }
    const random = CryptoUtils.generateToken(CONSTANTS.TOKEN_BYTES);
    const expiresAt = Date.now() + this._ttlMs;
    const payload = `${userId}.${expiresAt}.${random}.${currentPasswordHash}`;
    const mac = CryptoUtils.hmacSign(payload, this._secret);
    const token = `${random}.${expiresAt}.${userId}.${mac}`;
    this._tokenExpiry.set(token, expiresAt);
    return { token, expiresAt };
  }

  /**
   * Validate a reset token.
   * @param {string} token
   * @param {string} userId - must match token's embedded userId
   * @param {string} currentPasswordHash - must match hash used at generation
   * @returns {{valid: boolean, reason?: string}}
   */
  validateToken(token, userId, currentPasswordHash) {
    if (!token || !userId || !currentPasswordHash) {
      return { valid: false, reason: "Missing required arguments" };
    }
    if (this._used.has(token)) {
      return { valid: false, reason: "Token already used" };
    }
    try {
      const parts = token.split(".");
      if (parts.length !== 4) return { valid: false, reason: "Malformed token" };
      const [random, expiresAtStr, embeddedUserId, mac] = parts;
      if (!CryptoUtils.timingSafeEqual(embeddedUserId, userId)) {
        return { valid: false, reason: "User ID mismatch" };
      }
      const expiresAt = parseInt(expiresAtStr, 10);
      if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) {
        return { valid: false, reason: "Token expired" };
      }
      const payload = `${userId}.${expiresAt}.${random}.${currentPasswordHash}`;
      const expectedMac = CryptoUtils.hmacSign(payload, this._secret);
      if (!CryptoUtils.timingSafeEqual(mac, expectedMac)) {
        return { valid: false, reason: "Invalid signature" };
      }
      return { valid: true };
    } catch {
      return { valid: false, reason: "Validation error" };
    }
  }

  /**
   * Mark a token as consumed (single-use enforcement).
   * Call this immediately after a successful password reset.
   * @param {string} token
   */
  consumeToken(token) {
    if (typeof token === "string") {
      this._used.add(token);
    }
  }

  _evictExpired() {
    const now = Date.now();
    for (const [token, expiresAt] of this._tokenExpiry) {
      if (now > expiresAt) {
        this._used.delete(token);
        this._tokenExpiry.delete(token);
      }
    }
  }

  _validateUserId(userId) {
    if (typeof userId !== "string" || userId.trim().length === 0) {
      throw new TypeError("userId must be a non-empty string");
    }
  }

  shutdown() {
    clearInterval(this._cleanupTimer);
  }
}

// ---------------------------------------------------------------------------
// CookieUtils — secure cookie serialization and parsing
// ---------------------------------------------------------------------------

const CookieUtils = {
  /**
   * Serialize a cookie with secure attributes.
   * @param {string} name
   * @param {string} value
   * @param {object} options
   * @param {boolean} [options.secure]
   * @param {string} [options.sameSite]
   * @param {number} [options.maxAgeMs]
   * @param {string} [options.path]
   * @param {string} [options.domain]
   * @returns {string} Set-Cookie header value
   */
  serialize(name, value, options = {}) {
    if (!name || typeof name !== "string") throw new TypeError("Cookie name must be a string");
    if (typeof value !== "string") throw new TypeError("Cookie value must be a string");
    const {
      secure = true,
      sameSite = "Strict",
      maxAgeMs,
      path = "/",
      domain,
    } = options;
    const parts = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];
    parts.push("HttpOnly");
    if (secure) parts.push("Secure");
    parts.push(`SameSite=${sameSite}`);
    parts.push(`Path=${path}`);
    if (typeof maxAgeMs === "number" && maxAgeMs > 0) {
      parts.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
    }
    if (domain) parts.push(`Domain=${domain}`);
    return parts.join("; ");
  },

  /**
   * Parse the Cookie header string into a key-value map.
   * @param {string} cookieHeader
   * @returns {Record<string, string>}
   */
  parse(cookieHeader) {
    if (typeof cookieHeader !== "string") return {};
    return cookieHeader.split(";").reduce((acc, pair) => {
      const idx = pair.indexOf("=");
      if (idx === -1) return acc;
      const key = decodeURIComponent(pair.slice(0, idx).trim());
      const val = decodeURIComponent(pair.slice(idx + 1).trim());
      if (key) acc[key] = val;
      return acc;
    }, {});
  },

  /**
   * Build a Set-Cookie header that clears the named cookie.
   * @param {string} name
   * @param {string} [path]
   * @returns {string}
   */
  clear(name, path = "/") {
    return `${encodeURIComponent(name)}=; Max-Age=0; Path=${path}; HttpOnly; Secure; SameSite=Strict`;
  },
};

// ---------------------------------------------------------------------------
// AuthMiddleware — Express-compatible middleware factory
// ---------------------------------------------------------------------------

/**
 * Create the session + CSRF middleware.
 *
 * @param {object} config
 * @param {string} config.csrfSecret
 * @param {SessionStore} config.sessionStore
 * @param {CSRFProtection} config.csrfProtection
 * @param {boolean} [config.secureCookie]
 * @param {string} [config.sameSite]
 * @returns {function(req, res, next): void} Express middleware
 */
function createAuthMiddleware(config) {
  const {
    csrfSecret,
    sessionStore,
    csrfProtection,
    secureCookie = true,
    sameSite = "Strict",
  } = config;

  if (!sessionStore || !csrfProtection) {
    throw new TypeError("sessionStore and csrfProtection are required");
  }

  return function authMiddleware(req, res, next) {
    // 1. Parse cookies and extract session ID
    const cookies = CookieUtils.parse(req.headers?.cookie || "");
    const sessionId = cookies[CONSTANTS.COOKIE_NAME] || null;

    // 2. Attach session to request (or null if invalid/expired)
    req.session = null;
    req.sessionId = null;

    if (sessionId) {
      const session = sessionStore.get(sessionId);
      if (session) {
        req.session = session;
        req.sessionId = sessionId;

        // 3. Renew session if close to expiry (sliding window)
        const remaining = session.expiresAt - Date.now();
        if (remaining < CONSTANTS.SESSION_RENEWAL_THRESHOLD_MS) {
          sessionStore.renew(sessionId);
          res.setHeader(
            "Set-Cookie",
            CookieUtils.serialize(CONSTANTS.COOKIE_NAME, sessionId, {
              secure: secureCookie,
              sameSite,
              maxAgeMs: CONSTANTS.SESSION_TTL_MS,
            })
          );
        }
      } else {
        // Session expired or invalid — clear stale cookie
        res.setHeader("Set-Cookie", CookieUtils.clear(CONSTANTS.COOKIE_NAME));
      }
    }

    // 4. CSRF gate for state-changing requests
    if (!CONSTANTS.SAFE_METHODS.has(req.method)) {
      const csrfToken = csrfProtection.extractFromRequest(req);
      const currentSessionId = req.sessionId;

      if (!currentSessionId || !csrfToken || !csrfProtection.validateToken(csrfToken, currentSessionId)) {
        return res.status(403).json({
          error: "CSRF validation failed",
          code: "CSRF_INVALID",
        });
      }
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// AuthRouter — route handler factory
// ---------------------------------------------------------------------------

/**
 * Create login/logout/reset route handlers.
 *
 * @param {object} deps
 * @param {SessionStore} deps.sessionStore
 * @param {RateLimiter} deps.rateLimiter
 * @param {CSRFProtection} deps.csrfProtection
 * @param {PasswordResetManager} deps.passwordResetManager
 * @param {function(string): Promise<{id: string, passwordHash: string, passwordSalt: string} | null>} deps.findUserByUsername
 * @param {function(string, string): Promise<void>} deps.updateUserPassword - (userId, newHash+salt encoded)
 * @param {function(string): Promise<{id: string, passwordHash: string, passwordSalt: string, email: string} | null>} deps.findUserById
 * @param {function(string, {token: string, expiresAt: number}): Promise<void>} deps.sendResetEmail - integration point
 * @param {boolean} [deps.secureCookie]
 * @param {string} [deps.sameSite]
 * @returns {object} { login, logout, getCsrfToken, requestPasswordReset, confirmPasswordReset }
 */
function createAuthRouter(deps) {
  const {
    sessionStore,
    rateLimiter,
    csrfProtection,
    passwordResetManager,
    findUserByUsername,
    updateUserPassword,
    findUserById,
    sendResetEmail,
    secureCookie = true,
    sameSite = "Strict",
  } = deps;

  const required = ["sessionStore", "rateLimiter", "csrfProtection", "passwordResetManager",
    "findUserByUsername", "updateUserPassword", "findUserById", "sendResetEmail"];
  for (const key of required) {
    if (!deps[key]) throw new TypeError(`Missing required dependency: ${key}`);
  }

  // --- Helpers ---

  function setSessionCookie(res, sessionId) {
    res.setHeader(
      "Set-Cookie",
      CookieUtils.serialize(CONSTANTS.COOKIE_NAME, sessionId, {
        secure: secureCookie,
        sameSite,
        maxAgeMs: CONSTANTS.SESSION_TTL_MS,
      })
    );
  }

  function clearSessionCookie(res) {
    res.setHeader("Set-Cookie", CookieUtils.clear(CONSTANTS.COOKIE_NAME));
  }

  function validateUsernamePassword(username, password) {
    if (typeof username !== "string" || username.trim().length === 0) {
      return "Username must be a non-empty string";
    }
    if (username.length > 128) return "Username too long";
    if (typeof password !== "string" || password.length === 0) {
      return "Password must be a non-empty string";
    }
    if (password.length > 1024) return "Password too long";
    return null;
  }

  // --- Handlers ---

  /**
   * POST /auth/login
   * Body: { username: string, password: string }
   */
  async function login(req, res) {
    const { username, password } = req.body || {};

    const validationError = validateUsernamePassword(username, password);
    if (validationError) {
      return res.status(400).json({ error: validationError, code: "INVALID_INPUT" });
    }

    const normalizedUsername = username.trim().toLowerCase();

    // Check lockout before any DB access
    const lockoutStatus = rateLimiter.checkLockout(normalizedUsername);
    if (lockoutStatus.locked) {
      const retryAfterSec = Math.ceil((lockoutStatus.lockedUntil - Date.now()) / 1000);
      return res.status(429).json({
        error: "Account temporarily locked due to too many failed attempts",
        code: "ACCOUNT_LOCKED",
        retryAfterSeconds: retryAfterSec,
      });
    }

    let user;
    try {
      user = await findUserByUsername(normalizedUsername);
    } catch (err) {
      console.error("[AuthRouter.login] findUserByUsername error:", err);
      return res.status(500).json({ error: "Internal server error", code: "DB_ERROR" });
    }

    // Always run password verification to prevent user enumeration via timing
    const dummyHash = "0".repeat(128);
    const dummySalt = "0".repeat(32);
    const passwordValid = user
      ? await CryptoUtils.verifyPassword(password, user.passwordHash, user.passwordSalt)
      : await CryptoUtils.verifyPassword(password, dummyHash, dummySalt).then(() => false);

    if (!user || !passwordValid) {
      const result = rateLimiter.recordFailure(normalizedUsername);
      const response = {
        error: "Invalid username or password",
        code: "INVALID_CREDENTIALS",
      };
      if (result.locked) {
        response.code = "ACCOUNT_LOCKED";
        response.retryAfterSeconds = Math.ceil(CONSTANTS.LOCKOUT_DURATION_MS / 1000);
      } else {
        response.attemptsRemaining = result.attemptsRemaining;
      }
      return res.status(401).json(response);
    }

    // Success — reset failed attempts, create session
    rateLimiter.reset(normalizedUsername);

    // Destroy any existing session for this request (prevent session fixation)
    if (req.sessionId) {
      sessionStore.destroy(req.sessionId);
    }

    const sessionId = sessionStore.create({
      userId: user.id,
      username: normalizedUsername,
      loginAt: Date.now(),
    });

    // Generate CSRF token bound to new session
    const csrfToken = csrfProtection.generateToken(sessionId);

    setSessionCookie(res, sessionId);
    return res.status(200).json({
      message: "Login successful",
      csrfToken,
      user: { id: user.id, username: normalizedUsername },
    });
  }

  /**
   * POST /auth/logout
   * Requires active session (enforced by authMiddleware).
   */
  async function logout(req, res) {
    if (req.sessionId) {
      sessionStore.destroy(req.sessionId);
    }
    clearSessionCookie(res);
    return res.status(200).json({ message: "Logged out successfully" });
  }

  /**
   * GET /auth/csrf-token
   * Returns a fresh CSRF token for the current session.
   */
  function getCsrfToken(req, res) {
    if (!req.sessionId) {
      return res.status(401).json({ error: "No active session", code: "UNAUTHENTICATED" });
    }
    const csrfToken = csrfProtection.generateToken(req.sessionId);
    return res.status(200).json({ csrfToken });
  }

  /**
   * POST /auth/password-reset/request
   * Body: { userId: string }
   * Initiates password reset by generating and sending a time-limited token.
   */
  async function requestPasswordReset(req, res) {
    const { userId } = req.body || {};

    if (typeof userId !== "string" || userId.trim().length === 0) {
      // Return generic response to avoid user enumeration
      return res.status(200).json({ message: "If this account exists, a reset email has been sent" });
    }

    let user;
    try {
      user = await findUserById(userId.trim());
    } catch (err) {
      console.error("[AuthRouter.requestPasswordReset] findUserById error:", err);
      // Still return generic response
      return res.status(200).json({ message: "If this account exists, a reset email has been sent" });
    }

    if (user) {
      const { token, expiresAt } = passwordResetManager.generateToken(
        user.id,
        user.passwordHash
      );
      try {
        await sendResetEmail(user.email, { token, expiresAt });
      } catch (err) {
        console.error("[AuthRouter.requestPasswordReset] sendResetEmail error:", err);
        // Log but don't expose to caller
      }
    }

    return res.status(200).json({ message: "If this account exists, a reset email has been sent" });
  }

  /**
   * POST /auth/password-reset/confirm
   * Body: { userId: string, token: string, newPassword: string }
   * Validates the token and updates the password.
   */
  async function confirmPasswordReset(req, res) {
    const { userId, token, newPassword } = req.body || {};

    if (
      typeof userId !== "string" || userId.trim().length === 0 ||
      typeof token !== "string" || token.length === 0 ||
      typeof newPassword !== "string" || newPassword.length === 0
    ) {
      return res.status(400).json({ error: "Missing required fields", code: "INVALID_INPUT" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters", code: "WEAK_PASSWORD" });
    }
    if (newPassword.length > 1024) {
      return res.status(400).json({ error: "Password too long", code: "INVALID_INPUT" });
    }

    let user;
    try {
      user = await findUserById(userId.trim());
    } catch (err) {
      console.error("[AuthRouter.confirmPasswordReset] findUserById error:", err);
      return res.status(500).json({ error: "Internal server error", code: "DB_ERROR" });
    }

    if (!user) {
      return res.status(400).json({ error: "Invalid or expired reset token", code: "INVALID_TOKEN" });
    }

    const validation = passwordResetManager.validateToken(token, user.id, user.passwordHash);
    if (!validation.valid) {
      return res.status(400).json({
        error: "Invalid or expired reset token",
        code: "INVALID_TOKEN",
        reason: validation.reason,
      });
    }

    // Hash new password
    let newHash, newSalt;
    try {
      const result = await CryptoUtils.hashPassword(newPassword);
      newHash = result.hash;
      newSalt = result.salt;
    } catch (err) {
      console.error("[AuthRouter.confirmPasswordReset] hashPassword error:", err);
      return res.status(500).json({ error: "Internal server error", code: "HASH_ERROR" });
    }

    try {
      await updateUserPassword(user.id, { hash: newHash, salt: newSalt });
    } catch (err) {
      console.error("[AuthRouter.confirmPasswordReset] updateUserPassword error:", err);
      return res.status(500).json({ error: "Internal server error", code: "DB_ERROR" });
    }

    // Consume token so it cannot be reused
    passwordResetManager.consumeToken(token);

    return res.status(200).json({ message: "Password reset successfully" });
  }

  return { login, logout, getCsrfToken, requestPasswordReset, confirmPasswordReset };
}

// ---------------------------------------------------------------------------
// Factory — assemble the full auth system from config
// ---------------------------------------------------------------------------

/**
 * Bootstrap all auth subsystems and return ready-to-use middleware + handlers.
 *
 * @param {object} config
 * @param {string} config.csrfSecret               - minimum 32 chars
 * @param {string} config.resetTokenSecret          - minimum 32 chars
 * @param {function} config.findUserByUsername
 * @param {function} config.findUserById
 * @param {function} config.updateUserPassword
 * @param {function} config.sendResetEmail
 * @param {boolean} [config.secureCookie]
 * @param {string} [config.sameSite]
 * @returns {{ middleware: function, handlers: object, shutdown: function }}
 */
function createAuthSystem(config) {
  const {
    csrfSecret,
    resetTokenSecret,
    findUserByUsername,
    findUserById,
    updateUserPassword,
    sendResetEmail,
    secureCookie = true,
    sameSite = "Strict",
  } = config;

  if (typeof csrfSecret !== "string" || csrfSecret.length < 32) {
    throw new TypeError("csrfSecret must be at least 32 characters");
  }
  if (typeof resetTokenSecret !== "string" || resetTokenSecret.length < 32) {
    throw new TypeError("resetTokenSecret must be at least 32 characters");
  }

  const sessionStore = new SessionStore();
  const rateLimiter = new RateLimiter();
  const csrfProtection = new CSRFProtection(csrfSecret);
  const passwordResetManager = new PasswordResetManager(resetTokenSecret);

  const middleware = createAuthMiddleware({
    csrfSecret,
    sessionStore,
    csrfProtection,
    secureCookie,
    sameSite,
  });

  const handlers = createAuthRouter({
    sessionStore,
    rateLimiter,
    csrfProtection,
    passwordResetManager,
    findUserByUsername,
    findUserById,
    updateUserPassword,
    sendResetEmail,
    secureCookie,
    sameSite,
  });

  function shutdown() {
    sessionStore.shutdown();
    rateLimiter.shutdown();
    passwordResetManager.shutdown();
  }

  return { middleware, handlers, sessionStore, csrfProtection, shutdown };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  // Core classes (for testing / custom composition)
  CryptoUtils,
  SessionStore,
  RateLimiter,
  CSRFProtection,
  PasswordResetManager,
  CookieUtils,

  // Middleware / router factories
  createAuthMiddleware,
  createAuthRouter,

  // Top-level factory (recommended entry point)
  createAuthSystem,

  // Constants (for consumers that need TTL values, etc.)
  CONSTANTS,
};

// ---------------------------------------------------------------------------
// Usage Example (commented out — not executed)
// ---------------------------------------------------------------------------
/*
const express = require("express");
const app = express();
app.use(express.json());

const auth = createAuthSystem({
  csrfSecret: process.env.CSRF_SECRET,         // min 32 chars from env
  resetTokenSecret: process.env.RESET_SECRET,  // min 32 chars from env
  secureCookie: process.env.NODE_ENV === "production",

  async findUserByUsername(username) {
    // return { id, passwordHash, passwordSalt } or null
  },
  async findUserById(userId) {
    // return { id, passwordHash, passwordSalt, email } or null
  },
  async updateUserPassword(userId, { hash, salt }) {
    // persist new hash + salt
  },
  async sendResetEmail(email, { token, expiresAt }) {
    // send email with reset link containing token
  },
});

// Apply session + CSRF middleware globally
app.use(auth.middleware);

// Auth routes
app.post("/auth/login",                   auth.handlers.login);
app.post("/auth/logout",                  auth.handlers.logout);
app.get("/auth/csrf-token",               auth.handlers.getCsrfToken);
app.post("/auth/password-reset/request",  auth.handlers.requestPasswordReset);
app.post("/auth/password-reset/confirm",  auth.handlers.confirmPasswordReset);

// Graceful shutdown
process.on("SIGTERM", () => { auth.shutdown(); process.exit(0); });
*/
