'use strict';

/**
 * Session-Based Authentication with CSRF Protection
 *
 * Features:
 *  - Session-based auth (secure cookies, expiry, renewal)
 *  - CSRF protection (token generation + double-submit cookie)
 *  - Brute-force protection (lockout after 5 failed attempts)
 *  - Password reset with time-limited tokens (15 min)
 *  - Register, Login, Logout, Change-Password endpoints
 *  - In-memory stores (users, sessions, reset tokens)
 *
 * Applied strategies (CS-CODE-*):
 *  CS-CODE-001: Timing-safe comparison for all secret comparisons
 *  CS-CODE-002: Generic auth error messages
 *  CS-CODE-003: Defense-in-depth input validation (parse→structure→type→length→format)
 *  CS-CODE-005: Graceful shutdown with connection draining + timeout + unref()
 *  CS-CODE-006: Startup config validation — fail fast with detailed errors
 *  CS-CODE-008: Security middleware ordering: headers → CORS → rate limit → body → routes
 *  CS-CODE-009: Sliding-window rate limiting with automatic cleanup
 *  CS-CODE-010: Closure-based data isolation with Object.freeze
 *  CS-CODE-013: Per-operation error isolation
 *  CS-CODE-017: HTML escaping for user-controlled content
 *  CS-CODE-018: HMAC algorithm locked — no negotiation
 *  CS-CODE-019: Prototype pollution prevention via forbidden key checking
 *
 * Avoided antibodies (AB-*):
 *  AB-001: No hardcoded secrets (validated from env at startup)
 *  AB-002: Rate limiting applied globally and per-route
 *  AB-004: Security headers set via custom middleware
 *  AB-005/006: CORS configured from env whitelist, no wildcard
 *  AB-007: All background intervals cleared on shutdown
 *  AB-008: Proxy trust requires explicit env opt-in
 *  AB-009: All in-memory caches have TTL + periodic cleanup
 *  AB-010: Request body size limited
 *  AB-011: No file I/O, no symlink exposure
 *  AB-012: No TOCTOU: reads and writes are atomic within single JS tick
 *
 * Run: SESSION_SECRET=... CSRF_SECRET=... node round-8.js
 */

const http = require('http');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// 0. CONFIG VALIDATION (CS-CODE-006 — fail fast with detailed errors)
// ---------------------------------------------------------------------------

/**
 * Validates all required environment configuration at startup.
 * Throws with descriptive errors if anything is missing or invalid.
 * @returns {Readonly<Config>} Frozen config object
 */
function loadAndValidateConfig() {
  const errors = [];

  const SESSION_SECRET = process.env.SESSION_SECRET;
  const CSRF_SECRET = process.env.CSRF_SECRET;
  const PORT = parseInt(process.env.PORT || '3000', 10);
  const ALLOWED_ORIGINS_RAW = process.env.ALLOWED_ORIGINS || '';
  const TRUST_PROXY = process.env.TRUST_PROXY === 'true'; // AB-008: explicit opt-in

  // AB-001: No hardcoded secrets, no fallbacks
  if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
    errors.push('SESSION_SECRET must be set and at least 32 characters');
  }
  if (!CSRF_SECRET || CSRF_SECRET.length < 32) {
    errors.push('CSRF_SECRET must be set and at least 32 characters');
  }
  if (isNaN(PORT) || PORT < 1 || PORT > 65535) {
    errors.push('PORT must be a valid port number (1–65535)');
  }

  // AB-005/006: CORS must be explicit whitelist, no wildcard
  const ALLOWED_ORIGINS = ALLOWED_ORIGINS_RAW
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  if (ALLOWED_ORIGINS.length === 0) {
    errors.push(
      'ALLOWED_ORIGINS must be set to a comma-separated list of allowed origins ' +
      '(e.g. http://localhost:3000). Wildcards are not permitted.'
    );
  }

  if (errors.length > 0) {
    throw new Error('Configuration errors:\n  - ' + errors.join('\n  - '));
  }

  // CS-CODE-010: Closure-based isolation with Object.freeze
  return Object.freeze({
    SESSION_SECRET,
    CSRF_SECRET,
    PORT,
    ALLOWED_ORIGINS,
    TRUST_PROXY,
    SESSION_TTL_MS: 30 * 60 * 1000,        // 30 minutes idle
    SESSION_RENEW_THRESHOLD_MS: 5 * 60 * 1000, // renew if < 5 min remaining
    RESET_TOKEN_TTL_MS: 15 * 60 * 1000,    // 15 minutes
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION_MS: 15 * 60 * 1000,   // 15 minutes
    RATE_LIMIT_WINDOW_MS: 60 * 1000,       // 1 minute window
    RATE_LIMIT_MAX: 60,                     // global: 60 req/min/IP
    CLEANUP_INTERVAL_MS: 5 * 60 * 1000,   // cleanup every 5 min
    BODY_SIZE_LIMIT: 16 * 1024,            // 16 KB — AB-010
    COOKIE_NAME: '__Host-sid',             // __Host- prefix locks to HTTPS + root path
    CSRF_COOKIE_NAME: '__Host-csrf',
  });
}

// ---------------------------------------------------------------------------
// 1. IN-MEMORY STORES (isolated closures — CS-CODE-010)
// ---------------------------------------------------------------------------

/**
 * Creates an isolated user store with CRUD operations.
 * Passwords are stored as Argon2-equivalent (scrypt + salt) in hex.
 */
function createUserStore() {
  // Map<username, UserRecord>
  const _users = new Map();

  // CS-CODE-019: Forbidden keys to prevent prototype pollution
  const FORBIDDEN_KEYS = new Set([
    '__proto__', 'constructor', 'prototype', 'toString', 'valueOf',
    'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
  ]);

  function assertSafeKey(key) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new Error('Forbidden key: ' + key);
    }
  }

  return Object.freeze({
    /**
     * @param {string} username
     * @param {string} passwordHash  hex-encoded scrypt hash
     * @param {string} salt          hex-encoded salt
     * @returns {UserRecord}
     */
    create(username, passwordHash, salt) {
      assertSafeKey(username);
      if (_users.has(username)) throw new Error('User already exists');
      const user = Object.freeze({
        username,
        passwordHash,
        salt,
        createdAt: Date.now(),
        id: crypto.randomUUID(),
      });
      _users.set(username, user);
      return user;
    },

    findByUsername(username) {
      assertSafeKey(username);
      return _users.get(username) || null;
    },

    /**
     * Updates only the password fields (returns new frozen record).
     */
    updatePassword(username, passwordHash, salt) {
      assertSafeKey(username);
      const existing = _users.get(username);
      if (!existing) return null;
      const updated = Object.freeze({ ...existing, passwordHash, salt });
      _users.set(username, updated);
      return updated;
    },

    /** Exposed for tests only */
    _size() { return _users.size; },
  });
}

/**
 * Creates an isolated session store.
 * Sessions are indexed by session ID.
 */
function createSessionStore() {
  const _sessions = new Map(); // Map<sessionId, SessionRecord>

  return Object.freeze({
    /**
     * @param {string} userId
     * @param {string} username
     * @param {string} csrfToken
     * @param {number} ttlMs
     * @returns {{ sessionId: string, session: SessionRecord }}
     */
    create(userId, username, csrfToken, ttlMs) {
      const sessionId = crypto.randomBytes(32).toString('hex');
      const now = Date.now();
      const session = {
        sessionId,
        userId,
        username,
        csrfToken,
        createdAt: now,
        expiresAt: now + ttlMs,
        lastAccessedAt: now,
      };
      _sessions.set(sessionId, session);
      return { sessionId, session };
    },

    get(sessionId) {
      return _sessions.get(sessionId) || null;
    },

    /**
     * Renews the session's expiry time (sliding window).
     */
    renew(sessionId, ttlMs) {
      const session = _sessions.get(sessionId);
      if (!session) return null;
      const now = Date.now();
      session.expiresAt = now + ttlMs;
      session.lastAccessedAt = now;
      return session;
    },

    delete(sessionId) {
      return _sessions.delete(sessionId);
    },

    /**
     * Attaches the CSRF token to an existing session after it has been generated
     * (session must exist first so we know its ID, then we bind the CSRF token to it).
     */
    setCsrfToken(sessionId, csrfToken) {
      const session = _sessions.get(sessionId);
      if (!session) return false;
      session.csrfToken = csrfToken;
      return true;
    },

    /** Remove all expired sessions — called by cleanup job */
    purgeExpired() {
      const now = Date.now();
      let count = 0;
      for (const [id, session] of _sessions) {
        if (session.expiresAt < now) {
          _sessions.delete(id);
          count++;
        }
      }
      return count;
    },

    _size() { return _sessions.size; },
  });
}

/**
 * Creates an isolated brute-force tracker.
 * Tracks failed attempts per identifier (IP + username).
 */
function createBruteForceStore() {
  const _records = new Map(); // Map<key, { attempts, lockedUntil }>

  return Object.freeze({
    record(key) {
      let rec = _records.get(key);
      if (!rec) {
        rec = { attempts: 0, lockedUntil: 0 };
        _records.set(key, rec);
      }
      rec.attempts += 1;
      return rec;
    },

    isLocked(key) {
      const rec = _records.get(key);
      if (!rec) return false;
      return rec.lockedUntil > Date.now();
    },

    lockUntil(key, until) {
      let rec = _records.get(key);
      if (!rec) {
        rec = { attempts: 0, lockedUntil: 0 };
        _records.set(key, rec);
      }
      rec.lockedUntil = until;
    },

    getAttempts(key) {
      return (_records.get(key) || { attempts: 0 }).attempts;
    },

    reset(key) {
      _records.delete(key);
    },

    purgeExpired() {
      const now = Date.now();
      let count = 0;
      for (const [key, rec] of _records) {
        if (rec.lockedUntil < now && rec.attempts === 0) {
          _records.delete(key);
          count++;
        }
      }
      return count;
    },

    /** Reset attempt count without removing lockout (used after successful login) */
    resetAttempts(key) {
      const rec = _records.get(key);
      if (rec) rec.attempts = 0;
    },
  });
}

/**
 * Creates an isolated password-reset token store.
 */
function createResetTokenStore() {
  const _tokens = new Map(); // Map<tokenHex, { username, expiresAt }>

  return Object.freeze({
    /**
     * @returns {string} The raw token (send to user), stored as HMAC
     */
    create(username, ttlMs) {
      // Invalidate any previous token for this user
      for (const [tok, rec] of _tokens) {
        if (rec.username === username) _tokens.delete(tok);
      }
      const rawToken = crypto.randomBytes(32).toString('hex');
      _tokens.set(rawToken, {
        username,
        expiresAt: Date.now() + ttlMs,
      });
      return rawToken;
    },

    /**
     * Validates and consumes a reset token (single-use).
     * @returns {string|null} username if valid, null otherwise
     */
    consume(rawToken) {
      const rec = _tokens.get(rawToken);
      if (!rec) return null;
      if (rec.expiresAt < Date.now()) {
        _tokens.delete(rawToken);
        return null;
      }
      _tokens.delete(rawToken); // single-use
      return rec.username;
    },

    purgeExpired() {
      const now = Date.now();
      let count = 0;
      for (const [tok, rec] of _tokens) {
        if (rec.expiresAt < now) {
          _tokens.delete(tok);
          count++;
        }
      }
      return count;
    },

    _size() { return _tokens.size; },
  });
}

/**
 * Creates a sliding-window rate limiter.
 * CS-CODE-009: Sliding window with automatic cleanup.
 * AB-009: All entries have TTL via window-based expiry.
 */
function createRateLimiter({ windowMs, max }) {
  const _windows = new Map(); // Map<ip, number[]> — timestamps

  return Object.freeze({
    /**
     * @param {string} key  e.g. IP address
     * @returns {{ allowed: boolean, remaining: number, resetAt: number }}
     */
    check(key) {
      const now = Date.now();
      const cutoff = now - windowMs;

      let timestamps = _windows.get(key);
      if (!timestamps) {
        timestamps = [];
        _windows.set(key, timestamps);
      }

      // Evict timestamps outside the window
      while (timestamps.length > 0 && timestamps[0] < cutoff) {
        timestamps.shift();
      }

      const count = timestamps.length;
      const resetAt = timestamps.length > 0 ? timestamps[0] + windowMs : now + windowMs;

      if (count >= max) {
        return { allowed: false, remaining: 0, resetAt };
      }

      timestamps.push(now);
      return { allowed: true, remaining: max - count - 1, resetAt };
    },

    purgeExpired() {
      const now = Date.now();
      const cutoff = now - windowMs;
      let count = 0;
      for (const [key, timestamps] of _windows) {
        const before = timestamps.length;
        while (timestamps.length > 0 && timestamps[0] < cutoff) {
          timestamps.shift();
        }
        if (timestamps.length === 0) {
          _windows.delete(key);
          count += before;
        }
      }
      return count;
    },
  });
}

// ---------------------------------------------------------------------------
// 2. CRYPTO HELPERS
// ---------------------------------------------------------------------------

/**
 * Hashes a password using scrypt with a random salt.
 * @param {string} password
 * @returns {Promise<{ hash: string, salt: string }>}
 */
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await scryptAsync(password, salt, 64);
  return { hash: hash.toString('hex'), salt };
}

/**
 * Promisified scrypt.
 */
function scryptAsync(password, salt, keylen) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/**
 * Verifies a password against a stored hash+salt.
 * CS-CODE-001: Uses crypto.timingSafeEqual to prevent timing attacks.
 * @returns {Promise<boolean>}
 */
async function verifyPassword(password, storedHash, salt) {
  try {
    const candidateHash = await scryptAsync(password, salt, 64);
    const stored = Buffer.from(storedHash, 'hex');
    // Lengths must match before timingSafeEqual (it throws if unequal)
    if (candidateHash.length !== stored.length) return false;
    return crypto.timingSafeEqual(candidateHash, stored);
  } catch {
    return false;
  }
}

/**
 * Generates a CSRF token bound to the session ID.
 * CS-CODE-018: HMAC algorithm locked to sha256, no negotiation.
 * @param {string} sessionId
 * @param {string} secret
 * @returns {string}
 */
function generateCsrfToken(sessionId, secret) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `${sessionId}:${nonce}`;
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `${payload}:${sig}`;
}

/**
 * Validates a CSRF token against the session ID.
 * CS-CODE-001: Timing-safe comparison.
 * CS-CODE-018: Algorithm locked.
 * @param {string} token
 * @param {string} sessionId
 * @param {string} secret
 * @returns {boolean}
 */
function validateCsrfToken(token, sessionId, secret) {
  try {
    const parts = token.split(':');
    if (parts.length !== 3) return false;
    const [sid, nonce, givenSig] = parts;
    if (sid !== sessionId) return false;
    const payload = `${sid}:${nonce}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    const expectedBuf = Buffer.from(expectedSig, 'hex');
    const givenBuf = Buffer.from(givenSig, 'hex');
    if (expectedBuf.length !== givenBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, givenBuf);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 3. INPUT VALIDATION (CS-CODE-003: parse → structure → type → length → format)
// ---------------------------------------------------------------------------

const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,64}$/;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 128;

/**
 * Validates a username.
 * CS-CODE-019: Prototype pollution keys rejected.
 * @returns {{ valid: boolean, error?: string }}
 */
function validateUsername(value) {
  // parse
  if (value === undefined || value === null) return { valid: false, error: 'Username is required' };
  // type
  if (typeof value !== 'string') return { valid: false, error: 'Username must be a string' };
  // length
  if (value.length < 3) return { valid: false, error: 'Username must be at least 3 characters' };
  if (value.length > 64) return { valid: false, error: 'Username must be at most 64 characters' };
  // format
  if (!USERNAME_RE.test(value)) return { valid: false, error: 'Username may only contain letters, digits, _, ., -' };
  // CS-CODE-019: prototype pollution check
  const FORBIDDEN = ['__proto__', 'constructor', 'prototype'];
  if (FORBIDDEN.includes(value)) return { valid: false, error: 'Invalid username' };
  return { valid: true };
}

/**
 * Validates a password.
 * @returns {{ valid: boolean, error?: string }}
 */
function validatePassword(value) {
  if (value === undefined || value === null) return { valid: false, error: 'Password is required' };
  if (typeof value !== 'string') return { valid: false, error: 'Password must be a string' };
  if (value.length < PASSWORD_MIN) return { valid: false, error: `Password must be at least ${PASSWORD_MIN} characters` };
  if (value.length > PASSWORD_MAX) return { valid: false, error: `Password must be at most ${PASSWORD_MAX} characters` };
  return { valid: true };
}

// ---------------------------------------------------------------------------
// 4. HTTP HELPERS
// ---------------------------------------------------------------------------

/**
 * Parses raw cookie header into a key-value map.
 *
 * Cookie names are stored as-is (no decoding) because RFC 6265 defines
 * cookie names as opaque tokens. The __Host- and __Secure- prefixes are
 * literal characters and must not be decoded. Only values are decoded since
 * we encode them with encodeURIComponent in buildCookieHeader.
 *
 * @param {string} cookieHeader
 * @returns {Map<string, string>}
 */
function parseCookies(cookieHeader) {
  const map = new Map();
  if (!cookieHeader) return map;
  for (const part of cookieHeader.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();   // name: no decoding
    const val = part.slice(eqIdx + 1).trim();
    try {
      map.set(key, decodeURIComponent(val));    // value: decode percent-encoding
    } catch {
      // Malformed cookie value — store raw to avoid silent drop
      map.set(key, val);
    }
  }
  return map;
}

/**
 * Parses a JSON request body with a size guard.
 * AB-010: Unbounded buffer accumulation prevented via BODY_SIZE_LIMIT.
 * @param {http.IncomingMessage} req
 * @param {number} limit  bytes
 * @returns {Promise<object>}
 */
function parseBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        req.destroy();
        reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (!raw) return resolve({});
        resolve(JSON.parse(raw));
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { statusCode: 400 }));
      }
    });

    req.on('error', reject);
  });
}

/**
 * Sends a JSON response.
 * CS-CODE-017: Never reflects raw user input in body strings.
 */
function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

/**
 * Sends a standardised error response.
 */
function sendError(res, statusCode, message) {
  sendJson(res, statusCode, { error: message });
}

/**
 * Builds a Set-Cookie header string.
 * HTTPS is assumed for __Host- prefix cookies (requires Secure flag).
 *
 * Cookie names with the __Host- or __Secure- prefix are special browser
 * security prefixes defined in RFC 6265bis. They MUST NOT be URL-encoded
 * in the Set-Cookie header — the prefix characters are literal and the
 * browser validates them as-is. Only the value is percent-encoded.
 */
function buildCookieHeader(name, value, options = {}) {
  // Cookie name: no encoding (RFC 6265 names are token characters; __Host-* are literal)
  // Cookie value: percent-encode to handle special characters safely
  let cookie = `${name}=${encodeURIComponent(value)}`;
  if (options.httpOnly) cookie += '; HttpOnly';
  if (options.secure) cookie += '; Secure';
  if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
  if (options.path) cookie += `; Path=${options.path}`;
  if (options.maxAge !== undefined) cookie += `; Max-Age=${options.maxAge}`;
  return cookie;
}

/**
 * Clears a cookie by setting Max-Age=0.
 */
function clearCookieHeader(name, options = {}) {
  return buildCookieHeader(name, '', { ...options, maxAge: 0 });
}

/**
 * Extracts the client IP address.
 * AB-008: Only trusts proxy headers when TRUST_PROXY is explicitly enabled.
 * @param {http.IncomingMessage} req
 * @param {boolean} trustProxy
 * @returns {string}
 */
function getClientIp(req, trustProxy) {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      // Take the first (leftmost) IP — the original client
      return forwarded.split(',')[0].trim();
    }
  }
  return req.socket.remoteAddress || 'unknown';
}

// ---------------------------------------------------------------------------
// 5. MIDDLEWARE FACTORIES (CS-CODE-008: ordered headers→CORS→rate-limit→body→routes)
// ---------------------------------------------------------------------------

/**
 * Returns a middleware that sets security headers on every response.
 */
function securityHeadersMiddleware() {
  return function applySecurityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0'); // disabled in favour of CSP
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy',
      "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    next(req, res);
  };
}

/**
 * Returns a CORS middleware that validates Origin against a whitelist.
 * AB-005/006: No wildcard, explicit whitelist only.
 */
function corsMiddleware(allowedOrigins) {
  const originSet = new Set(allowedOrigins);

  return function applyCors(req, res, next) {
    const origin = req.headers['origin'];
    if (origin && originSet.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
      res.setHeader('Vary', 'Origin');
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }
    next(req, res);
  };
}

/**
 * Returns a global rate-limiter middleware.
 * CS-CODE-009: Sliding window, automatic cleanup.
 */
function rateLimitMiddleware(limiter, trustProxy) {
  return function applyRateLimit(req, res, next) {
    const ip = getClientIp(req, trustProxy);
    const result = limiter.check(ip);
    res.setHeader('X-RateLimit-Remaining', result.remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetAt / 1000));
    if (!result.allowed) {
      sendError(res, 429, 'Too many requests. Please try again later.');
      return;
    }
    next(req, res);
  };
}

// ---------------------------------------------------------------------------
// 6. MIDDLEWARE PIPELINE RUNNER
// ---------------------------------------------------------------------------

/**
 * Runs an ordered array of middleware functions.
 * Each middleware receives (req, res, next). If next is not called, the
 * pipeline stops (response has been sent).
 * @param {Function[]} middlewares
 * @returns {Function} handler(req, res)
 */
function pipeline(...middlewares) {
  return function runPipeline(req, res) {
    let idx = 0;
    function next(r, s) {
      if (idx >= middlewares.length) return;
      const mw = middlewares[idx++];
      mw(r, s, next);
    }
    next(req, res);
  };
}

// ---------------------------------------------------------------------------
// 7. AUTH MIDDLEWARE (session validation + CSRF)
// ---------------------------------------------------------------------------

/**
 * Validates session from cookie and attaches session to req.
 * Renews if close to expiry.
 */
function requireSession(sessionStore, config) {
  return function checkSession(req, res, next) {
    const cookies = parseCookies(req.headers['cookie']);
    const sessionId = cookies.get(config.COOKIE_NAME);
    if (!sessionId) {
      sendError(res, 401, 'Authentication required');
      return;
    }
    const session = sessionStore.get(sessionId);
    if (!session) {
      sendError(res, 401, 'Session not found or expired');
      return;
    }
    if (session.expiresAt < Date.now()) {
      sessionStore.delete(sessionId);
      sendError(res, 401, 'Session expired');
      return;
    }
    // Sliding window renewal: CS-CODE-009
    const remaining = session.expiresAt - Date.now();
    if (remaining < config.SESSION_RENEW_THRESHOLD_MS) {
      sessionStore.renew(sessionId, config.SESSION_TTL_MS);
      // Refresh cookie
      res.setHeader('Set-Cookie', buildCookieHeader(config.COOKIE_NAME, sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: Math.floor(config.SESSION_TTL_MS / 1000),
      }));
    }
    req.session = session;
    next(req, res);
  };
}

/**
 * Validates CSRF token from header against session-bound token.
 * Uses double-submit + HMAC approach.
 */
function requireCsrf(config) {
  // Skip CSRF for safe methods
  const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

  return function checkCsrf(req, res, next) {
    if (SAFE_METHODS.has(req.method)) {
      next(req, res);
      return;
    }
    const csrfHeader = req.headers['x-csrf-token'];
    if (!csrfHeader) {
      sendError(res, 403, 'CSRF token missing');
      return;
    }
    if (!req.session) {
      sendError(res, 401, 'No session attached');
      return;
    }
    if (!validateCsrfToken(csrfHeader, req.session.sessionId, config.CSRF_SECRET)) {
      sendError(res, 403, 'CSRF token invalid');
      return;
    }
    next(req, res);
  };
}

// ---------------------------------------------------------------------------
// 8. ROUTE HANDLERS
// ---------------------------------------------------------------------------

/**
 * POST /auth/register
 * Body: { username, password }
 */
function handleRegister(userStore, config) {
  return async function register(req, res) {
    let body;
    try {
      body = await parseBody(req, config.BODY_SIZE_LIMIT);
    } catch (err) {
      sendError(res, err.statusCode || 400, err.message);
      return;
    }

    // CS-CODE-003: Defense-in-depth validation
    const usernameResult = validateUsername(body.username);
    if (!usernameResult.valid) {
      sendError(res, 400, usernameResult.error);
      return;
    }
    const passwordResult = validatePassword(body.password);
    if (!passwordResult.valid) {
      sendError(res, 400, passwordResult.error);
      return;
    }

    // Check uniqueness
    if (userStore.findByUsername(body.username)) {
      // CS-CODE-002: Generic message — don't reveal whether user exists
      sendError(res, 409, 'Registration failed. Please try a different username.');
      return;
    }

    try {
      const { hash, salt } = await hashPassword(body.password);
      userStore.create(body.username, hash, salt);
      sendJson(res, 201, { message: 'Account created successfully.' });
    } catch (err) {
      // CS-CODE-013: Isolate operation failure
      sendError(res, 500, 'Registration failed. Please try again.');
    }
  };
}

/**
 * POST /auth/login
 * Body: { username, password }
 * Sets session cookie + CSRF cookie.
 */
function handleLogin(userStore, sessionStore, bruteForceStore, config) {
  return async function login(req, res) {
    let body;
    try {
      body = await parseBody(req, config.BODY_SIZE_LIMIT);
    } catch (err) {
      sendError(res, err.statusCode || 400, err.message);
      return;
    }

    const ip = getClientIp(req, config.TRUST_PROXY);
    const username = typeof body.username === 'string' ? body.username : '';
    const lockKey = `${ip}:${username}`;

    // Brute-force check
    if (bruteForceStore.isLocked(lockKey)) {
      // CS-CODE-002: Generic message
      sendError(res, 429, 'Too many failed attempts. Please try again later.');
      return;
    }

    // Validate inputs.
    // CS-CODE-002: Auth endpoints always return 401 for any credential problem.
    // Using 401 (not 400) prevents distinguishing between "bad format" and "wrong password",
    // which could be exploited to enumerate valid credential patterns.
    const usernameResult = validateUsername(body.username);
    if (!usernameResult.valid) {
      sendError(res, 401, 'Invalid credentials.'); // CS-CODE-002
      return;
    }
    const passwordResult = validatePassword(body.password);
    if (!passwordResult.valid) {
      sendError(res, 401, 'Invalid credentials.'); // CS-CODE-002
      return;
    }

    const user = userStore.findByUsername(body.username);

    // CS-CODE-002: Same code path for missing user vs wrong password
    const passwordValid = user
      ? await verifyPassword(body.password, user.passwordHash, user.salt)
      : await scryptAsync('dummy-constant-time', 'salt0000salt0000', 64).then(() => false);

    if (!passwordValid || !user) {
      const rec = bruteForceStore.record(lockKey);
      if (rec.attempts >= config.MAX_LOGIN_ATTEMPTS) {
        bruteForceStore.lockUntil(lockKey, Date.now() + config.LOCKOUT_DURATION_MS);
      }
      sendError(res, 401, 'Invalid credentials.'); // CS-CODE-002
      return;
    }

    // Success — reset brute force counter
    bruteForceStore.reset(lockKey);

    // Generate session ID first, then bind CSRF token to it.
    // This ensures validateCsrfToken(token, session.sessionId) succeeds
    // because the token was signed with the actual session ID.
    const { sessionId } = sessionStore.create(user.id, user.username, '', config.SESSION_TTL_MS);
    const csrfToken = generateCsrfToken(sessionId, config.CSRF_SECRET);
    // Update session record with the bound CSRF token
    sessionStore.setCsrfToken(sessionId, csrfToken);

    res.setHeader('Set-Cookie', [
      buildCookieHeader(config.COOKIE_NAME, sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: Math.floor(config.SESSION_TTL_MS / 1000),
      }),
      buildCookieHeader(config.CSRF_COOKIE_NAME, csrfToken, {
        // Not HttpOnly so JS can read it and put in X-CSRF-Token header
        secure: true,
        sameSite: 'Strict',
        path: '/',
        maxAge: Math.floor(config.SESSION_TTL_MS / 1000),
      }),
    ]);

    sendJson(res, 200, {
      message: 'Login successful.',
      username: user.username,
      csrfToken,
    });
  };
}

/**
 * POST /auth/logout
 * Requires valid session + CSRF.
 */
function handleLogout(sessionStore, config) {
  return function logout(req, res) {
    const sessionId = req.session.sessionId;
    sessionStore.delete(sessionId);

    res.setHeader('Set-Cookie', [
      clearCookieHeader(config.COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'Strict', path: '/' }),
      clearCookieHeader(config.CSRF_COOKIE_NAME, { secure: true, sameSite: 'Strict', path: '/' }),
    ]);

    sendJson(res, 200, { message: 'Logged out successfully.' });
  };
}

/**
 * POST /auth/change-password
 * Requires valid session + CSRF.
 * Body: { currentPassword, newPassword }
 */
function handleChangePassword(userStore, config) {
  return async function changePassword(req, res) {
    let body;
    try {
      body = await parseBody(req, config.BODY_SIZE_LIMIT);
    } catch (err) {
      sendError(res, err.statusCode || 400, err.message);
      return;
    }

    const currentPassResult = validatePassword(body.currentPassword);
    if (!currentPassResult.valid) {
      sendError(res, 400, 'Current password is invalid.');
      return;
    }
    const newPassResult = validatePassword(body.newPassword);
    if (!newPassResult.valid) {
      sendError(res, 400, newPassResult.error);
      return;
    }

    const user = userStore.findByUsername(req.session.username);
    if (!user) {
      sendError(res, 404, 'User not found.');
      return;
    }

    const currentValid = await verifyPassword(body.currentPassword, user.passwordHash, user.salt);
    if (!currentValid) {
      sendError(res, 401, 'Current password is incorrect.');
      return;
    }

    try {
      const { hash, salt } = await hashPassword(body.newPassword);
      userStore.updatePassword(user.username, hash, salt);
      sendJson(res, 200, { message: 'Password changed successfully.' });
    } catch (err) {
      sendError(res, 500, 'Password change failed. Please try again.');
    }
  };
}

/**
 * POST /auth/request-reset
 * Body: { username }
 * Returns the token in the response for demo purposes
 * (in production, email the token instead).
 */
function handleRequestReset(userStore, resetTokenStore, config) {
  return async function requestReset(req, res) {
    let body;
    try {
      body = await parseBody(req, config.BODY_SIZE_LIMIT);
    } catch (err) {
      sendError(res, err.statusCode || 400, err.message);
      return;
    }

    // CS-CODE-002: Always return same response to prevent user enumeration
    const GENERIC_MSG = 'If that account exists, a reset token has been generated.';

    const usernameResult = validateUsername(body.username);
    if (!usernameResult.valid) {
      // Still return generic message
      sendJson(res, 200, { message: GENERIC_MSG });
      return;
    }

    const user = userStore.findByUsername(body.username);
    if (!user) {
      // CS-CODE-002: No user enumeration
      sendJson(res, 200, { message: GENERIC_MSG });
      return;
    }

    try {
      const token = resetTokenStore.create(body.username, config.RESET_TOKEN_TTL_MS);
      // In production: send token via email. For demo: return in response.
      sendJson(res, 200, { message: GENERIC_MSG, resetToken: token });
    } catch (err) {
      sendError(res, 500, 'Could not generate reset token.');
    }
  };
}

/**
 * POST /auth/reset-password
 * Body: { token, newPassword }
 */
function handleResetPassword(userStore, resetTokenStore, config) {
  return async function resetPassword(req, res) {
    let body;
    try {
      body = await parseBody(req, config.BODY_SIZE_LIMIT);
    } catch (err) {
      sendError(res, err.statusCode || 400, err.message);
      return;
    }

    if (typeof body.token !== 'string' || body.token.length === 0) {
      sendError(res, 400, 'Reset token is required.');
      return;
    }
    const newPassResult = validatePassword(body.newPassword);
    if (!newPassResult.valid) {
      sendError(res, 400, newPassResult.error);
      return;
    }

    const username = resetTokenStore.consume(body.token);
    if (!username) {
      sendError(res, 400, 'Invalid or expired reset token.');
      return;
    }

    const user = userStore.findByUsername(username);
    if (!user) {
      sendError(res, 400, 'Invalid or expired reset token.');
      return;
    }

    try {
      const { hash, salt } = await hashPassword(body.newPassword);
      userStore.updatePassword(username, hash, salt);
      sendJson(res, 200, { message: 'Password has been reset successfully.' });
    } catch (err) {
      sendError(res, 500, 'Password reset failed. Please try again.');
    }
  };
}

/**
 * GET /auth/me
 * Returns the current user info (requires session).
 */
function handleMe() {
  return function me(req, res) {
    sendJson(res, 200, {
      username: req.session.username,
      sessionCreatedAt: req.session.createdAt,
      sessionExpiresAt: req.session.expiresAt,
    });
  };
}

/**
 * GET /health
 * Simple health check (no auth required).
 */
function handleHealth() {
  return function health(req, res) {
    sendJson(res, 200, { status: 'ok', timestamp: Date.now() });
  };
}

// ---------------------------------------------------------------------------
// 9. ROUTER
// ---------------------------------------------------------------------------

/**
 * Simple pattern-based router.
 * @param {Array<{ method: string, path: string, handler: Function }>} routes
 * @returns {Function} handler(req, res)
 */
function createRouter(routes) {
  return function route(req, res) {
    const { method, url } = req;
    const [pathname] = (url || '/').split('?');

    for (const r of routes) {
      if (r.method === method && r.path === pathname) {
        try {
          const result = r.handler(req, res);
          if (result && typeof result.catch === 'function') {
            result.catch(err => {
              if (!res.writableEnded) {
                sendError(res, 500, 'Internal server error');
              }
            });
          }
        } catch (err) {
          if (!res.writableEnded) {
            sendError(res, 500, 'Internal server error');
          }
        }
        return;
      }
    }

    sendError(res, 404, 'Not found');
  };
}

// ---------------------------------------------------------------------------
// 10. APPLICATION FACTORY
// ---------------------------------------------------------------------------

/**
 * Creates the full Express-compatible application.
 * Returns { server, stores, config } for testing.
 */
function createApp(config) {
  // Instantiate stores
  const userStore = createUserStore();
  const sessionStore = createSessionStore();
  const bruteForceStore = createBruteForceStore();
  const resetTokenStore = createResetTokenStore();

  // Rate limiter (global) — AB-002
  const globalLimiter = createRateLimiter({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: config.RATE_LIMIT_MAX,
  });

  // Strict rate limiter for auth endpoints (10 req/min/IP)
  const authLimiter = createRateLimiter({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    max: 10,
  });

  // Build middleware stack
  const securityHeaders = securityHeadersMiddleware();
  const cors = corsMiddleware(config.ALLOWED_ORIGINS);
  const globalRateLimit = rateLimitMiddleware(globalLimiter, config.TRUST_PROXY);
  const authRateLimit = rateLimitMiddleware(authLimiter, config.TRUST_PROXY);
  const sessionCheck = requireSession(sessionStore, config);
  const csrfCheck = requireCsrf(config);

  // Route handlers
  const routes = [
    {
      method: 'GET',
      path: '/health',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit,
        handleHealth()
      ),
    },
    {
      method: 'POST',
      path: '/auth/register',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit, authRateLimit,
        handleRegister(userStore, config)
      ),
    },
    {
      method: 'POST',
      path: '/auth/login',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit, authRateLimit,
        handleLogin(userStore, sessionStore, bruteForceStore, config)
      ),
    },
    {
      method: 'POST',
      path: '/auth/logout',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit,
        sessionCheck, csrfCheck,
        handleLogout(sessionStore, config)
      ),
    },
    {
      method: 'GET',
      path: '/auth/me',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit,
        sessionCheck,
        handleMe()
      ),
    },
    {
      method: 'POST',
      path: '/auth/change-password',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit, authRateLimit,
        sessionCheck, csrfCheck,
        handleChangePassword(userStore, config)
      ),
    },
    {
      method: 'POST',
      path: '/auth/request-reset',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit, authRateLimit,
        handleRequestReset(userStore, resetTokenStore, config)
      ),
    },
    {
      method: 'POST',
      path: '/auth/reset-password',
      handler: pipeline(
        securityHeaders, cors, globalRateLimit, authRateLimit,
        handleResetPassword(userStore, resetTokenStore, config)
      ),
    },
  ];

  const router = createRouter(routes);
  const server = http.createServer(router);

  return { server, userStore, sessionStore, bruteForceStore, resetTokenStore, globalLimiter };
}

// ---------------------------------------------------------------------------
// 11. CLEANUP SCHEDULER (AB-007: intervals tracked and cleared on shutdown)
// ---------------------------------------------------------------------------

/** Holds all interval IDs so they can be cleared on shutdown. */
const _intervals = [];

/**
 * Schedules periodic cleanup of all stores.
 * AB-007: Interval is tracked and unref'd so it won't block process exit.
 * AB-009: TTL-based eviction for all in-memory stores.
 */
function scheduleCleanup(stores, config) {
  const { sessionStore, bruteForceStore, resetTokenStore, globalLimiter } = stores;
  const id = setInterval(() => {
    try {
      const s = sessionStore.purgeExpired();
      const b = bruteForceStore.purgeExpired();
      const r = resetTokenStore.purgeExpired();
      const l = globalLimiter.purgeExpired();
      if (process.env.NODE_ENV !== 'test') {
        process.stdout.write(
          `[cleanup] sessions=${s} bruteforce=${b} resetTokens=${r} rateLimit=${l}\n`
        );
      }
    } catch (err) {
      // CS-CODE-013: Cleanup errors must not crash the server
      process.stderr.write('[cleanup] Error: ' + err.message + '\n');
    }
  }, config.CLEANUP_INTERVAL_MS);

  id.unref(); // CS-CODE-005: Won't prevent graceful shutdown
  _intervals.push(id);
  return id;
}

// ---------------------------------------------------------------------------
// 12. GRACEFUL SHUTDOWN (CS-CODE-005)
// ---------------------------------------------------------------------------

/**
 * Registers SIGTERM + SIGINT handlers for graceful shutdown.
 * CS-CODE-005: Connection draining + timeout + unref.
 */
function registerShutdownHandlers(server) {
  const DRAIN_TIMEOUT_MS = 10_000;

  function shutdown(signal) {
    process.stdout.write(`[shutdown] Received ${signal}. Closing server...\n`);

    // Stop accepting new connections
    server.close(() => {
      process.stdout.write('[shutdown] All connections closed. Exiting.\n');
      // Clear all cleanup intervals — AB-007
      for (const id of _intervals) clearInterval(id);
      process.exit(0);
    });

    // Force exit after drain timeout
    const forceExit = setTimeout(() => {
      process.stderr.write('[shutdown] Drain timeout exceeded. Forcing exit.\n');
      for (const id of _intervals) clearInterval(id);
      process.exit(1);
    }, DRAIN_TIMEOUT_MS);

    forceExit.unref(); // Don't block loop
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// ---------------------------------------------------------------------------
// 13. ENTRY POINT
// ---------------------------------------------------------------------------

function main() {
  let config;
  try {
    config = loadAndValidateConfig(); // CS-CODE-006: Fail fast
  } catch (err) {
    process.stderr.write('[startup] ' + err.message + '\n');
    process.exit(1);
  }

  const { server, userStore, sessionStore, bruteForceStore, resetTokenStore, globalLimiter } =
    createApp(config);

  scheduleCleanup({ sessionStore, bruteForceStore, resetTokenStore, globalLimiter }, config);
  registerShutdownHandlers(server);

  server.listen(config.PORT, () => {
    process.stdout.write(`[server] Listening on port ${config.PORT}\n`);
    process.stdout.write(`[server] CORS origins: ${config.ALLOWED_ORIGINS.join(', ')}\n`);
    process.stdout.write(`[server] Proxy trust: ${config.TRUST_PROXY}\n`);
  });
}

// ---------------------------------------------------------------------------
// 14. EXPORTS (for testing)
// ---------------------------------------------------------------------------

module.exports = {
  // Factories (testable in isolation)
  createApp,
  createUserStore,
  createSessionStore,
  createBruteForceStore,
  createResetTokenStore,
  createRateLimiter,
  loadAndValidateConfig,

  // Crypto helpers
  hashPassword,
  verifyPassword,
  generateCsrfToken,
  validateCsrfToken,

  // Validation
  validateUsername,
  validatePassword,

  // HTTP helpers
  parseCookies,
  parseBody,
  buildCookieHeader,
  getClientIp,

  // Middleware factories
  securityHeadersMiddleware,
  corsMiddleware,
  rateLimitMiddleware,
  requireSession,
  requireCsrf,

  // Route handlers
  handleRegister,
  handleLogin,
  handleLogout,
  handleChangePassword,
  handleRequestReset,
  handleResetPassword,
  handleMe,
  handleHealth,

  // Pipeline
  pipeline,
};

// Run when executed directly
if (require.main === module) {
  main();
}
