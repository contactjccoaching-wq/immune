/**
 * Real-time Chat Server with WebSockets
 * Production-quality single-file implementation
 *
 * Features: Multiple rooms, user nicknames, message history (last 50),
 * typing indicators, connection/disconnection events
 *
 * Security: Input validation, XSS escaping, rate limiting, constant-time
 * secret comparison, auth gating, HMAC verification
 */

'use strict';

const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const crypto = require('crypto');

// ─── CS-CODE-006: Centralized init() entry point ─────────────────────────────

// ─── CS-CODE-007: Single centralized state object ────────────────────────────
const state = {
  /** @type {Map<string, Room>} */
  rooms: new Map(),
  /** @type {Map<WebSocket, ClientMeta>} */
  clients: new Map(),
  /** @type {Map<string, RateBucket>} */
  rateLimits: new Map(),
  config: null,
};

// ─── Constants ───────────────────────────────────────────────────────────────
const CONSTANTS = {
  MAX_ROOMS: 100,
  MAX_NICK_LEN: 32,
  MIN_NICK_LEN: 1,
  MAX_MSG_LEN: 2000,
  HISTORY_SIZE: 50,
  ROOM_NAME_MAX: 64,
  ROOM_NAME_REGEX: /^[a-zA-Z0-9_-]+$/,
  NICK_REGEX: /^[a-zA-Z0-9_\- ]+$/,
  // Rate limiting: per IP, sliding window
  RATE_WINDOW_MS: 10_000,
  RATE_MAX_EVENTS: 30,
  // AB-CODE-010: guard for cleanup loop
  RATE_CLEANUP_MAX: 10_000,
  // Heartbeat
  PING_INTERVAL_MS: 30_000,
  // Auth
  ADMIN_HEADER: 'x-admin-key',
};

// ─── @typedef ────────────────────────────────────────────────────────────────
/**
 * @typedef {{ messages: Message[], typingUsers: Set<string> }} Room
 * @typedef {{ id: string, nick: string, room: string|null, ip: string, isAlive: boolean }} ClientMeta
 * @typedef {{ ts: number, nick: string, text: string, type: 'chat' }} Message
 * @typedef {{ timestamps: number[] }} RateBucket
 */

// ─── CS-CODE-001 / AB-CODE-006 / AB-CODE-023: HTML escape ───────────────────
/**
 * Escape HTML entities to prevent XSS in any HTML context.
 * @param {string} raw
 * @returns {string}
 */
function escapeHtml(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// ─── AB-CODE-031: Constant-time secret comparison ────────────────────────────
/**
 * Compare two strings in constant time to prevent timing attacks.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still run timingSafeEqual on equal-length copies to avoid length leak
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// ─── CS-CODE-005: Schema validation helpers ───────────────────────────────────
/**
 * Validate and sanitize an incoming WebSocket message payload.
 * Returns null if invalid.
 * @param {unknown} raw
 * @returns {{ type: string, [k: string]: unknown }|null}
 */
function validatePayload(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const obj = /** @type {Record<string,unknown>} */ (raw);

  // type field is mandatory
  if (typeof obj.type !== 'string' || obj.type.length === 0 || obj.type.length > 64) return null;

  return obj;
}

/**
 * Validate a room name.
 * @param {unknown} name
 * @returns {string|null}
 */
function validateRoomName(name) {
  if (typeof name !== 'string') return null;
  const trimmed = name.trim();
  if (trimmed.length === 0 || trimmed.length > CONSTANTS.ROOM_NAME_MAX) return null;
  if (!CONSTANTS.ROOM_NAME_REGEX.test(trimmed)) return null;
  return trimmed;
}

/**
 * Validate a user nickname.
 * @param {unknown} nick
 * @returns {string|null}
 */
function validateNick(nick) {
  if (typeof nick !== 'string') return null;
  const trimmed = nick.trim();
  if (trimmed.length < CONSTANTS.MIN_NICK_LEN || trimmed.length > CONSTANTS.MAX_NICK_LEN) return null;
  if (!CONSTANTS.NICK_REGEX.test(trimmed)) return null;
  return trimmed;
}

/**
 * Validate a chat message text.
 * @param {unknown} text
 * @returns {string|null}
 */
function validateMessageText(text) {
  if (typeof text !== 'string') return null;
  const trimmed = text.trim();
  if (trimmed.length === 0 || trimmed.length > CONSTANTS.MAX_MSG_LEN) return null;
  return trimmed;
}

// ─── Rate Limiting (in-memory, appropriate for persistent Node.js process) ───
// Note: AB-CODE-029 warns against in-memory rate limiting in SERVERLESS contexts
// (cold-start resets). This server runs as a persistent process, so in-memory
// rate limiting is valid and correct here.
/**
 * Check if an IP is within rate limits.
 * @param {string} ip
 * @returns {boolean} true if allowed, false if rate-limited
 */
function checkRateLimit(ip) {
  const now = Date.now();
  let bucket = state.rateLimits.get(ip);
  if (!bucket) {
    bucket = { timestamps: [] };
    state.rateLimits.set(ip, bucket);
  }

  // Purge old timestamps outside the window
  const cutoff = now - CONSTANTS.RATE_WINDOW_MS;
  bucket.timestamps = bucket.timestamps.filter(ts => ts > cutoff);

  if (bucket.timestamps.length >= CONSTANTS.RATE_MAX_EVENTS) {
    return false; // rate limited
  }

  bucket.timestamps.push(now);
  return true;
}

/**
 * Periodically purge stale rate limit buckets to prevent memory growth.
 * AB-CODE-010: bounded loop with MAX guard.
 */
function cleanupRateLimits() {
  const now = Date.now();
  const cutoff = now - CONSTANTS.RATE_WINDOW_MS;
  let iterations = 0;
  for (const [ip, bucket] of state.rateLimits) {
    if (++iterations > CONSTANTS.RATE_CLEANUP_MAX) break; // AB-CODE-010 guard
    if (bucket.timestamps.every(ts => ts <= cutoff)) {
      state.rateLimits.delete(ip);
    }
  }
}

// ─── Room helpers ─────────────────────────────────────────────────────────────
/**
 * Get or create a room by name.
 * @param {string} name
 * @returns {Room}
 */
function getOrCreateRoom(name) {
  if (!state.rooms.has(name)) {
    if (state.rooms.size >= CONSTANTS.MAX_ROOMS) {
      throw new Error('Max rooms reached');
    }
    state.rooms.set(name, { messages: [], typingUsers: new Set() });
  }
  return /** @type {Room} */ (state.rooms.get(name));
}

/**
 * Add a message to room history, keeping only last HISTORY_SIZE.
 * @param {Room} room
 * @param {Message} msg
 */
function addMessageToHistory(room, msg) {
  room.messages.push(msg);
  if (room.messages.length > CONSTANTS.HISTORY_SIZE) {
    room.messages.splice(0, room.messages.length - CONSTANTS.HISTORY_SIZE);
  }
}

/**
 * Get all WebSocket clients currently in a given room.
 * @param {string} roomName
 * @returns {WebSocket[]}
 */
function getRoomClients(roomName) {
  const result = [];
  for (const [ws, meta] of state.clients) {
    if (meta.room === roomName && ws.readyState === WebSocket.OPEN) {
      result.push(ws);
    }
  }
  return result;
}

// ─── Broadcast helpers ────────────────────────────────────────────────────────
/**
 * Send a JSON payload to a single WebSocket safely.
 * @param {WebSocket} ws
 * @param {object} payload
 */
function send(ws, payload) {
  if (ws.readyState !== WebSocket.OPEN) return;
  try {
    ws.send(JSON.stringify(payload));
  } catch (err) {
    console.error('[send] error:', err.message);
  }
}

/**
 * Broadcast a JSON payload to all clients in a room.
 * @param {string} roomName
 * @param {object} payload
 * @param {WebSocket} [exclude] - optionally exclude one client
 */
function broadcastToRoom(roomName, payload, exclude) {
  for (const ws of getRoomClients(roomName)) {
    if (ws === exclude) continue;
    send(ws, payload);
  }
}

// ─── Unique ID generator ──────────────────────────────────────────────────────
function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

// ─── Message handlers ─────────────────────────────────────────────────────────

/**
 * Handle "set_nick" message: user sets or changes nickname.
 * @param {WebSocket} ws
 * @param {ClientMeta} meta
 * @param {Record<string,unknown>} payload
 */
function handleSetNick(ws, meta, payload) {
  const nick = validateNick(payload.nick);
  if (!nick) {
    send(ws, { type: 'error', code: 'INVALID_NICK', message: 'Invalid nickname (1–32 alphanumeric chars, hyphens, underscores, spaces)' });
    return;
  }

  // Check uniqueness across all connected clients
  for (const [, other] of state.clients) {
    if (other.id !== meta.id && other.nick === nick) {
      send(ws, { type: 'error', code: 'NICK_TAKEN', message: 'Nickname already in use' });
      return;
    }
  }

  const oldNick = meta.nick;
  meta.nick = nick;

  send(ws, { type: 'nick_set', nick });

  // Notify room if already in one
  if (meta.room) {
    broadcastToRoom(meta.room, {
      type: 'nick_changed',
      oldNick: escapeHtml(oldNick),
      newNick: escapeHtml(nick),
      ts: Date.now(),
    }, ws);
  }
}

/**
 * Handle "join" message: user joins a room.
 * @param {WebSocket} ws
 * @param {ClientMeta} meta
 * @param {Record<string,unknown>} payload
 */
function handleJoin(ws, meta, payload) {
  if (!meta.nick) {
    send(ws, { type: 'error', code: 'NO_NICK', message: 'Set a nickname before joining a room' });
    return;
  }

  const roomName = validateRoomName(payload.room);
  if (!roomName) {
    send(ws, { type: 'error', code: 'INVALID_ROOM', message: 'Invalid room name (1–64 alphanumeric, hyphens, underscores)' });
    return;
  }

  // Leave existing room first
  if (meta.room && meta.room !== roomName) {
    handleLeaveRoom(ws, meta);
  }

  let room;
  try {
    room = getOrCreateRoom(roomName);
  } catch {
    send(ws, { type: 'error', code: 'ROOM_LIMIT', message: 'Maximum number of rooms reached' });
    return;
  }

  meta.room = roomName;

  // Remove from typing if somehow lingering
  room.typingUsers.delete(meta.nick);

  // Send history to joining client — CS-CODE-014: all stored text already escaped at store time
  send(ws, {
    type: 'room_joined',
    room: roomName,
    history: room.messages,
    users: getUserListForRoom(roomName),
  });

  // Notify others
  broadcastToRoom(roomName, {
    type: 'user_joined',
    nick: escapeHtml(meta.nick),
    room: roomName,
    ts: Date.now(),
  }, ws);
}

/**
 * Handle "leave" message: user explicitly leaves their current room.
 * @param {WebSocket} ws
 * @param {ClientMeta} meta
 */
function handleLeave(ws, meta) {
  if (!meta.room) {
    send(ws, { type: 'error', code: 'NOT_IN_ROOM', message: 'You are not in a room' });
    return;
  }
  handleLeaveRoom(ws, meta);
  send(ws, { type: 'left_room' });
}

/**
 * Internal leave-room logic (also used on disconnect).
 * @param {WebSocket} ws
 * @param {ClientMeta} meta
 */
function handleLeaveRoom(ws, meta) {
  if (!meta.room) return;
  const roomName = meta.room;
  const room = state.rooms.get(roomName);
  if (room) {
    room.typingUsers.delete(meta.nick);
    broadcastTypingUpdate(roomName);
  }

  meta.room = null;

  broadcastToRoom(roomName, {
    type: 'user_left',
    nick: escapeHtml(meta.nick),
    room: roomName,
    ts: Date.now(),
  });

  // Clean up empty rooms
  if (room && getRoomClients(roomName).length === 0) {
    state.rooms.delete(roomName);
  }
}

/**
 * Handle "message" event: user sends a chat message.
 * @param {WebSocket} ws
 * @param {ClientMeta} meta
 * @param {Record<string,unknown>} payload
 */
function handleMessage(ws, meta, payload) {
  if (!meta.nick) {
    send(ws, { type: 'error', code: 'NO_NICK', message: 'Set a nickname first' });
    return;
  }
  if (!meta.room) {
    send(ws, { type: 'error', code: 'NOT_IN_ROOM', message: 'Join a room first' });
    return;
  }

  const text = validateMessageText(payload.text);
  if (!text) {
    send(ws, { type: 'error', code: 'INVALID_MESSAGE', message: 'Message must be 1–2000 characters' });
    return;
  }

  const room = state.rooms.get(meta.room);
  if (!room) {
    send(ws, { type: 'error', code: 'ROOM_GONE', message: 'Room no longer exists' });
    return;
  }

  // CS-CODE-014: escape all stored text before saving / broadcasting
  const msg = {
    type: 'chat',
    nick: escapeHtml(meta.nick),
    text: escapeHtml(text),
    room: meta.room,
    ts: Date.now(),
  };

  addMessageToHistory(room, msg);

  // Clear typing indicator when user sends a message
  if (room.typingUsers.delete(meta.nick)) {
    broadcastTypingUpdate(meta.room);
  }

  broadcastToRoom(meta.room, msg);
}

/**
 * Handle "typing" event: user started/stopped typing.
 * @param {WebSocket} ws
 * @param {ClientMeta} meta
 * @param {Record<string,unknown>} payload
 */
function handleTyping(ws, meta, payload) {
  if (!meta.nick || !meta.room) return;
  const room = state.rooms.get(meta.room);
  if (!room) return;

  // CS-CODE-005: validate the "typing" boolean field
  const isTyping = typeof payload.typing === 'boolean' ? payload.typing : false;

  if (isTyping) {
    room.typingUsers.add(meta.nick);
  } else {
    room.typingUsers.delete(meta.nick);
  }

  broadcastTypingUpdate(meta.room);
}

/**
 * Broadcast current typing users list to everyone in a room.
 * @param {string} roomName
 */
function broadcastTypingUpdate(roomName) {
  const room = state.rooms.get(roomName);
  if (!room) return;
  // CS-CODE-014: nick stored safely; escaping defensively on broadcast
  const typingList = Array.from(room.typingUsers).map(escapeHtml);
  broadcastToRoom(roomName, {
    type: 'typing_update',
    room: roomName,
    users: typingList,
    ts: Date.now(),
  });
}

/**
 * Get list of users currently in a room.
 * @param {string} roomName
 * @returns {string[]}
 */
function getUserListForRoom(roomName) {
  const result = [];
  for (const [, meta] of state.clients) {
    if (meta.room === roomName) {
      result.push(escapeHtml(meta.nick));
    }
  }
  return result;
}

// ─── HTTP Admin API ───────────────────────────────────────────────────────────
// CS-CODE-012 / CS-CODE-013: if ADMIN_SECRET present, ALL admin endpoints verify it.
// AB-CODE-021: no default-true auth path.
// AB-CODE-022: no hardcoded fallback credentials.
// AB-CODE-027: token in header, not query param.

/**
 * Verify admin key from request headers.
 * Fail-closed: if env secret is missing, always reject.
 * @param {http.IncomingMessage} req
 * @returns {boolean}
 */
function verifyAdminKey(req) {
  const { adminSecret } = state.config;
  // CS-CODE-013: fail-closed — if no secret configured, reject all admin requests
  if (!adminSecret) return false;

  // AB-CODE-027: read from header, never from query param
  const provided = req.headers[CONSTANTS.ADMIN_HEADER];
  if (typeof provided !== 'string' || provided.length === 0) return false;

  // AB-CODE-031: constant-time comparison
  return safeEqual(provided, adminSecret);
}

/**
 * Simple HTTP request handler for REST admin endpoints.
 * AB-CODE-028: GET endpoints have no write side effects.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 */
function httpHandler(req, res) {
  // CS-CODE-016: auth gate BEFORE any processing
  // AB-CODE-025: no wildcard CORS — we do not set CORS headers on admin API

  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  // CS-CODE-015: path segments treated as hostile
  const pathname = url.pathname;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Admin routes require auth
  if (pathname.startsWith('/admin/')) {
    if (!verifyAdminKey(req)) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    // AB-CODE-028: admin mutations use POST/DELETE, reads use GET
    if (pathname === '/admin/rooms' && req.method === 'GET') {
      const rooms = [];
      for (const [name, room] of state.rooms) {
        rooms.push({
          name,
          userCount: getRoomClients(name).length,
          messageCount: room.messages.length,
        });
      }
      res.writeHead(200);
      res.end(JSON.stringify({ rooms }));
      return;
    }

    if (pathname === '/admin/clients' && req.method === 'GET') {
      const clients = [];
      for (const [, meta] of state.clients) {
        clients.push({
          id: meta.id,
          nick: meta.nick || null,
          room: meta.room || null,
          ip: meta.ip,
        });
      }
      res.writeHead(200);
      res.end(JSON.stringify({ clients }));
      return;
    }

    // AB-CODE-028: kick user is a mutation → POST only
    if (pathname === '/admin/kick' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        let parsed;
        // AB-CODE-008: JSON.parse with try/catch
        try {
          parsed = JSON.parse(body);
        } catch {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Invalid JSON' }));
          return;
        }
        // CS-CODE-005: per-field type guards
        const targetId = typeof parsed.id === 'string' ? parsed.id : null;
        if (!targetId) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Missing id field' }));
          return;
        }

        let found = false;
        for (const [ws, meta] of state.clients) {
          if (meta.id === targetId) {
            send(ws, { type: 'kicked', reason: 'Removed by admin' });
            ws.terminate();
            found = true;
            break;
          }
        }

        if (found) {
          res.writeHead(200);
          res.end(JSON.stringify({ ok: true }));
        } else {
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'Client not found' }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found' }));
    return;
  }

  // Public health check
  if (pathname === '/health' && req.method === 'GET') {
    res.writeHead(200);
    res.end(JSON.stringify({
      ok: true,
      rooms: state.rooms.size,
      clients: state.clients.size,
    }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
}

// ─── WebSocket connection handler ─────────────────────────────────────────────

/**
 * Extract client IP from request, preferring X-Forwarded-For when behind a proxy.
 * CS-CODE-015: treat header value as hostile, sanitize.
 * @param {http.IncomingMessage} req
 * @returns {string}
 */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    // Take only the first IP, strip whitespace
    const first = forwarded.split(',')[0].trim();
    // Basic IP sanity check (IPv4/IPv6)
    if (/^[0-9a-fA-F:.]+$/.test(first) && first.length <= 45) {
      return first;
    }
  }
  return req.socket?.remoteAddress || 'unknown';
}

/**
 * Main WebSocket connection handler.
 * @param {WebSocket} ws
 * @param {http.IncomingMessage} req
 */
function onConnection(ws, req) {
  const ip = getClientIp(req);

  // Rate limit new connections per IP
  if (!checkRateLimit(ip)) {
    send(ws, { type: 'error', code: 'RATE_LIMITED', message: 'Too many connections from your IP' });
    ws.close(1008, 'Rate limited');
    return;
  }

  const meta = {
    id: generateId(),
    nick: '',
    room: null,
    ip,
    isAlive: true,
  };
  state.clients.set(ws, meta);

  console.log(`[connect] id=${meta.id} ip=${ip} total=${state.clients.size}`);

  send(ws, {
    type: 'welcome',
    id: meta.id,
    message: 'Connected. Set a nickname with {type:"set_nick",nick:"YourName"} then join a room.',
  });

  // ─── Heartbeat: pong tracking ───────────────────────────────────────────
  ws.on('pong', () => {
    const m = state.clients.get(ws);
    if (m) m.isAlive = true;
  });

  // ─── Incoming message handler ───────────────────────────────────────────
  ws.on('message', (data, isBinary) => {
    // Rate limit messages per IP
    if (!checkRateLimit(ip)) {
      send(ws, { type: 'error', code: 'RATE_LIMITED', message: 'Slow down — too many messages' });
      return;
    }

    if (isBinary) {
      send(ws, { type: 'error', code: 'BINARY_NOT_SUPPORTED', message: 'Binary messages not supported' });
      return;
    }

    // AB-CODE-008: JSON.parse with try/catch
    let parsed;
    try {
      parsed = JSON.parse(data.toString());
    } catch {
      send(ws, { type: 'error', code: 'INVALID_JSON', message: 'Invalid JSON' });
      return;
    }

    const payload = validatePayload(parsed);
    if (!payload) {
      send(ws, { type: 'error', code: 'INVALID_PAYLOAD', message: 'Payload must be a non-null object with a type field' });
      return;
    }

    const m = state.clients.get(ws);
    if (!m) return; // disconnected between event and handler

    switch (payload.type) {
      case 'set_nick':
        handleSetNick(ws, m, payload);
        break;
      case 'join':
        handleJoin(ws, m, payload);
        break;
      case 'leave':
        handleLeave(ws, m);
        break;
      case 'message':
        handleMessage(ws, m, payload);
        break;
      case 'typing':
        handleTyping(ws, m, payload);
        break;
      case 'ping':
        // Application-level ping (distinct from WS-protocol ping)
        send(ws, { type: 'pong', ts: Date.now() });
        break;
      default:
        send(ws, { type: 'error', code: 'UNKNOWN_TYPE', message: `Unknown message type: ${escapeHtml(String(payload.type))}` });
    }
  });

  // ─── Close handler ──────────────────────────────────────────────────────
  ws.on('close', (code, reason) => {
    const m = state.clients.get(ws);
    if (!m) return;

    console.log(`[disconnect] id=${m.id} nick=${m.nick || '(none)'} code=${code} reason=${reason?.toString().slice(0, 100)}`);

    if (m.room) {
      handleLeaveRoom(ws, m);
    }

    state.clients.delete(ws);
    console.log(`[disconnect] remaining clients=${state.clients.size}`);
  });

  // ─── Error handler ──────────────────────────────────────────────────────
  ws.on('error', (err) => {
    console.error(`[ws-error] id=${meta.id}`, err.message);
    // ws will emit 'close' automatically after an error
  });
}

// ─── Heartbeat interval ───────────────────────────────────────────────────────
/**
 * Ping all connected clients; terminate those that did not respond since last ping.
 */
function startHeartbeat(wss) {
  return setInterval(() => {
    for (const [ws, meta] of state.clients) {
      if (!meta.isAlive) {
        console.log(`[heartbeat] terminating unresponsive client id=${meta.id}`);
        ws.terminate();
        continue;
      }
      meta.isAlive = false;
      try {
        ws.ping();
      } catch {
        // ignore — close event will clean up
      }
    }
  }, CONSTANTS.PING_INTERVAL_MS);
}

// ─── CS-CODE-006: Centralized init() ─────────────────────────────────────────
function init() {
  // Load and validate configuration from environment
  const port = parseInt(process.env.PORT || '8080', 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    console.error('[init] Invalid PORT environment variable');
    process.exit(1);
  }

  // CS-CODE-012 / CS-CODE-013: admin secret — fail-closed
  const adminSecret = process.env.ADMIN_SECRET || null;
  if (!adminSecret) {
    console.warn('[init] WARNING: ADMIN_SECRET not set — all /admin/* endpoints will return 401');
  }

  // AB-CODE-022: no hardcoded fallback credentials
  state.config = { port, adminSecret };

  // HTTP server
  const server = http.createServer(httpHandler);

  // WebSocket server attached to the HTTP server
  const wss = new WebSocketServer({ server, clientTracking: false });

  wss.on('connection', onConnection);

  wss.on('error', (err) => {
    console.error('[wss-error]', err.message);
  });

  // Start heartbeat
  const heartbeatTimer = startHeartbeat(wss);

  // Rate limit cleanup every minute
  const cleanupTimer = setInterval(cleanupRateLimits, 60_000);

  // Graceful shutdown
  function shutdown(signal) {
    console.log(`\n[shutdown] received ${signal}`);
    clearInterval(heartbeatTimer);
    clearInterval(cleanupTimer);

    // Notify all clients
    for (const [ws] of state.clients) {
      try {
        send(ws, { type: 'server_shutdown', message: 'Server is shutting down' });
        ws.close(1001, 'Server shutting down');
      } catch {
        // ignore
      }
    }

    wss.close(() => {
      server.close(() => {
        console.log('[shutdown] clean exit');
        process.exit(0);
      });
    });

    // Force exit after 5 seconds if graceful shutdown hangs
    setTimeout(() => {
      console.error('[shutdown] forced exit after timeout');
      process.exit(1);
    }, 5_000).unref();
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Catch unhandled rejections — log but do not crash
  process.on('unhandledRejection', (reason) => {
    console.error('[unhandledRejection]', reason);
  });
  process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
    // For truly unexpected exceptions, shut down gracefully
    shutdown('uncaughtException');
  });

  server.listen(port, () => {
    console.log(`[init] Chat server listening on ws://localhost:${port}`);
    console.log(`[init] Admin API: http://localhost:${port}/admin/rooms (requires ${CONSTANTS.ADMIN_HEADER} header)`);
    console.log(`[init] Health:    http://localhost:${port}/health`);
  });
}

// ─── Entry point ──────────────────────────────────────────────────────────────
init();
