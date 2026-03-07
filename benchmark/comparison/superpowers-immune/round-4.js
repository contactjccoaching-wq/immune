"use strict";

// ---------------------------------------------------------------------------
// Real-time WebSocket Chat Server
// ---------------------------------------------------------------------------
// Architecture:
//   Layer 1 — Config & Validation   (startup validation, input validators)
//   Layer 2 — Data Layer            (in-memory stores, closure-isolated)
//   Layer 3 — Business Logic        (room ops, rate limiting, message flow)
//   Layer 4 — Transport Layer       (WebSocket handlers, HTTP REST API)
//   Layer 5 — Lifecycle             (graceful shutdown, resource cleanup)
// ---------------------------------------------------------------------------

import http from "node:http";
import crypto from "node:crypto";
import { WebSocketServer } from "ws";

// ---------------------------------------------------------------------------
// LAYER 1 — Configuration & Startup Validation (CS-CODE-006, AB-001)
// ---------------------------------------------------------------------------

// CS-CODE-006: Fail fast on invalid config before accepting connections.
// AB-001: No hardcoded secrets or insecure defaults. CORS_ORIGIN must be
//         explicitly set in production — no wildcard fallback allowed via env.
function loadConfig() {
  const raw = {
    PORT: process.env.PORT,
    CORS_ORIGINS: process.env.CORS_ORIGINS,
    NODE_ENV: process.env.NODE_ENV || "development",
    // WebSocket per-client rate limiting
    WS_RATE_WINDOW_MS: process.env.WS_RATE_WINDOW_MS || "10000",
    WS_RATE_MAX: process.env.WS_RATE_MAX || "30",
    // Sizing limits
    MAX_MESSAGE_LEN: process.env.MAX_MESSAGE_LEN || "2000",
    MAX_NICKNAME_LEN: process.env.MAX_NICKNAME_LEN || "30",
    MAX_ROOM_NAME_LEN: process.env.MAX_ROOM_NAME_LEN || "50",
    MESSAGE_HISTORY_SIZE: process.env.MESSAGE_HISTORY_SIZE || "50",
    // Typing indicator auto-clear timeout (ms)
    TYPING_TIMEOUT_MS: process.env.TYPING_TIMEOUT_MS || "8000",
    // Graceful shutdown grace period
    SHUTDOWN_GRACE_MS: process.env.SHUTDOWN_GRACE_MS || "10000",
  };

  const port = parseInt(raw.PORT || "3000", 10);
  const wsRateWindowMs = parseInt(raw.WS_RATE_WINDOW_MS, 10);
  const wsRateMax = parseInt(raw.WS_RATE_MAX, 10);
  const maxMessageLen = parseInt(raw.MAX_MESSAGE_LEN, 10);
  const maxNicknameLen = parseInt(raw.MAX_NICKNAME_LEN, 10);
  const maxRoomNameLen = parseInt(raw.MAX_ROOM_NAME_LEN, 10);
  const messageHistorySize = parseInt(raw.MESSAGE_HISTORY_SIZE, 10);
  const typingTimeoutMs = parseInt(raw.TYPING_TIMEOUT_MS, 10);
  const shutdownGraceMs = parseInt(raw.SHUTDOWN_GRACE_MS, 10);

  const numericFields = {
    port,
    wsRateWindowMs,
    wsRateMax,
    maxMessageLen,
    maxNicknameLen,
    maxRoomNameLen,
    messageHistorySize,
    typingTimeoutMs,
    shutdownGraceMs,
  };

  const errors = [];

  for (const [key, value] of Object.entries(numericFields)) {
    if (!Number.isFinite(value) || value <= 0) {
      errors.push(`${key} must be a positive finite number (got: ${value})`);
    }
  }

  if (port < 1 || port > 65535) {
    errors.push(`PORT must be between 1 and 65535 (got: ${port})`);
  }

  // AB-006: CORS wildcard disallowed in production.
  const isProduction = raw.NODE_ENV === "production";
  if (isProduction && !raw.CORS_ORIGINS) {
    errors.push("CORS_ORIGINS env var is required in production (AB-006: no wildcard fallback)");
  }

  if (errors.length > 0) {
    for (const err of errors) console.error(`[FATAL CONFIG] ${err}`);
    process.exit(1);
  }

  // Parse comma-separated CORS origins
  const corsOrigins = raw.CORS_ORIGINS
    ? new Set(raw.CORS_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean))
    : null; // null = allow all (dev mode only)

  return Object.freeze({
    port,
    corsOrigins,
    isProduction,
    wsRateWindowMs,
    wsRateMax,
    maxMessageLen,
    maxNicknameLen,
    maxRoomNameLen,
    messageHistorySize,
    typingTimeoutMs,
    shutdownGraceMs,
  });
}

const CONFIG = loadConfig();

// ---------------------------------------------------------------------------
// LAYER 2 — Input Validation (CS-CODE-003, CS-CODE-007)
// ---------------------------------------------------------------------------

const NICKNAME_RE = /^[\w\s\-]{1,}$/; // alphanum + underscore + space + hyphen
const ROOM_NAME_RE = /^[\w\s\-]{1,}$/;

/**
 * Escapes HTML special characters to prevent XSS injection in stored content.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

/**
 * @typedef {{ ok: true, value: string } | { ok: false, error: string, code: string }} ValidationResult
 */

/** @returns {ValidationResult} */
function validateNickname(raw) {
  if (typeof raw !== "string") return { ok: false, error: "Nickname must be a string", code: "INVALID_NICKNAME" };
  const v = raw.trim();
  if (v.length === 0) return { ok: false, error: "Nickname cannot be empty", code: "INVALID_NICKNAME" };
  if (v.length > CONFIG.maxNicknameLen)
    return { ok: false, error: `Nickname must be ≤ ${CONFIG.maxNicknameLen} characters`, code: "INVALID_NICKNAME" };
  if (!NICKNAME_RE.test(v))
    return { ok: false, error: "Nickname may only contain letters, numbers, spaces, hyphens, underscores", code: "INVALID_NICKNAME" };
  return { ok: true, value: escapeHtml(v) };
}

/** @returns {ValidationResult} */
function validateRoomName(raw) {
  if (typeof raw !== "string") return { ok: false, error: "Room name must be a string", code: "INVALID_ROOM" };
  const v = raw.trim();
  if (v.length === 0) return { ok: false, error: "Room name cannot be empty", code: "INVALID_ROOM" };
  if (v.length > CONFIG.maxRoomNameLen)
    return { ok: false, error: `Room name must be ≤ ${CONFIG.maxRoomNameLen} characters`, code: "INVALID_ROOM" };
  if (!ROOM_NAME_RE.test(v))
    return { ok: false, error: "Room name may only contain letters, numbers, spaces, hyphens, underscores", code: "INVALID_ROOM" };
  return { ok: true, value: escapeHtml(v) };
}

/** @returns {ValidationResult} */
function validateMessageContent(raw) {
  if (typeof raw !== "string") return { ok: false, error: "Message content must be a string", code: "INVALID_MESSAGE" };
  const v = raw.trim();
  if (v.length === 0) return { ok: false, error: "Message cannot be empty", code: "INVALID_MESSAGE" };
  if (v.length > CONFIG.maxMessageLen)
    return { ok: false, error: `Message must be ≤ ${CONFIG.maxMessageLen} characters`, code: "INVALID_MESSAGE" };
  return { ok: true, value: escapeHtml(v) };
}

/**
 * CS-CODE-007: Reject non-object bodies before property access.
 * @param {unknown} parsed
 * @returns {{ ok: true, value: object } | { ok: false, error: string }}
 */
function validateParsedFrame(parsed) {
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, error: "Message must be a JSON object" };
  }
  if (typeof parsed.type !== "string" || parsed.type.trim().length === 0) {
    return { ok: false, error: "Message must have a non-empty string 'type' field" };
  }
  return { ok: true, value: parsed };
}

// ---------------------------------------------------------------------------
// LAYER 2 — In-Memory Data Stores (CS-CODE-010, AB-009)
// ---------------------------------------------------------------------------
// CS-CODE-010: Closure-based data isolation — internal Maps never exposed.
// AB-009: Rooms cleaned up when last member leaves; typing timers cleared.

/**
 * @typedef {Object} StoredMessage
 * @property {string} id
 * @property {string} clientId
 * @property {string} nickname
 * @property {string} room
 * @property {string} content
 * @property {string} timestamp  ISO-8601
 */

/**
 * @typedef {Object} Room
 * @property {string} name
 * @property {StoredMessage[]} history
 * @property {Set<string>} members      clientId set
 * @property {Map<string, NodeJS.Timeout>} typingTimers  clientId → auto-clear timer
 * @property {Set<string>} typing       clientId set (currently typing)
 * @property {string} createdAt         ISO-8601
 */

/**
 * @typedef {Object} ClientState
 * @property {string} id
 * @property {string} nickname
 * @property {string|null} currentRoom
 * @property {import('ws').WebSocket} ws
 * @property {string} connectedAt       ISO-8601
 * @property {number[]} wsTimestamps    sliding-window timestamps for rate limiting
 */

const roomStore = (() => {
  /** @type {Map<string, Room>} */
  const _rooms = new Map();

  /** @param {string} name @returns {Room} */
  function getOrCreate(name) {
    if (_rooms.has(name)) return _rooms.get(name);
    const room = {
      name,
      history: [],
      members: new Set(),
      typingTimers: new Map(),
      typing: new Set(),
      createdAt: new Date().toISOString(),
    };
    _rooms.set(name, room);
    return room;
  }

  /** @param {string} name @returns {Room|undefined} */
  function get(name) {
    return _rooms.get(name);
  }

  /** @param {string} name */
  function deleteIfEmpty(name) {
    const room = _rooms.get(name);
    if (room && room.members.size === 0) {
      // AB-009: Clean up all typing timers before deleting room
      for (const timer of room.typingTimers.values()) clearTimeout(timer);
      _rooms.delete(name);
    }
  }

  /** @returns {Array<{ name: string, membersCount: number, createdAt: string }>} */
  function listRooms() {
    const result = [];
    for (const [name, room] of _rooms) {
      result.push({ name, membersCount: room.members.size, createdAt: room.createdAt });
    }
    return result;
  }

  /**
   * Append a message to room history, capping at CONFIG.messageHistorySize.
   * @param {Room} room
   * @param {StoredMessage} msg
   */
  function appendMessage(room, msg) {
    room.history.push(msg);
    if (room.history.length > CONFIG.messageHistorySize) {
      room.history.shift(); // remove oldest
    }
  }

  /** @returns {number} */
  function count() {
    return _rooms.size;
  }

  return Object.freeze({ getOrCreate, get, deleteIfEmpty, listRooms, appendMessage, count });
})();

const clientStore = (() => {
  /** @type {Map<string, ClientState>} */
  const _clients = new Map();

  /** @type {Map<import('ws').WebSocket, string>} */
  const _wsIndex = new Map();

  /** @param {ClientState} client */
  function add(client) {
    _clients.set(client.id, client);
    _wsIndex.set(client.ws, client.id);
  }

  /** @param {import('ws').WebSocket} ws @returns {ClientState|undefined} */
  function getByWs(ws) {
    const id = _wsIndex.get(ws);
    return id ? _clients.get(id) : undefined;
  }

  /** @param {string} id @returns {ClientState|undefined} */
  function getById(id) {
    return _clients.get(id);
  }

  /** @param {import('ws').WebSocket} ws */
  function remove(ws) {
    const id = _wsIndex.get(ws);
    if (id) {
      _clients.delete(id);
      _wsIndex.delete(ws);
    }
  }

  /** @returns {number} */
  function count() {
    return _clients.size;
  }

  return Object.freeze({ add, getByWs, getById, remove, count });
})();

// ---------------------------------------------------------------------------
// LAYER 3 — Business Logic
// ---------------------------------------------------------------------------

// --- Rate limiting (CS-CODE-009: sliding window per client) ---

/**
 * Returns true if the client should be rate-limited, false otherwise.
 * Mutates client.wsTimestamps (sliding window — auto-prunes expired entries).
 * @param {ClientState} client
 * @returns {boolean}
 */
function isWsRateLimited(client) {
  const now = Date.now();
  // Prune timestamps outside current window
  const windowStart = now - CONFIG.wsRateWindowMs;
  client.wsTimestamps = client.wsTimestamps.filter((ts) => ts > windowStart);
  if (client.wsTimestamps.length >= CONFIG.wsRateMax) return true;
  client.wsTimestamps.push(now);
  return false;
}

// --- Transport helpers ---

/**
 * Send a JSON payload to a single WebSocket client. No-op if socket is not OPEN.
 * @param {import('ws').WebSocket} ws
 * @param {object} payload
 */
function sendTo(ws, payload) {
  if (ws.readyState === ws.OPEN) {
    try {
      ws.send(JSON.stringify(payload));
    } catch (err) {
      console.error("[sendTo] Failed to send:", err.message);
    }
  }
}

/**
 * Broadcast a JSON payload to all members of a room.
 * @param {string} roomName
 * @param {object} payload
 * @param {string|null} [excludeClientId]
 */
function broadcastToRoom(roomName, payload, excludeClientId = null) {
  const room = roomStore.get(roomName);
  if (!room) return;
  const data = JSON.stringify(payload);
  for (const memberId of room.members) {
    if (memberId === excludeClientId) continue;
    const member = clientStore.getById(memberId);
    if (member && member.ws.readyState === member.ws.OPEN) {
      try {
        member.ws.send(data);
      } catch (err) {
        console.error(`[broadcastToRoom] Failed to send to ${memberId}:`, err.message);
      }
    }
  }
}

/**
 * Send an error frame to a client WebSocket.
 * @param {import('ws').WebSocket} ws
 * @param {string} message
 * @param {string} code
 */
function sendWsError(ws, message, code) {
  sendTo(ws, { type: "error", code, message, timestamp: new Date().toISOString() });
}

// --- Room membership ---

/**
 * Remove a client from their current room. Broadcasts departure event.
 * Deletes room if it becomes empty (AB-009).
 * @param {ClientState} client
 */
function leaveCurrentRoom(client) {
  if (!client.currentRoom) return;
  const roomName = client.currentRoom;
  const room = roomStore.get(roomName);
  client.currentRoom = null;

  if (!room) return;

  // Clear typing state
  clearTypingIndicator(room, client.id);

  room.members.delete(client.id);

  if (room.members.size > 0) {
    broadcastToRoom(roomName, {
      type: "user_left",
      clientId: client.id,
      nickname: client.nickname,
      room: roomName,
      membersCount: room.members.size,
      timestamp: new Date().toISOString(),
    });
  }

  // AB-009: Clean up empty room
  roomStore.deleteIfEmpty(roomName);
}

/**
 * Join a client to a room, sending history and notifying room members.
 * @param {ClientState} client
 * @param {string} roomName  (already validated)
 */
function joinRoom(client, roomName) {
  leaveCurrentRoom(client);

  const room = roomStore.getOrCreate(roomName);
  room.members.add(client.id);
  client.currentRoom = roomName;

  // Send room state to joining client
  const membersList = buildMembersList(room);
  const typingList = buildTypingList(room);

  sendTo(client.ws, {
    type: "joined",
    clientId: client.id,
    nickname: client.nickname,
    room: roomName,
    history: [...room.history],
    members: membersList,
    membersCount: room.members.size,
    typing: typingList,
    timestamp: new Date().toISOString(),
  });

  // Notify existing room members
  broadcastToRoom(
    roomName,
    {
      type: "user_joined",
      clientId: client.id,
      nickname: client.nickname,
      room: roomName,
      membersCount: room.members.size,
      timestamp: new Date().toISOString(),
    },
    client.id,
  );
}

/**
 * Serialize room members to a safe client-facing shape.
 * @param {Room} room
 * @returns {Array<{ id: string, nickname: string }>}
 */
function buildMembersList(room) {
  const result = [];
  for (const memberId of room.members) {
    const m = clientStore.getById(memberId);
    if (m) result.push({ id: m.id, nickname: m.nickname });
  }
  return result;
}

/**
 * Serialize typing users to a safe client-facing shape.
 * @param {Room} room
 * @returns {Array<{ id: string, nickname: string }>}
 */
function buildTypingList(room) {
  const result = [];
  for (const typingId of room.typing) {
    const m = clientStore.getById(typingId);
    if (m) result.push({ id: m.id, nickname: m.nickname });
  }
  return result;
}

/**
 * Set a client's typing state. Auto-clears after TYPING_TIMEOUT_MS if
 * no stop signal is received (AB-009: prevents leaked typing state).
 * @param {Room} room
 * @param {ClientState} client
 * @param {boolean} isTyping
 */
function setTypingIndicator(room, client, isTyping) {
  const existingTimer = room.typingTimers.get(client.id);
  if (existingTimer) {
    clearTimeout(existingTimer);
    room.typingTimers.delete(client.id);
  }

  if (isTyping) {
    room.typing.add(client.id);
    // Auto-clear typing indicator if client never sends stop signal
    const timer = setTimeout(() => {
      clearTypingIndicator(room, client.id);
      broadcastToRoom(room.name, {
        type: "typing",
        clientId: client.id,
        nickname: client.nickname,
        isTyping: false,
        typing: buildTypingList(room),
        timestamp: new Date().toISOString(),
      });
    }, CONFIG.typingTimeoutMs);
    room.typingTimers.set(client.id, timer);
  } else {
    room.typing.delete(client.id);
  }
}

/**
 * Clear a client's typing state without broadcasting (used internally on leave/disconnect).
 * @param {Room} room
 * @param {string} clientId
 */
function clearTypingIndicator(room, clientId) {
  const timer = room.typingTimers.get(clientId);
  if (timer) {
    clearTimeout(timer);
    room.typingTimers.delete(clientId);
  }
  room.typing.delete(clientId);
}

// ---------------------------------------------------------------------------
// LAYER 4 — WebSocket Message Handlers
// ---------------------------------------------------------------------------

/**
 * @typedef {(client: ClientState, frame: object) => void} MessageHandler
 */

/** @type {Map<string, MessageHandler>} */
const wsHandlers = new Map();

// JOIN — set nickname and enter a room
wsHandlers.set("join", (client, frame) => {
  const nickResult = validateNickname(frame.nickname);
  if (!nickResult.ok) return sendWsError(client.ws, nickResult.error, nickResult.code);

  const roomResult = validateRoomName(frame.room);
  if (!roomResult.ok) return sendWsError(client.ws, roomResult.error, roomResult.code);

  client.nickname = nickResult.value;
  joinRoom(client, roomResult.value);
});

// MESSAGE — send a chat message to the current room
wsHandlers.set("message", (client, frame) => {
  if (!client.currentRoom) {
    return sendWsError(client.ws, "You must join a room before sending messages", "NOT_IN_ROOM");
  }

  const contentResult = validateMessageContent(frame.content);
  if (!contentResult.ok) return sendWsError(client.ws, contentResult.error, contentResult.code);

  const room = roomStore.get(client.currentRoom);
  if (!room) return sendWsError(client.ws, "Room not found", "ROOM_NOT_FOUND");

  // Sending a message clears the typing indicator
  clearTypingIndicator(room, client.id);

  /** @type {StoredMessage} */
  const msg = {
    id: crypto.randomUUID(),
    clientId: client.id,
    nickname: client.nickname,
    room: client.currentRoom,
    content: contentResult.value,
    timestamp: new Date().toISOString(),
  };

  roomStore.appendMessage(room, msg);

  // Broadcast to all room members including sender
  broadcastToRoom(client.currentRoom, { type: "message", ...msg });
});

// TYPING — update typing indicator state
wsHandlers.set("typing", (client, frame) => {
  if (!client.currentRoom) return; // silently ignore if not in room

  const room = roomStore.get(client.currentRoom);
  if (!room) return;

  const isTyping = Boolean(frame.isTyping);
  setTypingIndicator(room, client, isTyping);

  broadcastToRoom(
    client.currentRoom,
    {
      type: "typing",
      clientId: client.id,
      nickname: client.nickname,
      isTyping,
      typing: buildTypingList(room),
      timestamp: new Date().toISOString(),
    },
    client.id,
  );
});

// NICKNAME — change display name (affects current room visibility)
wsHandlers.set("nickname", (client, frame) => {
  const nickResult = validateNickname(frame.nickname);
  if (!nickResult.ok) return sendWsError(client.ws, nickResult.error, nickResult.code);

  const oldNickname = client.nickname;
  client.nickname = nickResult.value;

  const event = {
    type: "nickname_changed",
    clientId: client.id,
    oldNickname,
    newNickname: client.nickname,
    timestamp: new Date().toISOString(),
  };

  sendTo(client.ws, event);

  if (client.currentRoom) {
    broadcastToRoom(client.currentRoom, event, client.id);
  }
});

// LEAVE — explicitly leave the current room
wsHandlers.set("leave", (client) => {
  if (!client.currentRoom) {
    return sendWsError(client.ws, "You are not in any room", "NOT_IN_ROOM");
  }
  const roomName = client.currentRoom;
  leaveCurrentRoom(client);
  sendTo(client.ws, { type: "left", room: roomName, timestamp: new Date().toISOString() });
});

// GET_ROOMS — list active rooms
wsHandlers.set("get_rooms", (client) => {
  sendTo(client.ws, {
    type: "rooms_list",
    rooms: roomStore.listRooms(),
    timestamp: new Date().toISOString(),
  });
});

// GET_MEMBERS — list members in a specific room
wsHandlers.set("get_members", (client, frame) => {
  const roomResult = validateRoomName(frame.room);
  if (!roomResult.ok) return sendWsError(client.ws, roomResult.error, roomResult.code);

  const room = roomStore.get(roomResult.value);
  if (!room) return sendWsError(client.ws, "Room not found", "ROOM_NOT_FOUND");

  sendTo(client.ws, {
    type: "members_list",
    room: roomResult.value,
    members: buildMembersList(room),
    membersCount: room.members.size,
    timestamp: new Date().toISOString(),
  });
});

// PING — health check / keepalive
wsHandlers.set("ping", (client) => {
  sendTo(client.ws, { type: "pong", timestamp: new Date().toISOString() });
});

// ---------------------------------------------------------------------------
// LAYER 4 — WebSocket Connection Lifecycle
// ---------------------------------------------------------------------------

/**
 * Handle a new WebSocket connection.
 * @param {import('ws').WebSocket} ws
 * @param {http.IncomingMessage} req
 */
function handleConnection(ws, req) {
  const clientId = crypto.randomUUID();
  const defaultNickname = `User-${clientId.slice(0, 8)}`;

  /** @type {ClientState} */
  const client = {
    id: clientId,
    nickname: defaultNickname,
    currentRoom: null,
    ws,
    connectedAt: new Date().toISOString(),
    wsTimestamps: [],
  };

  clientStore.add(client);

  // Send welcome frame with assigned ID so client can identify itself
  sendTo(ws, {
    type: "welcome",
    clientId,
    nickname: defaultNickname,
    timestamp: new Date().toISOString(),
  });

  ws.on("message", (raw) => handleWsMessage(ws, client, raw));
  ws.on("close", () => handleWsClose(ws, client));
  ws.on("error", (err) => {
    console.error(`[WS] Client ${clientId} error:`, err.message);
    // 'close' will fire after 'error', so cleanup happens there
  });
}

/**
 * Process a raw WebSocket message frame.
 * @param {import('ws').WebSocket} ws
 * @param {ClientState} client
 * @param {Buffer|string} raw
 */
function handleWsMessage(ws, client, raw) {
  // CS-CODE-003: Parse + validate before any logic
  let parsed;
  try {
    parsed = JSON.parse(raw.toString());
  } catch {
    return sendWsError(ws, "Message must be valid JSON", "PARSE_ERROR");
  }

  // CS-CODE-007: Reject non-object frames
  const frameResult = validateParsedFrame(parsed);
  if (!frameResult.ok) return sendWsError(ws, frameResult.error, "INVALID_FRAME");

  // CS-CODE-009: Per-client sliding-window rate limit
  if (isWsRateLimited(client)) {
    return sendWsError(ws, "Too many messages — slow down", "RATE_LIMITED");
  }

  const handler = wsHandlers.get(parsed.type);
  if (!handler) {
    return sendWsError(ws, `Unknown message type: "${escapeHtml(String(parsed.type))}"`, "UNKNOWN_TYPE");
  }

  try {
    handler(client, parsed);
  } catch (err) {
    console.error(`[WS] Handler error for type '${parsed.type}':`, err);
    sendWsError(ws, "Internal error processing your request", "INTERNAL_ERROR");
  }
}

/**
 * Clean up client state on WebSocket close.
 * @param {import('ws').WebSocket} ws
 * @param {ClientState} client
 */
function handleWsClose(ws, client) {
  leaveCurrentRoom(client);
  clientStore.remove(ws);
}

// ---------------------------------------------------------------------------
// LAYER 4 — HTTP Server (lightweight REST API, no Express dependency)
// ---------------------------------------------------------------------------
// WebSocket-only server; REST endpoints use raw Node HTTP for minimal overhead.

/** @type {Map<string, (req: http.IncomingMessage, res: http.ServerResponse, match: RegExpMatchArray|null) => void>} */
const httpRoutes = [];

/**
 * Register an HTTP GET route.
 * @param {RegExp} pattern
 * @param {Function} handler
 */
function addRoute(pattern, handler) {
  httpRoutes.push({ pattern, handler });
}

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;

  if (!origin) return; // non-browser / same-origin

  // AB-005, AB-006: Explicit origin whitelist — no wildcard in production
  if (!CONFIG.corsOrigins) {
    // Development: allow all origins
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else if (CONFIG.corsOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  // If origin not in whitelist, no CORS header → browser blocks the request
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function setSecurityHeaders(res) {
  // AB-004: Security headers (helmet equivalent, manual)
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "0"); // modern recommendation: disable legacy XSS filter
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cache-Control", "no-store");
  if (CONFIG.isProduction) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}

function jsonResponse(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function handleHttpRequest(req, res) {
  setCorsHeaders(req, res);
  setSecurityHeaders(res);

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method !== "GET") {
    return jsonResponse(res, 405, { error: "Method not allowed" });
  }

  const url = req.url ? req.url.split("?")[0] : "/";

  for (const route of httpRoutes) {
    const match = url.match(route.pattern);
    if (match) {
      try {
        route.handler(req, res, match);
      } catch (err) {
        console.error("[HTTP] Route handler error:", err);
        jsonResponse(res, 500, { error: "Internal server error" });
      }
      return;
    }
  }

  jsonResponse(res, 404, { error: "Not found" });
}

// --- Route: GET /health ---
addRoute(/^\/health$/, (_req, res) => {
  jsonResponse(res, 200, {
    status: "ok",
    uptime: process.uptime(),
    rooms: roomStore.count(),
    clients: clientStore.count(),
    timestamp: new Date().toISOString(),
  });
});

// --- Route: GET /api/rooms ---
addRoute(/^\/api\/rooms$/, (_req, res) => {
  jsonResponse(res, 200, { rooms: roomStore.listRooms() });
});

// --- Route: GET /api/rooms/:name ---
addRoute(/^\/api\/rooms\/([^/]+)$/, (_req, res, match) => {
  const roomResult = validateRoomName(decodeURIComponent(match[1]));
  if (!roomResult.ok) return jsonResponse(res, 400, { error: roomResult.error });

  const room = roomStore.get(roomResult.value);
  if (!room) return jsonResponse(res, 404, { error: "Room not found" });

  jsonResponse(res, 200, {
    name: room.name,
    membersCount: room.members.size,
    members: buildMembersList(room),
    history: [...room.history],
    createdAt: room.createdAt,
  });
});

// --- Route: GET /api/stats ---
addRoute(/^\/api\/stats$/, (_req, res) => {
  let totalMessages = 0;
  for (const { membersCount: _, ...r } of roomStore.listRooms()) {
    const room = roomStore.get(r.name);
    if (room) totalMessages += room.history.length;
  }
  jsonResponse(res, 200, {
    rooms: roomStore.count(),
    clients: clientStore.count(),
    totalMessagesInHistory: totalMessages,
    timestamp: new Date().toISOString(),
  });
});

// ---------------------------------------------------------------------------
// LAYER 5 — Server Bootstrap & Graceful Shutdown (CS-CODE-005, AB-007)
// ---------------------------------------------------------------------------

const httpServer = http.createServer(handleHttpRequest);
const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

wss.on("connection", handleConnection);

wss.on("error", (err) => {
  console.error("[WSS] Server error:", err.message);
});

httpServer.on("error", (err) => {
  console.error("[HTTP] Server error:", err.message);
  process.exit(1);
});

/**
 * Perform a graceful shutdown:
 * 1. Stop accepting new connections
 * 2. Notify connected WS clients
 * 3. Close WS server, then HTTP server
 * 4. Enforce timeout to prevent hanging (CS-CODE-005)
 *
 * AB-007: No background intervals in this server — nothing to clearInterval.
 *         Typing timers are per-room and tracked in room.typingTimers.
 *         They are already cleared in deleteIfEmpty and leaveCurrentRoom.
 *
 * @param {string} signal
 */
function gracefulShutdown(signal) {
  console.log(`\n[${signal}] Initiating graceful shutdown...`);

  // CS-CODE-005: Enforce hard deadline to prevent zombie process
  const forceExitTimer = setTimeout(() => {
    console.error("[Shutdown] Grace period exceeded — forcing exit.");
    process.exit(1);
  }, CONFIG.shutdownGraceMs);
  forceExitTimer.unref(); // AB-007 pattern: don't block event loop if graceful completes first

  // Notify all connected clients before closing
  const shutdownPayload = JSON.stringify({
    type: "server_shutdown",
    message: "Server is shutting down. Please reconnect shortly.",
    timestamp: new Date().toISOString(),
  });

  for (const clientWs of wss.clients) {
    if (clientWs.readyState === clientWs.OPEN) {
      try {
        clientWs.send(shutdownPayload);
        clientWs.close(1001, "Server shutting down");
      } catch {
        // Ignore errors during shutdown notification
      }
    }
  }

  wss.close(() => {
    httpServer.close(() => {
      clearTimeout(forceExitTimer);
      console.log("[Shutdown] Complete.");
      process.exit(0);
    });
  });
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// Unhandled rejection safety net — log and continue
process.on("unhandledRejection", (reason) => {
  console.error("[UnhandledRejection]", reason);
});

process.on("uncaughtException", (err) => {
  console.error("[UncaughtException]", err);
  gracefulShutdown("uncaughtException");
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

httpServer.listen(CONFIG.port, () => {
  console.log(`[Chat Server] Listening on port ${CONFIG.port}`);
  console.log(`[Chat Server] WebSocket endpoint : ws://localhost:${CONFIG.port}/ws`);
  console.log(`[Chat Server] REST API           : http://localhost:${CONFIG.port}/api`);
  console.log(`[Chat Server] Health             : http://localhost:${CONFIG.port}/health`);
  console.log(`[Chat Server] Environment        : ${CONFIG.isProduction ? "production" : "development"}`);
  if (!CONFIG.isProduction) {
    console.log(`[Chat Server] CORS               : open (development mode — set CORS_ORIGINS in production)`);
  }
});

// ---------------------------------------------------------------------------
// Exports (for testing)
// ---------------------------------------------------------------------------

export {
  CONFIG,
  // Validation
  validateNickname,
  validateRoomName,
  validateMessageContent,
  validateParsedFrame,
  // Utilities
  escapeHtml,
  isWsRateLimited,
  // Stores
  roomStore,
  clientStore,
  // Server handles
  httpServer,
  wss,
};
