import http from "node:http";
import crypto from "node:crypto";
import { WebSocketServer } from "ws";
import helmet from "helmet";
import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";

// ---------------------------------------------------------------------------
// 1. Environment variable validation (mandatory at startup)
// ---------------------------------------------------------------------------
const REQUIRED_ENV = {
  PORT: process.env.PORT || "3000",
  CORS_ORIGIN: process.env.CORS_ORIGIN || "*",
  RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || "60000",
  RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX || "100",
  WS_RATE_LIMIT_WINDOW_MS: process.env.WS_RATE_LIMIT_WINDOW_MS || "10000",
  WS_RATE_LIMIT_MAX: process.env.WS_RATE_LIMIT_MAX || "30",
  MAX_MESSAGE_LENGTH: process.env.MAX_MESSAGE_LENGTH || "2000",
  MAX_NICKNAME_LENGTH: process.env.MAX_NICKNAME_LENGTH || "30",
  MAX_ROOM_NAME_LENGTH: process.env.MAX_ROOM_NAME_LENGTH || "50",
  MESSAGE_HISTORY_SIZE: process.env.MESSAGE_HISTORY_SIZE || "50",
};

const CONFIG = Object.freeze({
  port: parseInt(REQUIRED_ENV.PORT, 10),
  corsOrigin: REQUIRED_ENV.CORS_ORIGIN,
  rateLimitWindowMs: parseInt(REQUIRED_ENV.RATE_LIMIT_WINDOW_MS, 10),
  rateLimitMax: parseInt(REQUIRED_ENV.RATE_LIMIT_MAX, 10),
  wsRateLimitWindowMs: parseInt(REQUIRED_ENV.WS_RATE_LIMIT_WINDOW_MS, 10),
  wsRateLimitMax: parseInt(REQUIRED_ENV.WS_RATE_LIMIT_MAX, 10),
  maxMessageLength: parseInt(REQUIRED_ENV.MAX_MESSAGE_LENGTH, 10),
  maxNicknameLength: parseInt(REQUIRED_ENV.MAX_NICKNAME_LENGTH, 10),
  maxRoomNameLength: parseInt(REQUIRED_ENV.MAX_ROOM_NAME_LENGTH, 10),
  messageHistorySize: parseInt(REQUIRED_ENV.MESSAGE_HISTORY_SIZE, 10),
});

for (const [key, value] of Object.entries(CONFIG)) {
  if (typeof value === "number" && isNaN(value)) {
    console.error(`[FATAL] Invalid numeric config for "${key}". Exiting.`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// 2. Validation constants (reused across handlers)
// ---------------------------------------------------------------------------
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NICKNAME_REGEX = /^[a-zA-Z0-9_\-\s]{1,}$/;
const ROOM_NAME_REGEX = /^[a-zA-Z0-9_\-\s]{1,}$/;

// ---------------------------------------------------------------------------
// 3. In-memory storage using Maps — O(1) lookups
// ---------------------------------------------------------------------------

/** @type {Map<string, Room>} roomName → Room */
const rooms = new Map();

/** @type {Map<string, Client>} clientId → Client */
const clients = new Map();

/** @type {Map<import('ws').WebSocket, string>} ws → clientId */
const wsToClient = new Map();

/**
 * @typedef {Object} Message
 * @property {string} id
 * @property {string} clientId
 * @property {string} nickname
 * @property {string} room
 * @property {string} content
 * @property {Date} createdAt
 */

/**
 * @typedef {Object} Room
 * @property {string} name
 * @property {Message[]} history    — kept sorted by createdAt, capped at MESSAGE_HISTORY_SIZE
 * @property {Set<string>} members  — set of clientIds
 * @property {Set<string>} typing   — set of clientIds currently typing
 * @property {Date} createdAt
 */

/**
 * @typedef {Object} Client
 * @property {string} id
 * @property {string} nickname
 * @property {string|null} room
 * @property {import('ws').WebSocket} ws
 * @property {Date} connectedAt
 * @property {number[]} messageTimestamps — for per-client WS rate limiting
 */

// ---------------------------------------------------------------------------
// 4. Input validation / sanitisation helpers
// ---------------------------------------------------------------------------

function sanitizeString(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .trim();
}

function validateNickname(raw) {
  if (typeof raw !== "string") return { ok: false, error: "Nickname must be a string" };
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, error: "Nickname cannot be empty" };
  if (trimmed.length > CONFIG.maxNicknameLength)
    return { ok: false, error: `Nickname exceeds ${CONFIG.maxNicknameLength} characters` };
  if (!NICKNAME_REGEX.test(trimmed))
    return { ok: false, error: "Nickname contains invalid characters (alphanumeric, _, - only)" };
  return { ok: true, value: sanitizeString(trimmed) };
}

function validateRoomName(raw) {
  if (typeof raw !== "string") return { ok: false, error: "Room name must be a string" };
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, error: "Room name cannot be empty" };
  if (trimmed.length > CONFIG.maxRoomNameLength)
    return { ok: false, error: `Room name exceeds ${CONFIG.maxRoomNameLength} characters` };
  if (!ROOM_NAME_REGEX.test(trimmed))
    return { ok: false, error: "Room name contains invalid characters" };
  return { ok: true, value: sanitizeString(trimmed) };
}

function validateMessage(raw) {
  if (typeof raw !== "string") return { ok: false, error: "Message must be a string" };
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, error: "Message cannot be empty" };
  if (trimmed.length > CONFIG.maxMessageLength)
    return { ok: false, error: `Message exceeds ${CONFIG.maxMessageLength} characters` };
  return { ok: true, value: sanitizeString(trimmed) };
}

function validateUUID(raw) {
  if (typeof raw !== "string") return { ok: false, error: "ID must be a string" };
  if (!UUID_REGEX.test(raw)) return { ok: false, error: "Malformed UUID" };
  return { ok: true, value: raw };
}

// ---------------------------------------------------------------------------
// 5. Per-client WebSocket rate limiter
// ---------------------------------------------------------------------------

function isWsRateLimited(client) {
  const now = Date.now();
  // Prune timestamps outside the window
  client.messageTimestamps = client.messageTimestamps.filter(
    (ts) => now - ts < CONFIG.wsRateLimitWindowMs
  );
  if (client.messageTimestamps.length >= CONFIG.wsRateLimitMax) {
    return true;
  }
  client.messageTimestamps.push(now);
  return false;
}

// ---------------------------------------------------------------------------
// 6. Room helpers
// ---------------------------------------------------------------------------

function getOrCreateRoom(name) {
  if (rooms.has(name)) return rooms.get(name);
  const room = {
    name,
    history: [],
    members: new Set(),
    typing: new Set(),
    createdAt: new Date(),
  };
  rooms.set(name, room);
  return room;
}

function addMessageToHistory(room, message) {
  room.history.push(message);
  // Sort by createdAt for stable ordering then cap
  room.history.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
  if (room.history.length > CONFIG.messageHistorySize) {
    room.history = room.history.slice(room.history.length - CONFIG.messageHistorySize);
  }
}

// ---------------------------------------------------------------------------
// 7. Broadcast helpers
// ---------------------------------------------------------------------------

function broadcastToRoom(roomName, payload, excludeClientId = null) {
  const room = rooms.get(roomName);
  if (!room) return;
  const data = JSON.stringify(payload);
  for (const memberId of room.members) {
    if (memberId === excludeClientId) continue;
    const member = clients.get(memberId);
    if (member && member.ws.readyState === member.ws.OPEN) {
      member.ws.send(data);
    }
  }
}

function sendTo(ws, payload) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function sendError(ws, message, code = "ERROR") {
  sendTo(ws, { type: "error", code, message });
}

// ---------------------------------------------------------------------------
// 8. Connection / Disconnection handling
// ---------------------------------------------------------------------------

function handleDisconnect(ws) {
  const clientId = wsToClient.get(ws);
  if (!clientId) return;

  const client = clients.get(clientId);
  if (client && client.room) {
    const room = rooms.get(client.room);
    if (room) {
      room.members.delete(clientId);
      room.typing.delete(clientId);

      broadcastToRoom(client.room, {
        type: "user_disconnected",
        clientId,
        nickname: client.nickname,
        room: client.room,
        timestamp: new Date().toISOString(),
        membersCount: room.members.size,
      });

      // Clean up empty rooms
      if (room.members.size === 0) {
        rooms.delete(client.room);
      }
    }
  }

  clients.delete(clientId);
  wsToClient.delete(ws);
}

// ---------------------------------------------------------------------------
// 9. WebSocket message handlers (by type)
// ---------------------------------------------------------------------------

const messageHandlers = new Map();

// --- JOIN ---
messageHandlers.set("join", (client, data) => {
  const nickResult = validateNickname(data.nickname);
  if (!nickResult.ok) return sendError(client.ws, nickResult.error, "INVALID_NICKNAME");

  const roomResult = validateRoomName(data.room);
  if (!roomResult.ok) return sendError(client.ws, roomResult.error, "INVALID_ROOM");

  // Leave current room if already in one
  if (client.room) {
    const prevRoom = rooms.get(client.room);
    if (prevRoom) {
      prevRoom.members.delete(client.id);
      prevRoom.typing.delete(client.id);
      broadcastToRoom(client.room, {
        type: "user_left",
        clientId: client.id,
        nickname: client.nickname,
        room: client.room,
        timestamp: new Date().toISOString(),
        membersCount: prevRoom.members.size,
      });
      if (prevRoom.members.size === 0) rooms.delete(client.room);
    }
  }

  client.nickname = nickResult.value;
  client.room = roomResult.value;

  const room = getOrCreateRoom(client.room);
  room.members.add(client.id);

  // Send message history to the joining client (sorted by createdAt)
  const sortedHistory = [...room.history].sort(
    (a, b) => a.createdAt.getTime() - b.createdAt.getTime()
  );
  sendTo(client.ws, {
    type: "joined",
    clientId: client.id,
    nickname: client.nickname,
    room: client.room,
    history: sortedHistory.map((m) => ({
      id: m.id,
      clientId: m.clientId,
      nickname: m.nickname,
      content: m.content,
      createdAt: m.createdAt.toISOString(),
    })),
    members: [...room.members].map((mid) => {
      const m = clients.get(mid);
      return m ? { id: m.id, nickname: m.nickname } : null;
    }).filter(Boolean),
    membersCount: room.members.size,
    timestamp: new Date().toISOString(),
  });

  // Notify others
  broadcastToRoom(
    client.room,
    {
      type: "user_joined",
      clientId: client.id,
      nickname: client.nickname,
      room: client.room,
      timestamp: new Date().toISOString(),
      membersCount: room.members.size,
    },
    client.id
  );
});

// --- MESSAGE ---
messageHandlers.set("message", (client, data) => {
  if (!client.room) return sendError(client.ws, "You must join a room first", "NOT_IN_ROOM");

  const msgResult = validateMessage(data.content);
  if (!msgResult.ok) return sendError(client.ws, msgResult.error, "INVALID_MESSAGE");

  const room = rooms.get(client.room);
  if (!room) return sendError(client.ws, "Room not found", "ROOM_NOT_FOUND");

  // Clear typing indicator on message send
  room.typing.delete(client.id);

  const message = {
    id: crypto.randomUUID(),
    clientId: client.id,
    nickname: client.nickname,
    room: client.room,
    content: msgResult.value,
    createdAt: new Date(),
  };

  addMessageToHistory(room, message);

  // Broadcast to entire room including sender
  broadcastToRoom(client.room, {
    type: "message",
    id: message.id,
    clientId: message.clientId,
    nickname: message.nickname,
    room: message.room,
    content: message.content,
    createdAt: message.createdAt.toISOString(),
  });
});

// --- TYPING ---
messageHandlers.set("typing", (client, data) => {
  if (!client.room) return;

  const room = rooms.get(client.room);
  if (!room) return;

  const isTyping = !!data.isTyping;
  if (isTyping) {
    room.typing.add(client.id);
  } else {
    room.typing.delete(client.id);
  }

  broadcastToRoom(
    client.room,
    {
      type: "typing",
      clientId: client.id,
      nickname: client.nickname,
      isTyping,
      typingUsers: [...room.typing]
        .map((tid) => {
          const t = clients.get(tid);
          return t ? { id: t.id, nickname: t.nickname } : null;
        })
        .filter(Boolean),
      timestamp: new Date().toISOString(),
    },
    client.id
  );
});

// --- NICKNAME CHANGE ---
messageHandlers.set("nickname", (client, data) => {
  const nickResult = validateNickname(data.nickname);
  if (!nickResult.ok) return sendError(client.ws, nickResult.error, "INVALID_NICKNAME");

  const oldNickname = client.nickname;
  client.nickname = nickResult.value;

  sendTo(client.ws, {
    type: "nickname_changed",
    clientId: client.id,
    oldNickname,
    newNickname: client.nickname,
    timestamp: new Date().toISOString(),
  });

  if (client.room) {
    broadcastToRoom(
      client.room,
      {
        type: "nickname_changed",
        clientId: client.id,
        oldNickname,
        newNickname: client.nickname,
        timestamp: new Date().toISOString(),
      },
      client.id
    );
  }
});

// --- GET ROOMS ---
messageHandlers.set("get_rooms", (client) => {
  const roomList = [];
  for (const [name, room] of rooms) {
    roomList.push({
      name,
      membersCount: room.members.size,
      createdAt: room.createdAt.toISOString(),
    });
  }
  sendTo(client.ws, { type: "rooms_list", rooms: roomList });
});

// --- GET MEMBERS ---
messageHandlers.set("get_members", (client, data) => {
  const roomResult = validateRoomName(data.room);
  if (!roomResult.ok) return sendError(client.ws, roomResult.error, "INVALID_ROOM");

  const room = rooms.get(roomResult.value);
  if (!room) return sendError(client.ws, "Room not found", "ROOM_NOT_FOUND");

  const members = [...room.members]
    .map((mid) => {
      const m = clients.get(mid);
      return m ? { id: m.id, nickname: m.nickname } : null;
    })
    .filter(Boolean);

  sendTo(client.ws, { type: "members_list", room: roomResult.value, members });
});

// --- PING ---
messageHandlers.set("ping", (client) => {
  sendTo(client.ws, { type: "pong", timestamp: new Date().toISOString() });
});

// ---------------------------------------------------------------------------
// 10. Express app — REST endpoints with security middleware
// ---------------------------------------------------------------------------

const app = express();

// Security middleware applied before route handlers
app.use(helmet());
app.use(
  cors({
    origin: CONFIG.corsOrigin === "*" ? true : CONFIG.corsOrigin.split(","),
  })
);
app.use(express.json({ limit: "16kb" }));

// General rate limiter
const generalLimiter = rateLimit({
  windowMs: CONFIG.rateLimitWindowMs,
  max: CONFIG.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});
app.use(generalLimiter);

// Stricter rate limiter for sensitive endpoints
const strictLimiter = rateLimit({
  windowMs: CONFIG.rateLimitWindowMs,
  max: Math.max(1, Math.floor(CONFIG.rateLimitMax / 5)),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Rate limit exceeded for this endpoint." },
});

// --- Health ---
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    rooms: rooms.size,
    clients: clients.size,
  });
});

// --- List rooms ---
app.get("/api/rooms", (_req, res) => {
  const roomList = [];
  for (const [name, room] of rooms) {
    roomList.push({
      name,
      membersCount: room.members.size,
      createdAt: room.createdAt.toISOString(),
    });
  }
  res.json({ rooms: roomList });
});

// --- Room details (history + members) ---
app.get("/api/rooms/:name", (req, res) => {
  const roomResult = validateRoomName(req.params.name);
  if (!roomResult.ok) return res.status(400).json({ error: roomResult.error });

  const room = rooms.get(roomResult.value);
  if (!room) return res.status(404).json({ error: "Room not found" });

  const sortedHistory = [...room.history].sort(
    (a, b) => a.createdAt.getTime() - b.createdAt.getTime()
  );

  res.json({
    name: room.name,
    membersCount: room.members.size,
    members: [...room.members]
      .map((mid) => {
        const m = clients.get(mid);
        return m ? { id: m.id, nickname: m.nickname } : null;
      })
      .filter(Boolean),
    history: sortedHistory.map((m) => ({
      id: m.id,
      clientId: m.clientId,
      nickname: m.nickname,
      content: m.content,
      createdAt: m.createdAt.toISOString(),
    })),
    createdAt: room.createdAt.toISOString(),
  });
});

// --- Client info ---
app.get("/api/clients/:id", strictLimiter, (req, res) => {
  const idResult = validateUUID(req.params.id);
  if (!idResult.ok) return res.status(400).json({ error: idResult.error });

  const client = clients.get(idResult.value);
  if (!client) return res.status(404).json({ error: "Client not found" });

  res.json({
    id: client.id,
    nickname: client.nickname,
    room: client.room,
    connectedAt: client.connectedAt.toISOString(),
  });
});

// --- Stats ---
app.get("/api/stats", (_req, res) => {
  let totalMessages = 0;
  for (const room of rooms.values()) {
    totalMessages += room.history.length;
  }
  res.json({
    rooms: rooms.size,
    clients: clients.size,
    totalMessagesInHistory: totalMessages,
  });
});

// ---------------------------------------------------------------------------
// 11. Express error handler — differentiated by error type
// ---------------------------------------------------------------------------

app.use((err, _req, res, _next) => {
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON in request body" });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body too large" });
  }
  if (err.name === "SyntaxError") {
    return res.status(400).json({ error: "Malformed request" });
  }
  if (err.status === 404 || err.statusCode === 404) {
    return res.status(404).json({ error: "Not found" });
  }
  console.error("[HTTP Error]", err);
  res.status(500).json({ error: "Internal server error" });
});

// 404 catch-all
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ---------------------------------------------------------------------------
// 12. HTTP Server + WebSocket Server
// ---------------------------------------------------------------------------

const server = http.createServer(app);

const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws, req) => {
  const clientId = crypto.randomUUID();
  const client = {
    id: clientId,
    nickname: `User-${clientId.slice(0, 6)}`,
    room: null,
    ws,
    connectedAt: new Date(),
    messageTimestamps: [],
  };

  clients.set(clientId, client);
  wsToClient.set(ws, clientId);

  // Send welcome with assigned client ID
  sendTo(ws, {
    type: "welcome",
    clientId,
    nickname: client.nickname,
    timestamp: new Date().toISOString(),
  });

  ws.on("message", (raw) => {
    let parsed;
    try {
      parsed = JSON.parse(raw.toString());
    } catch {
      return sendError(ws, "Invalid JSON", "PARSE_ERROR");
    }

    if (!parsed || typeof parsed.type !== "string") {
      return sendError(ws, "Missing 'type' field", "MISSING_TYPE");
    }

    // Per-client WS rate limiting
    if (isWsRateLimited(client)) {
      return sendError(ws, "Too many messages, slow down", "WS_RATE_LIMITED");
    }

    const handler = messageHandlers.get(parsed.type);
    if (!handler) {
      return sendError(ws, `Unknown message type: "${sanitizeString(parsed.type)}"`, "UNKNOWN_TYPE");
    }

    try {
      handler(client, parsed);
    } catch (err) {
      console.error(`[WS Handler Error] type=${parsed.type}`, err);
      sendError(ws, "Internal server error processing your request", "INTERNAL_ERROR");
    }
  });

  ws.on("close", () => handleDisconnect(ws));
  ws.on("error", (err) => {
    console.error(`[WS Error] client=${clientId}`, err.message);
    handleDisconnect(ws);
  });
});

// ---------------------------------------------------------------------------
// 13. Graceful shutdown
// ---------------------------------------------------------------------------

function gracefulShutdown(signal) {
  console.log(`\n[${signal}] Shutting down gracefully...`);

  // Notify all connected clients
  for (const client of clients.values()) {
    sendTo(client.ws, {
      type: "server_shutdown",
      message: "Server is shutting down",
      timestamp: new Date().toISOString(),
    });
    client.ws.close(1001, "Server shutting down");
  }

  wss.close(() => {
    server.close(() => {
      console.log("[Shutdown] Complete.");
      process.exit(0);
    });
  });

  // Force exit after 10s
  setTimeout(() => {
    console.error("[Shutdown] Forced exit after timeout.");
    process.exit(1);
  }, 10000);
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// ---------------------------------------------------------------------------
// 14. Start server
// ---------------------------------------------------------------------------

server.listen(CONFIG.port, () => {
  console.log(`[Chat Server] Listening on port ${CONFIG.port}`);
  console.log(`[Chat Server] WebSocket endpoint: ws://localhost:${CONFIG.port}/ws`);
  console.log(`[Chat Server] REST API: http://localhost:${CONFIG.port}/api`);
  console.log(`[Chat Server] Health: http://localhost:${CONFIG.port}/health`);
});
