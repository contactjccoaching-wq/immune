const http = require('http');
const { WebSocketServer } = require('ws');
const crypto = require('crypto');

// ─── Config validation ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['*'];

// ─── Validation constants ────────────────────────────────────────────────────
const NICKNAME_MIN = 1;
const NICKNAME_MAX = 32;
const ROOM_NAME_MIN = 1;
const ROOM_NAME_MAX = 64;
const MESSAGE_MAX = 2000;
const HISTORY_LIMIT = 50;
const TYPING_DEBOUNCE_MS = 3000;

// Rate limiting constants
const CONNECT_RATE_WINDOW_MS = 60_000;
const CONNECT_RATE_LIMIT = 20;
const MESSAGE_RATE_WINDOW_MS = 1_000;
const MESSAGE_RATE_LIMIT = 10;

// ─── In-memory storage (Map for O(1) lookups) ────────────────────────────────
// rooms: Map<roomName, { clients: Map<clientId, ws>, history: Message[], typing: Map<clientId, timer> }>
const rooms = new Map();

// clients: Map<clientId, { ws, nickname, roomName, messageCount, messageWindowStart }>
const clients = new Map();

// IP-based connection rate limiter: Map<ip, { count, windowStart }>
const connectRateMap = new Map();

// ─── Helpers ─────────────────────────────────────────────────────────────────
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').trim();
}

function validateNickname(nickname) {
  const clean = sanitizeString(nickname);
  if (clean.length < NICKNAME_MIN || clean.length > NICKNAME_MAX) {
    return { valid: false, error: `Nickname must be ${NICKNAME_MIN}-${NICKNAME_MAX} chars` };
  }
  if (!/^[\w\- ]+$/.test(clean)) {
    return { valid: false, error: 'Nickname contains invalid characters' };
  }
  return { valid: true, value: clean };
}

function validateRoomName(name) {
  const clean = sanitizeString(name);
  if (clean.length < ROOM_NAME_MIN || clean.length > ROOM_NAME_MAX) {
    return { valid: false, error: `Room name must be ${ROOM_NAME_MIN}-${ROOM_NAME_MAX} chars` };
  }
  if (!/^[\w\-]+$/.test(clean)) {
    return { valid: false, error: 'Room name may only contain letters, digits, hyphens, underscores' };
  }
  return { valid: true, value: clean };
}

function validateMessage(text) {
  if (typeof text !== 'string') return { valid: false, error: 'Message must be a string' };
  const clean = text.trim();
  if (clean.length === 0) return { valid: false, error: 'Message cannot be empty' };
  if (clean.length > MESSAGE_MAX) return { valid: false, error: `Message exceeds ${MESSAGE_MAX} chars` };
  return { valid: true, value: clean };
}

function checkConnectRate(ip) {
  const now = Date.now();
  let entry = connectRateMap.get(ip);
  if (!entry || now - entry.windowStart > CONNECT_RATE_WINDOW_MS) {
    entry = { count: 0, windowStart: now };
    connectRateMap.set(ip, entry);
  }
  entry.count++;
  return entry.count <= CONNECT_RATE_LIMIT;
}

function checkMessageRate(clientId) {
  const client = clients.get(clientId);
  if (!client) return false;
  const now = Date.now();
  if (now - client.messageWindowStart > MESSAGE_RATE_WINDOW_MS) {
    client.messageCount = 0;
    client.messageWindowStart = now;
  }
  client.messageCount++;
  return client.messageCount <= MESSAGE_RATE_LIMIT;
}

function getOrCreateRoom(roomName) {
  if (!rooms.has(roomName)) {
    rooms.set(roomName, {
      clients: new Map(),
      history: [],
      typing: new Map(),
    });
  }
  return rooms.get(roomName);
}

function addToHistory(room, message) {
  room.history.push(message);
  if (room.history.length > HISTORY_LIMIT) {
    // Sort by createdAt for stable order before slicing
    room.history.sort((a, b) => a.createdAt - b.createdAt);
    room.history = room.history.slice(room.history.length - HISTORY_LIMIT);
  }
}

function broadcast(room, payload, excludeClientId = null) {
  const data = JSON.stringify(payload);
  for (const [clientId, ws] of room.clients) {
    if (clientId === excludeClientId) continue;
    if (ws.readyState === ws.OPEN) {
      ws.send(data);
    }
  }
}

function sendToClient(ws, payload) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function sendError(ws, code, message) {
  sendToClient(ws, { type: 'error', code, message });
}

function clearTyping(room, clientId) {
  const timer = room.typing.get(clientId);
  if (timer) {
    clearTimeout(timer);
    room.typing.delete(clientId);
  }
}

function leaveRoom(clientId) {
  const client = clients.get(clientId);
  if (!client || !client.roomName) return;
  const room = rooms.get(client.roomName);
  if (!room) return;

  clearTyping(room, clientId);
  room.clients.delete(clientId);

  broadcast(room, {
    type: 'user_left',
    clientId,
    nickname: client.nickname,
    timestamp: Date.now(),
    onlineCount: room.clients.size,
  });

  // Clean up empty rooms
  if (room.clients.size === 0) {
    rooms.delete(client.roomName);
  }

  client.roomName = null;
}

// ─── HTTP server (for health check + origin validation) ──────────────────────
const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', rooms: rooms.size, clients: clients.size }));
    return;
  }
  res.writeHead(404);
  res.end('Not found');
});

// ─── WebSocket server ─────────────────────────────────────────────────────────
const wss = new WebSocketServer({
  server,
  verifyClient({ req }, done) {
    // CORS-style origin check
    const origin = req.headers.origin;
    if (ALLOWED_ORIGINS.includes('*') || !origin || ALLOWED_ORIGINS.includes(origin)) {
      // Connection rate limiting by IP
      const ip = req.socket.remoteAddress || 'unknown';
      if (!checkConnectRate(ip)) {
        done(false, 429, 'Too Many Connections');
        return;
      }
      done(true);
    } else {
      done(false, 403, 'Origin not allowed');
    }
  },
});

wss.on('connection', (ws, req) => {
  const clientId = crypto.randomUUID();
  const ip = req.socket.remoteAddress || 'unknown';

  clients.set(clientId, {
    ws,
    nickname: null,
    roomName: null,
    messageCount: 0,
    messageWindowStart: Date.now(),
    ip,
  });

  // Send welcome with assigned clientId
  sendToClient(ws, { type: 'welcome', clientId });

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      sendError(ws, 'INVALID_JSON', 'Message must be valid JSON');
      return;
    }

    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') {
      sendError(ws, 'INVALID_FORMAT', 'Message must have a string "type" field');
      return;
    }

    handleMessage(clientId, ws, msg);
  });

  ws.on('close', () => {
    leaveRoom(clientId);
    clients.delete(clientId);
  });

  ws.on('error', (err) => {
    // Log but don't crash
    console.error(`[ws] client ${clientId} error:`, err.message);
  });
});

// ─── Message handler ──────────────────────────────────────────────────────────
function handleMessage(clientId, ws, msg) {
  const client = clients.get(clientId);
  if (!client) return;

  switch (msg.type) {

    // ── JOIN: set nickname and enter room ─────────────────────────────────────
    case 'join': {
      const nickResult = validateNickname(msg.nickname);
      if (!nickResult.valid) {
        sendError(ws, 'INVALID_NICKNAME', nickResult.error);
        return;
      }
      const roomResult = validateRoomName(msg.room);
      if (!roomResult.valid) {
        sendError(ws, 'INVALID_ROOM', roomResult.error);
        return;
      }

      // Leave current room if in one
      if (client.roomName) {
        leaveRoom(clientId);
      }

      client.nickname = nickResult.value;
      client.roomName = roomResult.value;

      const room = getOrCreateRoom(roomResult.value);
      room.clients.set(clientId, ws);

      // Send history sorted by createdAt
      const sortedHistory = [...room.history].sort((a, b) => a.createdAt - b.createdAt);
      sendToClient(ws, {
        type: 'room_joined',
        room: roomResult.value,
        nickname: nickResult.value,
        clientId,
        history: sortedHistory,
        onlineCount: room.clients.size,
      });

      // Notify others
      broadcast(room, {
        type: 'user_joined',
        clientId,
        nickname: nickResult.value,
        timestamp: Date.now(),
        onlineCount: room.clients.size,
      }, clientId);

      break;
    }

    // ── MESSAGE: send to room ─────────────────────────────────────────────────
    case 'message': {
      if (!client.roomName) {
        sendError(ws, 'NOT_IN_ROOM', 'Join a room before sending messages');
        return;
      }

      // Differentiated rate limit for messages (stricter)
      if (!checkMessageRate(clientId)) {
        sendError(ws, 'RATE_LIMITED', 'Sending too fast — slow down');
        return;
      }

      const msgResult = validateMessage(msg.text);
      if (!msgResult.valid) {
        sendError(ws, 'INVALID_MESSAGE', msgResult.error);
        return;
      }

      const room = rooms.get(client.roomName);
      if (!room) return;

      // Clear any typing indicator
      clearTyping(room, clientId);

      const message = {
        id: crypto.randomUUID(),
        clientId,
        nickname: client.nickname,
        text: msgResult.value,
        createdAt: Date.now(),
        room: client.roomName,
      };

      addToHistory(room, message);

      broadcast(room, { type: 'message', ...message });
      break;
    }

    // ── TYPING: broadcast typing indicator with auto-clear ────────────────────
    case 'typing': {
      if (!client.roomName) return;
      const room = rooms.get(client.roomName);
      if (!room) return;

      // Reset debounce timer
      clearTyping(room, clientId);

      broadcast(room, {
        type: 'typing',
        clientId,
        nickname: client.nickname,
        timestamp: Date.now(),
      }, clientId);

      // Auto-clear typing after debounce window
      const timer = setTimeout(() => {
        room.typing.delete(clientId);
        broadcast(room, {
          type: 'stopped_typing',
          clientId,
          nickname: client.nickname,
          timestamp: Date.now(),
        }, clientId);
      }, TYPING_DEBOUNCE_MS);

      room.typing.set(clientId, timer);
      break;
    }

    // ── LEAVE: leave current room ─────────────────────────────────────────────
    case 'leave': {
      if (!client.roomName) {
        sendError(ws, 'NOT_IN_ROOM', 'You are not in any room');
        return;
      }
      leaveRoom(clientId);
      sendToClient(ws, { type: 'left_room', timestamp: Date.now() });
      break;
    }

    // ── LIST_ROOMS: send available room names and counts ──────────────────────
    case 'list_rooms': {
      const roomList = [];
      for (const [name, room] of rooms) {
        roomList.push({ name, onlineCount: room.clients.size });
      }
      sendToClient(ws, { type: 'room_list', rooms: roomList });
      break;
    }

    default:
      sendError(ws, 'UNKNOWN_TYPE', `Unknown message type: ${msg.type}`);
  }
}

// ─── Periodic cleanup of stale rate limit entries ────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of connectRateMap) {
    if (now - entry.windowStart > CONNECT_RATE_WINDOW_MS * 2) {
      connectRateMap.delete(ip);
    }
  }
}, CONNECT_RATE_WINDOW_MS);

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, HOST, () => {
  console.log(`[server] WebSocket chat server listening on ws://${HOST}:${PORT}`);
  console.log(`[server] Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
});
