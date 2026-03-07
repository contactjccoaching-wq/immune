'use strict';

/**
 * Real-time WebSocket chat server
 * Supports: multiple rooms, nicknames, message history (last 50),
 *           typing indicators, connection/disconnection events.
 *
 * Architecture:
 *   RoomManager      — room lifecycle, membership, message history
 *   UserManager      — nickname registry per connection
 *   MessageRouter    — dispatches incoming client messages
 *   ConnectionHandler— manages a single WebSocket connection
 *   ChatServer       — orchestrates startup / shutdown
 */

const WebSocket = require('ws');
const http = require('http');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MESSAGE_HISTORY_LIMIT = 50;

const CLIENT_MSG = {
  JOIN:   'join',
  LEAVE:  'leave',
  CHAT:   'chat',
  TYPING: 'typing',
  NICK:   'nick',
};

const SERVER_MSG = {
  JOINED:       'joined',
  LEFT:         'left',
  CHAT:         'chat',
  HISTORY:      'history',
  TYPING:       'typing',
  NICK_OK:      'nick_ok',
  USER_LIST:    'user_list',
  ERROR:        'error',
  CONNECTED:    'connected',
  DISCONNECTED: 'disconnected',
};

const ERRORS = {
  NICK_REQUIRED:    'A nickname is required before joining a room.',
  NICK_EMPTY:       'Nickname must be a non-empty string.',
  NICK_TOO_LONG:    'Nickname must be 32 characters or fewer.',
  NICK_TAKEN:       'That nickname is already taken in this room.',
  ROOM_EMPTY:       'Room name must be a non-empty string.',
  ROOM_TOO_LONG:    'Room name must be 64 characters or fewer.',
  ROOM_INVALID:     'Room name may only contain letters, numbers, hyphens, and underscores.',
  NOT_IN_ROOM:      'You are not a member of that room.',
  MSG_EMPTY:        'Message text must be a non-empty string.',
  MSG_TOO_LONG:     'Message must be 2000 characters or fewer.',
  UNKNOWN_ACTION:   'Unknown action type.',
  MALFORMED:        'Message must be a JSON object with a "type" field.',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Creates a standardised server-to-client payload.
 * @param {string} type
 * @param {Object} payload
 * @returns {string} JSON string
 */
function buildMessage(type, payload = {}) {
  return JSON.stringify({ type, ts: Date.now(), ...payload });
}

/**
 * Sends a message to a single WebSocket if it is open.
 * @param {WebSocket} ws
 * @param {string} data  Pre-serialised JSON string
 */
function sendTo(ws, data) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(data);
  }
}

/**
 * Validates and normalises a nickname string.
 * Returns { valid: true, value } or { valid: false, error }.
 */
function validateNick(nick) {
  if (typeof nick !== 'string' || nick.trim() === '') {
    return { valid: false, error: ERRORS.NICK_EMPTY };
  }
  const trimmed = nick.trim();
  if (trimmed.length > 32) {
    return { valid: false, error: ERRORS.NICK_TOO_LONG };
  }
  return { valid: true, value: trimmed };
}

/**
 * Validates and normalises a room name string.
 * Returns { valid: true, value } or { valid: false, error }.
 */
function validateRoom(room) {
  if (typeof room !== 'string' || room.trim() === '') {
    return { valid: false, error: ERRORS.ROOM_EMPTY };
  }
  const trimmed = room.trim();
  if (trimmed.length > 64) {
    return { valid: false, error: ERRORS.ROOM_TOO_LONG };
  }
  if (!/^[\w-]+$/.test(trimmed)) {
    return { valid: false, error: ERRORS.ROOM_INVALID };
  }
  return { valid: true, value: trimmed };
}

/**
 * Validates a chat message body.
 * Returns { valid: true, value } or { valid: false, error }.
 */
function validateChatText(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    return { valid: false, error: ERRORS.MSG_EMPTY };
  }
  const trimmed = text.trim();
  if (trimmed.length > 2000) {
    return { valid: false, error: ERRORS.MSG_TOO_LONG };
  }
  return { valid: true, value: trimmed };
}

// ---------------------------------------------------------------------------
// RoomManager
// ---------------------------------------------------------------------------

/**
 * Manages room lifecycle, membership, and per-room message history.
 *
 * Internal shape of a room:
 * {
 *   name:    string,
 *   members: Map<connectionId, { ws, nick }>,
 *   history: Array<{ nick, text, ts }>,           // capped at MESSAGE_HISTORY_LIMIT
 *   typing:  Set<nick>,
 * }
 */
class RoomManager {
  constructor() {
    /** @type {Map<string, Object>} */
    this._rooms = new Map();
  }

  // ---- private helpers ----------------------------------------------------

  _getOrCreate(roomName) {
    if (!this._rooms.has(roomName)) {
      this._rooms.set(roomName, {
        name:    roomName,
        members: new Map(),
        history: [],
        typing:  new Set(),
      });
    }
    return this._rooms.get(roomName);
  }

  _pruneIfEmpty(roomName) {
    const room = this._rooms.get(roomName);
    if (room && room.members.size === 0) {
      this._rooms.delete(roomName);
    }
  }

  // ---- public API ---------------------------------------------------------

  /**
   * Checks whether `nick` is already used by another connection in `roomName`.
   */
  isNickTaken(roomName, nick, connectionId) {
    const room = this._rooms.get(roomName);
    if (!room) return false;
    for (const [cid, member] of room.members) {
      if (cid !== connectionId && member.nick === nick) return true;
    }
    return false;
  }

  /**
   * Adds `connectionId` with `nick`/`ws` to `roomName`.
   * Returns the room's message history snapshot.
   */
  join(roomName, connectionId, nick, ws) {
    const room = this._getOrCreate(roomName);
    room.members.set(connectionId, { ws, nick });
    return [...room.history];
  }

  /**
   * Removes `connectionId` from `roomName`.
   * Returns the nick that was removed, or null if not found.
   */
  leave(roomName, connectionId) {
    const room = this._rooms.get(roomName);
    if (!room) return null;
    const member = room.members.get(connectionId);
    if (!member) return null;
    const { nick } = member;
    room.members.delete(connectionId);
    room.typing.delete(nick);
    this._pruneIfEmpty(roomName);
    return nick;
  }

  /**
   * Removes `connectionId` from every room it is in.
   * Returns an array of { roomName, nick } for each removal.
   */
  leaveAll(connectionId) {
    const departed = [];
    for (const [roomName] of this._rooms) {
      const nick = this.leave(roomName, connectionId);
      if (nick !== null) {
        departed.push({ roomName, nick });
      }
    }
    return departed;
  }

  /**
   * Appends a message to the room history (capped at MESSAGE_HISTORY_LIMIT).
   * Returns the stored message object.
   */
  addMessage(roomName, nick, text) {
    const room = this._rooms.get(roomName);
    if (!room) return null;
    const msg = { nick, text, ts: Date.now() };
    room.history.push(msg);
    if (room.history.length > MESSAGE_HISTORY_LIMIT) {
      room.history.shift();
    }
    return msg;
  }

  /**
   * Updates typing state for `nick` in `roomName`.
   * Returns Set of currently-typing nicks, or null if room missing.
   */
  setTyping(roomName, nick, isTyping) {
    const room = this._rooms.get(roomName);
    if (!room) return null;
    if (isTyping) {
      room.typing.add(nick);
    } else {
      room.typing.delete(nick);
    }
    return new Set(room.typing);
  }

  /**
   * Returns an iterator over open WebSocket connections in `roomName`,
   * optionally excluding one connectionId.
   */
  *membersOf(roomName, excludeConnectionId = null) {
    const room = this._rooms.get(roomName);
    if (!room) return;
    for (const [cid, member] of room.members) {
      if (cid !== excludeConnectionId) {
        yield member;
      }
    }
  }

  /**
   * Returns an array of nicks currently in `roomName`.
   */
  getNicks(roomName) {
    const room = this._rooms.get(roomName);
    if (!room) return [];
    return Array.from(room.members.values()).map(m => m.nick);
  }

  /**
   * Returns whether `connectionId` is in `roomName`.
   */
  isMember(roomName, connectionId) {
    const room = this._rooms.get(roomName);
    return room ? room.members.has(connectionId) : false;
  }
}

// ---------------------------------------------------------------------------
// UserManager
// ---------------------------------------------------------------------------

/**
 * Tracks the per-connection nickname (set before any room is joined).
 */
class UserManager {
  constructor() {
    /** @type {Map<string, string>} connectionId → nick */
    this._nicks = new Map();
  }

  setNick(connectionId, nick) {
    this._nicks.set(connectionId, nick);
  }

  getNick(connectionId) {
    return this._nicks.get(connectionId) ?? null;
  }

  remove(connectionId) {
    this._nicks.delete(connectionId);
  }
}

// ---------------------------------------------------------------------------
// MessageRouter
// ---------------------------------------------------------------------------

/**
 * Parses raw WebSocket data and dispatches to the correct handler method.
 */
class MessageRouter {
  /**
   * @param {RoomManager}  roomManager
   * @param {UserManager}  userManager
   */
  constructor(roomManager, userManager) {
    this._rooms = roomManager;
    this._users = userManager;
  }

  /**
   * Entry point: parse raw text, validate shape, dispatch.
   * @param {string}    rawData
   * @param {string}    connectionId
   * @param {WebSocket} ws
   */
  route(rawData, connectionId, ws) {
    let msg;
    try {
      msg = JSON.parse(rawData);
    } catch (_) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.MALFORMED }));
      return;
    }

    if (typeof msg !== 'object' || msg === null || typeof msg.type !== 'string') {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.MALFORMED }));
      return;
    }

    switch (msg.type) {
      case CLIENT_MSG.NICK:   this._handleNick(msg, connectionId, ws);   break;
      case CLIENT_MSG.JOIN:   this._handleJoin(msg, connectionId, ws);   break;
      case CLIENT_MSG.LEAVE:  this._handleLeave(msg, connectionId, ws);  break;
      case CLIENT_MSG.CHAT:   this._handleChat(msg, connectionId, ws);   break;
      case CLIENT_MSG.TYPING: this._handleTyping(msg, connectionId, ws); break;
      default:
        sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.UNKNOWN_ACTION }));
    }
  }

  // ---- handlers -----------------------------------------------------------

  _handleNick(msg, connectionId, ws) {
    const v = validateNick(msg.nick);
    if (!v.valid) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: v.error }));
      return;
    }
    this._users.setNick(connectionId, v.value);
    sendTo(ws, buildMessage(SERVER_MSG.NICK_OK, { nick: v.value }));
  }

  _handleJoin(msg, connectionId, ws) {
    const nick = this._users.getNick(connectionId);
    if (!nick) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.NICK_REQUIRED }));
      return;
    }

    const rv = validateRoom(msg.room);
    if (!rv.valid) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: rv.error }));
      return;
    }
    const roomName = rv.value;

    if (this._rooms.isNickTaken(roomName, nick, connectionId)) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.NICK_TAKEN }));
      return;
    }

    // Already in the room — idempotent, just resend history
    if (this._rooms.isMember(roomName, connectionId)) {
      const history = this._rooms.join(roomName, connectionId, nick, ws);
      sendTo(ws, buildMessage(SERVER_MSG.HISTORY, { room: roomName, messages: history }));
      return;
    }

    const history = this._rooms.join(roomName, connectionId, nick, ws);

    // Send history to the joiner
    sendTo(ws, buildMessage(SERVER_MSG.HISTORY, { room: roomName, messages: history }));

    // Broadcast join event to everyone in the room (including joiner)
    const nicks = this._rooms.getNicks(roomName);
    const joinMsg = buildMessage(SERVER_MSG.JOINED, { room: roomName, nick, users: nicks });
    for (const member of this._rooms.membersOf(roomName)) {
      sendTo(member.ws, joinMsg);
    }
  }

  _handleLeave(msg, connectionId, ws) {
    const rv = validateRoom(msg.room);
    if (!rv.valid) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: rv.error }));
      return;
    }
    const roomName = rv.value;

    if (!this._rooms.isMember(roomName, connectionId)) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.NOT_IN_ROOM }));
      return;
    }

    const nick = this._rooms.leave(roomName, connectionId);
    const nicks = this._rooms.getNicks(roomName);
    const leaveMsg = buildMessage(SERVER_MSG.LEFT, { room: roomName, nick, users: nicks });

    // Notify remaining members
    for (const member of this._rooms.membersOf(roomName)) {
      sendTo(member.ws, leaveMsg);
    }
    // Confirm to the leaver
    sendTo(ws, leaveMsg);
  }

  _handleChat(msg, connectionId, ws) {
    const nick = this._users.getNick(connectionId);
    if (!nick) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.NICK_REQUIRED }));
      return;
    }

    const rv = validateRoom(msg.room);
    if (!rv.valid) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: rv.error }));
      return;
    }
    const roomName = rv.value;

    if (!this._rooms.isMember(roomName, connectionId)) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: ERRORS.NOT_IN_ROOM }));
      return;
    }

    const tv = validateChatText(msg.text);
    if (!tv.valid) {
      sendTo(ws, buildMessage(SERVER_MSG.ERROR, { error: tv.error }));
      return;
    }

    // Clear typing state for sender
    this._rooms.setTyping(roomName, nick, false);

    const stored = this._rooms.addMessage(roomName, nick, tv.value);
    const chatMsg = buildMessage(SERVER_MSG.CHAT, {
      room: roomName,
      nick,
      text: stored.text,
      ts:   stored.ts,
    });

    for (const member of this._rooms.membersOf(roomName)) {
      sendTo(member.ws, chatMsg);
    }
  }

  _handleTyping(msg, connectionId, ws) {
    const nick = this._users.getNick(connectionId);
    if (!nick) return; // silently ignore typing before nick is set

    const rv = validateRoom(msg.room);
    if (!rv.valid) return; // silently ignore invalid room for typing

    const roomName = rv.value;
    if (!this._rooms.isMember(roomName, connectionId)) return;

    const isTyping = Boolean(msg.typing);
    const typingSet = this._rooms.setTyping(roomName, nick, isTyping);
    if (typingSet === null) return;

    const typingMsg = buildMessage(SERVER_MSG.TYPING, {
      room:   roomName,
      nick,
      typing: isTyping,
      typers: Array.from(typingSet),
    });

    // Broadcast to everyone except the sender
    for (const member of this._rooms.membersOf(roomName, connectionId)) {
      sendTo(member.ws, typingMsg);
    }
  }
}

// ---------------------------------------------------------------------------
// ConnectionHandler
// ---------------------------------------------------------------------------

let _nextId = 1;

/**
 * Represents a single WebSocket connection.
 * Wires up lifecycle events and delegates messages to the router.
 */
class ConnectionHandler {
  /**
   * @param {WebSocket}     ws
   * @param {MessageRouter} router
   * @param {RoomManager}   roomManager
   * @param {UserManager}   userManager
   */
  constructor(ws, router, roomManager, userManager) {
    this._ws          = ws;
    this._router      = router;
    this._rooms       = roomManager;
    this._users       = userManager;
    this._id          = String(_nextId++);

    this._attach();
  }

  _attach() {
    // Inform the client of its connection id
    sendTo(this._ws, buildMessage(SERVER_MSG.CONNECTED, { connectionId: this._id }));

    this._ws.on('message', (data) => {
      try {
        this._router.route(data.toString(), this._id, this._ws);
      } catch (err) {
        console.error(`[conn:${this._id}] Unhandled error in route():`, err);
        sendTo(this._ws, buildMessage(SERVER_MSG.ERROR, { error: 'Internal server error.' }));
      }
    });

    this._ws.on('close', () => this._handleClose());
    this._ws.on('error', (err) => this._handleError(err));
  }

  _handleClose() {
    const departed = this._rooms.leaveAll(this._id);
    this._users.remove(this._id);

    // Notify remaining room members of the disconnection
    for (const { roomName, nick } of departed) {
      const nicks = this._rooms.getNicks(roomName);
      const leftMsg = buildMessage(SERVER_MSG.DISCONNECTED, {
        room:  roomName,
        nick,
        users: nicks,
      });
      for (const member of this._rooms.membersOf(roomName)) {
        sendTo(member.ws, leftMsg);
      }
    }
  }

  _handleError(err) {
    console.error(`[conn:${this._id}] WebSocket error:`, err.message);
  }
}

// ---------------------------------------------------------------------------
// ChatServer
// ---------------------------------------------------------------------------

/**
 * Top-level orchestrator.  Creates the HTTP + WebSocket servers,
 * wires up all subsystems, handles graceful shutdown.
 */
class ChatServer {
  /**
   * @param {{ port?: number, host?: string }} [options]
   */
  constructor(options = {}) {
    this._port = options.port ?? 3000;
    this._host = options.host ?? '0.0.0.0';

    this._roomManager  = new RoomManager();
    this._userManager  = new UserManager();
    this._router       = new MessageRouter(this._roomManager, this._userManager);

    this._httpServer = null;
    this._wsServer   = null;
  }

  start() {
    this._httpServer = http.createServer(this._handleHttpRequest.bind(this));
    this._wsServer   = new WebSocket.Server({ server: this._httpServer });

    this._wsServer.on('connection', (ws) => {
      new ConnectionHandler(ws, this._router, this._roomManager, this._userManager);
    });

    this._wsServer.on('error', (err) => {
      console.error('[wss] Server error:', err.message);
    });

    this._httpServer.listen(this._port, this._host, () => {
      console.log(`[chat] WebSocket server listening on ws://${this._host}:${this._port}`);
    });

    this._registerShutdownHandlers();
  }

  /**
   * Minimal HTTP handler — returns server status for health checks.
   */
  _handleHttpRequest(req, res) {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', clients: this._wsServer.clients.size }));
      return;
    }
    res.writeHead(426, { 'Content-Type': 'text/plain' });
    res.end('Upgrade Required — connect via WebSocket.');
  }

  /**
   * Gracefully closes all connections and the HTTP server.
   */
  stop(callback) {
    console.log('[chat] Shutting down...');
    for (const ws of this._wsServer.clients) {
      ws.terminate();
    }
    this._wsServer.close(() => {
      this._httpServer.close(() => {
        console.log('[chat] Server stopped.');
        if (typeof callback === 'function') callback();
      });
    });
  }

  _registerShutdownHandlers() {
    const shutdown = (signal) => {
      console.log(`\n[chat] Received ${signal}.`);
      this.stop(() => process.exit(0));
    };
    process.once('SIGINT',  () => shutdown('SIGINT'));
    process.once('SIGTERM', () => shutdown('SIGTERM'));
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

if (require.main === module) {
  const port = parseInt(process.env.PORT ?? '3000', 10);
  const server = new ChatServer({ port });
  server.start();
}

module.exports = { ChatServer, RoomManager, UserManager, MessageRouter };
