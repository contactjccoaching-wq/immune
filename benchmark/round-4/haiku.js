const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');

// Configuration with mandatory validation
const PORT = parseInt(process.env.PORT || '8080', 10);
const MAX_MESSAGE_HISTORY = 50;
const TYPING_TIMEOUT = 3000; // ms

// Validation constants
const NICK_REGEX = /^[a-zA-Z0-9_-]{1,20}$/;
const ROOM_REGEX = /^[a-zA-Z0-9_-]{1,50}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MESSAGE_MAX_LENGTH = 5000;

// In-memory storage using Maps (O(1) lookups)
const rooms = new Map(); // roomId -> { users: Map<userId, user>, messages: [], typingUsers: Set }
const users = new Map(); // userId -> { userId, nickname, roomId, ws, connectedAt, typingTimeouts: Map }

// Helper function to generate user ID
function generateUserId() {
  return crypto.randomUUID();
}

// Validate nickname
function validateNickname(nick) {
  return typeof nick === 'string' && NICK_REGEX.test(nick);
}

// Validate room name
function validateRoomName(room) {
  return typeof room === 'string' && ROOM_REGEX.test(room);
}

// Validate message
function validateMessage(msg) {
  return typeof msg === 'string' && msg.length > 0 && msg.length <= MESSAGE_MAX_LENGTH;
}

// Get or create room
function getOrCreateRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      users: new Map(),
      messages: [],
      typingUsers: new Set(),
    });
  }
  return rooms.get(roomId);
}

// Broadcast to room (excluding sender if specified)
function broadcastToRoom(roomId, message, excludeUserId = null) {
  const room = rooms.get(roomId);
  if (!room) return;

  const payload = JSON.stringify(message);
  room.users.forEach((user, userId) => {
    if (excludeUserId && userId === excludeUserId) return;
    if (user.ws.readyState === WebSocket.OPEN) {
      user.ws.send(payload);
    }
  });
}

// Create WebSocket server
const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  res.writeHead(404);
  res.end('Not found');
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  const userId = generateUserId();
  let userNickname = null;
  let userRoom = null;

  // Send initial connection message
  ws.send(JSON.stringify({
    type: 'connected',
    userId,
    message: 'Connected to chat server'
  }));

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());
      const { type, nickname, room, text, typingStatus } = message;

      // Join room
      if (type === 'join') {
        if (!validateNickname(nickname)) {
          ws.send(JSON.stringify({
            type: 'error',
            code: 'INVALID_NICKNAME',
            message: 'Nickname must be 1-20 alphanumeric characters, hyphens or underscores'
          }));
          return;
        }

        if (!validateRoomName(room)) {
          ws.send(JSON.stringify({
            type: 'error',
            code: 'INVALID_ROOM',
            message: 'Room must be 1-50 alphanumeric characters, hyphens or underscores'
          }));
          return;
        }

        // Leave previous room if any
        if (userRoom) {
          const oldRoom = rooms.get(userRoom);
          if (oldRoom) {
            oldRoom.users.delete(userId);
            // Clear typing timeout
            const user = users.get(userId);
            if (user && user.typingTimeouts) {
              user.typingTimeouts.forEach(timeout => clearTimeout(timeout));
              user.typingTimeouts.clear();
            }
            broadcastToRoom(userRoom, {
              type: 'user_left',
              userId,
              nickname: userNickname,
              userCount: oldRoom.users.size
            });
            // Clean up empty rooms
            if (oldRoom.users.size === 0) {
              rooms.delete(userRoom);
            }
          }
        }

        userNickname = nickname;
        userRoom = room;

        // Add user to new room
        const newRoom = getOrCreateRoom(room);
        const userInfo = {
          userId,
          nickname,
          roomId: room,
          ws,
          connectedAt: new Date().toISOString(),
          typingTimeouts: new Map()
        };
        newRoom.users.set(userId, userInfo);
        users.set(userId, userInfo);

        // Send room history to user
        const history = newRoom.messages.slice(-MAX_MESSAGE_HISTORY).map(msg => ({
          type: 'message',
          userId: msg.userId,
          nickname: msg.nickname,
          text: msg.text,
          timestamp: msg.timestamp
        }));

        ws.send(JSON.stringify({
          type: 'joined',
          room,
          userId,
          nickname,
          userCount: newRoom.users.size,
          history,
          timestamp: new Date().toISOString()
        }));

        // Notify others
        broadcastToRoom(room, {
          type: 'user_joined',
          userId,
          nickname,
          userCount: newRoom.users.size,
          timestamp: new Date().toISOString()
        }, userId);

        return;
      }

      // Send message
      if (type === 'message') {
        if (!userRoom || !userNickname) {
          ws.send(JSON.stringify({
            type: 'error',
            code: 'NOT_IN_ROOM',
            message: 'Must join a room first'
          }));
          return;
        }

        if (!validateMessage(text)) {
          ws.send(JSON.stringify({
            type: 'error',
            code: 'INVALID_MESSAGE',
            message: 'Message must be 1-5000 characters'
          }));
          return;
        }

        const room = rooms.get(userRoom);
        if (!room) return;

        // Clear typing status
        room.typingUsers.delete(userId);

        const messageObj = {
          type: 'message',
          userId,
          nickname: userNickname,
          text,
          timestamp: new Date().toISOString()
        };

        // Store message
        room.messages.push(messageObj);
        if (room.messages.length > MAX_MESSAGE_HISTORY) {
          room.messages.shift();
        }

        // Broadcast message
        broadcastToRoom(userRoom, messageObj);
        return;
      }

      // Typing indicator
      if (type === 'typing') {
        if (!userRoom || !userNickname) return;

        const room = rooms.get(userRoom);
        if (!room) return;

        const user = users.get(userId);
        if (!user) return;

        // Clear existing timeout
        if (user.typingTimeouts.has(userId)) {
          clearTimeout(user.typingTimeouts.get(userId));
        }

        if (typingStatus === true) {
          room.typingUsers.add(userId);

          // Auto-clear typing status after timeout
          const timeout = setTimeout(() => {
            room.typingUsers.delete(userId);
            broadcastToRoom(userRoom, {
              type: 'typing',
              userId,
              nickname: userNickname,
              typingStatus: false,
              timestamp: new Date().toISOString()
            });
          }, TYPING_TIMEOUT);

          user.typingTimeouts.set(userId, timeout);

          broadcastToRoom(userRoom, {
            type: 'typing',
            userId,
            nickname: userNickname,
            typingStatus: true,
            timestamp: new Date().toISOString()
          });
        } else {
          room.typingUsers.delete(userId);
          user.typingTimeouts.delete(userId);

          broadcastToRoom(userRoom, {
            type: 'typing',
            userId,
            nickname: userNickname,
            typingStatus: false,
            timestamp: new Date().toISOString()
          });
        }
        return;
      }

      // Get room info
      if (type === 'get_room_info') {
        if (!userRoom) {
          ws.send(JSON.stringify({
            type: 'error',
            code: 'NOT_IN_ROOM',
            message: 'Must join a room first'
          }));
          return;
        }

        const room = rooms.get(userRoom);
        if (!room) return;

        const userList = Array.from(room.users.values()).map(u => ({
          userId: u.userId,
          nickname: u.nickname,
          connectedAt: u.connectedAt,
          isTyping: room.typingUsers.has(u.userId)
        }));

        ws.send(JSON.stringify({
          type: 'room_info',
          room: userRoom,
          userCount: room.users.size,
          users: userList,
          messageCount: room.messages.length,
          timestamp: new Date().toISOString()
        }));
        return;
      }

      ws.send(JSON.stringify({
        type: 'error',
        code: 'UNKNOWN_MESSAGE_TYPE',
        message: `Unknown message type: ${type}`
      }));

    } catch (error) {
      console.error('Message processing error:', error);
      ws.send(JSON.stringify({
        type: 'error',
        code: 'INVALID_JSON',
        message: 'Invalid JSON format'
      }));
    }
  });

  ws.on('close', () => {
    if (userRoom && userNickname) {
      const room = rooms.get(userRoom);
      if (room) {
        room.users.delete(userId);
        const user = users.get(userId);
        if (user && user.typingTimeouts) {
          user.typingTimeouts.forEach(timeout => clearTimeout(timeout));
        }
        room.typingUsers.delete(userId);

        broadcastToRoom(userRoom, {
          type: 'user_left',
          userId,
          nickname: userNickname,
          userCount: room.users.size,
          timestamp: new Date().toISOString()
        });

        // Clean up empty rooms
        if (room.users.size === 0) {
          rooms.delete(userRoom);
        }
      }
    }

    users.delete(userId);
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Chat server listening on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  wss.close(() => {
    server.close(() => {
      process.exit(0);
    });
  });
});

module.exports = { server, wss };
