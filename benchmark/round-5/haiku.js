const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Configuration & validation
const requiredEnvVars = [
  'THIRD_PARTY_API_KEY',
  'THIRD_PARTY_API_URL',
  'RATE_LIMIT_WINDOW_MS',
  'RATE_LIMIT_MAX_REQUESTS',
  'CACHE_TTL_MS',
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}

const CONFIG = {
  apiKey: process.env.THIRD_PARTY_API_KEY,
  apiKeys: (process.env.THIRD_PARTY_API_KEYS || process.env.THIRD_PARTY_API_KEY)
    .split(',')
    .map((k) => k.trim()),
  apiUrl: process.env.THIRD_PARTY_API_URL,
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000'),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  cacheTtlMs: parseInt(process.env.CACHE_TTL_MS || '300000'),
  circuitBreakerThreshold: parseInt(process.env.CIRCUIT_BREAKER_THRESHOLD || '5'),
  circuitBreakerResetMs: parseInt(process.env.CIRCUIT_BREAKER_RESET_MS || '60000'),
};

// In-memory cache & rate limiting
const responseCache = new Map();
const requestHistory = new Map();
const currentApiKeyIndex = { value: 0 };
const circuitBreaker = {
  state: 'CLOSED',
  failureCount: 0,
  lastFailureTime: null,
  successCount: 0,
};

function getCacheKey(method, path, params) {
  return `${method}:${path}:${JSON.stringify(params || {})}`;
}

function getCachedResponse(cacheKey) {
  const cached = responseCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.data;
  }
  if (cached) {
    responseCache.delete(cacheKey);
  }
  return null;
}

function setCachedResponse(cacheKey, data) {
  responseCache.set(cacheKey, {
    data,
    expiresAt: Date.now() + CONFIG.cacheTtlMs,
  });
}

function isRateLimited(clientId) {
  const now = Date.now();
  const windowStart = now - CONFIG.rateLimitWindowMs;

  if (!requestHistory.has(clientId)) {
    requestHistory.set(clientId, []);
  }

  const history = requestHistory.get(clientId);
  const validRequests = history.filter((t) => t > windowStart);

  if (validRequests.length >= CONFIG.rateLimitMaxRequests) {
    return true;
  }

  validRequests.push(now);
  requestHistory.set(clientId, validRequests);
  return false;
}

// API key rotation
function getNextApiKey() {
  const key = CONFIG.apiKeys[currentApiKeyIndex.value];
  currentApiKeyIndex.value = (currentApiKeyIndex.value + 1) % CONFIG.apiKeys.length;
  return key;
}

function rotateApiKey() {
  console.log(`[KEY_ROTATION] Rotating API key (index: ${currentApiKeyIndex.value})`);
  return getNextApiKey();
}

// Circuit breaker
function checkCircuitBreaker() {
  if (circuitBreaker.state === 'CLOSED') return true;

  if (circuitBreaker.state === 'OPEN') {
    const timeSinceLastFailure = Date.now() - circuitBreaker.lastFailureTime;
    if (timeSinceLastFailure > CONFIG.circuitBreakerResetMs) {
      circuitBreaker.state = 'HALF_OPEN';
      circuitBreaker.successCount = 0;
      return true;
    }
    return false;
  }

  return true;
}

function recordCircuitBreakerSuccess() {
  if (circuitBreaker.state === 'HALF_OPEN') {
    circuitBreaker.successCount++;
    if (circuitBreaker.successCount >= 3) {
      circuitBreaker.state = 'CLOSED';
      circuitBreaker.failureCount = 0;
    }
  }
}

function recordCircuitBreakerFailure() {
  circuitBreaker.failureCount++;
  circuitBreaker.lastFailureTime = Date.now();
  if (circuitBreaker.failureCount >= CONFIG.circuitBreakerThreshold) {
    circuitBreaker.state = 'OPEN';
  }
}

// Proxy function
async function proxyRequest(method, path, params, apiKey) {
  const url = `${CONFIG.apiUrl}${path}`;
  const options = {
    method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
  };

  if (method !== 'GET' && params) {
    options.body = JSON.stringify(params);
  }

  const response = await fetch(url, options);

  if (response.status === 401) {
    throw new Error('UNAUTHORIZED_401');
  }

  if (!response.ok) {
    throw new Error(`API_ERROR_${response.status}`);
  }

  return await response.json();
}

// Express setup
const app = express();

app.use(helmet());
app.use(cors());

const globalLimiter = rateLimit({
  windowMs: CONFIG.rateLimitWindowMs,
  max: CONFIG.rateLimitMaxRequests,
  message: 'Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: CONFIG.rateLimitWindowMs,
  max: Math.floor(CONFIG.rateLimitMaxRequests / 2),
  message: 'Too many requests on this endpoint.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);
app.use(express.json({ limit: '10mb' }));

// Validation
const VALIDATION_RULES = {
  pathMinLength: 1,
  pathMaxLength: 500,
  uuidRegex: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
};

function validatePath(path) {
  return path && path.length >= VALIDATION_RULES.pathMinLength && path.length <= VALIDATION_RULES.pathMaxLength;
}

// Routes
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    circuitBreakerState: circuitBreaker.state,
    cacheSize: responseCache.size,
  });
});

app.get('/metrics', (req, res) => {
  res.json({
    cacheSize: responseCache.size,
    requestHistorySize: requestHistory.size,
    circuitBreaker: {
      state: circuitBreaker.state,
      failureCount: circuitBreaker.failureCount,
      lastFailureTime: circuitBreaker.lastFailureTime,
    },
    timestamp: new Date().toISOString(),
  });
});

app.all('/proxy/:method/*', strictLimiter, async (req, res) => {
  const requestId = crypto.randomUUID();
  const clientId = req.ip || 'unknown';

  try {
    const method = req.params.method.toUpperCase();
    if (!['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      return res.status(400).json({ error: 'Invalid HTTP method', requestId });
    }

    const path = '/' + req.params[0];
    if (!validatePath(path)) {
      return res.status(400).json({ error: 'Invalid path', requestId });
    }

    if (isRateLimited(clientId)) {
      return res.status(429).json({ error: 'Rate limit exceeded', requestId });
    }

    if (!checkCircuitBreaker()) {
      return res.status(503).json({ error: 'Service unavailable - circuit breaker open', requestId });
    }

    const params = req.body || {};
    const cacheKey = getCacheKey(method, path, params);
    const cachedResponse = getCachedResponse(cacheKey);
    if (cachedResponse) {
      return res.json({ data: cachedResponse, cached: true, requestId });
    }

    let apiKey = CONFIG.apiKeys[currentApiKeyIndex.value];
    let response;
    let retryCount = 0;

    while (retryCount < CONFIG.apiKeys.length) {
      try {
        response = await proxyRequest(method, path, params, apiKey);
        recordCircuitBreakerSuccess();
        break;
      } catch (error) {
        if (error.message === 'UNAUTHORIZED_401') {
          apiKey = rotateApiKey();
          retryCount++;
        } else {
          recordCircuitBreakerFailure();
          throw error;
        }
      }
    }

    if (!response) {
      return res.status(401).json({ error: 'All API keys exhausted', requestId });
    }

    setCachedResponse(cacheKey, response);
    res.json({ data: response, cached: false, requestId });
  } catch (error) {
    console.error(`[ERROR] Request ${requestId}:`, error.message);
    recordCircuitBreakerFailure();

    if (error.message.includes('API_ERROR_') || error.message === 'UNAUTHORIZED_401') {
      return res.status(502).json({ error: 'Bad gateway - upstream API error', requestId });
    }

    res.status(500).json({ error: 'Internal server error', requestId });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[GLOBAL_ERROR]', err.message);

  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON', requestId: crypto.randomUUID() });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large', requestId: crypto.randomUUID() });
  }

  res.status(500).json({ error: 'Internal server error', requestId: crypto.randomUUID() });
});

// Graceful shutdown
const server = app.listen(process.env.PORT || 3000, () => {
  console.log(`[STARTUP] API Proxy listening on port ${process.env.PORT || 3000}`);
});

process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] SIGTERM received');
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  console.log('[SHUTDOWN] SIGINT received');
  server.close(() => process.exit(0));
});

module.exports = app;
