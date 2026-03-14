'use strict';

const SECRET_PATTERNS = [
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, // UUIDs
  /sk-[a-zA-Z0-9]{32,}/g,                                              // API keys (sk-...)
  /Bearer\s+[\S]+/g,                                                    // Bearer tokens
  /ghp_[a-zA-Z0-9]{36,}/g,                                             // GitHub PATs
  /wrangler\s+d1\s+execute\s+[^\n]*--command="[^"]*"/g,                 // Wrangler SQL commands
  /ANTHROPIC_API_KEY\s*=\s*[\S]+/g,                                     // Env var assignments
  /password\s*[:=]\s*["'][^"']+["']/gi,                                 // Password literals
];

function sanitize(text) {
  if (!text || typeof text !== 'string') return text || '';
  return SECRET_PATTERNS.reduce((t, p) => t.replace(p, '[REDACTED]'), text);
}

module.exports = { sanitize, SECRET_PATTERNS };
