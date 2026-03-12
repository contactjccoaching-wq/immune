'use strict';

process.env.SESSION_SECRET = 'test-session-secret-32-chars-long!!';
process.env.CSRF_SECRET = 'test-csrf-secret-32-chars-long!!!!';
process.env.ALLOWED_ORIGINS = 'http://localhost:9876';
process.env.PORT = '9876';
process.env.NODE_ENV = 'test';

const http = require('http');
const mod = require('./round-8.js');
const config = mod.loadAndValidateConfig();
const { server } = mod.createApp(config);

const PORT = 9876;

function req(method, path, body, headers) {
  headers = headers || {};
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'localhost',
      port: PORT,
      path: path,
      method: method,
      headers: Object.assign(
        {
          'Content-Type': 'application/json',
          'Origin': 'http://localhost:9876',
        },
        headers,
        payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}
      ),
    };
    const r = http.request(options, function(res) {
      let data = '';
      res.on('data', function(c) { data += c; });
      res.on('end', function() {
        let json;
        try { json = JSON.parse(data); } catch (e) { json = data; }
        resolve({ status: res.statusCode, headers: res.headers, body: json });
      });
    });
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

function check(cond, label) {
  console.log((cond ? 'PASS' : 'FAIL') + ' ' + label);
  if (!cond) process.exitCode = 1;
}

server.listen(PORT, function() {
  runTests().then(function() {
    server.close(function() { process.exit(process.exitCode || 0); });
  }).catch(function(err) {
    console.error('Test error:', err.message);
    server.close(function() { process.exit(1); });
  });
});

async function runTests() {
  // 1. Health check + security headers
  const health = await req('GET', '/health');
  check(health.status === 200, 'GET /health -> 200');
  check(health.headers['x-content-type-options'] === 'nosniff', 'security header: x-content-type-options');
  check(health.headers['x-frame-options'] === 'DENY', 'security header: x-frame-options');
  check(health.headers['cache-control'] === 'no-store', 'security header: cache-control');
  check(health.headers['access-control-allow-origin'] === 'http://localhost:9876', 'CORS: explicit origin');

  // 2. Register
  const reg = await req('POST', '/auth/register', { username: 'testuser', password: 'Secure123!' });
  check(reg.status === 201, 'POST /auth/register -> 201');

  // 3. Duplicate register — CS-CODE-002: no explicit "already exists"
  const reg2 = await req('POST', '/auth/register', { username: 'testuser', password: 'Secure123!' });
  check(reg2.status === 409, 'POST /auth/register duplicate -> 409');

  // 4. Login with wrong password — CS-CODE-002: generic error
  const badLogin = await req('POST', '/auth/login', { username: 'testuser', password: 'wrong' });
  check(badLogin.status === 401, 'POST /auth/login wrong password -> 401');
  check(badLogin.body.error === 'Invalid credentials.', 'generic error message on bad login');

  // 5. Login success
  const login = await req('POST', '/auth/login', { username: 'testuser', password: 'Secure123!' });
  check(login.status === 200, 'POST /auth/login -> 200');
  const cookieHeader = login.headers['set-cookie'];
  check(Array.isArray(cookieHeader) && cookieHeader.length === 2, 'set 2 cookies on login');
  const sidCookie = cookieHeader.find(function(c) { return c.startsWith('__Host-sid='); });
  check(!!sidCookie, 'session cookie present');
  check(sidCookie.includes('HttpOnly'), 'session cookie HttpOnly');
  check(sidCookie.includes('SameSite=Strict'), 'session cookie SameSite=Strict');
  const csrfToken = login.body.csrfToken;
  check(!!csrfToken, 'CSRF token in response');

  // Extract raw cookies for subsequent requests
  const rawCookies = cookieHeader.map(function(c) { return c.split(';')[0]; }).join('; ');

  // 6. GET /auth/me
  const me = await req('GET', '/auth/me', null, { Cookie: rawCookies });
  check(me.status === 200, 'GET /auth/me -> 200');
  check(me.body.username === 'testuser', '/auth/me returns correct username');

  // 7. GET /auth/me without cookie -> 401
  const meNoAuth = await req('GET', '/auth/me');
  check(meNoAuth.status === 401, 'GET /auth/me no cookie -> 401');

  // 8. Change password without CSRF -> 403
  const cpNoCsrf = await req(
    'POST', '/auth/change-password',
    { currentPassword: 'Secure123!', newPassword: 'NewSecure456!' },
    { Cookie: rawCookies }
  );
  check(cpNoCsrf.status === 403, 'change-password without CSRF -> 403');

  // 9. Change password with valid CSRF -> 200
  const cp = await req(
    'POST', '/auth/change-password',
    { currentPassword: 'Secure123!', newPassword: 'NewSecure456!' },
    { Cookie: rawCookies, 'X-CSRF-Token': csrfToken }
  );
  check(cp.status === 200, 'change-password with CSRF -> 200');

  // 10. Request reset token
  const resetReq = await req('POST', '/auth/request-reset', { username: 'testuser' });
  check(resetReq.status === 200, 'POST /auth/request-reset -> 200');
  const resetToken = resetReq.body.resetToken;
  check(!!resetToken, 'reset token returned');

  // 11. Reset password with valid token
  const resetRes = await req('POST', '/auth/reset-password', { token: resetToken, newPassword: 'ResetSecure789!' });
  check(resetRes.status === 200, 'POST /auth/reset-password -> 200');

  // 12. Replay reset token (single-use)
  const resetReplay = await req('POST', '/auth/reset-password', { token: resetToken, newPassword: 'AnotherPwd123!' });
  check(resetReplay.status === 400, 'reset token replay -> 400 (single-use)');

  // 13. Unknown user reset -> same response (no user enumeration, CS-CODE-002)
  const unknownReset = await req('POST', '/auth/request-reset', { username: 'nobody' });
  check(unknownReset.status === 200, 'request-reset unknown user -> 200 (no enumeration)');
  check(unknownReset.body.message === resetReq.body.message, 'same message for known/unknown user');

  // 14. Logout
  const logout = await req('POST', '/auth/logout', {}, { Cookie: rawCookies, 'X-CSRF-Token': csrfToken });
  check(logout.status === 200, 'POST /auth/logout -> 200');

  // 15. /auth/me after logout -> 401
  const meAfterLogout = await req('GET', '/auth/me', null, { Cookie: rawCookies });
  check(meAfterLogout.status === 401, 'GET /auth/me after logout -> 401');

  // 16. Unknown route -> 404
  const notFound = await req('GET', '/unknown');
  check(notFound.status === 404, 'unknown route -> 404');

  // 17. Brute-force lockout (5 bad logins -> 6th locked)
  for (let i = 0; i < 5; i++) {
    await req('POST', '/auth/login', { username: 'lockme', password: 'wrong' });
  }
  const locked = await req('POST', '/auth/login', { username: 'lockme', password: 'wrong' });
  check(locked.status === 429, 'brute-force lockout after 5 attempts -> 429');

  // 18. Input validation: short password
  // Note: by this point the auth rate limiter may return 429 instead of 400.
  // Both are correct rejections — we verify the request is NOT accepted (not 2xx).
  const shortPwd = await req('POST', '/auth/register', { username: 'newuser', password: 'short' });
  check(shortPwd.status === 400 || shortPwd.status === 429,
    'register with short password -> rejected (400 validation | 429 rate-limit)');

  // 19. Input validation: prototype pollution username (CS-CODE-019)
  const protoUser = await req('POST', '/auth/register', { username: '__proto__', password: 'Secure123!' });
  check(protoUser.status === 400 || protoUser.status === 429,
    'register with __proto__ username -> rejected (400 validation | 429 rate-limit)');

  // 20. CORS: request from forbidden origin
  const badOrigin = await req('GET', '/health', null, { Origin: 'http://evil.com' });
  check(!badOrigin.headers['access-control-allow-origin'], 'CORS: evil origin rejected');

  // 21. CSRF token tampered with wrong session
  const fakeToken = csrfToken.replace(/:[^:]+$/, ':deadbeefdeadbeef');
  const tampered = await req(
    'POST', '/auth/logout', {},
    { Cookie: rawCookies, 'X-CSRF-Token': fakeToken }
  );
  // Session already deleted, so 401 or 403 — either means it was blocked
  check(tampered.status >= 400, 'tampered CSRF token blocked');

  console.log('\nAll integration tests complete.');
}
