═══ IMMUNE CHEATSHEET — Code Quality (57 AB + 45 CS) ═══

WINNING STRATEGIES (apply these for best results):

✦ CS-CODE-001: Escape HTML via dedicated function — never use innerHTML with raw user data
✦ CS-CODE-005: Schema validation on data reads with per-field type guards and fallback defaults
✦ CS-CODE-006: Centralized init() function orchestrating all setup from a single entry point
✦ CS-CODE-007: Single centralized state object instead of scattered global variables
✦ CS-CODE-012: Credential-present implies validation-required — if a secret exists in env, endpoint MUST verify it
✦ CS-CODE-013: Fail-closed pattern for secrets — if secret missing from env, reject (don't fall through)
✦ CS-CODE-014: All stored/DB text fields require escapeHtml() before rendering in any response
✦ CS-CODE-015: Query params and path segments treated as hostile — validate type, length, format before use
✦ CS-CODE-016: Auth gate BEFORE cost-bearing or dangerous operations — verify credentials first, then act
✦ CS-CODE-017: Persistent rate limiting via DB/KV instead of in-memory counters (serverless resets on cold start)

KNOWN PITFALLS (avoid these — they WILL be detected):

⚠ AB-CODE-001: Dead code in impossible conditional branches → remove unused code paths
⚠ AB-CODE-002: Duplicated constants across modules (e.g., threshold 85500 vs 85000) → single source of truth
⚠ AB-CODE-003: Sequential API calls in loops → use Promise.all() for independent requests
⚠ AB-CODE-004: Missing HTTP 429 handling → check status, extract Retry-After, implement exponential backoff
⚠ AB-CODE-006: innerHTML/template literals with user data → XSS. Escape ALL user input before HTML insertion
⚠ AB-CODE-008: JSON.parse without try/catch → always wrap with fallback default value
⚠ AB-CODE-010: Unbounded while(true) loops → add max iteration guard (if (i > MAX) break)
⚠ AB-CODE-020: Webhook/callback without HMAC signature verification → verify signature before processing
⚠ AB-CODE-021: Auth function that always returns true / placeholder auth → never have default-true auth path
⚠ AB-CODE-022: Hardcoded fallback credentials in source → use env variables exclusively, fail-closed if missing
⚠ AB-CODE-023: Server-side template XSS — template literals with user data in HTML responses → escape first
⚠ AB-CODE-024: SSRF via fetch() with user-controlled URL → validate against domain allowlist
⚠ AB-CODE-025: Wildcard CORS (Access-Control-Allow-Origin: *) on sensitive endpoints → use explicit origin allowlist
⚠ AB-CODE-026: Cost-bearing API calls without authentication gate → verify auth BEFORE calling external API
⚠ AB-CODE-027: Auth/admin token in URL query parameters → use Authorization header (tokens leak in logs/referrer)
⚠ AB-CODE-028: GET endpoint with write side effects → use POST/PUT/DELETE for mutations
⚠ AB-CODE-029: In-memory rate limiting in serverless → resets on cold start, use persistent storage
⚠ AB-CODE-030: Dynamic SQL column/table names from user input → validate against allowlist (prepared stmts don't protect identifiers)
⚠ AB-CODE-031: Timing-unsafe string comparison for secrets (=== or ==) → use constant-time comparison

═══════════════════════════════════════════════════════
