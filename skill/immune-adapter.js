#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const lockfile = require('proper-lockfile');

const { sanitize } = require('./sanitizer');

const IMMUNE_DIR = __dirname;
const DB_PATH = path.join(IMMUNE_DIR, 'immune.sqlite');
const JSON_AB = path.join(IMMUNE_DIR, 'immune_memory.json');
const JSON_CS = path.join(IMMUNE_DIR, 'cheatsheet_memory.json');
const MIGRATION_FILE = path.join(IMMUNE_DIR, 'migration_state.json');
const CONTEXT_DIR = path.join(IMMUNE_DIR, 'context');
const ARCHIVE_DIR = path.join(CONTEXT_DIR, 'archive');
const MEMORY_MD = path.join(IMMUNE_DIR, '..', '..', 'projects', 'C--Users-kiki', 'memory', 'MEMORY.md');
const USER_MD = path.join(IMMUNE_DIR, 'USER.md');
const ARCHIVE_AB = path.join(IMMUNE_DIR, 'archived_antibodies.json');
const ARCHIVE_CS = path.join(IMMUNE_DIR, 'archived_strategies.json');
const LOCK_FILE = DB_PATH + '.lock';
const MAX_CHUNKS = 2000;
const RETENTION_DAYS = 90;
const LIMITS = { max_antibodies: 500, max_strategies: 300, max_sqlite_mb: 50, max_context_files: 500 };

// ── Helpers ─────────────────────────────────────────────

function today() { return new Date().toISOString().slice(0, 10); }

function daysDiff(dateStr) {
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86400000);
}

function readJSON(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return null; }
}

function writeJSON(p, data) {
  fs.writeFileSync(p, JSON.stringify(data, null, 2), 'utf8');
}

function ensureLockFile() {
  if (!fs.existsSync(LOCK_FILE)) fs.writeFileSync(LOCK_FILE, '', 'utf8');
}

function getMigrationState() {
  let state = readJSON(MIGRATION_FILE);
  if (!state) {
    state = { version: '4.0.0', phase: 1, started: today(), sessions_in_phase: 0,
              sessions_required: 10, parity_passed: 0, last_parity: null,
              frozen: false, frozen_since: null, total_frozen_days: 0 };
    writeJSON(MIGRATION_FILE, state);
  }
  // Ensure freeze fields exist (migration from older state files)
  if (state.frozen === undefined) {
    state.frozen = false;
    state.frozen_since = null;
    state.total_frozen_days = 0;
    writeJSON(MIGRATION_FILE, state);
  }
  return state;
}

function getFrozenDays() {
  const state = getMigrationState();
  let frozen = state.total_frozen_days || 0;
  // If currently frozen, add days since freeze started
  if (state.frozen && state.frozen_since) {
    frozen += daysDiff(state.frozen_since);
  }
  return frozen;
}

// Adjusted daysDiff that subtracts frozen time
function daysDiffAdjusted(dateStr) {
  return Math.max(0, daysDiff(dateStr) - getFrozenDays());
}

// ── Hot/Cold Classification ─────────────────────────────

function isHotAntibody(ab) {
  if (ab.severity === 'critical') return true;
  if (ab.seen_count >= 3) return true;
  if (ab.last_seen && daysDiffAdjusted(ab.last_seen) < 30) return true;
  return false;
}

function isHotStrategy(cs) {
  if (cs.effectiveness >= 0.7) return true;
  if (cs.seen_count >= 3) return true;
  if (cs.last_seen && daysDiffAdjusted(cs.last_seen) < 30) return true;
  return false;
}

function domainMatch(itemDomains, targetDomains) {
  const d = Array.isArray(itemDomains) ? itemDomains : [itemDomains || '_global'];
  return d.some(x => targetDomains.includes(x) || x === '_global');
}

// ── JSON Operations ─────────────────────────────────────

function loadAntibodies() {
  const data = readJSON(JSON_AB);
  if (!data) return { version: 4, antibodies: [], stats: { outputs_checked: 0, issues_caught: 0, antibodies_total: 0 } };
  // v2 migration
  if (data.version === 2) {
    data.antibodies.forEach(ab => { if (ab.domain && !ab.domains) { ab.domains = [ab.domain]; delete ab.domain; } });
    data.version = 3;
    writeJSON(JSON_AB, data);
  }
  return data;
}

function loadStrategies() {
  const data = readJSON(JSON_CS);
  if (!data) return { version: 4, strategies: [], stats: { outputs_assisted: 0, strategies_applied: 0, strategies_total: 0 } };
  return data;
}

// ── SQLite Operations ───────────────────────────────────

let _db = null;

async function getDB() {
  if (_db) return _db;
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    _db = new SQL.Database(buf);
  } else {
    _db = new SQL.Database();
  }
  initSchema(_db);
  return _db;
}

function initSchema(db) {
  db.run(`CREATE TABLE IF NOT EXISTS antibodies (
    id TEXT PRIMARY KEY, domains TEXT NOT NULL, pattern TEXT NOT NULL,
    severity TEXT NOT NULL, correction TEXT NOT NULL,
    seen_count INTEGER DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    quality_gate INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS strategies (
    id TEXT PRIMARY KEY, domains TEXT NOT NULL, pattern TEXT NOT NULL,
    example TEXT, effectiveness REAL DEFAULT 0.5,
    seen_count INTEGER DEFAULT 1, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    quality_gate INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS session_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL, type TEXT NOT NULL,
    domains TEXT, summary TEXT NOT NULL, details TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS stats (key TEXT PRIMARY KEY, value TEXT)`);
  // FTS5 — catch error if already exists with different schema
  try {
    db.run(`CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts4(
      text, source_type, source_id, domains, tokenize=porter
    )`);
  } catch (e) {
    // FTS5 table exists with compatible schema
  }
}

function saveDB(db) {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

function syncToSQLite(db, antibodies, strategies) {
  // Upsert antibodies
  const stmtAb = db.prepare(`INSERT OR REPLACE INTO antibodies
    (id, domains, pattern, severity, correction, seen_count, first_seen, last_seen, quality_gate)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  for (const ab of antibodies) {
    const domains = JSON.stringify(Array.isArray(ab.domains) ? ab.domains : [ab.domains || '_global']);
    stmtAb.run([ab.id, domains, ab.pattern, ab.severity, ab.correction,
                ab.seen_count || 1, ab.first_seen || today(), ab.last_seen || today(), ab.quality_gate || 0]);
  }
  stmtAb.free();

  // Upsert strategies
  const stmtCs = db.prepare(`INSERT OR REPLACE INTO strategies
    (id, domains, pattern, example, effectiveness, seen_count, first_seen, last_seen, quality_gate)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  for (const cs of strategies) {
    const domains = JSON.stringify(Array.isArray(cs.domains) ? cs.domains : [cs.domains || '_global']);
    stmtCs.run([cs.id, domains, cs.pattern, cs.example || '', cs.effectiveness || 0.5,
                cs.seen_count || 1, cs.first_seen || today(), cs.last_seen || today(), cs.quality_gate || 0]);
  }
  stmtCs.free();
}

function rebuildFTS(db) {
  db.run(`DELETE FROM chunks_fts`);
  let count = 0;
  const stmt = db.prepare(`INSERT INTO chunks_fts (text, source_type, source_id, domains) VALUES (?, ?, ?, ?)`);
  // Index antibodies
  const abs = db.prepare(`SELECT id, domains, pattern, correction FROM antibodies`);
  while (abs.step()) {
    if (count >= MAX_CHUNKS) break;
    const row = abs.getAsObject();
    stmt.run([`${row.pattern} ${row.correction}`, 'antibody', row.id, row.domains]);
    count++;
  }
  abs.free();
  // Index strategies
  const css = db.prepare(`SELECT id, domains, pattern, example FROM strategies`);
  while (css.step()) {
    if (count >= MAX_CHUNKS) break;
    const row = css.getAsObject();
    stmt.run([`${row.pattern} ${row.example || ''}`, 'strategy', row.id, row.domains]);
    count++;
  }
  css.free();
  stmt.free();
  return count;
}

// ── Commands ────────────────────────────────────────────

async function cmdGetAntibodies(args) {
  const domains = JSON.parse(args.domains || '["_global"]');
  const tier = args.tier || 'hot';
  const limit = parseInt(args.limit) || 15;

  const data = loadAntibodies();
  let filtered = data.antibodies.filter(ab => domainMatch(ab.domains, domains));

  if (tier === 'hot') {
    filtered = filtered.filter(isHotAntibody);
    filtered.sort((a, b) => {
      const sev = { critical: 3, warning: 2, info: 1 };
      const sa = sev[a.severity] || 0, sb = sev[b.severity] || 0;
      if (sa !== sb) return sb - sa;
      return (b.seen_count || 0) - (a.seen_count || 0);
    });
    filtered = filtered.slice(0, limit);
  } else if (tier === 'cold') {
    filtered = filtered.filter(ab => !isHotAntibody(ab));
  }
  // tier === 'all' → no filter

  return { count: filtered.length, antibodies: filtered };
}

async function cmdGetStrategies(args) {
  const domains = JSON.parse(args.domains || '["_global"]');
  const tier = args.tier || 'hot';
  const limit = parseInt(args.limit) || 15;

  const data = loadStrategies();
  let filtered = data.strategies.filter(cs => domainMatch(cs.domains, domains));

  if (tier === 'hot') {
    filtered = filtered.filter(isHotStrategy);
    filtered.sort((a, b) => (b.effectiveness || 0) - (a.effectiveness || 0));
    filtered = filtered.slice(0, limit);
  } else if (tier === 'cold') {
    filtered = filtered.filter(cs => !isHotStrategy(cs));
  }

  return { count: filtered.length, strategies: filtered };
}

async function cmdAddAntibody(args) {
  const ab = JSON.parse(args.json);
  if (!ab.id || !ab.pattern || !ab.severity || !ab.correction) {
    return { error: 'Missing required fields: id, pattern, severity, correction' };
  }
  if (!ab.domains) ab.domains = ['_global'];
  if (!ab.seen_count) ab.seen_count = 1;
  if (!ab.first_seen) ab.first_seen = today();
  if (!ab.last_seen) ab.last_seen = today();

  // Write to JSON
  const data = loadAntibodies();
  const idx = data.antibodies.findIndex(x => x.id === ab.id);
  if (idx >= 0) data.antibodies[idx] = ab;
  else data.antibodies.push(ab);
  data.stats.antibodies_total = data.antibodies.length;
  writeJSON(JSON_AB, data);

  // Write to SQLite (dual-write)
  const db = await getDB();
  syncToSQLite(db, [ab], []);
  saveDB(db);

  return { ok: true, id: ab.id, total: data.antibodies.length };
}

async function cmdAddStrategy(args) {
  const cs = JSON.parse(args.json);
  if (!cs.id || !cs.pattern) {
    return { error: 'Missing required fields: id, pattern' };
  }
  if (!cs.domains) cs.domains = ['_global'];
  if (!cs.effectiveness) cs.effectiveness = 0.5;
  if (!cs.seen_count) cs.seen_count = 1;
  if (!cs.first_seen) cs.first_seen = today();
  if (!cs.last_seen) cs.last_seen = today();

  const data = loadStrategies();
  const idx = data.strategies.findIndex(x => x.id === cs.id);
  if (idx >= 0) data.strategies[idx] = cs;
  else data.strategies.push(cs);
  data.stats.strategies_total = data.strategies.length;
  writeJSON(JSON_CS, data);

  const db = await getDB();
  syncToSQLite(db, [], [cs]);
  saveDB(db);

  return { ok: true, id: cs.id, total: data.strategies.length };
}

async function cmdImport(args) {
  if (!args.file) return { error: 'Usage: import --file <path.immune.json>' };
  const fs = require('fs');
  const content = fs.readFileSync(args.file, 'utf-8');
  const pack = JSON.parse(content);

  let abCount = 0, csCount = 0;

  if (pack.antibodies && Array.isArray(pack.antibodies)) {
    const abData = loadAntibodies();
    for (const ab of pack.antibodies) {
      if (!ab.id || !ab.pattern) continue;
      if (!ab.domains) ab.domains = ['_global'];
      if (!ab.seen_count) ab.seen_count = 1;
      if (!ab.first_seen) ab.first_seen = today();
      if (!ab.last_seen) ab.last_seen = today();
      const idx = abData.antibodies.findIndex(x => x.id === ab.id);
      if (idx >= 0) abData.antibodies[idx] = ab;
      else abData.antibodies.push(ab);
      abCount++;
    }
    abData.stats.antibodies_total = abData.antibodies.length;
    writeJSON(JSON_AB, abData);
    const db = await getDB();
    syncToSQLite(db, pack.antibodies, []);
    saveDB(db);
  }

  if (pack.strategies && Array.isArray(pack.strategies)) {
    const csData = loadStrategies();
    for (const cs of pack.strategies) {
      if (!cs.id || !cs.pattern) continue;
      if (!cs.domains) cs.domains = ['_global'];
      if (!cs.effectiveness) cs.effectiveness = 0.5;
      if (!cs.seen_count) cs.seen_count = 1;
      if (!cs.first_seen) cs.first_seen = today();
      if (!cs.last_seen) cs.last_seen = today();
      const idx = csData.strategies.findIndex(x => x.id === cs.id);
      if (idx >= 0) csData.strategies[idx] = cs;
      else csData.strategies.push(cs);
      csCount++;
    }
    csData.stats.strategies_total = csData.strategies.length;
    writeJSON(JSON_CS, csData);
    const db = await getDB();
    syncToSQLite(db, [], pack.strategies);
    saveDB(db);
  }

  return { ok: true, imported: { antibodies: abCount, strategies: csCount } };
}

async function cmdUpdateAntibody(args) {
  const data = loadAntibodies();
  const ab = data.antibodies.find(x => x.id === args.id);
  if (!ab) return { error: `Antibody ${args.id} not found` };

  if (args.seen_count) ab.seen_count = parseInt(args.seen_count);
  if (args.last_seen) ab.last_seen = args.last_seen;
  if (args.increment_seen) ab.seen_count = (ab.seen_count || 0) + 1;
  writeJSON(JSON_AB, data);

  const db = await getDB();
  syncToSQLite(db, [ab], []);
  saveDB(db);

  return { ok: true, id: ab.id, seen_count: ab.seen_count, last_seen: ab.last_seen };
}

async function cmdUpdateStrategy(args) {
  const data = loadStrategies();
  const cs = data.strategies.find(x => x.id === args.id);
  if (!cs) return { error: `Strategy ${args.id} not found` };

  if (args.seen_count) cs.seen_count = parseInt(args.seen_count);
  if (args.last_seen) cs.last_seen = args.last_seen;
  if (args.effectiveness) cs.effectiveness = parseFloat(args.effectiveness);
  if (args.increment_seen) cs.seen_count = (cs.seen_count || 0) + 1;
  writeJSON(JSON_CS, data);

  const db = await getDB();
  syncToSQLite(db, [], [cs]);
  saveDB(db);

  return { ok: true, id: cs.id, seen_count: cs.seen_count, effectiveness: cs.effectiveness };
}

async function cmdSearch(args) {
  const query = args.query;
  const type = args.type || 'all';
  const limit = parseInt(args.limit) || 10;

  const db = await getDB();
  // Check if FTS has data
  const countRes = db.exec(`SELECT count(*) FROM chunks_fts`);
  if (!countRes.length || countRes[0].values[0][0] === 0) {
    // Index first
    const abData = loadAntibodies();
    const csData = loadStrategies();
    syncToSQLite(db, abData.antibodies, csData.strategies);
    rebuildFTS(db);
    saveDB(db);
  }

  let sql = `SELECT source_type, source_id, snippet(chunks_fts, '>>>', '<<<', '...') as snippet
             FROM chunks_fts WHERE chunks_fts MATCH ?`;
  const params = [query];

  if (type !== 'all') {
    sql += ` AND source_type = ?`;
    params.push(type === 'antibodies' ? 'antibody' : 'strategy');
  }
  sql += ` LIMIT ?`;
  params.push(limit);

  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    const row = stmt.getAsObject();
    results.push({ source_type: row.source_type, source_id: row.source_id,
                   snippet: row.snippet });
  }
  stmt.free();

  return { count: results.length, results };
}

async function cmdIndex(args) {
  const db = await getDB();
  const abData = loadAntibodies();
  const csData = loadStrategies();
  syncToSQLite(db, abData.antibodies, csData.strategies);
  const count = rebuildFTS(db);
  saveDB(db);
  return { ok: true, chunks_indexed: count, antibodies: abData.antibodies.length,
           strategies: csData.strategies.length };
}

async function cmdStats() {
  const abData = loadAntibodies();
  const csData = loadStrategies();
  const migration = getMigrationState();
  return {
    antibodies: { total: abData.antibodies.length, ...abData.stats },
    strategies: { total: csData.strategies.length, ...csData.stats },
    migration
  };
}

async function cmdMigrateStatus() {
  return getMigrationState();
}

async function cmdMigrateAdvance() {
  const state = getMigrationState();
  if (state.phase >= 3) return { ok: false, message: 'Already at phase 3 (final)' };
  state.phase++;
  state.sessions_in_phase = 0;
  state.last_parity = today();
  writeJSON(MIGRATION_FILE, state);
  return { ok: true, phase: state.phase, message: `Advanced to phase ${state.phase}` };
}

async function cmdIntegrityCheck() {
  try {
    const db = await getDB();
    const res = db.exec(`PRAGMA integrity_check`);
    const ok = res.length && res[0].values[0][0] === 'ok';
    return { ok, result: res.length ? res[0].values[0][0] : 'empty' };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ── ContextMemory Commands ──────────────────────────────

async function cmdLogSession(args) {
  const date = args.date || today();
  const domains = args.domains || '["_global"]';
  const result = args.result || 'clean';
  const summary = args.summary || '';
  const score = args.score ? parseInt(args.score) : null;

  // Write to context/YYYY-MM-DD.md (append)
  if (!fs.existsSync(CONTEXT_DIR)) fs.mkdirSync(CONTEXT_DIR, { recursive: true });
  const logFile = path.join(CONTEXT_DIR, `${date}.md`);
  const timestamp = new Date().toISOString().slice(11, 19);
  const entry = `\n## ${timestamp} | ${result} | domains=${domains}${score !== null ? ` | score=${score}` : ''}\n${summary}\n`;
  fs.appendFileSync(logFile, entry, 'utf8');

  // Write to SQLite session_logs
  const db = await getDB();
  db.run(`INSERT INTO session_logs (date, type, domains, summary, details) VALUES (?, ?, ?, ?, ?)`,
    [date, result, domains, summary, args.details || '']);
  saveDB(db);

  // Index into FTS4
  const sanitized = sanitize(summary);
  const stmt = db.prepare(`INSERT INTO chunks_fts (text, source_type, source_id, domains) VALUES (?, ?, ?, ?)`);
  stmt.run([sanitized, 'session', `session-${date}-${timestamp}`, domains]);
  stmt.free();
  saveDB(db);

  return { ok: true, file: logFile, date, result };
}

async function cmdGetContext(args) {
  const query = args.query;
  const days = parseInt(args.days) || 90;
  const limit = parseInt(args.limit) || 5;

  const db = await getDB();

  // Search session_logs via FTS4
  const cutoff = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  let sql = `SELECT source_type, source_id, snippet(chunks_fts, '>>>', '<<<', '...') as snippet
             FROM chunks_fts WHERE chunks_fts MATCH ? AND source_type = 'session' LIMIT ?`;
  const stmt = db.prepare(sql);
  stmt.bind([query, limit]);
  const results = [];
  while (stmt.step()) {
    const row = stmt.getAsObject();
    results.push({ source_id: row.source_id, snippet: row.snippet });
  }
  stmt.free();

  // Also search session_logs table for date filtering
  const logs = db.prepare(`SELECT date, type, domains, summary FROM session_logs
    WHERE date >= ? ORDER BY date DESC LIMIT ?`);
  logs.bind([cutoff, limit]);
  const recentLogs = [];
  while (logs.step()) {
    recentLogs.push(logs.getAsObject());
  }
  logs.free();

  return { count: results.length, results, recent_logs: recentLogs };
}

async function cmdIndexContext() {
  const db = await getDB();
  let count = 0;
  const stmt = db.prepare(`INSERT INTO chunks_fts (text, source_type, source_id, domains) VALUES (?, ?, ?, ?)`);

  // Index MEMORY.md if it exists
  if (fs.existsSync(MEMORY_MD)) {
    const content = sanitize(fs.readFileSync(MEMORY_MD, 'utf8'));
    // Chunk into ~400 token blocks (~1600 chars)
    const chunks = chunkText(content, 1600);
    for (const [i, chunk] of chunks.entries()) {
      stmt.run([chunk, 'memory_md', `memory-md-${i}`, '["_global"]']);
      count++;
    }
  }

  // Index USER.md if it exists
  if (fs.existsSync(USER_MD)) {
    const content = sanitize(fs.readFileSync(USER_MD, 'utf8'));
    const chunks = chunkText(content, 1600);
    for (const [i, chunk] of chunks.entries()) {
      stmt.run([chunk, 'user_md', `user-md-${i}`, '["_global"]']);
      count++;
    }
  }

  // Index context/*.md files
  if (fs.existsSync(CONTEXT_DIR)) {
    const files = fs.readdirSync(CONTEXT_DIR).filter(f => f.endsWith('.md'));
    for (const file of files) {
      const content = sanitize(fs.readFileSync(path.join(CONTEXT_DIR, file), 'utf8'));
      const chunks = chunkText(content, 1600);
      for (const [i, chunk] of chunks.entries()) {
        stmt.run([chunk, 'context', `ctx-${file}-${i}`, '["_global"]']);
        count++;
      }
    }
  }
  stmt.free();
  saveDB(db);

  return { ok: true, chunks_indexed: count };
}

function chunkText(text, maxChars) {
  const chunks = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + maxChars, text.length);
    // Try to break at newline
    if (end < text.length) {
      const nl = text.lastIndexOf('\n', end);
      if (nl > start + maxChars * 0.5) end = nl + 1;
    }
    chunks.push(text.slice(start, end));
    start = end;
  }
  return chunks;
}

async function cmdRetentionCleanup() {
  if (!fs.existsSync(CONTEXT_DIR)) return { ok: true, archived: 0 };
  if (!fs.existsSync(ARCHIVE_DIR)) fs.mkdirSync(ARCHIVE_DIR, { recursive: true });

  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86400000).toISOString().slice(0, 10);
  const files = fs.readdirSync(CONTEXT_DIR).filter(f => f.endsWith('.md'));
  let archived = 0;

  for (const file of files) {
    const dateMatch = file.match(/^(\d{4}-\d{2}-\d{2})\.md$/);
    if (dateMatch && dateMatch[1] < cutoff) {
      fs.renameSync(path.join(CONTEXT_DIR, file), path.join(ARCHIVE_DIR, file));
      archived++;
    }
  }

  return { ok: true, archived, cutoff };
}

// ── Score Command ───────────────────────────────────────

async function cmdScore(args) {
  const domains = JSON.parse(args.domains || '["_global"]');
  const corrections = parseInt(args.corrections) || 0;
  const threats = parseInt(args.threats) || 0;
  const severities = args.severities ? JSON.parse(args.severities) : [];
  // severities: array of {severity, count}

  // Base 100, deductions
  let score = 100;
  let deductions = [];
  for (const s of severities) {
    const pts = s.severity === 'critical' ? 20 : s.severity === 'warning' ? 10 : 5;
    const total = pts * (s.count || 1);
    score -= total;
    deductions.push({ severity: s.severity, count: s.count, points: -total });
  }
  score = Math.max(0, score);

  // Domain normalization via Welford's online algorithm
  const db = await getDB();
  const domainKey = domains.sort().join(',');
  const baselineRow = db.exec(`SELECT value FROM stats WHERE key = 'baseline_${domainKey}'`);

  let baseline = { mean: 75, std: 10, n: 0, threshold: 65 };
  if (baselineRow.length && baselineRow[0].values[0][0]) {
    try { baseline = JSON.parse(baselineRow[0].values[0][0]); } catch {}
  }

  // Welford update
  baseline.n++;
  const delta = score - baseline.mean;
  baseline.mean += delta / baseline.n;
  const delta2 = score - baseline.mean;
  if (!baseline._m2) baseline._m2 = 0;
  baseline._m2 += delta * delta2;
  baseline.std = baseline.n > 1 ? Math.sqrt(baseline._m2 / (baseline.n - 1)) : 10;
  baseline.threshold = Math.max(0, baseline.mean - baseline.std);

  // Z-score
  const z = baseline.std > 0 ? (score - baseline.mean) / baseline.std : 0;
  const pass = score >= baseline.threshold;

  // Save updated baseline
  db.run(`INSERT OR REPLACE INTO stats (key, value) VALUES (?, ?)`,
    [`baseline_${domainKey}`, JSON.stringify(baseline)]);
  saveDB(db);

  return {
    score, pass, z: Math.round(z * 100) / 100,
    baseline: { mean: Math.round(baseline.mean * 10) / 10, std: Math.round(baseline.std * 10) / 10,
                threshold: Math.round(baseline.threshold * 10) / 10, n: baseline.n },
    deductions
  };
}

// ── Flush Pre-Compaction ────────────────────────────────

async function cmdFlushPending(args) {
  const pending = JSON.parse(args.json || '{"antibodies":[],"strategies":[]}');
  const flushed = { antibodies: 0, strategies: 0, rejected: [] };

  const db = await getDB();

  // Quality gate for antibodies
  for (const ab of (pending.antibodies || [])) {
    const reject = qualityGate(ab, 'antibody');
    if (reject) { flushed.rejected.push({ id: ab.id, reason: reject }); continue; }

    // FTS4 duplicate check
    const dup = checkFTSDuplicate(db, ab.pattern, 'antibody');
    if (dup) { flushed.rejected.push({ id: ab.id, reason: `duplicate of ${dup}` }); continue; }

    ab.quality_gate = 1;
    ab.first_seen = ab.first_seen || today();
    ab.last_seen = ab.last_seen || today();
    ab.seen_count = ab.seen_count || 1;
    if (!ab.domains) ab.domains = ['_global'];

    // Write to JSON
    const data = loadAntibodies();
    const idx = data.antibodies.findIndex(x => x.id === ab.id);
    if (idx >= 0) data.antibodies[idx] = ab;
    else data.antibodies.push(ab);
    data.stats.antibodies_total = data.antibodies.length;
    writeJSON(JSON_AB, data);

    // Write to SQLite
    syncToSQLite(db, [ab], []);
    flushed.antibodies++;
  }

  // Quality gate for strategies
  for (const cs of (pending.strategies || [])) {
    const reject = qualityGate(cs, 'strategy');
    if (reject) { flushed.rejected.push({ id: cs.id, reason: reject }); continue; }

    const dup = checkFTSDuplicate(db, cs.pattern, 'strategy');
    if (dup) { flushed.rejected.push({ id: cs.id, reason: `duplicate of ${dup}` }); continue; }

    cs.quality_gate = 1;
    cs.first_seen = cs.first_seen || today();
    cs.last_seen = cs.last_seen || today();
    cs.seen_count = cs.seen_count || 1;
    cs.effectiveness = cs.effectiveness || 0.5;
    if (!cs.domains) cs.domains = ['_global'];

    const data = loadStrategies();
    const idx = data.strategies.findIndex(x => x.id === cs.id);
    if (idx >= 0) data.strategies[idx] = cs;
    else data.strategies.push(cs);
    data.stats.strategies_total = data.strategies.length;
    writeJSON(JSON_CS, data);

    syncToSQLite(db, [], [cs]);
    flushed.strategies++;
  }

  // Rebuild FTS after flush
  rebuildFTS(db);
  saveDB(db);

  return { ok: true, flushed, total_ab: loadAntibodies().antibodies.length,
           total_cs: loadStrategies().strategies.length };
}

function qualityGate(item, type) {
  if (!item.id) return 'missing id';
  if (!item.pattern || item.pattern.length < 20) return 'pattern too short (min 20 chars)';
  if (type === 'antibody') {
    if (!item.severity) return 'missing severity';
    if (!item.correction) return 'missing correction';
  }
  return null;
}

function checkFTSDuplicate(db, pattern, type) {
  // Extract first 3 significant words for FTS match
  const words = pattern.split(/\s+/).filter(w => w.length > 3).slice(0, 3).join(' ');
  if (!words) return null;
  try {
    const stmt = db.prepare(`SELECT source_id FROM chunks_fts
      WHERE chunks_fts MATCH ? AND source_type = ? LIMIT 1`);
    stmt.bind([words, type]);
    if (stmt.step()) {
      const id = stmt.getAsObject().source_id;
      stmt.free();
      return id;
    }
    stmt.free();
  } catch {}
  return null;
}

// ── Housekeeping ────────────────────────────────────────

async function cmdFreeze() {
  const state = getMigrationState();
  if (state.frozen) return { ok: false, message: `Already frozen since ${state.frozen_since}` };
  state.frozen = true;
  state.frozen_since = today();
  writeJSON(MIGRATION_FILE, state);
  return { ok: true, message: `Frozen. All aging clocks paused. Run 'unfreeze' to resume.`, frozen_since: state.frozen_since };
}

async function cmdUnfreeze() {
  const state = getMigrationState();
  if (!state.frozen) return { ok: false, message: 'Not frozen' };
  const frozenDays = daysDiff(state.frozen_since);
  state.total_frozen_days = (state.total_frozen_days || 0) + frozenDays;
  state.frozen = false;
  state.frozen_since = null;
  writeJSON(MIGRATION_FILE, state);
  return { ok: true, message: `Unfrozen. ${frozenDays} days were frozen (total: ${state.total_frozen_days}d). Clocks resumed.`,
           frozen_days_added: frozenDays, total_frozen_days: state.total_frozen_days };
}

async function cmdHousekeep() {
  // Block housekeep if frozen
  const freezeState = getMigrationState();
  if (freezeState.frozen) {
    return { ok: false, message: `System is frozen since ${freezeState.frozen_since}. Run 'unfreeze' first.` };
  }

  const report = { archived_ab: 0, archived_cs: 0, context_archived: 0, warnings: [] };

  // --- Check limits ---
  const abData = loadAntibodies();
  const csData = loadStrategies();

  // SQLite size check
  if (fs.existsSync(DB_PATH)) {
    const sizeMB = fs.statSync(DB_PATH).size / (1024 * 1024);
    if (sizeMB > LIMITS.max_sqlite_mb) {
      report.warnings.push(`SQLite size ${sizeMB.toFixed(1)}MB exceeds limit ${LIMITS.max_sqlite_mb}MB`);
    }
  }

  // Context files check
  if (fs.existsSync(CONTEXT_DIR)) {
    const ctxFiles = fs.readdirSync(CONTEXT_DIR).filter(f => f.endsWith('.md'));
    if (ctxFiles.length > LIMITS.max_context_files) {
      // Archive oldest beyond limit
      if (!fs.existsSync(ARCHIVE_DIR)) fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
      const sorted = ctxFiles.sort();
      const toArchive = sorted.slice(0, ctxFiles.length - LIMITS.max_context_files);
      for (const f of toArchive) {
        fs.renameSync(path.join(CONTEXT_DIR, f), path.join(ARCHIVE_DIR, f));
        report.context_archived++;
      }
    }
  }

  // --- Archive useless antibodies (COLD + severity!=critical + seen_count<=1 + >180 days old) ---
  if (abData.antibodies.length > LIMITS.max_antibodies) {
    const candidates = abData.antibodies.filter(ab =>
      !isHotAntibody(ab) &&
      ab.severity !== 'critical' &&
      (ab.seen_count || 1) <= 1 &&
      ab.last_seen && daysDiffAdjusted(ab.last_seen) > 180
    );

    // Sort by last_seen ascending (oldest first), archive enough to get under limit
    candidates.sort((a, b) => (a.last_seen || '').localeCompare(b.last_seen || ''));
    const excess = abData.antibodies.length - LIMITS.max_antibodies;
    const toArchive = candidates.slice(0, Math.max(excess, 0));

    if (toArchive.length > 0) {
      // Load or create archive file
      let archive = readJSON(ARCHIVE_AB) || { archived: [], archived_at: [] };
      const archiveIds = new Set(toArchive.map(a => a.id));

      for (const ab of toArchive) {
        archive.archived.push(ab);
        archive.archived_at.push({ id: ab.id, date: today(), reason: 'housekeep: never-useful (COLD, seen<=1, >180d, non-critical)' });
      }
      writeJSON(ARCHIVE_AB, archive);

      // Remove from active list
      abData.antibodies = abData.antibodies.filter(ab => !archiveIds.has(ab.id));
      abData.stats.antibodies_total = abData.antibodies.length;
      writeJSON(JSON_AB, abData);
      report.archived_ab = toArchive.length;
    }

    if (abData.antibodies.length > LIMITS.max_antibodies) {
      report.warnings.push(`Still ${abData.antibodies.length} antibodies after archival (limit: ${LIMITS.max_antibodies}). No more safe candidates.`);
    }
  }

  // --- Archive useless strategies (COLD + seen_count<=1 + effectiveness<0.3 + >180 days old) ---
  if (csData.strategies.length > LIMITS.max_strategies) {
    const candidates = csData.strategies.filter(cs =>
      !isHotStrategy(cs) &&
      (cs.seen_count || 1) <= 1 &&
      (cs.effectiveness || 0.5) < 0.3 &&
      cs.last_seen && daysDiffAdjusted(cs.last_seen) > 180
    );

    candidates.sort((a, b) => (a.last_seen || '').localeCompare(b.last_seen || ''));
    const excess = csData.strategies.length - LIMITS.max_strategies;
    const toArchive = candidates.slice(0, Math.max(excess, 0));

    if (toArchive.length > 0) {
      let archive = readJSON(ARCHIVE_CS) || { archived: [], archived_at: [] };
      const archiveIds = new Set(toArchive.map(s => s.id));

      for (const cs of toArchive) {
        archive.archived.push(cs);
        archive.archived_at.push({ id: cs.id, date: today(), reason: 'housekeep: low-value (COLD, seen<=1, eff<0.3, >180d)' });
      }
      writeJSON(ARCHIVE_CS, archive);

      csData.strategies = csData.strategies.filter(cs => !archiveIds.has(cs.id));
      csData.stats.strategies_total = csData.strategies.length;
      writeJSON(JSON_CS, csData);
      report.archived_cs = toArchive.length;
    }

    if (csData.strategies.length > LIMITS.max_strategies) {
      report.warnings.push(`Still ${csData.strategies.length} strategies after archival (limit: ${LIMITS.max_strategies}). No more safe candidates.`);
    }
  }

  // Rebuild SQLite + FTS after archival
  if (report.archived_ab > 0 || report.archived_cs > 0) {
    const db = await getDB();
    const freshAb = loadAntibodies();
    const freshCs = loadStrategies();
    // Clear and re-sync
    db.run(`DELETE FROM antibodies`);
    db.run(`DELETE FROM strategies`);
    syncToSQLite(db, freshAb.antibodies, freshCs.strategies);
    rebuildFTS(db);
    saveDB(db);
  }

  report.current = {
    antibodies: loadAntibodies().antibodies.length,
    strategies: loadStrategies().strategies.length,
    limits: LIMITS
  };

  return { ok: true, ...report };
}

// ── CLI Router ──────────────────────────────────────────

function parseArgs(argv) {
  const args = {};
  let command = null;
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (!command && !arg.startsWith('--')) { command = arg; continue; }
    if (arg.startsWith('--')) {
      const key = arg.slice(2).replace(/-/g, '_');
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) { args[key] = next; i++; }
      else args[key] = true;
    }
  }
  return { command, args };
}

const COMMANDS = {
  'get-antibodies': cmdGetAntibodies,
  'get-strategies': cmdGetStrategies,
  'add-antibody': cmdAddAntibody,
  'add-strategy': cmdAddStrategy,
  'update-antibody': cmdUpdateAntibody,
  'update-strategy': cmdUpdateStrategy,
  'search': cmdSearch,
  'index': cmdIndex,
  'stats': cmdStats,
  'migrate-status': cmdMigrateStatus,
  'migrate-advance': cmdMigrateAdvance,
  'integrity-check': cmdIntegrityCheck,
  'log-session': cmdLogSession,
  'get-context': cmdGetContext,
  'index-context': cmdIndexContext,
  'retention-cleanup': cmdRetentionCleanup,
  'score': cmdScore,
  'flush-pending': cmdFlushPending,
  'housekeep': cmdHousekeep,
  'freeze': cmdFreeze,
  'unfreeze': cmdUnfreeze,
  'import': cmdImport,
};

async function main() {
  const { command, args } = parseArgs(process.argv);
  if (!command || !COMMANDS[command]) {
    console.error(`Usage: node immune-adapter.js <command> [options]
Commands: ${Object.keys(COMMANDS).join(', ')}`);
    process.exit(1);
  }

  ensureLockFile();
  const needsLock = ['add-antibody', 'add-strategy', 'update-antibody',
                     'update-strategy', 'index', 'migrate-advance',
                     'log-session', 'index-context', 'score', 'flush-pending',
                     'housekeep'].includes(command);
  let result;
  try {
    if (needsLock) {
      const release = await lockfile.lock(LOCK_FILE, {
        retries: { retries: 5, minTimeout: 100, maxTimeout: 1000 },
        stale: 10000
      });
      try { result = await COMMANDS[command](args); }
      finally { await release(); }
    } else {
      result = await COMMANDS[command](args);
    }
    console.log(JSON.stringify(result));
  } catch (e) {
    console.error(JSON.stringify({ error: e.message, stack: e.stack }));
    process.exit(1);
  }
}

main();
