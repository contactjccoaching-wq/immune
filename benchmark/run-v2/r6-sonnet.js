#!/usr/bin/env node
/**
 * md-index — CLI tool: reads markdown files, extracts frontmatter,
 * generates a static JSON search index, and outputs an HTML sitemap.
 *
 * Production-quality, pure Node.js, no frameworks.
 *
 * Applied strategies (from cheatsheet):
 *   CS-CODE-001  Escape HTML via dedicated function
 *   CS-CODE-005  Schema validation on data reads with per-field type guards + fallback defaults
 *   CS-CODE-006  Centralized init() function orchestrating all setup from a single entry point
 *   CS-CODE-007  Single centralized state object instead of scattered global variables
 *   CS-CODE-015  CLI args treated as hostile — validate type, length, format before use
 *
 * Avoided pitfalls (from cheatsheet):
 *   AB-CODE-001  No dead code / impossible branches
 *   AB-CODE-002  No duplicated constants — single source of truth
 *   AB-CODE-003  Parallel I/O via Promise.all() instead of sequential loop
 *   AB-CODE-006  No innerHTML / template literals with raw user data — escapeHtml() everywhere
 *   AB-CODE-008  JSON.parse always wrapped in try/catch
 *   AB-CODE-010  No unbounded loops — all loops have a finite upper bound
 *   AB-CODE-023  No server-side template XSS — all user/file data escaped before insertion into HTML
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ─── Constants (single source of truth — AB-CODE-002) ────────────────────────
const CONSTANTS = Object.freeze({
  MAX_FILES:          10_000,   // guard for unbounded loop (AB-CODE-010)
  MAX_PATH_LENGTH:    4_096,
  MAX_FRONTMATTER_LINES: 200,
  ENCODING:           'utf8',
  MARKDOWN_EXT:       '.md',
  JSON_OUTPUT:        'search-index.json',
  HTML_OUTPUT:        'sitemap.html',
  INDENT:             2,
  VALID_FIELD_KEYS:   new Set(['title', 'date', 'description', 'tags', 'slug', 'author', 'draft']),
});

// ─── Single centralized state (CS-CODE-007) ──────────────────────────────────
const state = {
  inputDir:   null,
  outputDir:  null,
  verbose:    false,
  errors:     [],
  warnings:   [],
};

// ─── HTML escaping — dedicated function, no raw user data in HTML (CS-CODE-001, AB-CODE-006, AB-CODE-023) ──
/**
 * Escape a value for safe insertion into HTML text nodes or attribute values.
 * @param {unknown} value
 * @returns {string}
 */
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#39;')
    .replace(/\//g, '&#x2F;');
}

// ─── Logging ──────────────────────────────────────────────────────────────────
function log(msg)        { process.stdout.write(msg + '\n'); }
function logVerbose(msg) { if (state.verbose) log('[verbose] ' + msg); }
function logWarn(msg)    { state.warnings.push(msg); process.stderr.write('[warn]  ' + msg + '\n'); }
function logError(msg)   { state.errors.push(msg);   process.stderr.write('[error] ' + msg + '\n'); }

// ─── CLI argument parsing + validation (CS-CODE-015) ─────────────────────────
/**
 * Parse and validate CLI arguments.
 * Usage: node r6-sonnet.js <input-dir> [output-dir] [--verbose]
 * @returns {{ inputDir: string, outputDir: string, verbose: boolean } | null}
 */
function parseArgs(argv) {
  const args = argv.slice(2); // skip node + script
  const positional = [];
  let verbose = false;

  for (const arg of args) {
    if (arg === '--verbose' || arg === '-v') {
      verbose = true;
    } else if (arg.startsWith('--')) {
      logError('Unknown flag: ' + arg);
      return null;
    } else {
      positional.push(arg);
    }
  }

  if (positional.length < 1) {
    logError('Usage: node r6-sonnet.js <input-dir> [output-dir] [--verbose]');
    return null;
  }

  const inputDir  = path.resolve(positional[0]);
  const outputDir = positional[1] ? path.resolve(positional[1]) : inputDir;

  // Validate path lengths (CS-CODE-015)
  if (inputDir.length > CONSTANTS.MAX_PATH_LENGTH) {
    logError('Input path exceeds maximum length.');
    return null;
  }
  if (outputDir.length > CONSTANTS.MAX_PATH_LENGTH) {
    logError('Output path exceeds maximum length.');
    return null;
  }

  return { inputDir, outputDir, verbose };
}

// ─── Directory validation ─────────────────────────────────────────────────────
/**
 * Ensure a path exists and is a directory.
 * @param {string} dirPath
 * @returns {boolean}
 */
function validateDirectory(dirPath) {
  let stat;
  try {
    stat = fs.statSync(dirPath);
  } catch (err) {
    logError('Cannot access path "' + dirPath + '": ' + err.message);
    return false;
  }
  if (!stat.isDirectory()) {
    logError('Path is not a directory: "' + dirPath + '"');
    return false;
  }
  return true;
}

// ─── Path traversal guard ─────────────────────────────────────────────────────
/**
 * Ensure that a resolved file path is contained within the allowed base dir.
 * Prevents path-traversal via crafted filenames.
 * @param {string} filePath  - resolved absolute path
 * @param {string} baseDir   - resolved absolute base directory
 * @returns {boolean}
 */
function isWithinBase(filePath, baseDir) {
  const rel = path.relative(baseDir, filePath);
  return !rel.startsWith('..') && !path.isAbsolute(rel);
}

// ─── Frontmatter parsing ──────────────────────────────────────────────────────
/**
 * Parse YAML-style frontmatter from a markdown string.
 * Only supports simple key: value pairs (no nested objects, no arrays-in-YAML).
 * Tags as YAML arrays (- item) are supported.
 *
 * @param {string} content
 * @returns {{ frontmatter: Record<string, unknown>, body: string }}
 */
function parseFrontmatter(content) {
  const empty = { frontmatter: {}, body: content };

  if (!content.startsWith('---')) {
    return empty;
  }

  // Find the closing ---
  const afterOpen = content.indexOf('\n', 0);
  if (afterOpen === -1) return empty;

  const closeIdx = content.indexOf('\n---', afterOpen);
  if (closeIdx === -1) return empty;

  const yamlBlock = content.slice(afterOpen + 1, closeIdx);
  const body      = content.slice(closeIdx + 4).replace(/^\n/, '');

  const lines = yamlBlock.split('\n');

  // Guard against pathologically large frontmatter (AB-CODE-010)
  if (lines.length > CONSTANTS.MAX_FRONTMATTER_LINES) {
    logWarn('Frontmatter exceeds max line limit; truncating to ' + CONSTANTS.MAX_FRONTMATTER_LINES + ' lines.');
  }

  const frontmatter = {};
  let currentKey    = null;
  let collectingArray = false;

  // Finite loop — lines.length is bounded by MAX_FRONTMATTER_LINES after the guard
  const limit = Math.min(lines.length, CONSTANTS.MAX_FRONTMATTER_LINES);
  for (let i = 0; i < limit; i++) {
    const line = lines[i];

    // Array item continuation
    if (collectingArray && /^\s*-\s+/.test(line)) {
      const item = line.replace(/^\s*-\s+/, '').trim();
      if (currentKey && Array.isArray(frontmatter[currentKey])) {
        frontmatter[currentKey].push(item);
      }
      continue;
    }

    collectingArray = false;

    // key: value pair
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)/);
    if (!match) continue;

    const rawKey   = match[1].trim().toLowerCase();
    const rawValue = match[2].trim();

    // Only allow known field keys (CS-CODE-015 — treat file data as hostile)
    if (!CONSTANTS.VALID_FIELD_KEYS.has(rawKey)) {
      logVerbose('Skipping unknown frontmatter key: ' + rawKey);
      continue;
    }

    currentKey = rawKey;

    if (rawValue === '') {
      // Might be start of a YAML array
      frontmatter[currentKey] = [];
      collectingArray = true;
    } else if (rawValue.startsWith('[')) {
      // Inline array: [a, b, c]
      const inner = rawValue.replace(/^\[/, '').replace(/\]$/, '');
      frontmatter[currentKey] = inner.split(',').map(s => s.trim()).filter(Boolean);
    } else {
      // Scalar — strip optional surrounding quotes
      frontmatter[currentKey] = rawValue.replace(/^["']|["']$/g, '');
    }
  }

  return { frontmatter, body };
}

// ─── Frontmatter schema validation (CS-CODE-005) ─────────────────────────────
/**
 * Validate and normalise a raw frontmatter object into a typed record.
 * Unknown keys are silently dropped; missing keys get safe fallback defaults.
 *
 * @param {Record<string, unknown>} raw
 * @param {string} filePath  used only for warning messages
 * @returns {ArticleRecord}
 *
 * @typedef {{ title: string, date: string, description: string,
 *             tags: string[], slug: string, author: string, draft: boolean }} ArticleRecord
 */
function validateFrontmatter(raw, filePath) {
  const basename = path.basename(filePath, CONSTANTS.MARKDOWN_EXT);

  // Per-field type guards with fallback defaults (CS-CODE-005)
  const title = (typeof raw.title === 'string' && raw.title.trim())
    ? raw.title.trim()
    : basename; // fallback: filename without extension

  const date = (typeof raw.date === 'string' && /^\d{4}-\d{2}-\d{2}/.test(raw.date))
    ? raw.date.trim()
    : '';

  const description = (typeof raw.description === 'string')
    ? raw.description.trim()
    : '';

  const tags = Array.isArray(raw.tags)
    ? raw.tags.filter(t => typeof t === 'string').map(t => t.trim()).filter(Boolean)
    : [];

  // Slug: use provided value, else derive from filename
  const rawSlug = typeof raw.slug === 'string' ? raw.slug.trim() : '';
  const slug = rawSlug
    ? rawSlug.toLowerCase().replace(/[^a-z0-9-_]/g, '-')
    : basename.toLowerCase().replace(/[^a-z0-9-_]/g, '-');

  const author = (typeof raw.author === 'string') ? raw.author.trim() : '';

  const draft = raw.draft === true || raw.draft === 'true';

  if (!date) {
    logWarn('Missing or invalid "date" in: ' + filePath);
  }

  return { title, date, description, tags, slug, author, draft };
}

// ─── File discovery ───────────────────────────────────────────────────────────
/**
 * Recursively list all markdown files under a directory.
 * Bounded by CONSTANTS.MAX_FILES (AB-CODE-010).
 *
 * @param {string} dir
 * @param {string} baseDir - original root dir for traversal guard
 * @returns {string[]} absolute file paths
 */
function collectMarkdownFiles(dir, baseDir) {
  const results = [];
  const queue   = [dir];

  // Finite loop with explicit upper-bound guard (AB-CODE-010)
  let iterations = 0;
  while (queue.length > 0 && iterations < CONSTANTS.MAX_FILES) {
    iterations++;
    const current = queue.shift();

    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (err) {
      logWarn('Cannot read directory "' + current + '": ' + err.message);
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);

      // Path traversal guard — skip anything outside the base dir
      if (!isWithinBase(fullPath, baseDir)) {
        logWarn('Skipping path outside base directory: ' + fullPath);
        continue;
      }

      if (entry.isDirectory()) {
        queue.push(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(CONSTANTS.MARKDOWN_EXT)) {
        results.push(fullPath);
        if (results.length >= CONSTANTS.MAX_FILES) {
          logWarn('File limit (' + CONSTANTS.MAX_FILES + ') reached; remaining files ignored.');
          return results;
        }
      }
    }
  }

  return results;
}

// ─── Single-file processing ───────────────────────────────────────────────────
/**
 * Read one markdown file and return its search-index entry.
 * @param {string} filePath
 * @param {string} baseDir
 * @returns {Promise<{ record: ArticleRecord, filePath: string } | null>}
 */
async function processFile(filePath, baseDir) {
  // Extra traversal check (CS-CODE-015)
  if (!isWithinBase(filePath, baseDir)) {
    logWarn('Skipping path outside base directory: ' + filePath);
    return null;
  }

  let raw;
  try {
    raw = await fs.promises.readFile(filePath, CONSTANTS.ENCODING);
  } catch (err) {
    logWarn('Cannot read file "' + filePath + '": ' + err.message);
    return null;
  }

  const { frontmatter } = parseFrontmatter(raw);
  const record          = validateFrontmatter(frontmatter, filePath);

  logVerbose('Processed: ' + path.relative(baseDir, filePath));
  return { record, filePath };
}

// ─── JSON index generation ────────────────────────────────────────────────────
/**
 * Build and write the JSON search index.
 * @param {Array<{ record: ArticleRecord, filePath: string }>} entries
 * @param {string} outputDir
 * @returns {Promise<void>}
 */
async function writeSearchIndex(entries, outputDir) {
  // Exclude draft articles from the public index
  const published = entries.filter(e => !e.record.draft);

  const index = published.map(({ record, filePath }) => ({
    slug:        record.slug,
    title:       record.title,
    date:        record.date,
    description: record.description,
    tags:        record.tags,
    author:      record.author,
    // Relative path from outputDir is stable across environments
    file:        path.basename(filePath),
  }));

  // Sort by date descending (drafts excluded, so no date may be '')
  index.sort((a, b) => (b.date > a.date ? 1 : b.date < a.date ? -1 : 0));

  const json = JSON.stringify(index, null, CONSTANTS.INDENT);

  const outPath = path.join(outputDir, CONSTANTS.JSON_OUTPUT);
  try {
    await fs.promises.writeFile(outPath, json, CONSTANTS.ENCODING);
    log('JSON index written: ' + outPath + ' (' + index.length + ' entries)');
  } catch (err) {
    logError('Failed to write JSON index: ' + err.message);
  }
}

// ─── HTML sitemap generation (CS-CODE-001, AB-CODE-023) ──────────────────────
/**
 * Build and write the HTML sitemap.
 * ALL user/file-derived data is passed through escapeHtml() before insertion.
 * @param {Array<{ record: ArticleRecord, filePath: string }>} entries
 * @param {string} outputDir
 * @returns {Promise<void>}
 */
async function writeSitemap(entries, outputDir) {
  // Include all entries (drafts marked visually)
  const sorted = entries.slice().sort((a, b) => {
    const da = a.record.date || '0000-00-00';
    const db = b.record.date || '0000-00-00';
    return db > da ? 1 : db < da ? -1 : 0;
  });

  // Build rows — every value escaped (CS-CODE-001, AB-CODE-006, AB-CODE-023)
  const rows = sorted.map(({ record }) => {
    const title       = escapeHtml(record.title);
    const date        = escapeHtml(record.date || '—');
    const description = escapeHtml(record.description || '');
    const author      = escapeHtml(record.author || '—');
    const tags        = record.tags.map(t => '<span class="tag">' + escapeHtml(t) + '</span>').join(' ');
    const slug        = escapeHtml(record.slug);
    const draftBadge  = record.draft ? ' <span class="badge draft">DRAFT</span>' : '';

    return [
      '    <article class="entry' + (record.draft ? ' is-draft' : '') + '">',
      '      <h2><a href="' + slug + '.html">' + title + '</a>' + draftBadge + '</h2>',
      '      <p class="meta"><time datetime="' + date + '">' + date + '</time> &mdash; ' + author + '</p>',
      '      <p class="desc">' + description + '</p>',
      '      <div class="tags">' + (tags || '<em>no tags</em>') + '</div>',
      '    </article>',
    ].join('\n');
  }).join('\n\n');

  // Stats
  const total    = entries.length;
  const drafts   = entries.filter(e => e.record.draft).length;
  const published = total - drafts;

  // Full HTML document — no raw user data, only escaped values (AB-CODE-023)
  const html = [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '  <meta charset="UTF-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
    '  <title>Sitemap</title>',
    '  <style>',
    '    *, *::before, *::after { box-sizing: border-box; }',
    '    body { font-family: system-ui, sans-serif; max-width: 860px; margin: 2rem auto; padding: 0 1rem; color: #222; }',
    '    h1 { font-size: 1.6rem; border-bottom: 2px solid #ddd; padding-bottom: .5rem; }',
    '    .stats { font-size: .9rem; color: #555; margin-bottom: 2rem; }',
    '    .entry { border: 1px solid #e4e4e4; border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1rem; }',
    '    .entry.is-draft { opacity: .65; border-style: dashed; }',
    '    .entry h2 { margin: 0 0 .25rem; font-size: 1.1rem; }',
    '    .entry h2 a { text-decoration: none; color: #0057b7; }',
    '    .entry h2 a:hover { text-decoration: underline; }',
    '    .meta { font-size: .8rem; color: #777; margin: 0 0 .5rem; }',
    '    .desc { margin: 0 0 .5rem; font-size: .9rem; }',
    '    .tags { font-size: .8rem; }',
    '    .tag { display: inline-block; background: #f0f0f0; border-radius: 3px; padding: 1px 6px; margin: 2px; }',
    '    .badge { font-size: .7rem; font-weight: bold; padding: 1px 5px; border-radius: 3px; vertical-align: middle; }',
    '    .draft { background: #ffe4b5; color: #7a4f00; }',
    '  </style>',
    '</head>',
    '<body>',
    '  <h1>Sitemap</h1>',
    '  <p class="stats">Total: ' + total + ' &bull; Published: ' + published + ' &bull; Drafts: ' + drafts + '</p>',
    '  <section>',
    rows,
    '  </section>',
    '</body>',
    '</html>',
  ].join('\n');

  const outPath = path.join(outputDir, CONSTANTS.HTML_OUTPUT);
  try {
    await fs.promises.writeFile(outPath, html, CONSTANTS.ENCODING);
    log('HTML sitemap written: ' + outPath + ' (' + total + ' entries)');
  } catch (err) {
    logError('Failed to write HTML sitemap: ' + err.message);
  }
}

// ─── Ensure output directory exists ──────────────────────────────────────────
/**
 * Create the output directory (and parents) if it does not exist.
 * @param {string} outputDir
 * @returns {boolean}
 */
function ensureOutputDir(outputDir) {
  try {
    fs.mkdirSync(outputDir, { recursive: true });
    return true;
  } catch (err) {
    logError('Failed to create output directory "' + outputDir + '": ' + err.message);
    return false;
  }
}

// ─── Main entry point (CS-CODE-006) ──────────────────────────────────────────
/**
 * Centralized init() that orchestrates all setup and execution.
 * Single entry point — no logic scattered at module level.
 */
async function init() {
  const parsed = parseArgs(process.argv);
  if (!parsed) {
    process.exitCode = 1;
    return;
  }

  // Populate state (CS-CODE-007)
  state.inputDir  = parsed.inputDir;
  state.outputDir = parsed.outputDir;
  state.verbose   = parsed.verbose;

  log('Input  directory: ' + state.inputDir);
  log('Output directory: ' + state.outputDir);

  // Validate input directory
  if (!validateDirectory(state.inputDir)) {
    process.exitCode = 1;
    return;
  }

  // Ensure output directory exists
  if (!ensureOutputDir(state.outputDir)) {
    process.exitCode = 1;
    return;
  }

  // Discover markdown files
  const files = collectMarkdownFiles(state.inputDir, state.inputDir);
  log('Found ' + files.length + ' markdown file(s).');

  if (files.length === 0) {
    log('No markdown files found. Outputs will be empty.');
  }

  // Process all files in parallel (AB-CODE-003 — no sequential loop over I/O)
  const results = await Promise.all(
    files.map(f => processFile(f, state.inputDir))
  );

  // Filter out files that could not be processed
  const entries = results.filter(Boolean);

  // Write outputs in parallel — independent writes, no dependency
  await Promise.all([
    writeSearchIndex(entries, state.outputDir),
    writeSitemap(entries, state.outputDir),
  ]);

  // Summary
  const warnCount  = state.warnings.length;
  const errorCount = state.errors.length;

  log('Done. Warnings: ' + warnCount + ', Errors: ' + errorCount + '.');

  if (errorCount > 0) {
    process.exitCode = 1;
  }
}

// ─── Bootstrap ───────────────────────────────────────────────────────────────
init().catch(err => {
  process.stderr.write('[fatal] Unhandled error: ' + err.message + '\n');
  process.exitCode = 1;
});
