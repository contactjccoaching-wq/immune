#!/usr/bin/env node
'use strict';

/**
 * md-index — Markdown Indexer + Sitemap Generator
 * Usage: node round-6.js <input-dir> [options]
 *
 * Options:
 *   --output-dir <dir>     Output directory (default: ./output)
 *   --base-url <url>       Base URL for sitemap (default: https://example.com)
 *   --format <fmt>         Output format: json|html|both (default: both)
 *   --recursive            Scan subdirectories recursively
 *   --verbose              Enable verbose logging
 */

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Constants & Config
// ---------------------------------------------------------------------------

const DEFAULTS = Object.freeze({
  outputDir: './output',
  baseUrl: 'https://example.com',
  format: 'both',
  recursive: false,
  verbose: false,
});

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB — guard AB-010
const MAX_FILES = 10_000;                     // guard AB-010 unbounded accumulation
const VALID_FORMATS = Object.freeze(['json', 'html', 'both']);

// ---------------------------------------------------------------------------
// Structured Logger (CS-CODE-015)
// ---------------------------------------------------------------------------

const Logger = (() => {
  let _verbose = false;

  function setVerbose(v) { _verbose = v; }

  function log(level, message, meta = {}) {
    const entry = JSON.stringify({ ts: new Date().toISOString(), level, message, ...meta });
    if (level === 'error') {
      process.stderr.write(entry + '\n');
    } else if (level === 'debug' && !_verbose) {
      return;
    } else {
      process.stdout.write(entry + '\n');
    }
  }

  return Object.freeze({
    setVerbose,
    info: (msg, meta) => log('info', msg, meta),
    debug: (msg, meta) => log('debug', msg, meta),
    warn: (msg, meta) => log('warn', msg, meta),
    error: (msg, meta) => log('error', msg, meta),
  });
})();

// ---------------------------------------------------------------------------
// Layer 1 — Input Validation (CS-CODE-006, CS-CODE-003)
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    printHelp();
    process.exit(0);
  }

  const inputDir = args[0];
  const options = { ...DEFAULTS };

  // Parse flags
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];

    switch (flag) {
      case '--output-dir':
        if (!args[i + 1]) die(`--output-dir requires a value`);
        options.outputDir = args[++i];
        break;
      case '--base-url':
        if (!args[i + 1]) die(`--base-url requires a value`);
        options.baseUrl = args[++i];
        break;
      case '--format':
        if (!args[i + 1]) die(`--format requires a value`);
        options.format = args[++i];
        break;
      case '--recursive':
        options.recursive = true;
        break;
      case '--verbose':
        options.verbose = true;
        break;
      default:
        die(`Unknown option: ${flag}. Run with --help for usage.`);
    }
  }

  return { inputDir, options };
}

function validateConfig(inputDir, options) {
  const errors = [];

  // 1. Parse → structure
  if (typeof inputDir !== 'string' || inputDir.trim() === '') {
    errors.push('Input directory must be a non-empty string');
  }

  // 2. Type checks
  if (!VALID_FORMATS.includes(options.format)) {
    errors.push(`--format must be one of: ${VALID_FORMATS.join(', ')}`);
  }

  // 3. Format checks
  if (options.baseUrl) {
    try {
      const u = new URL(options.baseUrl);
      if (!['http:', 'https:'].includes(u.protocol)) {
        errors.push('--base-url must use http or https');
      }
    } catch {
      errors.push(`--base-url is not a valid URL: "${options.baseUrl}"`);
    }
  }

  // 4. Path safety — prevent directory traversal
  const resolvedInput = path.resolve(inputDir);
  if (resolvedInput.includes('\0')) {
    errors.push('Input directory path contains null bytes');
  }

  if (errors.length > 0) {
    errors.forEach(e => Logger.error(e));
    die('Configuration validation failed. Aborting.');
  }

  return path.resolve(inputDir);
}

function validateInputDirectory(resolvedPath) {
  let stat;
  try {
    stat = fs.statSync(resolvedPath);
  } catch {
    die(`Input directory does not exist or is not accessible: "${resolvedPath}"`);
  }
  if (!stat.isDirectory()) {
    die(`Input path is not a directory: "${resolvedPath}"`);
  }
}

// ---------------------------------------------------------------------------
// Layer 2 — File Discovery
// ---------------------------------------------------------------------------

function discoverMarkdownFiles(dir, recursive) {
  const files = [];
  let count = 0;

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      Logger.warn('Cannot read directory', { dir: currentDir, error: err.message });
      return;
    }

    for (const entry of entries) {
      if (count >= MAX_FILES) {
        Logger.warn(`File limit reached (${MAX_FILES}). Stopping discovery.`);
        return;
      }

      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory() && recursive) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith('.md')) {
        files.push(fullPath);
        count++;
      }
    }
  }

  walk(dir);
  Logger.debug('File discovery complete', { found: files.length });
  return files;
}

// ---------------------------------------------------------------------------
// Layer 3 — Parsing (Single Responsibility per function)
// ---------------------------------------------------------------------------

/**
 * Safely read a file, returning null on error or if it exceeds size limit.
 */
function readFileSafe(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_FILE_SIZE_BYTES) {
      Logger.warn('File exceeds size limit, skipping', { file: filePath, size: stat.size });
      return null;
    }
    return fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    Logger.warn('Could not read file', { file: filePath, error: err.message });
    return null;
  }
}

/**
 * Extract YAML-style frontmatter block from raw markdown content.
 * Returns { frontmatterRaw, bodyContent }.
 */
function splitFrontmatter(content) {
  const FENCE = '---';
  if (!content.startsWith(FENCE)) {
    return { frontmatterRaw: '', bodyContent: content };
  }

  const secondFence = content.indexOf('\n---', FENCE.length);
  if (secondFence === -1) {
    return { frontmatterRaw: '', bodyContent: content };
  }

  const frontmatterRaw = content.slice(FENCE.length, secondFence).trim();
  const bodyContent = content.slice(secondFence + 4).trim(); // skip "\n---"
  return { frontmatterRaw, bodyContent };
}

/**
 * Parse a simple key: value YAML subset into a plain object.
 * Supports strings, arrays (comma-separated inline or YAML list style), dates.
 */
function parseFrontmatterFields(raw) {
  const fields = {};
  if (!raw) return fields;

  const lines = raw.split('\n');
  let currentKey = null;
  let collectingList = false;

  for (const line of lines) {
    // YAML list item under current key
    if (collectingList && line.trimStart().startsWith('- ')) {
      const item = line.trim().slice(2).trim();
      if (item) {
        fields[currentKey] = fields[currentKey] || [];
        fields[currentKey].push(item);
      }
      continue;
    }

    // New key: value line
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) {
      collectingList = false;
      continue;
    }

    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const rawValue = line.slice(colonIdx + 1).trim();
    currentKey = key;
    collectingList = false;

    if (rawValue === '' || rawValue === null) {
      // Value may follow as a YAML list on next lines
      collectingList = true;
      fields[key] = [];
      continue;
    }

    // Inline array: [a, b, c] or a, b, c (for tags)
    if (rawValue.startsWith('[') && rawValue.endsWith(']')) {
      fields[key] = rawValue
        .slice(1, -1)
        .split(',')
        .map(s => s.trim().replace(/^["']|["']$/g, ''))
        .filter(Boolean);
      continue;
    }

    // Unquoted value — strip surrounding quotes if present
    fields[key] = rawValue.replace(/^["']|["']$/g, '');
  }

  return fields;
}

/**
 * Extract the first H1 heading from markdown body as a fallback title.
 */
function extractH1(body) {
  const match = body.match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : null;
}

/**
 * Derive the URL slug from the file path relative to the input directory.
 */
function deriveSlug(filePath, inputDir) {
  const relative = path.relative(inputDir, filePath);
  return relative
    .replace(/\\/g, '/')       // Windows → Unix separators
    .replace(/\.md$/, '')      // strip extension
    .toLowerCase()
    .replace(/\s+/g, '-');     // spaces to dashes
}

/**
 * Normalise a date string to ISO 8601 (YYYY-MM-DD). Returns null if unparseable.
 */
function normaliseDate(raw) {
  if (!raw) return null;
  const d = new Date(raw);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

/**
 * Parse a single markdown file into a structured entry.
 */
function parseMarkdownFile(filePath, inputDir) {
  const raw = readFileSafe(filePath);
  if (raw === null) return null;

  const { frontmatterRaw, bodyContent } = splitFrontmatter(raw);
  const fields = parseFrontmatterFields(frontmatterRaw);

  const title =
    fields.title ||
    extractH1(bodyContent) ||
    path.basename(filePath, '.md');

  const tags = Array.isArray(fields.tags)
    ? fields.tags
    : typeof fields.tags === 'string'
    ? fields.tags.split(',').map(s => s.trim()).filter(Boolean)
    : [];

  return {
    slug: deriveSlug(filePath, inputDir),
    title: String(title),
    date: normaliseDate(fields.date || fields.published || null),
    description: fields.description || fields.excerpt || '',
    tags,
    filePath,
  };
}

// ---------------------------------------------------------------------------
// Layer 4 — Index Builder
// ---------------------------------------------------------------------------

/**
 * Build a JSON search index array from parsed entries.
 */
function buildSearchIndex(entries) {
  return entries.map(entry => ({
    slug: entry.slug,
    title: entry.title,
    date: entry.date,
    description: entry.description,
    tags: entry.tags,
  }));
}

// ---------------------------------------------------------------------------
// Layer 5 — Output Generation
// ---------------------------------------------------------------------------

/**
 * Escape special HTML characters to prevent XSS in generated HTML.
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Build an absolute URL from base URL and slug.
 */
function buildUrl(baseUrl, slug) {
  const trimmedBase = baseUrl.replace(/\/$/, '');
  return `${trimmedBase}/${slug}`;
}

/**
 * Generate an HTML sitemap string from entries.
 */
function generateHtmlSitemap(entries, baseUrl) {
  const rows = entries.map(entry => {
    const url = escapeHtml(buildUrl(baseUrl, entry.slug));
    const title = escapeHtml(entry.title);
    const date = escapeHtml(entry.date || '—');
    const description = escapeHtml(entry.description);
    const tags = entry.tags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join(' ');

    return `    <tr>
      <td><a href="${url}">${title}</a></td>
      <td>${date}</td>
      <td>${description}</td>
      <td>${tags}</td>
    </tr>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sitemap</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; color: #222; }
    h1 { font-size: 1.5rem; margin-bottom: 1rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }
    th { background: #f5f5f5; font-weight: 600; }
    tr:nth-child(even) { background: #fafafa; }
    a { color: #0057b7; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .tag { display: inline-block; background: #e8f0fe; color: #1a56db;
           font-size: 0.75rem; padding: 2px 6px; border-radius: 3px; margin: 1px; }
    .meta { color: #666; font-size: 0.85rem; margin-top: 0.5rem; }
  </style>
</head>
<body>
  <h1>Sitemap</h1>
  <p class="meta">Generated: ${new Date().toISOString()} — ${entries.length} page(s)</p>
  <table>
    <thead>
      <tr>
        <th>Title</th>
        <th>Date</th>
        <th>Description</th>
        <th>Tags</th>
      </tr>
    </thead>
    <tbody>
${rows}
    </tbody>
  </table>
</body>
</html>`;
}

/**
 * Write a file, creating parent directories as needed. CS-CODE-013.
 */
function writeFileSafe(filePath, content) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content, 'utf8');
    Logger.info('Wrote file', { path: filePath, bytes: Buffer.byteLength(content) });
    return true;
  } catch (err) {
    Logger.error('Failed to write file', { path: filePath, error: err.message });
    return false;
  }
}

// ---------------------------------------------------------------------------
// Layer 6 — Orchestration
// ---------------------------------------------------------------------------

/**
 * Main pipeline. Returns a result summary object.
 * CS-CODE-013: per-operation error handling, errors don't cascade.
 */
function run(inputDir, options = {}) {
  const config = { ...DEFAULTS, ...options };
  Logger.setVerbose(config.verbose);

  // CS-CODE-006: Fail fast with detailed errors
  const resolvedInput = validateConfig(inputDir, config);
  validateInputDirectory(resolvedInput);

  const resolvedOutput = path.resolve(config.outputDir);
  const baseUrl = config.baseUrl.replace(/\/$/, '');

  Logger.info('Starting md-index', {
    inputDir: resolvedInput,
    outputDir: resolvedOutput,
    format: config.format,
    recursive: config.recursive,
  });

  // Discover files
  const filePaths = discoverMarkdownFiles(resolvedInput, config.recursive);
  if (filePaths.length === 0) {
    Logger.warn('No markdown files found', { dir: resolvedInput });
    return { parsed: 0, skipped: 0, written: [] };
  }
  Logger.info(`Found ${filePaths.length} markdown file(s)`);

  // Parse files (CS-CODE-013: per-file try-catch inside parseMarkdownFile)
  const entries = [];
  let skipped = 0;
  for (const fp of filePaths) {
    const entry = parseMarkdownFile(fp, resolvedInput);
    if (entry) {
      entries.push(entry);
      Logger.debug('Parsed', { slug: entry.slug });
    } else {
      skipped++;
    }
  }
  Logger.info(`Parsed ${entries.length} file(s), skipped ${skipped}`);

  // Sort by date descending (nulls last)
  entries.sort((a, b) => {
    if (!a.date && !b.date) return 0;
    if (!a.date) return 1;
    if (!b.date) return -1;
    return b.date.localeCompare(a.date);
  });

  const written = [];

  // Output JSON index
  if (config.format === 'json' || config.format === 'both') {
    const index = buildSearchIndex(entries);
    const jsonPath = path.join(resolvedOutput, 'search-index.json');
    const ok = writeFileSafe(jsonPath, JSON.stringify(index, null, 2));
    if (ok) written.push(jsonPath);
  }

  // Output HTML sitemap
  if (config.format === 'html' || config.format === 'both') {
    const html = generateHtmlSitemap(entries, baseUrl);
    const htmlPath = path.join(resolvedOutput, 'sitemap.html');
    const ok = writeFileSafe(htmlPath, html);
    if (ok) written.push(htmlPath);
  }

  Logger.info('Done', { parsed: entries.length, skipped, written });
  return { parsed: entries.length, skipped, written };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function die(message) {
  Logger.error(message);
  process.exit(1);
}

function printHelp() {
  const help = `
md-index — Markdown Indexer + Sitemap Generator

Usage:
  node round-6.js <input-dir> [options]

Arguments:
  <input-dir>          Directory containing .md files

Options:
  --output-dir <dir>   Output directory (default: ./output)
  --base-url <url>     Base URL for sitemap links (default: https://example.com)
  --format <fmt>       Output: json | html | both (default: both)
  --recursive          Recurse into subdirectories
  --verbose            Enable verbose debug logging
  --help, -h           Show this help

Examples:
  node round-6.js ./docs
  node round-6.js ./docs --format json --output-dir ./dist
  node round-6.js ./docs --base-url https://myblog.com --recursive
`.trim();
  process.stdout.write(help + '\n');
}

// ---------------------------------------------------------------------------
// Graceful shutdown (CS-CODE-005)
// ---------------------------------------------------------------------------

function registerShutdownHandlers() {
  function onSignal(sig) {
    Logger.info(`Received ${sig}, shutting down gracefully`);
    process.exit(0);
  }
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  process.on('uncaughtException', (err) => {
    Logger.error('Uncaught exception', { error: err.message, stack: err.stack });
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    Logger.error('Unhandled promise rejection', { reason: String(reason) });
    process.exit(1);
  });
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

if (require.main === module) {
  registerShutdownHandlers();
  const { inputDir, options } = parseArgs(process.argv);
  run(inputDir, options);
}

// ---------------------------------------------------------------------------
// Public API (for testing)
// ---------------------------------------------------------------------------

module.exports = Object.freeze({
  run,
  parseArgs,
  validateConfig,
  discoverMarkdownFiles,
  parseMarkdownFile,
  splitFrontmatter,
  parseFrontmatterFields,
  extractH1,
  deriveSlug,
  normaliseDate,
  buildSearchIndex,
  generateHtmlSitemap,
  buildUrl,
  escapeHtml,
});
