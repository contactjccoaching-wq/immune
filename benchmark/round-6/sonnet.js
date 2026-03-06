#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Constants ───────────────────────────────────────────────────────────────

const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

const VALIDATION_RULES = {
  MIN_TITLE_LENGTH: 1,
  MAX_TITLE_LENGTH: 500,
  MAX_DESCRIPTION_LENGTH: 2000,
  SUPPORTED_EXTENSIONS: new Set(['.md', '.markdown']),
  MAX_FILE_SIZE_BYTES: 10 * 1024 * 1024, // 10MB
  MAX_TAG_COUNT: 50,
  MAX_TAG_LENGTH: 100,
};

const FRONTMATTER_DELIMITER = '---';

const DEFAULT_CONFIG = {
  inputDir: null,
  outputJsonPath: null,
  outputHtmlPath: null,
  logLevel: 'INFO',
  baseUrl: 'http://localhost',
  sitemapTitle: 'Site Map',
};

// ─── Metrics ─────────────────────────────────────────────────────────────────

const metrics = {
  filesDiscovered: 0,
  filesProcessed: 0,
  filesSkipped: 0,
  filesErrored: 0,
  documentsIndexed: 0,
  startTime: null,
  endTime: null,

  record(event, value = 1) {
    if (this[event] !== undefined && typeof this[event] === 'number') {
      this[event] += value;
    }
  },

  summary() {
    const duration = this.endTime && this.startTime
      ? ((this.endTime - this.startTime) / 1000).toFixed(3)
      : 'N/A';
    return {
      filesDiscovered: this.filesDiscovered,
      filesProcessed: this.filesProcessed,
      filesSkipped: this.filesSkipped,
      filesErrored: this.filesErrored,
      documentsIndexed: this.documentsIndexed,
      durationSeconds: duration,
    };
  },
};

// ─── Logger ──────────────────────────────────────────────────────────────────

const logger = {
  level: LOG_LEVELS.INFO,

  setLevel(levelName) {
    const level = LOG_LEVELS[levelName.toUpperCase()];
    if (level === undefined) {
      this.warn(`Unknown log level "${levelName}", defaulting to INFO`);
      return;
    }
    this.level = level;
  },

  _log(levelName, message, data) {
    const levelValue = LOG_LEVELS[levelName];
    if (levelValue < this.level) return;

    const entry = {
      timestamp: new Date().toISOString(),
      level: levelName,
      message,
      ...(data !== undefined ? { data } : {}),
    };
    const stream = levelValue >= LOG_LEVELS.WARN ? process.stderr : process.stdout;
    stream.write(JSON.stringify(entry) + '\n');
  },

  debug(msg, data) { this._log('DEBUG', msg, data); },
  info(msg, data)  { this._log('INFO',  msg, data); },
  warn(msg, data)  { this._log('WARN',  msg, data); },
  error(msg, data) { this._log('ERROR', msg, data); },
};

// ─── Config Loader ───────────────────────────────────────────────────────────

function loadConfig() {
  const config = { ...DEFAULT_CONFIG };

  config.inputDir       = process.env.INPUT_DIR       || null;
  config.outputJsonPath = process.env.OUTPUT_JSON     || null;
  config.outputHtmlPath = process.env.OUTPUT_HTML     || null;
  config.logLevel       = process.env.LOG_LEVEL       || DEFAULT_CONFIG.logLevel;
  config.baseUrl        = process.env.BASE_URL        || DEFAULT_CONFIG.baseUrl;
  config.sitemapTitle   = process.env.SITEMAP_TITLE   || DEFAULT_CONFIG.sitemapTitle;

  // CLI overrides
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--input'      && args[i + 1]) { config.inputDir       = args[++i]; }
    else if (arg === '--json'  && args[i + 1]) { config.outputJsonPath = args[++i]; }
    else if (arg === '--html'  && args[i + 1]) { config.outputHtmlPath = args[++i]; }
    else if (arg === '--base-url' && args[i + 1]) { config.baseUrl      = args[++i]; }
    else if (arg === '--log-level' && args[i + 1]) { config.logLevel    = args[++i]; }
    else if (arg === '--sitemap-title' && args[i + 1]) { config.sitemapTitle = args[++i]; }
    else if (arg === '--help') {
      printUsage();
      process.exit(0);
    }
  }

  return config;
}

function validateConfig(config) {
  const errors = [];

  if (!config.inputDir) {
    errors.push('INPUT_DIR or --input <directory> is required');
  } else {
    const absInput = path.resolve(config.inputDir);
    if (!fs.existsSync(absInput)) {
      errors.push(`Input directory does not exist: ${absInput}`);
    } else {
      const stat = fs.statSync(absInput);
      if (!stat.isDirectory()) {
        errors.push(`Input path is not a directory: ${absInput}`);
      }
    }
    config.inputDir = absInput;
  }

  if (!config.outputJsonPath) {
    errors.push('OUTPUT_JSON or --json <path> is required');
  } else {
    config.outputJsonPath = path.resolve(config.outputJsonPath);
  }

  if (!config.outputHtmlPath) {
    errors.push('OUTPUT_HTML or --html <path> is required');
  } else {
    config.outputHtmlPath = path.resolve(config.outputHtmlPath);
  }

  if (!config.baseUrl.startsWith('http://') && !config.baseUrl.startsWith('https://')) {
    errors.push(`BASE_URL must start with http:// or https:// — got: ${config.baseUrl}`);
  }

  if (errors.length > 0) {
    for (const err of errors) logger.error('Config validation error', { error: err });
    throw new ConfigError(`Invalid configuration:\n  - ${errors.join('\n  - ')}`);
  }

  return config;
}

function printUsage() {
  const usage = `
Usage: node code.js [options]

Options:
  --input <dir>          Directory containing markdown files (or set INPUT_DIR)
  --json  <path>         Output path for JSON search index (or set OUTPUT_JSON)
  --html  <path>         Output path for HTML sitemap (or set OUTPUT_HTML)
  --base-url <url>       Base URL for sitemap links (default: http://localhost)
  --log-level <level>    DEBUG | INFO | WARN | ERROR (default: INFO)
  --sitemap-title <str>  Title for the HTML sitemap page
  --help                 Show this help message

Environment variables mirror the --flags above.
`;
  process.stdout.write(usage);
}

// ─── Custom Errors ────────────────────────────────────────────────────────────

class ConfigError extends Error {
  constructor(message) { super(message); this.name = 'ConfigError'; }
}

class ParseError extends Error {
  constructor(message, filePath) {
    super(message);
    this.name = 'ParseError';
    this.filePath = filePath;
  }
}

class IOError extends Error {
  constructor(message, filePath, cause) {
    super(message);
    this.name = 'IOError';
    this.filePath = filePath;
    this.cause = cause;
  }
}

// ─── Frontmatter Parser ───────────────────────────────────────────────────────

/**
 * Parses YAML-like frontmatter from a markdown string.
 * Supports: string, number, boolean, array (dash list), null/undefined.
 * Returns { frontmatter, body }.
 */
function parseFrontmatter(content, filePath) {
  const lines = content.split('\n');
  let i = 0;

  // Skip BOM
  if (lines[0] && lines[0].startsWith('\uFEFF')) {
    lines[0] = lines[0].slice(1);
  }

  // Must start with ---
  if (!lines[0] || lines[0].trim() !== FRONTMATTER_DELIMITER) {
    return { frontmatter: {}, body: content };
  }

  i = 1;
  const yamlLines = [];

  while (i < lines.length) {
    if (lines[i].trim() === FRONTMATTER_DELIMITER) {
      i++;
      break;
    }
    yamlLines.push(lines[i]);
    i++;
  }

  const body = lines.slice(i).join('\n').trimStart();
  const frontmatter = parseSimpleYaml(yamlLines, filePath);
  return { frontmatter, body };
}

function parseSimpleYaml(lines, filePath) {
  const result = {};
  let j = 0;

  while (j < lines.length) {
    const line = lines[j];

    // Skip comments and blank lines
    if (!line.trim() || line.trim().startsWith('#')) {
      j++;
      continue;
    }

    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) {
      logger.debug('Skipping non-key:value YAML line', { filePath, line });
      j++;
      continue;
    }

    const key = line.slice(0, colonIdx).trim();
    const rawValue = line.slice(colonIdx + 1).trimEnd();

    if (!key) { j++; continue; }

    // Collect array values (lines starting with '  - ')
    if (rawValue.trim() === '' || rawValue.trim() === null) {
      // Possibly a block (array)
      const arrayItems = [];
      j++;
      while (j < lines.length && /^\s+-\s/.test(lines[j])) {
        const item = lines[j].replace(/^\s+-\s/, '').trim();
        arrayItems.push(coerceScalar(item));
        j++;
      }
      result[key] = arrayItems.length > 0 ? arrayItems : null;
      continue;
    }

    // Inline array: key: [a, b, c]
    const inlineArray = tryParseInlineArray(rawValue.trim());
    if (inlineArray !== null) {
      result[key] = inlineArray;
      j++;
      continue;
    }

    result[key] = coerceScalar(rawValue.trim());
    j++;
  }

  return result;
}

function tryParseInlineArray(value) {
  if (!value.startsWith('[') || !value.endsWith(']')) return null;
  const inner = value.slice(1, -1).trim();
  if (!inner) return [];
  // Simple split — does not handle nested brackets or escaped commas
  return inner.split(',').map(s => coerceScalar(s.trim()));
}

function coerceScalar(value) {
  if (value === 'null' || value === '~') return null;
  if (value === 'true')  return true;
  if (value === 'false') return false;

  const num = Number(value);
  if (!isNaN(num) && value !== '') return num;

  // Strip surrounding quotes
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }

  return value;
}

// ─── Document Validation ──────────────────────────────────────────────────────

function validateDocument(frontmatter, filePath) {
  const warnings = [];

  // Title
  const title = String(frontmatter.title || '').trim();
  if (title.length < VALIDATION_RULES.MIN_TITLE_LENGTH) {
    warnings.push('Missing or empty title');
  } else if (title.length > VALIDATION_RULES.MAX_TITLE_LENGTH) {
    warnings.push(`Title exceeds ${VALIDATION_RULES.MAX_TITLE_LENGTH} characters`);
  }

  // Description
  const description = String(frontmatter.description || '').trim();
  if (description.length > VALIDATION_RULES.MAX_DESCRIPTION_LENGTH) {
    warnings.push(`Description exceeds ${VALIDATION_RULES.MAX_DESCRIPTION_LENGTH} characters`);
  }

  // Tags
  const tags = normalizeTags(frontmatter.tags);
  if (tags.length > VALIDATION_RULES.MAX_TAG_COUNT) {
    warnings.push(`Too many tags: ${tags.length} (max ${VALIDATION_RULES.MAX_TAG_COUNT})`);
  }
  for (const tag of tags) {
    if (tag.length > VALIDATION_RULES.MAX_TAG_LENGTH) {
      warnings.push(`Tag "${tag.slice(0, 40)}…" exceeds max length`);
    }
  }

  // Date
  if (frontmatter.date !== undefined && frontmatter.date !== null) {
    const d = new Date(frontmatter.date);
    if (isNaN(d.getTime())) {
      warnings.push(`Invalid date value: ${frontmatter.date}`);
    }
  }

  if (warnings.length > 0) {
    logger.warn('Document validation warnings', { filePath, warnings });
  }

  return warnings;
}

function normalizeTags(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.map(t => String(t).trim()).filter(Boolean);
  if (typeof raw === 'string') return raw.split(',').map(t => t.trim()).filter(Boolean);
  return [];
}

// ─── File Discovery ────────────────────────────────────────────────────────────

function discoverMarkdownFiles(dir) {
  const files = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      throw new IOError(`Cannot read directory: ${currentDir}`, currentDir, err);
    }

    // Sort for stable ordering
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        // Skip hidden directories
        if (!entry.name.startsWith('.')) {
          walk(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = path.extname(entry.name).toLowerCase();
      if (!VALIDATION_RULES.SUPPORTED_EXTENSIONS.has(ext)) continue;

      files.push(fullPath);
    }
  }

  walk(dir);
  return files;
}

// ─── File Processor ────────────────────────────────────────────────────────────

function processFile(filePath, inputDir) {
  // Check file size
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (err) {
    throw new IOError(`Cannot stat file: ${filePath}`, filePath, err);
  }

  if (stat.size > VALIDATION_RULES.MAX_FILE_SIZE_BYTES) {
    throw new ParseError(
      `File exceeds maximum size of ${VALIDATION_RULES.MAX_FILE_SIZE_BYTES} bytes (size: ${stat.size})`,
      filePath
    );
  }

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new IOError(`Cannot read file: ${filePath}`, filePath, err);
  }

  const { frontmatter, body } = parseFrontmatter(content, filePath);
  validateDocument(frontmatter, filePath);

  // Compute slug from relative path
  const rel = path.relative(inputDir, filePath);
  const slug = rel
    .replace(/\\/g, '/')
    .replace(/\.md$|\.markdown$/i, '')
    .toLowerCase()
    .replace(/\s+/g, '-');

  const tags = normalizeTags(frontmatter.tags);

  // Stable createdAt: prefer frontmatter date, fall back to file mtime
  let createdAt;
  if (frontmatter.date) {
    const d = new Date(frontmatter.date);
    createdAt = isNaN(d.getTime()) ? stat.mtime.toISOString() : d.toISOString();
  } else {
    createdAt = stat.mtime.toISOString();
  }

  const updatedAt = frontmatter.updated
    ? (new Date(frontmatter.updated).toISOString() || stat.mtime.toISOString())
    : stat.mtime.toISOString();

  return {
    id: crypto.randomUUID(),
    slug,
    filePath,
    title:       String(frontmatter.title       || path.basename(filePath, path.extname(filePath))).trim(),
    description: String(frontmatter.description || '').trim(),
    author:      String(frontmatter.author      || '').trim(),
    tags,
    category:    frontmatter.category ? String(frontmatter.category).trim() : null,
    draft:       frontmatter.draft === true,
    createdAt,
    updatedAt,
    bodySnippet: body.replace(/#+\s/g, '').replace(/\*+/g, '').slice(0, 200).trim(),
  };
}

// ─── Search Index Generator ───────────────────────────────────────────────────

function buildSearchIndex(documents) {
  // Use Map for O(1) lookups by slug
  const slugMap = new Map();

  for (const doc of documents) {
    if (slugMap.has(doc.slug)) {
      logger.warn('Duplicate slug detected — later document wins', {
        slug: doc.slug,
        existing: slugMap.get(doc.slug).filePath,
        duplicate: doc.filePath,
      });
    }
    slugMap.set(doc.slug, doc);
  }

  // Sort by createdAt for stable ordering
  const sorted = [...slugMap.values()].sort((a, b) =>
    a.createdAt.localeCompare(b.createdAt)
  );

  return {
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    totalDocuments: sorted.length,
    documents: sorted.map(doc => ({
      id: doc.id,
      slug: doc.slug,
      title: doc.title,
      description: doc.description,
      author: doc.author,
      tags: doc.tags,
      category: doc.category,
      draft: doc.draft,
      createdAt: doc.createdAt,
      updatedAt: doc.updatedAt,
      bodySnippet: doc.bodySnippet,
    })),
  };
}

// ─── HTML Sitemap Generator ────────────────────────────────────────────────────

function buildHtmlSitemap(documents, config) {
  const baseUrl = config.baseUrl.replace(/\/$/, '');
  const title = escapeHtml(config.sitemapTitle);

  // Group by category
  const categoryMap = new Map();
  for (const doc of documents) {
    if (doc.draft) continue;
    const cat = doc.category || 'Uncategorized';
    if (!categoryMap.has(cat)) categoryMap.set(cat, []);
    categoryMap.get(cat).push(doc);
  }

  // Sort categories alphabetically
  const sortedCategories = [...categoryMap.keys()].sort();

  let sectionsHtml = '';
  for (const cat of sortedCategories) {
    const docs = categoryMap.get(cat).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    const itemsHtml = docs.map(doc => {
      const url = `${baseUrl}/${doc.slug}`;
      const tagsHtml = doc.tags.length
        ? `<span class="tags">${doc.tags.map(escapeHtml).join(', ')}</span>`
        : '';
      return `
      <li class="doc-item">
        <a href="${escapeAttr(url)}" class="doc-link">${escapeHtml(doc.title)}</a>
        <span class="doc-meta">
          <time datetime="${escapeAttr(doc.createdAt)}">${formatDate(doc.createdAt)}</time>
          ${doc.author ? `<span class="author"> · ${escapeHtml(doc.author)}</span>` : ''}
          ${tagsHtml}
        </span>
        ${doc.description ? `<p class="doc-desc">${escapeHtml(doc.description)}</p>` : ''}
      </li>`;
    }).join('');

    sectionsHtml += `
    <section class="category-section">
      <h2 class="category-title">${escapeHtml(cat)}</h2>
      <ul class="doc-list">${itemsHtml}
      </ul>
    </section>`;
  }

  const totalPublished = documents.filter(d => !d.draft).length;
  const generatedAt = new Date().toISOString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8f9fa;
      color: #1a1a2e;
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .container { max-width: 900px; margin: 0 auto; }
    header { margin-bottom: 2.5rem; border-bottom: 2px solid #e0e0e0; padding-bottom: 1rem; }
    h1 { font-size: 2rem; color: #16213e; }
    .meta { font-size: 0.85rem; color: #666; margin-top: 0.5rem; }
    .category-section { margin-bottom: 2rem; background: #fff; border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
    .category-title { font-size: 1.2rem; color: #0f3460; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: .05em; }
    .doc-list { list-style: none; }
    .doc-item { padding: 0.75rem 0; border-bottom: 1px solid #f0f0f0; }
    .doc-item:last-child { border-bottom: none; }
    .doc-link { font-size: 1rem; font-weight: 600; color: #0f3460; text-decoration: none; }
    .doc-link:hover { text-decoration: underline; }
    .doc-meta { display: block; font-size: 0.8rem; color: #888; margin-top: 0.2rem; }
    .tags { margin-left: 0.5rem; font-style: italic; }
    .doc-desc { font-size: 0.9rem; color: #555; margin-top: 0.3rem; }
    footer { margin-top: 3rem; text-align: center; font-size: 0.8rem; color: #aaa; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>${title}</h1>
      <p class="meta">${totalPublished} published document${totalPublished !== 1 ? 's' : ''} &bull; Generated: <time datetime="${generatedAt}">${formatDate(generatedAt)}</time></p>
    </header>
    <main>${sectionsHtml}
    </main>
    <footer>Generated by markdown-indexer</footer>
  </div>
</body>
</html>`;
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(str) {
  return escapeHtml(str);
}

function formatDate(isoString) {
  try {
    return new Date(isoString).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  } catch {
    return isoString;
  }
}

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function writeFileSafe(filePath, content, description) {
  ensureDir(filePath);
  try {
    fs.writeFileSync(filePath, content, 'utf8');
    logger.info(`${description} written`, { path: filePath, bytes: Buffer.byteLength(content) });
  } catch (err) {
    throw new IOError(`Failed to write ${description}: ${filePath}`, filePath, err);
  }
}

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

let shutdownRequested = false;
const cleanupCallbacks = [];

function registerCleanup(fn) {
  cleanupCallbacks.push(fn);
}

async function shutdown(signal, exitCode = 0) {
  if (shutdownRequested) return;
  shutdownRequested = true;

  logger.info('Shutdown initiated', { signal });

  for (const fn of cleanupCallbacks) {
    try { await fn(); } catch (err) {
      logger.error('Error during cleanup', { error: err.message });
    }
  }

  metrics.endTime = Date.now();
  logger.info('Final metrics', metrics.summary());
  process.exit(exitCode);
}

process.on('SIGINT',  () => shutdown('SIGINT', 0));
process.on('SIGTERM', () => shutdown('SIGTERM', 0));
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { name: err.name, message: err.message, stack: err.stack });
  shutdown('uncaughtException', 1);
});
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason: String(reason) });
  shutdown('unhandledRejection', 1);
});

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  metrics.startTime = Date.now();

  // 1. Load and validate config
  let config;
  try {
    config = validateConfig(loadConfig());
  } catch (err) {
    if (err instanceof ConfigError) {
      logger.error(err.message);
      printUsage();
      process.exit(1);
    }
    throw err;
  }

  logger.setLevel(config.logLevel);
  logger.info('Starting markdown indexer', {
    inputDir: config.inputDir,
    outputJson: config.outputJsonPath,
    outputHtml: config.outputHtmlPath,
    baseUrl: config.baseUrl,
  });

  // 2. Discover files
  let files;
  try {
    files = discoverMarkdownFiles(config.inputDir);
  } catch (err) {
    if (err instanceof IOError) {
      logger.error('Failed to discover files', { error: err.message, path: err.filePath });
      process.exit(1);
    }
    throw err;
  }

  metrics.record('filesDiscovered', files.length);
  logger.info('Files discovered', { count: files.length });

  if (files.length === 0) {
    logger.warn('No markdown files found in input directory', { inputDir: config.inputDir });
  }

  // 3. Process files
  const documents = [];

  for (const filePath of files) {
    if (shutdownRequested) break;

    logger.debug('Processing file', { filePath });

    try {
      const doc = processFile(filePath, config.inputDir);
      documents.push(doc);
      metrics.record('filesProcessed');
      metrics.record('documentsIndexed');
      logger.debug('File processed', { slug: doc.slug, title: doc.title, draft: doc.draft });
    } catch (err) {
      metrics.record('filesErrored');

      if (err instanceof ParseError) {
        logger.warn('Parse error — skipping file', {
          filePath: err.filePath,
          error: err.message,
        });
        metrics.record('filesSkipped');
      } else if (err instanceof IOError) {
        logger.warn('IO error — skipping file', {
          filePath: err.filePath,
          error: err.message,
        });
        metrics.record('filesSkipped');
      } else {
        logger.error('Unexpected error processing file', {
          filePath,
          error: err.message,
          stack: err.stack,
        });
        metrics.record('filesSkipped');
      }
    }
  }

  logger.info('Processing complete', {
    processed: metrics.filesProcessed,
    skipped: metrics.filesSkipped,
    errored: metrics.filesErrored,
  });

  // 4. Build and write JSON search index
  const searchIndex = buildSearchIndex(documents);
  writeFileSafe(
    config.outputJsonPath,
    JSON.stringify(searchIndex, null, 2),
    'JSON search index'
  );

  // 5. Build and write HTML sitemap
  // Sort documents by createdAt for stable sitemap output
  const sortedDocs = [...documents].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const htmlSitemap = buildHtmlSitemap(sortedDocs, config);
  writeFileSafe(config.outputHtmlPath, htmlSitemap, 'HTML sitemap');

  metrics.endTime = Date.now();
  logger.info('Done', metrics.summary());
}

main().catch(err => {
  logger.error('Fatal error', { name: err.name, message: err.message, stack: err.stack });
  process.exit(1);
});
