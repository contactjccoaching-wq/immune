#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promises: fsPromises } = require('fs');

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  markdownDir: process.env.MARKDOWN_DIR || './markdown',
  outputDir: process.env.OUTPUT_DIR || './output',
  indexFile: process.env.INDEX_FILE || 'search-index.json',
  sitemapFile: process.env.SITEMAP_FILE || 'sitemap.html',
  logLevel: process.env.LOG_LEVEL || 'info',
};

const VALIDATION_RULES = {
  markdown_extensions: ['.md', '.markdown'],
  max_file_size: 10 * 1024 * 1024, // 10MB
  frontmatter_delimiter: '---',
  required_frontmatter_fields: ['title'],
};

// ============================================================================
// LOGGER
// ============================================================================

const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

class Logger {
  constructor(level = 'info') {
    this.level = LOG_LEVELS[level] || LOG_LEVELS.info;
  }

  debug(message, meta = {}) {
    if (this.level <= LOG_LEVELS.debug) {
      console.log(`[DEBUG] ${message}`, meta);
    }
  }

  info(message, meta = {}) {
    if (this.level <= LOG_LEVELS.info) {
      console.log(`[INFO] ${message}`, meta);
    }
  }

  warn(message, meta = {}) {
    if (this.level <= LOG_LEVELS.warn) {
      console.warn(`[WARN] ${message}`, meta);
    }
  }

  error(message, meta = {}) {
    if (this.level <= LOG_LEVELS.error) {
      console.error(`[ERROR] ${message}`, meta);
    }
  }
}

const logger = new Logger(CONFIG.logLevel);

// ============================================================================
// METRICS
// ============================================================================

class Metrics {
  constructor() {
    this.reset();
  }

  reset() {
    this.filesScanned = 0;
    this.filesParsed = 0;
    this.filesFailed = 0;
    this.startTime = Date.now();
    this.endTime = null;
  }

  recordSuccess() {
    this.filesParsed++;
  }

  recordFailure() {
    this.filesFailed++;
  }

  recordScanned() {
    this.filesScanned++;
  }

  finish() {
    this.endTime = Date.now();
  }

  getReport() {
    const duration = this.endTime ? this.endTime - this.startTime : Date.now() - this.startTime;
    return {
      filesScanned: this.filesScanned,
      filesParsed: this.filesParsed,
      filesFailed: this.filesFailed,
      durationMs: duration,
      successRate: this.filesScanned > 0 ? ((this.filesParsed / this.filesScanned) * 100).toFixed(2) + '%' : 'N/A',
    };
  }
}

const metrics = new Metrics();

// ============================================================================
// VALIDATION
// ============================================================================

function validateConfig() {
  const errors = [];

  if (!CONFIG.markdownDir) {
    errors.push('MARKDOWN_DIR is required');
  }

  if (!CONFIG.outputDir) {
    errors.push('OUTPUT_DIR is required');
  }

  if (!Object.keys(LOG_LEVELS).includes(CONFIG.logLevel)) {
    errors.push(`LOG_LEVEL must be one of: ${Object.keys(LOG_LEVELS).join(', ')}`);
  }

  if (errors.length > 0) {
    logger.error('Configuration validation failed', { errors });
    process.exit(1);
  }

  logger.debug('Configuration validated', CONFIG);
}

async function validateInputDirectory() {
  try {
    const stats = await fsPromises.stat(CONFIG.markdownDir);
    if (!stats.isDirectory()) {
      throw new Error('MARKDOWN_DIR is not a directory');
    }
    logger.info('Input directory validated', { path: CONFIG.markdownDir });
  } catch (err) {
    logger.error('Input directory validation failed', { error: err.message });
    process.exit(1);
  }
}

async function validateOutputDirectory() {
  try {
    await fsPromises.mkdir(CONFIG.outputDir, { recursive: true });
    logger.info('Output directory ensured', { path: CONFIG.outputDir });
  } catch (err) {
    logger.error('Output directory creation failed', { error: err.message });
    process.exit(1);
  }
}

function isValidMarkdownFile(filename) {
  return VALIDATION_RULES.markdown_extensions.some(ext =>
    filename.toLowerCase().endsWith(ext)
  );
}

async function validateFileSize(filepath) {
  try {
    const stats = await fsPromises.stat(filepath);
    if (stats.size > VALIDATION_RULES.max_file_size) {
      throw new Error(`File size ${stats.size} exceeds maximum ${VALIDATION_RULES.max_file_size}`);
    }
    return true;
  } catch (err) {
    logger.warn('File size validation failed', { file: filepath, error: err.message });
    return false;
  }
}

function validateFrontmatter(frontmatter) {
  const errors = [];

  for (const field of VALIDATION_RULES.required_frontmatter_fields) {
    if (!frontmatter[field]) {
      errors.push(`Required field missing: ${field}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

// ============================================================================
// FRONTMATTER PARSING
// ============================================================================

function parseFrontmatter(content) {
  const lines = content.split('\n');

  if (lines[0]?.trim() !== VALIDATION_RULES.frontmatter_delimiter) {
    return { frontmatter: null, body: content };
  }

  let endIndex = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i]?.trim() === VALIDATION_RULES.frontmatter_delimiter) {
      endIndex = i;
      break;
    }
  }

  if (endIndex === -1) {
    return { frontmatter: null, body: content };
  }

  const frontmatterText = lines.slice(1, endIndex).join('\n');
  const body = lines.slice(endIndex + 1).join('\n').trim();

  const frontmatter = {};
  const lines_fm = frontmatterText.split('\n');

  for (const line of lines_fm) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const colonIndex = trimmed.indexOf(':');
    if (colonIndex === -1) continue;

    const key = trimmed.slice(0, colonIndex).trim();
    let value = trimmed.slice(colonIndex + 1).trim();

    // Remove quotes if present
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    // Parse arrays (simple comma-separated)
    if (value.includes(',')) {
      value = value.split(',').map(v => v.trim());
    }

    // Parse boolean
    if (value.toLowerCase() === 'true') value = true;
    if (value.toLowerCase() === 'false') value = false;

    // Parse numbers
    if (!isNaN(value) && value !== '') {
      value = Number(value);
    }

    frontmatter[key] = value;
  }

  return { frontmatter, body };
}

// ============================================================================
// FILE PROCESSING
// ============================================================================

async function processMarkdownFile(filepath, relativePath) {
  metrics.recordScanned();

  try {
    // Validate file size
    const isValid = await validateFileSize(filepath);
    if (!isValid) {
      metrics.recordFailure();
      return null;
    }

    // Read file
    const content = await fsPromises.readFile(filepath, 'utf-8');
    const { frontmatter, body } = parseFrontmatter(content);

    // Validate frontmatter exists
    if (!frontmatter) {
      logger.warn('No frontmatter found', { file: relativePath });
      metrics.recordFailure();
      return null;
    }

    // Validate required fields
    const validation = validateFrontmatter(frontmatter);
    if (!validation.valid) {
      logger.warn('Frontmatter validation failed', {
        file: relativePath,
        errors: validation.errors,
      });
      metrics.recordFailure();
      return null;
    }

    // Generate ID and extract content summary
    const id = crypto.randomUUID();
    const excerpt = body.substring(0, 200).replace(/\n/g, ' ').trim();
    const wordCount = body.split(/\s+/).length;

    const doc = {
      id,
      path: relativePath,
      url: '/' + relativePath.replace(/\\/g, '/').replace(/\.md$/, '.html'),
      title: frontmatter.title,
      frontmatter,
      excerpt,
      wordCount,
      createdAt: new Date().toISOString(),
    };

    metrics.recordSuccess();
    logger.debug('File processed successfully', { file: relativePath, id });

    return doc;
  } catch (err) {
    logger.error('File processing error', { file: relativePath, error: err.message });
    metrics.recordFailure();
    return null;
  }
}

async function scanDirectory(dir, baseDir = '') {
  const documents = [];

  try {
    const entries = await fsPromises.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.join(baseDir, entry.name);

      if (entry.isDirectory()) {
        // Recursively scan subdirectories
        const subDocs = await scanDirectory(fullPath, relativePath);
        documents.push(...subDocs);
      } else if (entry.isFile() && isValidMarkdownFile(entry.name)) {
        const doc = await processMarkdownFile(fullPath, relativePath);
        if (doc) {
          documents.push(doc);
        }
      }
    }
  } catch (err) {
    logger.error('Directory scan error', { dir, error: err.message });
  }

  return documents;
}

// ============================================================================
// SEARCH INDEX GENERATION
// ============================================================================

function buildSearchIndex(documents) {
  const index = new Map();
  const docMap = new Map();

  // Index documents by ID
  for (const doc of documents) {
    docMap.set(doc.id, doc);
  }

  // Build word index for full-text search
  for (const doc of documents) {
    const searchText = [
      doc.title,
      doc.excerpt,
      ...(Array.isArray(doc.frontmatter.tags) ? doc.frontmatter.tags : []),
      doc.frontmatter.description || '',
    ].join(' ').toLowerCase();

    const words = searchText.match(/\b\w+\b/g) || [];

    for (const word of words) {
      if (!index.has(word)) {
        index.set(word, []);
      }
      index.get(word).push(doc.id);
    }
  }

  // Sort documents by createdAt for stable ordering
  const sortedDocs = [...documents].sort((a, b) =>
    new Date(a.createdAt) - new Date(b.createdAt)
  );

  return {
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    documentCount: documents.length,
    documents: sortedDocs.map(doc => ({
      id: doc.id,
      path: doc.path,
      url: doc.url,
      title: doc.title,
      excerpt: doc.excerpt,
      wordCount: doc.wordCount,
      createdAt: doc.createdAt,
      metadata: doc.frontmatter,
    })),
    index: Object.fromEntries(index),
  };
}

// ============================================================================
// SITEMAP GENERATION
// ============================================================================

function buildSitemap(documents) {
  // Sort by createdAt for stable ordering
  const sortedDocs = [...documents].sort((a, b) =>
    new Date(a.createdAt) - new Date(b.createdAt)
  );

  const entriesHtml = sortedDocs.map(doc => {
    const safeTitle = doc.title.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const lastmod = new Date(doc.createdAt).toISOString().split('T')[0];

    return `    <li>
      <a href="${doc.url}">${safeTitle}</a>
      <span class="meta">${doc.wordCount} words | ${lastmod}</span>
    </li>`;
  }).join('\n');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sitemap</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      color: #333;
      background: #f5f5f5;
      padding: 20px;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    h1 {
      color: #2c3e50;
      margin-bottom: 10px;
      font-size: 2rem;
    }
    .summary {
      background: #ecf0f1;
      padding: 15px;
      border-radius: 4px;
      margin-bottom: 30px;
      color: #555;
      font-size: 0.95rem;
    }
    .summary p {
      margin: 5px 0;
    }
    ul {
      list-style: none;
    }
    li {
      padding: 12px;
      border-bottom: 1px solid #ecf0f1;
      transition: background 0.2s;
    }
    li:hover {
      background: #f9f9f9;
    }
    li:last-child {
      border-bottom: none;
    }
    a {
      color: #3498db;
      text-decoration: none;
      font-weight: 500;
      display: inline-block;
      margin-bottom: 5px;
    }
    a:hover {
      color: #2980b9;
      text-decoration: underline;
    }
    .meta {
      display: block;
      font-size: 0.85rem;
      color: #999;
      margin-top: 5px;
    }
    footer {
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #ecf0f1;
      color: #999;
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Sitemap</h1>
    <div class="summary">
      <p><strong>Total Documents:</strong> ${documents.length}</p>
      <p><strong>Generated:</strong> ${new Date().toISOString()}</p>
    </div>
    <ul>
${entriesHtml}
    </ul>
    <footer>
      <p>Automatically generated by markdown-indexer CLI</p>
    </footer>
  </div>
</body>
</html>`;

  return html;
}

// ============================================================================
// OUTPUT WRITING
// ============================================================================

async function writeSearchIndex(searchIndex) {
  const filepath = path.join(CONFIG.outputDir, CONFIG.indexFile);

  try {
    await fsPromises.writeFile(
      filepath,
      JSON.stringify(searchIndex, null, 2),
      'utf-8'
    );
    logger.info('Search index written', { file: filepath, documents: searchIndex.documentCount });
  } catch (err) {
    logger.error('Failed to write search index', { file: filepath, error: err.message });
    throw err;
  }
}

async function writeSitemap(html) {
  const filepath = path.join(CONFIG.outputDir, CONFIG.sitemapFile);

  try {
    await fsPromises.writeFile(filepath, html, 'utf-8');
    logger.info('Sitemap written', { file: filepath });
  } catch (err) {
    logger.error('Failed to write sitemap', { file: filepath, error: err.message });
    throw err;
  }
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

function setupSignalHandlers() {
  const shutdown = (signal) => {
    logger.info('Shutting down', { signal });
    metrics.finish();
    const report = metrics.getReport();
    logger.info('Metrics report', report);
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  logger.info('Starting markdown indexer');
  setupSignalHandlers();

  try {
    // Validate configuration
    validateConfig();

    // Validate directories
    await validateInputDirectory();
    await validateOutputDirectory();

    // Scan markdown files
    logger.info('Scanning markdown directory', { path: CONFIG.markdownDir });
    const documents = await scanDirectory(CONFIG.markdownDir);

    if (documents.length === 0) {
      logger.warn('No markdown files found');
    } else {
      logger.info('Markdown files scanned', { count: documents.length });
    }

    // Generate search index
    logger.info('Building search index');
    const searchIndex = buildSearchIndex(documents);

    // Generate sitemap
    logger.info('Building sitemap');
    const sitemap = buildSitemap(documents);

    // Write outputs
    await writeSearchIndex(searchIndex);
    await writeSitemap(sitemap);

    // Metrics
    metrics.finish();
    const report = metrics.getReport();
    logger.info('Processing complete', report);

    process.exit(0);
  } catch (err) {
    logger.error('Fatal error', { error: err.message, stack: err.stack });
    metrics.finish();
    process.exit(1);
  }
}

main();
