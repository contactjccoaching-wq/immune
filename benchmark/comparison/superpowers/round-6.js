#!/usr/bin/env node

/**
 * md-index: CLI tool to read markdown files, extract frontmatter,
 * generate a JSON search index, and output an HTML sitemap.
 *
 * Usage:
 *   node round-6.js <input-dir> [options]
 *
 * Options:
 *   --output-dir <dir>     Directory to write output files (default: current dir)
 *   --index-file <name>    JSON index filename (default: search-index.json)
 *   --sitemap-file <name>  HTML sitemap filename (default: sitemap.html)
 *   --base-url <url>       Base URL for sitemap links (default: "")
 *   --recursive            Recurse into subdirectories (default: true)
 *   --help                 Show usage
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULTS = {
  outputDir: process.cwd(),
  indexFile: 'search-index.json',
  sitemapFile: 'sitemap.html',
  baseUrl: '',
  recursive: true,
};

const FRONTMATTER_DELIMITER = '---';
const MARKDOWN_EXTENSION = '.md';

// ---------------------------------------------------------------------------
// CLI Argument Parsing
// ---------------------------------------------------------------------------

/**
 * Parse process.argv into a structured options object.
 * @returns {{ inputDir: string, options: object } | null} Parsed args or null on error.
 */
function parseArgs(argv) {
  const args = argv.slice(2); // remove 'node' and script name

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    return null;
  }

  // First positional argument is the input directory
  const inputDir = args[0];
  if (!inputDir || inputDir.startsWith('--')) {
    return null;
  }

  const options = { ...DEFAULTS };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--output-dir':
        if (!args[i + 1] || args[i + 1].startsWith('--')) {
          throw new Error(`--output-dir requires a value`);
        }
        options.outputDir = args[++i];
        break;

      case '--index-file':
        if (!args[i + 1] || args[i + 1].startsWith('--')) {
          throw new Error(`--index-file requires a value`);
        }
        options.indexFile = args[++i];
        break;

      case '--sitemap-file':
        if (!args[i + 1] || args[i + 1].startsWith('--')) {
          throw new Error(`--sitemap-file requires a value`);
        }
        options.sitemapFile = args[++i];
        break;

      case '--base-url':
        if (!args[i + 1] || args[i + 1].startsWith('--')) {
          throw new Error(`--base-url requires a value`);
        }
        options.baseUrl = args[++i].replace(/\/$/, ''); // strip trailing slash
        break;

      case '--no-recursive':
        options.recursive = false;
        break;

      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  return { inputDir, options };
}

// ---------------------------------------------------------------------------
// Filesystem Helpers
// ---------------------------------------------------------------------------

/**
 * Validate that a path exists and is a readable directory.
 * @param {string} dirPath
 * @throws {Error} if path is invalid or not a directory
 */
function validateDirectory(dirPath) {
  if (!dirPath || typeof dirPath !== 'string' || dirPath.trim() === '') {
    throw new Error('Directory path must be a non-empty string');
  }

  let stat;
  try {
    stat = fs.statSync(dirPath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`Directory does not exist: ${dirPath}`);
    }
    throw new Error(`Cannot access directory "${dirPath}": ${err.message}`);
  }

  if (!stat.isDirectory()) {
    throw new Error(`Path is not a directory: ${dirPath}`);
  }
}

/**
 * Ensure a directory exists, creating it recursively if needed.
 * @param {string} dirPath
 */
function ensureDirectory(dirPath) {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch (err) {
    throw new Error(`Cannot create output directory "${dirPath}": ${err.message}`);
  }
}

/**
 * Recursively collect all markdown file paths under a directory.
 * @param {string} dirPath - Root directory to scan
 * @param {boolean} recursive - Whether to recurse into subdirectories
 * @returns {string[]} Absolute file paths, sorted lexicographically
 */
function collectMarkdownFiles(dirPath, recursive) {
  const results = [];

  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch (err) {
    throw new Error(`Cannot read directory "${dirPath}": ${err.message}`);
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (recursive) {
        const subResults = collectMarkdownFiles(fullPath, recursive);
        results.push(...subResults);
      }
    } else if (entry.isFile() && entry.name.endsWith(MARKDOWN_EXTENSION)) {
      results.push(fullPath);
    }
  }

  return results.sort();
}

/**
 * Read a file's content as a UTF-8 string.
 * @param {string} filePath
 * @returns {string}
 */
function readFileContent(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new Error(`Cannot read file "${filePath}": ${err.message}`);
  }
}

/**
 * Write content to a file, overwriting if it exists.
 * @param {string} filePath
 * @param {string} content
 */
function writeFile(filePath, content) {
  try {
    fs.writeFileSync(filePath, content, 'utf8');
  } catch (err) {
    throw new Error(`Cannot write file "${filePath}": ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Frontmatter Parsing
// ---------------------------------------------------------------------------

/**
 * Detect whether a file's content begins with a frontmatter block.
 * @param {string} content
 * @returns {boolean}
 */
function hasFrontmatter(content) {
  return content.trimStart().startsWith(FRONTMATTER_DELIMITER + '\n') ||
    content.trimStart().startsWith(FRONTMATTER_DELIMITER + '\r\n');
}

/**
 * Extract the raw YAML string from a frontmatter block.
 * Returns null if no valid frontmatter block is found.
 * @param {string} content
 * @returns {{ yaml: string, body: string } | null}
 */
function extractFrontmatterBlock(content) {
  if (!hasFrontmatter(content)) {
    return null;
  }

  // Normalise line endings
  const normalised = content.replace(/\r\n/g, '\n').trimStart();

  // Content must start with ---\n
  const afterFirstDelimiter = normalised.slice(FRONTMATTER_DELIMITER.length + 1); // skip '---\n'

  const closingIndex = afterFirstDelimiter.indexOf('\n' + FRONTMATTER_DELIMITER);
  if (closingIndex === -1) {
    // Opening delimiter found but no closing delimiter — treat as no frontmatter
    return null;
  }

  const yaml = afterFirstDelimiter.slice(0, closingIndex).trim();
  const body = afterFirstDelimiter.slice(closingIndex + 1 + FRONTMATTER_DELIMITER.length).trim();

  return { yaml, body };
}

/**
 * Parse a minimal subset of YAML: key: value pairs, including arrays.
 *
 * Supported forms:
 *   key: scalar value
 *   key: "quoted value"
 *   key: 'single quoted'
 *   key: 123
 *   key: true / false
 *   key: [item1, item2]          (inline array)
 *   key:                         (block array)
 *     - item1
 *     - item2
 *
 * Note: Nested objects are not supported. Values are kept as strings
 * unless they are valid numbers or the literals true/false/null.
 *
 * @param {string} yaml - Raw YAML string (no delimiters)
 * @returns {Record<string, unknown>}
 */
function parseYaml(yaml) {
  if (!yaml || yaml.trim() === '') {
    return {};
  }

  const result = {};
  const lines = yaml.split('\n');
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Skip blank lines and comments
    if (line.trim() === '' || line.trim().startsWith('#')) {
      i++;
      continue;
    }

    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) {
      i++;
      continue;
    }

    const key = line.slice(0, colonIndex).trim();
    if (!key) {
      i++;
      continue;
    }

    const rawValue = line.slice(colonIndex + 1).trim();

    if (rawValue === '' || rawValue === null) {
      // Potential block sequence
      const items = [];
      i++;
      while (i < lines.length && lines[i].trim().startsWith('- ')) {
        items.push(coerceScalar(lines[i].trim().slice(2).trim()));
        i++;
      }
      result[key] = items.length > 0 ? items : null;
      continue;
    }

    // Inline array: key: [a, b, c]
    if (rawValue.startsWith('[') && rawValue.endsWith(']')) {
      const inner = rawValue.slice(1, -1).trim();
      if (inner === '') {
        result[key] = [];
      } else {
        result[key] = inner.split(',').map((s) => coerceScalar(s.trim()));
      }
      i++;
      continue;
    }

    result[key] = coerceScalar(rawValue);
    i++;
  }

  return result;
}

/**
 * Coerce a raw YAML scalar string to an appropriate JS primitive.
 * @param {string} raw
 * @returns {string | number | boolean | null}
 */
function coerceScalar(raw) {
  if (!raw || raw === '') return '';

  // Quoted strings — strip quotes
  if (
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"))
  ) {
    return raw.slice(1, -1);
  }

  // Boolean literals
  if (raw === 'true') return true;
  if (raw === 'false') return false;

  // Null literals
  if (raw === 'null' || raw === '~') return null;

  // Numeric
  const num = Number(raw);
  if (!isNaN(num) && raw.trim() !== '') return num;

  return raw;
}

/**
 * Parse a markdown file's content into frontmatter metadata and body text.
 * @param {string} content - Full file content
 * @returns {{ metadata: Record<string, unknown>, body: string }}
 */
function parseMarkdownFile(content) {
  if (!content || content.trim() === '') {
    return { metadata: {}, body: '' };
  }

  const block = extractFrontmatterBlock(content);
  if (!block) {
    return { metadata: {}, body: content.trim() };
  }

  const metadata = parseYaml(block.yaml);
  return { metadata, body: block.body };
}

// ---------------------------------------------------------------------------
// Text Extraction (for search index)
// ---------------------------------------------------------------------------

/**
 * Strip markdown syntax from a body string to produce plain text suitable
 * for inclusion in a search index.
 * Removes: headings (#), bold/italic (*_), inline code (`), links, images,
 * blockquotes (>), horizontal rules, HTML tags.
 * @param {string} markdown
 * @returns {string}
 */
function stripMarkdown(markdown) {
  if (!markdown) return '';

  return markdown
    // Remove HTML tags
    .replace(/<[^>]+>/g, ' ')
    // Remove images: ![alt](url)
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    // Replace links with their display text: [text](url)
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    // Remove inline code
    .replace(/`[^`]*`/g, '')
    // Remove fenced code blocks
    .replace(/```[\s\S]*?```/g, '')
    // Remove headings markers
    .replace(/^#{1,6}\s+/gm, '')
    // Remove bold/italic (**, __, *, _)
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(\*|_)(.*?)\1/g, '$2')
    // Remove blockquotes
    .replace(/^\s*>\s*/gm, '')
    // Remove horizontal rules
    .replace(/^[-*_]{3,}\s*$/gm, '')
    // Collapse whitespace
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Derive a URL-friendly slug from a file path relative to the input directory.
 * Example: "posts/hello-world.md" → "posts/hello-world"
 * @param {string} filePath - Absolute file path
 * @param {string} inputDir - Absolute root directory
 * @returns {string}
 */
function deriveSlug(filePath, inputDir) {
  const relative = path.relative(inputDir, filePath);
  // Normalise to forward slashes and strip extension
  return relative.replace(/\\/g, '/').replace(/\.md$/i, '');
}

// ---------------------------------------------------------------------------
// Search Index Generation
// ---------------------------------------------------------------------------

/**
 * Build a search index entry for a single document.
 * @param {string} filePath
 * @param {string} inputDir
 * @param {Record<string, unknown>} metadata
 * @param {string} body
 * @param {string} baseUrl
 * @returns {object}
 */
function buildIndexEntry(filePath, inputDir, metadata, body, baseUrl) {
  const slug = deriveSlug(filePath, inputDir);
  const url = baseUrl ? `${baseUrl}/${slug}` : `/${slug}`;

  // Prefer frontmatter fields; fall back to derived values
  const title =
    (metadata.title != null ? String(metadata.title) : null) ||
    slugToTitle(path.basename(filePath, MARKDOWN_EXTENSION));

  const excerpt =
    (metadata.excerpt != null ? String(metadata.excerpt) : null) ||
    (metadata.description != null ? String(metadata.description) : null) ||
    truncateText(stripMarkdown(body), 160);

  return {
    slug,
    url,
    title,
    excerpt,
    // Spread all metadata so custom fields are preserved
    ...flattenMetadata(metadata),
    // Ensure computed fields are not overwritten by raw metadata
    slug,
    url,
    title,
    excerpt,
  };
}

/**
 * Convert a filename slug to a human-readable title.
 * "hello-world_2024" → "Hello World 2024"
 * @param {string} slug
 * @returns {string}
 */
function slugToTitle(slug) {
  return slug
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Truncate text to a maximum length, appending "…" if truncated.
 * @param {string} text
 * @param {number} maxLength
 * @returns {string}
 */
function truncateText(text, maxLength) {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 1).trimEnd() + '\u2026';
}

/**
 * Flatten metadata: convert arrays to strings where sensible,
 * remove null/undefined, stringify non-primitive values.
 * @param {Record<string, unknown>} metadata
 * @returns {Record<string, unknown>}
 */
function flattenMetadata(metadata) {
  const flat = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (value == null) continue;
    if (Array.isArray(value)) {
      flat[key] = value.map(String).join(', ');
    } else if (typeof value === 'object') {
      flat[key] = JSON.stringify(value);
    } else {
      flat[key] = value;
    }
  }
  return flat;
}

/**
 * Build the complete JSON search index from parsed file data.
 * @param {Array<{ filePath: string, metadata: object, body: string }>} documents
 * @param {string} inputDir
 * @param {string} baseUrl
 * @returns {string} Pretty-printed JSON
 */
function buildSearchIndex(documents, inputDir, baseUrl) {
  if (!Array.isArray(documents) || documents.length === 0) {
    return JSON.stringify({ generated: new Date().toISOString(), documents: [] }, null, 2);
  }

  const entries = documents.map(({ filePath, metadata, body }) =>
    buildIndexEntry(filePath, inputDir, metadata, body, baseUrl)
  );

  const index = {
    generated: new Date().toISOString(),
    total: entries.length,
    documents: entries,
  };

  return JSON.stringify(index, null, 2);
}

// ---------------------------------------------------------------------------
// HTML Sitemap Generation
// ---------------------------------------------------------------------------

/**
 * Escape a string for safe inclusion in HTML attribute values and text.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Format a date string or Date object as YYYY-MM-DD, or return '—' if invalid.
 * @param {unknown} value
 * @returns {string}
 */
function formatDate(value) {
  if (!value) return '\u2014';
  const d = new Date(String(value));
  if (isNaN(d.getTime())) return '\u2014';
  return d.toISOString().slice(0, 10);
}

/**
 * Render a single sitemap row for a document.
 * @param {object} entry
 * @returns {string}
 */
function renderSitemapRow(entry) {
  const title = escapeHtml(entry.title || entry.slug);
  const url = escapeHtml(entry.url || '');
  const date = escapeHtml(formatDate(entry.date || entry.lastmod || entry.updated));
  const tags = escapeHtml(entry.tags || entry.keywords || '');
  const category = escapeHtml(entry.category || '');

  return `      <tr>
        <td><a href="${url}">${title}</a></td>
        <td>${category}</td>
        <td class="tags">${tags}</td>
        <td>${date}</td>
      </tr>`;
}

/**
 * Group documents by category for the sitemap.
 * Documents without a category go under 'Uncategorised'.
 * @param {object[]} entries
 * @returns {Map<string, object[]>}
 */
function groupByCategory(entries) {
  const groups = new Map();

  for (const entry of entries) {
    const category = (entry.category != null && String(entry.category).trim() !== '')
      ? String(entry.category)
      : 'Uncategorised';

    if (!groups.has(category)) {
      groups.set(category, []);
    }
    groups.get(category).push(entry);
  }

  // Sort categories: named categories first (sorted), then Uncategorised
  const sorted = new Map(
    [...groups.entries()].sort(([a], [b]) => {
      if (a === 'Uncategorised') return 1;
      if (b === 'Uncategorised') return -1;
      return a.localeCompare(b);
    })
  );

  return sorted;
}

/**
 * Build the complete HTML sitemap document.
 * @param {object[]} indexEntries - Search index entries
 * @param {string} baseUrl
 * @param {string} inputDirName - Display name of input directory
 * @returns {string} Full HTML document
 */
function buildSitemap(indexEntries, baseUrl, inputDirName) {
  if (!Array.isArray(indexEntries) || indexEntries.length === 0) {
    return buildEmptySitemap(inputDirName);
  }

  const generated = new Date().toLocaleString('en-GB', { timeZone: 'UTC' }) + ' UTC';
  const groups = groupByCategory(indexEntries);

  const sections = [];
  for (const [category, entries] of groups) {
    const rows = entries.map(renderSitemapRow).join('\n');
    sections.push(`    <section>
      <h2>${escapeHtml(category)} <span class="count">(${entries.length})</span></h2>
      <table>
        <thead>
          <tr>
            <th>Title</th>
            <th>Category</th>
            <th>Tags / Keywords</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
${rows}
        </tbody>
      </table>
    </section>`);
  }

  const totalDocuments = indexEntries.length;
  const baseUrlDisplay = baseUrl || '(none)';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sitemap &mdash; ${escapeHtml(inputDirName)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: #1a1a1a;
      background: #f9f9f9;
      padding: 2rem 1rem;
      line-height: 1.5;
    }
    .container { max-width: 960px; margin: 0 auto; }
    header { margin-bottom: 2rem; }
    header h1 { font-size: 1.75rem; margin-bottom: 0.25rem; }
    header p { color: #555; font-size: 0.875rem; }
    section { margin-bottom: 2.5rem; }
    h2 { font-size: 1.2rem; margin-bottom: 0.75rem; color: #333; }
    .count { font-weight: 400; color: #777; font-size: 0.9em; }
    table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    thead { background: #f0f0f0; }
    th, td { text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #e8e8e8; font-size: 0.875rem; }
    th { font-weight: 600; color: #444; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #fafafa; }
    a { color: #0066cc; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .tags { color: #666; font-size: 0.8rem; }
    footer { margin-top: 3rem; font-size: 0.8rem; color: #999; text-align: center; }
    .summary { background: #fff; border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); font-size: 0.875rem; color: #555; }
    .summary strong { color: #1a1a1a; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Sitemap</h1>
      <p>Generated from: <strong>${escapeHtml(inputDirName)}</strong></p>
    </header>

    <div class="summary">
      <strong>${totalDocuments}</strong> document${totalDocuments !== 1 ? 's' : ''} indexed &bull;
      Base URL: <strong>${escapeHtml(baseUrlDisplay)}</strong> &bull;
      Generated: ${escapeHtml(generated)}
    </div>

${sections.join('\n\n')}

    <footer>
      Generated by md-index &bull; ${escapeHtml(generated)}
    </footer>
  </div>
</body>
</html>`;
}

/**
 * Build an empty sitemap page when no documents are found.
 * @param {string} inputDirName
 * @returns {string}
 */
function buildEmptySitemap(inputDirName) {
  const generated = new Date().toLocaleString('en-GB', { timeZone: 'UTC' }) + ' UTC';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sitemap &mdash; ${escapeHtml(inputDirName)}</title>
</head>
<body>
  <h1>Sitemap</h1>
  <p>No markdown files found in <strong>${escapeHtml(inputDirName)}</strong>.</p>
  <p>Generated: ${escapeHtml(generated)}</p>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main Orchestrator
// ---------------------------------------------------------------------------

/**
 * Process a single markdown file and return its parsed data.
 * Returns null if the file cannot be read (error is logged but not thrown).
 * @param {string} filePath
 * @returns {{ filePath: string, metadata: object, body: string } | null}
 */
function processMarkdownFile(filePath) {
  let content;
  try {
    content = readFileContent(filePath);
  } catch (err) {
    console.error(`  [warn] ${err.message}`);
    return null;
  }

  const { metadata, body } = parseMarkdownFile(content);
  return { filePath, metadata, body };
}

/**
 * Print usage information to stdout.
 */
function printUsage() {
  console.log(`
Usage:
  node round-6.js <input-dir> [options]

Arguments:
  <input-dir>               Directory containing markdown files

Options:
  --output-dir <dir>        Directory to write output files (default: current dir)
  --index-file <name>       JSON index filename (default: search-index.json)
  --sitemap-file <name>     HTML sitemap filename (default: sitemap.html)
  --base-url <url>          Base URL for sitemap links (default: "")
  --no-recursive            Do not recurse into subdirectories
  --help, -h                Show this help message

Examples:
  node round-6.js ./docs
  node round-6.js ./content --output-dir ./dist --base-url https://example.com
  node round-6.js ./posts --index-file index.json --sitemap-file site.html
`.trim());
}

/**
 * Main entry point.
 */
function main() {
  // Parse arguments
  let parsed;
  try {
    parsed = parseArgs(process.argv);
  } catch (err) {
    console.error(`Error: ${err.message}\n`);
    printUsage();
    process.exit(1);
  }

  if (!parsed) {
    printUsage();
    process.exit(0);
  }

  const { inputDir, options } = parsed;
  const absoluteInputDir = path.resolve(inputDir);

  // Validate input directory
  try {
    validateDirectory(absoluteInputDir);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  // Ensure output directory exists
  const absoluteOutputDir = path.resolve(options.outputDir);
  try {
    ensureDirectory(absoluteOutputDir);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  console.log(`Scanning: ${absoluteInputDir}`);

  // Collect markdown files
  let filePaths;
  try {
    filePaths = collectMarkdownFiles(absoluteInputDir, options.recursive);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  console.log(`Found: ${filePaths.length} markdown file${filePaths.length !== 1 ? 's' : ''}`);

  if (filePaths.length === 0) {
    console.warn('Warning: No markdown files found. Output files will be empty.');
  }

  // Process all files
  const documents = [];
  for (const filePath of filePaths) {
    const result = processMarkdownFile(filePath);
    if (result) {
      documents.push(result);
    }
  }

  console.log(`Processed: ${documents.length} file${documents.length !== 1 ? 's' : ''} successfully`);

  // Build search index
  const indexJson = buildSearchIndex(documents, absoluteInputDir, options.baseUrl);
  const indexPath = path.join(absoluteOutputDir, options.indexFile);

  try {
    writeFile(indexPath, indexJson);
    console.log(`Index written: ${indexPath}`);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  // Build sitemap
  // Re-parse the index entries from the generated JSON to ensure consistency
  let indexEntries;
  try {
    const parsed = JSON.parse(indexJson);
    indexEntries = parsed.documents || [];
  } catch {
    indexEntries = [];
  }

  const inputDirName = path.basename(absoluteInputDir);
  const sitemapHtml = buildSitemap(indexEntries, options.baseUrl, inputDirName);
  const sitemapPath = path.join(absoluteOutputDir, options.sitemapFile);

  try {
    writeFile(sitemapPath, sitemapHtml);
    console.log(`Sitemap written: ${sitemapPath}`);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  console.log('Done.');
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

main();
