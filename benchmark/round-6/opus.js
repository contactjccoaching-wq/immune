#!/usr/bin/env node

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// =============================================================================
// CONSTANTS & VALIDATION RULES
// =============================================================================

const VALID_LOG_LEVELS = new Map([
  ["debug", 0],
  ["info", 1],
  ["warn", 2],
  ["error", 3],
  ["silent", 4],
]);

const FRONTMATTER_DELIMITER = "---";
const MARKDOWN_EXTENSION = ".md";
const DEFAULT_OUTPUT_DIR = "./output";
const DEFAULT_LOG_LEVEL = "info";
const MAX_TITLE_LENGTH = 300;
const MAX_DESCRIPTION_LENGTH = 1000;
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

const REQUIRED_ENV_VARS = {
  MD_INPUT_DIR: "Path to the directory containing markdown files",
};

const OPTIONAL_ENV_VARS = {
  MD_OUTPUT_DIR: `Output directory (default: ${DEFAULT_OUTPUT_DIR})`,
  MD_BASE_URL: "Base URL for sitemap links (default: https://example.com)",
  MD_LOG_LEVEL: `Log level: ${[...VALID_LOG_LEVELS.keys()].join(", ")} (default: ${DEFAULT_LOG_LEVEL})`,
  MD_SITE_NAME: "Site name for HTML sitemap header (default: Site)",
};

// =============================================================================
// STRUCTURED LOGGER
// =============================================================================

class Logger {
  constructor(level = DEFAULT_LOG_LEVEL) {
    const normalizedLevel = level.toLowerCase();
    if (!VALID_LOG_LEVELS.has(normalizedLevel)) {
      throw new ConfigError(
        `Invalid log level "${level}". Valid levels: ${[...VALID_LOG_LEVELS.keys()].join(", ")}`
      );
    }
    this.threshold = VALID_LOG_LEVELS.get(normalizedLevel);
    this.levelName = normalizedLevel;
  }

  _log(level, message, data = {}) {
    if (VALID_LOG_LEVELS.get(level) < this.threshold) return;
    const entry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      ...data,
    };
    const stream = level === "error" || level === "warn" ? process.stderr : process.stdout;
    stream.write(JSON.stringify(entry) + "\n");
  }

  debug(msg, data) { this._log("debug", msg, data); }
  info(msg, data) { this._log("info", msg, data); }
  warn(msg, data) { this._log("warn", msg, data); }
  error(msg, data) { this._log("error", msg, data); }
}

// =============================================================================
// CUSTOM ERROR TYPES
// =============================================================================

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigError";
  }
}

class InputValidationError extends Error {
  constructor(message, filePath) {
    super(message);
    this.name = "InputValidationError";
    this.filePath = filePath;
  }
}

class FrontmatterParseError extends Error {
  constructor(message, filePath) {
    super(message);
    this.name = "FrontmatterParseError";
    this.filePath = filePath;
  }
}

class OutputError extends Error {
  constructor(message, outputPath) {
    super(message);
    this.name = "OutputError";
    this.outputPath = outputPath;
  }
}

// =============================================================================
// METRICS TRACKER
// =============================================================================

class Metrics {
  constructor() {
    this.startTime = Date.now();
    this.counters = new Map();
    this.timings = new Map();
  }

  increment(name, amount = 1) {
    this.counters.set(name, (this.counters.get(name) || 0) + amount);
  }

  startTimer(name) {
    this.timings.set(name, Date.now());
  }

  endTimer(name) {
    const start = this.timings.get(name);
    if (start) {
      const elapsed = Date.now() - start;
      this.timings.set(name, elapsed);
      return elapsed;
    }
    return 0;
  }

  summary() {
    return {
      totalDurationMs: Date.now() - this.startTime,
      counters: Object.fromEntries(this.counters),
      timingsMs: Object.fromEntries(
        [...this.timings.entries()].filter(([, v]) => typeof v === "number" && v < Date.now())
      ),
    };
  }
}

// =============================================================================
// CONFIG LOADER WITH VALIDATION
// =============================================================================

function loadConfig(logger) {
  const errors = [];

  for (const [key, description] of Object.entries(REQUIRED_ENV_VARS)) {
    if (!process.env[key] || process.env[key].trim() === "") {
      errors.push(`Missing required env var ${key}: ${description}`);
    }
  }

  if (errors.length > 0) {
    const helpLines = [
      "\nRequired environment variables:",
      ...Object.entries(REQUIRED_ENV_VARS).map(([k, v]) => `  ${k} - ${v}`),
      "\nOptional environment variables:",
      ...Object.entries(OPTIONAL_ENV_VARS).map(([k, v]) => `  ${k} - ${v}`),
    ];
    throw new ConfigError(errors.join("\n") + "\n" + helpLines.join("\n"));
  }

  const inputDir = path.resolve(process.env.MD_INPUT_DIR.trim());
  const outputDir = path.resolve((process.env.MD_OUTPUT_DIR || DEFAULT_OUTPUT_DIR).trim());
  const baseUrl = (process.env.MD_BASE_URL || "https://example.com").trim().replace(/\/+$/, "");
  const logLevel = (process.env.MD_LOG_LEVEL || DEFAULT_LOG_LEVEL).trim();
  const siteName = (process.env.MD_SITE_NAME || "Site").trim();

  if (!fs.existsSync(inputDir)) {
    throw new ConfigError(`Input directory does not exist: ${inputDir}`);
  }

  const stat = fs.statSync(inputDir);
  if (!stat.isDirectory()) {
    throw new ConfigError(`Input path is not a directory: ${inputDir}`);
  }

  try {
    new URL(baseUrl);
  } catch {
    throw new ConfigError(`Invalid base URL: ${baseUrl}`);
  }

  const config = { inputDir, outputDir, baseUrl, logLevel, siteName };
  logger.info("Configuration loaded", { config });
  return config;
}

// =============================================================================
// FRONTMATTER PARSER
// =============================================================================

function parseFrontmatter(content, filePath) {
  const trimmed = content.trim();

  if (!trimmed.startsWith(FRONTMATTER_DELIMITER)) {
    return { metadata: {}, body: trimmed };
  }

  const secondDelimiterIndex = trimmed.indexOf(
    `\n${FRONTMATTER_DELIMITER}`,
    FRONTMATTER_DELIMITER.length
  );

  if (secondDelimiterIndex === -1) {
    throw new FrontmatterParseError(
      "Frontmatter opening delimiter found but no closing delimiter",
      filePath
    );
  }

  const frontmatterBlock = trimmed.slice(
    FRONTMATTER_DELIMITER.length + 1,
    secondDelimiterIndex
  );

  const body = trimmed.slice(
    secondDelimiterIndex + FRONTMATTER_DELIMITER.length + 1
  ).trim();

  const metadata = parseYamlLike(frontmatterBlock, filePath);
  return { metadata, body };
}

function parseYamlLike(block, filePath) {
  const result = {};
  const lines = block.split("\n");
  let currentKey = null;
  let currentArrayItems = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmedLine = line.trim();

    if (trimmedLine === "" || trimmedLine.startsWith("#")) continue;

    // Array item under current key
    if (trimmedLine.startsWith("- ") && currentKey !== null) {
      if (currentArrayItems === null) currentArrayItems = [];
      currentArrayItems.push(trimmedLine.slice(2).trim());
      continue;
    }

    // Flush pending array
    if (currentKey !== null && currentArrayItems !== null) {
      result[currentKey] = currentArrayItems;
      currentKey = null;
      currentArrayItems = null;
    }

    const colonIndex = trimmedLine.indexOf(":");
    if (colonIndex === -1) {
      throw new FrontmatterParseError(
        `Invalid YAML line ${i + 1}: "${trimmedLine}"`,
        filePath
      );
    }

    const key = trimmedLine.slice(0, colonIndex).trim();
    const rawValue = trimmedLine.slice(colonIndex + 1).trim();

    if (rawValue === "") {
      // Could be start of an array or nested object — treat as array start
      currentKey = key;
      currentArrayItems = null;
      continue;
    }

    currentKey = null;
    currentArrayItems = null;

    // Handle quoted strings
    if (
      (rawValue.startsWith('"') && rawValue.endsWith('"')) ||
      (rawValue.startsWith("'") && rawValue.endsWith("'"))
    ) {
      result[key] = rawValue.slice(1, -1);
    }
    // Handle inline arrays [a, b, c]
    else if (rawValue.startsWith("[") && rawValue.endsWith("]")) {
      result[key] = rawValue
        .slice(1, -1)
        .split(",")
        .map((s) => s.trim().replace(/^["']|["']$/g, ""))
        .filter((s) => s.length > 0);
    }
    // Handle booleans
    else if (rawValue === "true") {
      result[key] = true;
    } else if (rawValue === "false") {
      result[key] = false;
    }
    // Handle numbers
    else if (!isNaN(rawValue) && rawValue !== "") {
      result[key] = Number(rawValue);
    }
    // Handle dates (YYYY-MM-DD or ISO 8601)
    else if (/^\d{4}-\d{2}-\d{2}/.test(rawValue)) {
      result[key] = rawValue;
    }
    // Plain string
    else {
      result[key] = rawValue;
    }
  }

  // Flush trailing array
  if (currentKey !== null && currentArrayItems !== null) {
    result[currentKey] = currentArrayItems;
  }

  return result;
}

// =============================================================================
// MARKDOWN FILE DISCOVERY
// =============================================================================

function discoverMarkdownFiles(inputDir, logger) {
  const files = [];

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      logger.warn("Cannot read directory, skipping", { dir, error: err.message });
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(MARKDOWN_EXTENSION)) {
        files.push(fullPath);
      }
    }
  }

  walk(inputDir);
  return files.sort();
}

// =============================================================================
// FILE PROCESSOR
// =============================================================================

function processFile(filePath, inputDir, baseUrl, logger, metrics) {
  const stat = fs.statSync(filePath);

  if (stat.size > MAX_FILE_SIZE_BYTES) {
    throw new InputValidationError(
      `File exceeds maximum size of ${MAX_FILE_SIZE_BYTES} bytes (actual: ${stat.size})`,
      filePath
    );
  }

  if (stat.size === 0) {
    throw new InputValidationError("File is empty", filePath);
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const { metadata, body } = parseFrontmatter(content, filePath);

  const relativePath = path.relative(inputDir, filePath).replace(/\\/g, "/");
  const slug = relativePath.replace(/\.md$/, "").replace(/\s+/g, "-").toLowerCase();
  const url = `${baseUrl}/${slug}`;

  // Validate metadata fields
  if (metadata.title && typeof metadata.title === "string" && metadata.title.length > MAX_TITLE_LENGTH) {
    logger.warn("Title exceeds max length, truncating", {
      filePath,
      originalLength: metadata.title.length,
      maxLength: MAX_TITLE_LENGTH,
    });
    metadata.title = metadata.title.slice(0, MAX_TITLE_LENGTH);
  }

  if (
    metadata.description &&
    typeof metadata.description === "string" &&
    metadata.description.length > MAX_DESCRIPTION_LENGTH
  ) {
    logger.warn("Description exceeds max length, truncating", {
      filePath,
      originalLength: metadata.description.length,
      maxLength: MAX_DESCRIPTION_LENGTH,
    });
    metadata.description = metadata.description.slice(0, MAX_DESCRIPTION_LENGTH);
  }

  // Extract first heading from body if no title in frontmatter
  let title = metadata.title;
  if (!title) {
    const headingMatch = body.match(/^#\s+(.+)$/m);
    title = headingMatch ? headingMatch[1].trim() : path.basename(filePath, MARKDOWN_EXTENSION);
  }

  // Extract plain text snippet for search
  const plainBody = body
    .replace(/^#{1,6}\s+.*$/gm, "")
    .replace(/!\[.*?\]\(.*?\)/g, "")
    .replace(/\[([^\]]*)\]\(.*?\)/g, "$1")
    .replace(/[`*_~]/g, "")
    .replace(/```[\s\S]*?```/g, "")
    .replace(/<[^>]+>/g, "")
    .replace(/\n{2,}/g, "\n")
    .trim();

  const snippet = plainBody.slice(0, 200).trim();

  const createdAt = metadata.date || metadata.created || metadata.createdAt || stat.birthtime.toISOString();
  const updatedAt = metadata.updated || metadata.updatedAt || stat.mtime.toISOString();

  const entry = {
    id: crypto.randomUUID(),
    filePath: relativePath,
    slug,
    url,
    title,
    description: metadata.description || metadata.excerpt || snippet,
    author: metadata.author || null,
    tags: normalizeTags(metadata.tags || metadata.categories || []),
    draft: metadata.draft === true,
    createdAt,
    updatedAt,
    wordCount: plainBody.split(/\s+/).filter(Boolean).length,
    metadata: { ...metadata },
  };

  metrics.increment("files_processed");
  if (entry.draft) metrics.increment("drafts_found");
  metrics.increment("total_words", entry.wordCount);

  logger.debug("Processed file", { filePath: relativePath, title: entry.title, wordCount: entry.wordCount });

  return entry;
}

function normalizeTags(tags) {
  if (typeof tags === "string") {
    return tags
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
  }
  if (Array.isArray(tags)) {
    return tags.map((t) => String(t).trim().toLowerCase()).filter(Boolean);
  }
  return [];
}

// =============================================================================
// SEARCH INDEX GENERATOR
// =============================================================================

function generateSearchIndex(entries) {
  // Use Map for O(1) tag lookups
  const tagIndex = new Map();
  const authorIndex = new Map();

  // Sort by createdAt for stable ordering
  const sorted = [...entries].sort((a, b) => {
    const dateA = new Date(a.createdAt).getTime() || 0;
    const dateB = new Date(b.createdAt).getTime() || 0;
    return dateA - dateB;
  });

  for (const entry of sorted) {
    for (const tag of entry.tags) {
      if (!tagIndex.has(tag)) tagIndex.set(tag, []);
      tagIndex.get(tag).push(entry.id);
    }

    if (entry.author) {
      if (!authorIndex.has(entry.author)) authorIndex.set(entry.author, []);
      authorIndex.get(entry.author).push(entry.id);
    }
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    totalEntries: sorted.length,
    entries: sorted.map((e) => ({
      id: e.id,
      slug: e.slug,
      url: e.url,
      title: e.title,
      description: e.description,
      author: e.author,
      tags: e.tags,
      draft: e.draft,
      createdAt: e.createdAt,
      updatedAt: e.updatedAt,
      wordCount: e.wordCount,
    })),
    indices: {
      tags: Object.fromEntries(tagIndex),
      authors: Object.fromEntries(authorIndex),
    },
  };
}

// =============================================================================
// HTML SITEMAP GENERATOR
// =============================================================================

function generateSitemap(entries, config) {
  const sorted = [...entries]
    .filter((e) => !e.draft)
    .sort((a, b) => {
      const dateA = new Date(a.createdAt).getTime() || 0;
      const dateB = new Date(b.createdAt).getTime() || 0;
      return dateA - dateB;
    });

  // Group by tag using Map
  const byTag = new Map();
  byTag.set("_all", []);

  for (const entry of sorted) {
    byTag.get("_all").push(entry);
    if (entry.tags.length === 0) {
      if (!byTag.has("uncategorized")) byTag.set("uncategorized", []);
      byTag.get("uncategorized").push(entry);
    } else {
      for (const tag of entry.tags) {
        if (!byTag.has(tag)) byTag.set(tag, []);
        byTag.get(tag).push(entry);
      }
    }
  }

  const tagSections = [...byTag.entries()]
    .filter(([key]) => key !== "_all")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([tag, items]) => {
      const itemsHtml = items
        .map(
          (entry) =>
            `      <li>
        <a href="${escapeHtml(entry.url)}">${escapeHtml(entry.title)}</a>
        ${entry.description ? `<p>${escapeHtml(entry.description)}</p>` : ""}
        <small>
          ${entry.author ? `By ${escapeHtml(entry.author)} | ` : ""}${escapeHtml(entry.createdAt)}
          ${entry.wordCount ? ` | ${entry.wordCount} words` : ""}
        </small>
      </li>`
        )
        .join("\n");

      return `    <section>
      <h2>${escapeHtml(tag)} (${items.length})</h2>
      <ul>
${itemsHtml}
      </ul>
    </section>`;
    })
    .join("\n\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sitemap - ${escapeHtml(config.siteName)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; max-width: 900px; margin: 0 auto; padding: 2rem 1rem; color: #1a1a1a; background: #fafafa; }
    h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
    .meta { color: #666; margin-bottom: 2rem; font-size: 0.9rem; }
    section { margin-bottom: 2rem; }
    h2 { font-size: 1.3rem; margin-bottom: 0.75rem; color: #2563eb; text-transform: capitalize; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.25rem; }
    ul { list-style: none; }
    li { margin-bottom: 1rem; padding: 0.75rem; background: #fff; border-radius: 6px; border: 1px solid #e5e7eb; }
    a { color: #2563eb; text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline; }
    p { color: #555; font-size: 0.9rem; margin-top: 0.25rem; }
    small { color: #999; font-size: 0.8rem; display: block; margin-top: 0.25rem; }
  </style>
</head>
<body>
  <header>
    <h1>Sitemap - ${escapeHtml(config.siteName)}</h1>
    <div class="meta">
      <span>${sorted.length} pages</span> |
      <span>Generated ${new Date().toISOString()}</span> |
      <span><a href="${escapeHtml(config.baseUrl)}">${escapeHtml(config.baseUrl)}</a></span>
    </div>
  </header>
  <main>
${tagSections}
  </main>
</body>
</html>`;
}

function escapeHtml(str) {
  if (typeof str !== "string") return String(str);
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// =============================================================================
// OUTPUT WRITER
// =============================================================================

function writeOutput(outputDir, searchIndex, sitemapHtml, logger) {
  try {
    fs.mkdirSync(outputDir, { recursive: true });
  } catch (err) {
    throw new OutputError(`Cannot create output directory: ${err.message}`, outputDir);
  }

  const indexPath = path.join(outputDir, "search-index.json");
  const sitemapPath = path.join(outputDir, "sitemap.html");

  try {
    fs.writeFileSync(indexPath, JSON.stringify(searchIndex, null, 2), "utf-8");
    logger.info("Search index written", { path: indexPath, entries: searchIndex.totalEntries });
  } catch (err) {
    throw new OutputError(`Cannot write search index: ${err.message}`, indexPath);
  }

  try {
    fs.writeFileSync(sitemapPath, sitemapHtml, "utf-8");
    logger.info("HTML sitemap written", { path: sitemapPath });
  } catch (err) {
    throw new OutputError(`Cannot write sitemap: ${err.message}`, sitemapPath);
  }

  return { indexPath, sitemapPath };
}

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================

function setupGracefulShutdown(logger, cleanup) {
  let shuttingDown = false;

  const handler = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.warn("Received shutdown signal, cleaning up", { signal });
    try {
      cleanup();
    } catch (err) {
      logger.error("Error during cleanup", { error: err.message });
    }
    process.exit(1);
  };

  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
  process.on("uncaughtException", (err) => {
    logger.error("Uncaught exception", { error: err.message, stack: err.stack });
    process.exit(1);
  });
  process.on("unhandledRejection", (reason) => {
    logger.error("Unhandled rejection", { reason: String(reason) });
    process.exit(1);
  });
}

// =============================================================================
// MAIN
// =============================================================================

function main() {
  const metrics = new Metrics();
  metrics.startTimer("total");

  // Pre-create logger with default level; re-create after config loads
  let logger = new Logger(process.env.MD_LOG_LEVEL || DEFAULT_LOG_LEVEL);

  setupGracefulShutdown(logger, () => {
    logger.info("Shutdown cleanup complete");
  });

  let config;
  try {
    config = loadConfig(logger);
  } catch (err) {
    if (err instanceof ConfigError) {
      logger.error("Configuration error", { error: err.message });
      process.exit(2);
    }
    throw err;
  }

  // Re-create logger with configured level
  logger = new Logger(config.logLevel);

  // Discover files
  metrics.startTimer("discovery");
  const mdFiles = discoverMarkdownFiles(config.inputDir, logger);
  metrics.endTimer("discovery");
  metrics.increment("files_found", mdFiles.length);

  if (mdFiles.length === 0) {
    logger.warn("No markdown files found in input directory", { inputDir: config.inputDir });
    process.exit(0);
  }

  logger.info("Markdown files discovered", { count: mdFiles.length });

  // Process files
  metrics.startTimer("processing");
  const entries = [];
  const errors = [];

  for (const filePath of mdFiles) {
    try {
      const entry = processFile(filePath, config.inputDir, config.baseUrl, logger, metrics);
      entries.push(entry);
    } catch (err) {
      if (err instanceof InputValidationError || err instanceof FrontmatterParseError) {
        errors.push({ file: err.filePath || filePath, error: err.message, type: err.name });
        logger.warn("Skipping file due to error", {
          file: filePath,
          errorType: err.name,
          error: err.message,
        });
        metrics.increment("files_skipped");
      } else {
        throw err;
      }
    }
  }
  metrics.endTimer("processing");

  if (entries.length === 0) {
    logger.error("All files failed processing", { errorCount: errors.length });
    process.exit(3);
  }

  // Generate outputs
  metrics.startTimer("generation");
  const searchIndex = generateSearchIndex(entries);
  const sitemapHtml = generateSitemap(entries, config);
  metrics.endTimer("generation");

  // Write outputs
  metrics.startTimer("writing");
  const { indexPath, sitemapPath } = writeOutput(config.outputDir, searchIndex, sitemapHtml, logger);
  metrics.endTimer("writing");

  metrics.endTimer("total");

  // Final summary
  const summary = metrics.summary();
  logger.info("Processing complete", {
    metrics: summary,
    output: { indexPath, sitemapPath },
    errors: errors.length > 0 ? errors : undefined,
  });
}

main();
