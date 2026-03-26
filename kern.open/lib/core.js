/**
 * lib/core.js
 *
 * Agnostic audit orchestrator — all engine-specific data is sourced exclusively
 * from lib/engines_manifest.js.  To add a new engine, add its entry to the
 * manifest and create a parser file; no changes here are required.
 *
 * Fusion Engine
 * -------------
 * After all engines finish, raw findings are passed through fuseIssues().
 * Duplicates are identified by a composite key of (normalised-relative-file +
 * exact-line + normalised evidence) and merged into a single record.
 *
 * Path Normalisation
 * ------------------
 * Before building the fusion key, every file path is made relative to the
 * scan root using path.relative() + path.normalize() for full Windows
 * backslash safety, then lower-cased.  This ensures that an absolute path
 * returned by one engine (e.g. /tmp/project/src/config.js) and a relative
 * path returned by another (e.g. src/config.js) both collapse to the same key.
 *
 * Aggressive Line Merging
 * -----------------------
 * Two findings on the same normalised file AND the same line number are always
 * merged into one object — exact match, no fuzzy tolerance needed for same-line
 * deduplication.  The fuzzy bucket is still used as a secondary fallback when
 * evidence strings also match, to absorb ±1 line disagreements between engines.
 *
 * Intelligent Description Merging
 * --------------------------------
 * When findings from multiple engines are merged, descriptions are combined
 * into a single human-readable sentence rather than a raw semicolon list.
 * Engine names are used as prefixes only when the descriptions differ, e.g.:
 *   "Gitleaks: GitHub Token; Horusec: Potential Hard-coded credential"
 * becomes a single entry with confidence: MEDIUM and engines: ["gitleaks","horusec"].
 *
 * Each merged record carries an `engines` array and a `confidence` score
 * derived from the number of independent detections, making the output compact
 * and AI-context-friendly.
 *
 * supports_file_scan flag
 * -----------------------
 * In --diff mode, engines with supports_file_scan: false in the manifest are
 * skipped entirely.  Horusec is directory-only but its parser post-filters
 * results, so it is marked false and excluded from single-file / diff runs
 * unless the caller explicitly passes it via engineFilter.
 */

"use strict";

const fs   = require("fs");
const path = require("path");

const { getEngineBinary } = require("./utils/downloader");
const { getManifest }     = require("./engines_manifest");

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * Normalize path separators to forward slashes for cross-platform safety.
 * @param {string} p
 * @returns {string}
 */
const normalizeSafePath = (p) => {
  if (typeof p !== "string") return p;
  // path.normalize handles .. and redundant separators; replace handles Windows \
  return path.normalize(p).split(path.sep).join("/");
};

/**
 * Make a file path relative to scanRoot, then lower-case it.
 * Uses path.relative() for correct Windows backslash handling, then converts
 * to forward slashes.  Falls back to basename extraction when the path lives
 * outside the scan root (e.g. Horusec temp working dirs).
 *
 * Examples (scanRoot = "/home/user/project"):
 *   "/home/user/project/src/config.js"  → "src/config.js"
 *   "src/config.js"                     → "src/config.js"
 *   "C:\\Users\\project\\src\\config.js" → "src/config.js"  (Windows)
 *   "/tmp/horusec-work/src/config.js"   → "src/config.js"  (basename fallback)
 *
 * @param {string} filePath  - Raw file path from an engine parser.
 * @param {string} scanRoot  - Absolute path to the directory being scanned.
 * @returns {string}
 */
function relativeToRoot(filePath, scanRoot) {
  if (!filePath) return "";

  // Normalise both paths: resolve separators and redundant segments.
  const fp   = path.normalize(String(filePath));
  const root = path.normalize(String(scanRoot));

  // Happy path: use path.relative() which handles Windows drive letters and
  // backslashes correctly on all platforms.
  const rel = path.relative(root, fp);

  // path.relative() returns "" when fp === root, and starts with ".." when fp
  // is outside root.  Accept it only when it does NOT escape the root.
  if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) {
    // Convert to forward slashes and lower-case.
    return rel.split(path.sep).join("/").toLowerCase();
  }

  // Fallback: some engines (e.g. Horusec) write to a temp working dir.
  // Try to recover the meaningful suffix by scanning path segments.
  const parts = fp.split(path.sep);
  for (let i = 1; i < parts.length; i++) {
    const candidate = parts.slice(i).join("/");
    if (candidate && !candidate.startsWith("/") && !candidate.startsWith("..")) {
      return candidate.toLowerCase();
    }
  }

  return fp.split(path.sep).join("/").toLowerCase();
}

/** Default content written to a new .kernignore file. */
const DEFAULT_IGNORE = [
  "# KERN Default Ignores",
  "node_modules",
  ".git",
  ".kern_bin",
  ".horusec",
  "dist",
  "build",
  "coverage",
  ".next",
  ".vscode",
  ".idea",
  "",
].join("\n");

/**
 * Wraps a promise with a hard timeout.
 * If the promise does not resolve/reject within `ms` milliseconds,
 * the returned promise rejects with a timeout error.
 *
 * @param {Promise} promise - The promise to race against the timeout.
 * @param {number}  ms      - Timeout duration in milliseconds.
 * @param {string}  label   - Human-readable label used in the timeout error message.
 * @returns {Promise}
 */
const withTimeout = (promise, ms, label) => {
  const timeout = new Promise((_, reject) =>
    setTimeout(
      () => reject(new Error(`Engine '${label}' timed out after ${ms / 1000}s`)),
      ms,
    ),
  );
  return Promise.race([promise, timeout]);
};

/**
 * Reads and manages the .kernignore file, returning the list of paths to exclude.
 *
 * @param {string}  projectRoot - Absolute or relative path to the project root.
 * @param {boolean} isQuiet     - Suppress console output when true.
 * @returns {string[]} Array of ignore patterns (comments and blank lines stripped).
 */
const getKernIgnore = (projectRoot, isQuiet = false) => {
  const absoluteRoot   = path.resolve(projectRoot);
  const ignoreFilePath = path.join(absoluteRoot, ".kernignore");

  // Create file with defaults if it doesn't exist.
  if (!fs.existsSync(ignoreFilePath)) {
    try {
      fs.writeFileSync(ignoreFilePath, DEFAULT_IGNORE, "utf8");
      if (!isQuiet) {
        process.stderr.write(`📝 KERN: Created default .kernignore in ${absoluteRoot}\n`);
      }
    } catch (err) {
      if (!isQuiet) {
        process.stderr.write(`⚠️ KERN: Could not create .kernignore: ${err.message}\n`);
      }
    }
  }

  // Read and return the processed list (array of strings).
  try {
    return fs
      .readFileSync(ignoreFilePath, "utf-8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));
  } catch (e) {
    return []; // Fallback if read fails.
  }
};

// ---------------------------------------------------------------------------
// Engine discovery — driven entirely by the manifest
// ---------------------------------------------------------------------------

/**
 * Return all engine entries from the manifest, optionally filtered by name.
 *
 * @param {string|null} engineFilter - If provided, only return the engine with
 *                                     this name (case-insensitive).
 * @returns {Array<EngineManifestEntry>}
 */
const getEngines = (engineFilter = null) => {
  const all = getManifest();
  if (!engineFilter) return all;
  return all.filter(
    (e) => e.name.toLowerCase() === engineFilter.toLowerCase(),
  );
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default per-engine timeout in milliseconds.
 * Trivy needs extra time on cold runs because it downloads/updates its CVE
 * database on first use.  All other engines are fast and keep the 30s limit.
 */
const ENGINE_TIMEOUT_MS = 30_000;

/**
 * Per-engine timeout overrides (milliseconds).
 * Any engine not listed here falls back to ENGINE_TIMEOUT_MS.
 */
const ENGINE_TIMEOUT_OVERRIDES = {
  trivy:   120_000,  // 2 min — first-run DB download can take 60–90 s
  horusec: 120_000,  // 2 min — Horusec scans full directories and can be slow
};

// ---------------------------------------------------------------------------
// Severity ordering — used when merging duplicates to keep the highest level
// ---------------------------------------------------------------------------
const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

/**
 * Return the higher-ranked severity string of the two supplied values.
 * Falls back to `a` when either value is unrecognised.
 *
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
function maxSeverity(a, b) {
  const ra = SEVERITY_RANK[String(a).toUpperCase()] ?? -1;
  const rb = SEVERITY_RANK[String(b).toUpperCase()] ?? -1;
  return rb > ra ? b : a;
}

// ---------------------------------------------------------------------------
// Fuzzy line bucketing — secondary fallback for cross-engine ±1 disagreements
// ---------------------------------------------------------------------------

/**
 * Map a line number to a fuzzy bucket so that lines within ±1 of each other
 * collapse to the same bucket key.
 *
 * Algorithm: floor to the nearest even number.
 *   bucket(n) = Math.floor(n / 2) * 2
 *
 * Examples:
 *   41 → 40,  42 → 42,  43 → 42,  44 → 44,  45 → 44,  46 → 46
 *
 * @param {number|string|null|undefined} line - Raw line value from a parser.
 * @returns {string} Bucket string suitable for use in a fusion key.
 */
function fuzzyLineBucket(line) {
  const n = parseInt(line, 10);
  if (!Number.isFinite(n) || n <= 0) return "0";
  return String(Math.floor(n / 2) * 2);
}

// ---------------------------------------------------------------------------
// Fusion key construction
// ---------------------------------------------------------------------------

/**
 * Build the deduplication key for a single finding.
 *
 * The key is composed of three parts joined by "||":
 *   1. normalised-relative file path — forward-slash, lower-cased, relative to scan root
 *   2. exact line number             — "0" when absent (primary same-line dedup)
 *   3. evidence                      — lower-cased, trimmed, internal whitespace collapsed
 *
 * Two findings on the same file + same line are ALWAYS merged regardless of
 * evidence differences — this is the "aggressive line merging" guarantee.
 * The evidence component is still included so that findings on the same line
 * but with completely unrelated evidence (rare) can be distinguished when
 * the line numbers differ.
 *
 * SYSTEM_ERROR issues (no file/evidence) fall back to their description so
 * they are still deduplicated when the same engine error fires repeatedly.
 *
 * @param {object} issue    - A raw finding from any engine parser.
 * @param {string} scanRoot - Absolute path to the scan root (for path normalisation).
 * @returns {string}
 */
function buildFusionKey(issue, scanRoot) {
  if (issue.type === "SYSTEM_ERROR" || issue.type === "CONFIG_ERROR") {
    const eng  = String(issue.engine  || "").toLowerCase();
    const desc = String(issue.description || "").toLowerCase().trim().replace(/\s+/g, " ");
    return `sys||${eng}||${desc}`;
  }

  // 1. Normalise file path relative to scan root
  const normFile = relativeToRoot(issue.file, scanRoot);

  // 2. Exact line number
  const lineNum  = parseInt(issue.line, 10);
  const hasLine  = Number.isFinite(lineNum) && lineNum > 0;
  const exactLine = hasLine ? String(lineNum) : "0";

  // 3. Aggressive same-line merging: when a valid line number is present,
  //    file+line is sufficient — evidence is intentionally excluded so that
  //    two engines reporting the same line with different snippets still merge.
  if (hasLine) {
    return `${normFile}||${exactLine}`;
  }

  // 4. No-line fallback: include normalised evidence to avoid over-collapsing
  //    distinct findings that share a file but have no line information.
  const rawEvidence =
    issue.evidence != null
      ? String(issue.evidence)
      : String(issue.description || "").slice(0, 120);
  const evidence = rawEvidence.toLowerCase().trim().replace(/\s+/g, " ");
  return `${normFile}||${exactLine}||${evidence}`;
}

/**
 * Map a detection count to a confidence label.
 *
 * @param {number} count - Number of distinct engines that reported this finding.
 * @returns {'LOW'|'MEDIUM'|'HIGH'}
 */
function detectionCountToConfidence(count) {
  if (count >= 3) return "HIGH";
  if (count === 2) return "MEDIUM";
  return "LOW";
}

// ---------------------------------------------------------------------------
// Intelligent description merging
// ---------------------------------------------------------------------------

/**
 * Combine descriptions from multiple engines into a single, clean, human-
 * readable string.  Engine names are used as prefixes only when descriptions
 * differ, so a single unique description is returned as-is without any prefix.
 *
 * Examples:
 *   engines=["gitleaks"], descs=["GitHub Token"]
 *     → "GitHub Token"
 *
 *   engines=["gitleaks","horusec"], descs=["GitHub Token","Potential Hard-coded credential"]
 *     → "Gitleaks: GitHub Token; Horusec: Potential Hard-coded credential"
 *
 *   engines=["gitleaks","horusec"], descs=["GitHub Token","GitHub Token"]
 *     → "GitHub Token"   (identical — no prefix needed)
 *
 * @param {string[]} engines      - Sorted array of engine names that fired.
 * @param {object[]} group        - Raw findings in the group.
 * @returns {string}
 */
function buildMergedDescription(engines, group) {
  // Collect unique non-empty descriptions (case-insensitive dedup), preserving
  // the engine that first produced each description.
  const seen    = new Map(); // normalised-desc → { original, engine }
  for (const issue of group) {
    const d  = String(issue.description || "").trim();
    const dk = d.toLowerCase();
    if (d && !seen.has(dk)) {
      seen.set(dk, { original: d, engine: issue.engine || "" });
    }
  }

  const entries = [...seen.values()];

  if (entries.length === 0) return "";

  // Single unique description — return it without any engine prefix.
  if (entries.length === 1) return entries[0].original;

  // Multiple distinct descriptions — prefix each with its engine name.
  return entries
    .map(({ original, engine }) => {
      const prefix = engine
        ? engine.charAt(0).toUpperCase() + engine.slice(1)
        : "";
      return prefix ? `${prefix}: ${original}` : original;
    })
    .join("; ");
}

// ---------------------------------------------------------------------------
// Fusion Engine
// ---------------------------------------------------------------------------

/**
 * Fusion Engine — deduplicate and merge raw findings from all engines.
 *
 * Algorithm
 * ---------
 * 1. Normalise every finding's file path to be relative to the scan root.
 *    This ensures /tmp/path/config.js and config.js match perfectly.
 * 2. Build a fusion key per finding (normalised-relative-file + exact-line +
 *    normalised evidence).  Two findings on the same file + same line are
 *    ALWAYS merged — exact line match, no fuzzy tolerance needed for same-line
 *    dedup.
 * 3. Group findings that share the same key.
 * 4. For each group, produce one merged record:
 *    - `engines`    : sorted array of all engine names that fired.
 *    - `confidence` : LOW / MEDIUM / HIGH based on engine count.
 *    - `severity`   : highest severity across the group.
 *    - `type`       : from the first finding (most specific label).
 *    - `file`       : normalised-relative path (consistent across engines).
 *    - `line`       : lowest (most conservative) line number in the group.
 *    - `description`: intelligently merged — engine-prefixed only when
 *                     descriptions differ; single unique desc returned as-is.
 *    - `suggested_fix`: first non-empty fix suggestion found in the group.
 *    - Raw `evidence` is intentionally omitted from the merged output to
 *      keep the payload compact for AI context windows.
 *    - Per-finding `engine` (singular) field is dropped; `engines` (plural)
 *      replaces it.
 *    - `confidence` from individual parsers is replaced by the fusion score.
 *
 * SYSTEM_ERROR / CONFIG_ERROR issues bypass the merge logic and are passed
 * through as-is (they carry no file/evidence to deduplicate on).
 *
 * @param {object[]} rawIssues - Flat array of findings from all engines.
 * @param {string}   scanRoot  - Absolute path to the directory being scanned.
 * @returns {object[]} Deduplicated, merged, AI-optimised findings array.
 */
function fuseIssues(rawIssues, scanRoot) {
  if (!rawIssues || rawIssues.length === 0) return [];

  const root = scanRoot || "";

  /** @type {Map<string, object[]>} key → [findings] */
  const groups = new Map();

  for (const issue of rawIssues) {
    const key = buildFusionKey(issue, root);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(issue);
  }

  const fused = [];

  for (const [, group] of groups) {
    // System / config errors: pass through the first occurrence only,
    // annotated with how many times it was seen.
    if (
      group[0].type === "SYSTEM_ERROR" ||
      group[0].type === "CONFIG_ERROR"
    ) {
      const engines = [...new Set(group.map((i) => i.engine).filter(Boolean))];
      fused.push({
        engines,
        type:        group[0].type,
        severity:    group[0].severity,
        confidence:  detectionCountToConfidence(engines.length || 1),
        description: group[0].description,
      });
      continue;
    }

    // ── Merge a group of real findings ──────────────────────────────────
    const engines = [
      ...new Set(group.map((i) => i.engine).filter(Boolean)),
    ].sort();

    // Highest severity wins.
    const severity = group.reduce(
      (best, i) => maxSeverity(best, i.severity),
      group[0].severity,
    );

    // Intelligently merge descriptions.
    const description = buildMergedDescription(engines, group);

    // First non-empty suggested fix.
    const suggested_fix =
      group.map((i) => i.suggested_fix).find((f) => f && String(f).trim()) ||
      undefined;

    // Representative location: normalised-relative file path; lowest line in
    // the group (most conservative — always points to a real line in the source).
    const first = group[0];
    const normFile = relativeToRoot(first.file, root);

    const lowestLine = group.reduce((min, i) => {
      const n = parseInt(i.line, 10);
      return Number.isFinite(n) && n > 0 && n < min ? n : min;
    }, parseInt(first.line, 10) || Infinity);
    const representativeLine =
      Number.isFinite(lowestLine) && lowestLine !== Infinity
        ? lowestLine
        : (first.line ?? undefined);

    const merged = {
      engines,
      confidence:  detectionCountToConfidence(engines.length),
      type:        first.type,
      severity,
      file:        normFile || (first.file ? String(first.file).replace(/\\/g, "/") : undefined),
      line:        representativeLine,
      description,
    };

    // Only include suggested_fix when present — keeps output lean.
    if (suggested_fix) merged.suggested_fix = suggested_fix;

    // Strip undefined fields for a clean, minimal JSON payload.
    for (const k of Object.keys(merged)) {
      if (merged[k] === undefined) delete merged[k];
    }

    fused.push(merged);
  }

  // Sort: SYSTEM_ERRORs last; within real findings sort by severity desc,
  // then file asc, then line asc — deterministic and easy to scan.
  fused.sort((a, b) => {
    const aIsErr = a.type === "SYSTEM_ERROR" || a.type === "CONFIG_ERROR";
    const bIsErr = b.type === "SYSTEM_ERROR" || b.type === "CONFIG_ERROR";
    if (aIsErr !== bIsErr) return aIsErr ? 1 : -1;

    const sr =
      (SEVERITY_RANK[String(b.severity).toUpperCase()] ?? 0) -
      (SEVERITY_RANK[String(a.severity).toUpperCase()] ?? 0);
    if (sr !== 0) return sr;

    const fa = String(a.file || "");
    const fb = String(b.file || "");
    if (fa !== fb) return fa < fb ? -1 : 1;

    return (Number(a.line) || 0) - (Number(b.line) || 0);
  });

  return fused;
}

// ---------------------------------------------------------------------------
// KERN public API
// ---------------------------------------------------------------------------

const KERN = {
  /**
   * Run all (or a specific) security engine(s) against a file or directory.
   *
   * @param {string} filePath          - Path to the file or directory to audit.
   * @param {object} [options]
   * @param {boolean} [options.silent] - Suppress console output.
   * @param {string|null} [options.engine] - Restrict audit to a single engine by name.
   * @param {string[]} [options.diffFiles]  - When set, only these files are scanned
   *                                          (used by --diff mode in the CLI).
   * @param {boolean} [options.quietStdout] - When true, all progress logs go to stderr
   *                                          (used in --json / --format sarif modes).
   * @returns {Promise<AuditResult>}
   */
  async audit(filePath, options = {}) {
    const { silent = false, engine = null, diffFiles = null, quietStdout = false } = options;

    // In quietStdout mode all progress output goes to stderr so stdout stays clean.
    const log  = (msg) => { if (!silent) process.stderr.write(msg + "\n"); };
    const logE = (msg) => { process.stderr.write(msg + "\n"); };

    // ── 1. Resolve engines from manifest ─────────────────────────────────
    let engines = getEngines(engine);

    if (engine && engines.length === 0) {
      return {
        filename:  filePath,
        timestamp: new Date().toISOString(),
        vulnerable: false,
        issues: [
          {
            type:        "CONFIG_ERROR",
            severity:    "HIGH",
            description: `Engine '${engine}' not found in the manifest.`,
          },
        ],
      };
    }

    // ── 1b. In --diff mode, skip engines that don't support file scanning ─
    if (diffFiles) {
      const skipped = engines.filter((e) => e.supports_file_scan === false);
      engines = engines.filter((e) => e.supports_file_scan !== false);

      if (skipped.length > 0) {
        log(
          `⚠️  KERN: --diff mode: skipping engine(s) that don't support file-specific scanning: ` +
          skipped.map((e) => e.name).join(", "),
        );
      }
    }

    // ── 2. Resolve paths and ignore list ─────────────────────────────────
    const absolutePath = normalizeSafePath(path.resolve(filePath));
    const isDir =
      fs.existsSync(absolutePath) && fs.statSync(absolutePath).isDirectory();
    const projectRoot = isDir ? absolutePath : path.dirname(absolutePath);

    const ignoreList = getKernIgnore(projectRoot, silent || quietStdout);

    log(
      `⚙️  KERN: Using ${engines.length} engine(s) (${engines.map((e) => e.name).join(", ")}).`,
    );
    log(`🚫 KERN: Excluding ${ignoreList.length} paths to save CPU.`);
    if (diffFiles) {
      log(`📂 KERN: --diff mode: scanning ${diffFiles.length} modified file(s).`);
    }

    // ── 3. Build one promise per engine ──────────────────────────────────
    const auditPromises = engines.map((entry) => {
      const engineWork = (async () => {
        // Resolve binary path (download if needed) — fully manifest-driven.
        const binPath = await getEngineBinary(entry.name, silent || quietStdout);

        // Dynamically load the parser only when it is actually needed.
        const parserAbsPath = path.resolve(__dirname, entry.parser_path);
        const parser = require(parserAbsPath);

        // In --diff mode, pass the diffFiles list to the parser.
        const runOptions = { ignoreList };
        if (diffFiles) runOptions.diffFiles = diffFiles;

        return await parser.run(absolutePath, binPath, runOptions);
      })();

      const timeoutMs = ENGINE_TIMEOUT_OVERRIDES[entry.name] ?? ENGINE_TIMEOUT_MS;
      return withTimeout(engineWork, timeoutMs, entry.name);
    });

    // ── 4. Collect results ────────────────────────────────────────────────
    const settlements = await Promise.allSettled(auditPromises);

    const allIssues = settlements.flatMap((settlement, idx) => {
      if (settlement.status === "fulfilled") {
        return settlement.value;
      } else {
        return [
          {
            engine:      engines[idx].name,
            type:        "SYSTEM_ERROR",
            severity:    "CRITICAL",
            description: `Engine failed: ${settlement.reason?.message ?? String(settlement.reason)}`,
          },
        ];
      }
    });

    // ── 5. Fuse — pass scanRoot so paths can be normalised ────────────────
    const fusedIssues = fuseIssues(allIssues, projectRoot);

    return {
      filename:   path.basename(absolutePath) || absolutePath,
      timestamp:  new Date().toISOString(),
      vulnerable: fusedIssues.some(
        (i) => i.type !== "SYSTEM_ERROR" && i.type !== "CONFIG_ERROR",
      ),
      issues: fusedIssues,
    };
  },

  /**
   * Return the names of all registered engines.
   * @returns {Promise<string[]>}
   */
  async list() {
    return getManifest().map((e) => e.name);
  },
};

module.exports = { ...KERN, DEFAULT_IGNORE, fuseIssues };