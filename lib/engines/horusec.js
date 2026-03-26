/**
 * lib/engines/horusec.js
 *
 * Parser plugin for the Horusec SAST engine.
 *
 * Exports:
 *   name {string}                                    — unique engine identifier
 *   run(filePath, binPath, options) → Promise<Issue[]> — execute scan & normalise output
 *
 * To register this parser, ensure engines_manifest.js has an entry with:
 *   parser_path: "./engines/horusec.js"
 */

"use strict";

const { exec } = require("child_process");
const util     = require("util");
const path     = require("path");
const fs       = require("fs");
const os       = require("os");

const execPromise = util.promisify(exec);

/** Unique identifier — must match the `name` field in engines_manifest.js. */
const name = "horusec";

// ---------------------------------------------------------------------------
// Description cleaning
// ---------------------------------------------------------------------------

/**
 * Noise patterns that Horusec prepends to its vulnerability details.
 * These are useless for both human readers and LLM consumers.
 *
 * Patterns are applied in order; the first match wins.
 */
const HORUSEC_NOISE_PREFIXES = [
  // "(1/1) * Possible vulnerability detected: " and variants
  /^\(\d+\/\d+\)\s*\*\s*Possible vulnerability detected:\s*/i,
  // "(1/1) * " — generic numbered-item prefix
  /^\(\d+\/\d+\)\s*\*\s*/i,
  // "* Possible vulnerability detected: "
  /^\*\s*Possible vulnerability detected:\s*/i,
];

/**
 * Strip known Horusec noise prefixes from a description string.
 * Returns the cleaned description, trimmed.
 *
 * @param {string} raw - Raw description from Horusec's JSON output.
 * @returns {string}
 */
function cleanDescription(raw) {
  if (!raw) return raw;
  let s = raw.trim();
  for (const pattern of HORUSEC_NOISE_PREFIXES) {
    const cleaned = s.replace(pattern, "").trim();
    if (cleaned !== s) {
      // A pattern matched — return immediately (first-match-wins).
      return cleaned;
    }
  }
  return s;
}

// ---------------------------------------------------------------------------
// Path helper
// ---------------------------------------------------------------------------

/**
 * Resolve and normalise an absolute path, replacing backslashes with forward
 * slashes and stripping a trailing slash (unless it is a root path like "C:/").
 *
 * @param {string} p
 * @returns {string}
 */
const fixPath = (p) => {
  let cleanPath = path.resolve(p).replace(/\\/g, "/");
  if (cleanPath.endsWith("/") && cleanPath.length > 3) {
    cleanPath = cleanPath.slice(0, -1);
  }
  return cleanPath;
};

// ---------------------------------------------------------------------------
// Engine runner
// ---------------------------------------------------------------------------

/**
 * Run Horusec against `filePath` using the binary at `binPath`.
 *
 * Horusec only accepts a directory as its scan target.  When a single file is
 * provided we scan its parent directory and then filter the results down to
 * only issues that belong to that specific file.
 *
 * @param {string}   filePath          - Absolute path to the file or directory to scan.
 * @param {string}   binPath           - Absolute path to the horusec binary.
 * @param {object}   [options]
 * @param {string[]} [options.ignoreList] - Paths/patterns to exclude from results.
 * @param {string[]} [options.diffFiles]  - When set (--diff mode), restrict results
 *                                          to only these files (relative paths).
 *                                          Horusec always scans the full directory;
 *                                          we post-filter the output here.
 * @returns {Promise<Issue[]>}
 */
async function run(filePath, binPath, options = {}) {
  const { ignoreList = [], diffFiles = null } = options;

  // Adapt: if a single file is given, scan its parent directory.
  const stats        = fs.statSync(filePath);
  const isFile       = stats.isFile();
  const scanTarget   = isFile ? path.dirname(filePath) : filePath;
  const targetFileName = isFile ? path.basename(filePath) : null;

  const safeSource    = fixPath(scanTarget);
  const safeBin       = fixPath(binPath);
  const reportPath    = fixPath(
    path.join(os.tmpdir(), `horusec_res_${Date.now()}.json`),
  );
  const ignorePatterns = ignoreList.map((p) => `**/${p}/**`).join(",");

  // --log-level error suppresses noisy informational output.
  const command =
    `"${safeBin}" start` +
    ` -p "${safeSource}"` +
    ` -o json` +
    ` -O "${reportPath}"` +
    ` -i "${ignorePatterns}"` +
    ` --log-level error`;

  try {
    await execPromise(command, { timeout: 120000, maxBuffer: 10 * 1024 * 1024 });
  } catch (err) {
    // Timeout: Horusec exceeded the allowed scan time.
    if (err.killed || err.code === "ETIMEDOUT" || (err.message && err.message.includes("timed out"))) {
      return [
        {
          engine:      name,
          type:        "SYSTEM_ERROR",
          severity:    "CRITICAL",
          description: `Horusec scan timed out after 120s. Consider reducing the scan scope.`,
        },
      ];
    }
    // Horusec exits non-zero when it finds vulnerabilities; only treat it as a
    // hard failure when no report file was produced at all.
    if (!fs.existsSync(reportPath)) {
      return [
        {
          engine:      name,
          type:        "SYSTEM_ERROR",
          severity:    "CRITICAL",
          description: `Horusec failed to run: ${err.message}`,
        },
      ];
    }
  }

  if (!fs.existsSync(reportPath)) return [];

  try {
    const rawData = fs.readFileSync(reportPath, "utf8");
    try { fs.unlinkSync(reportPath); } catch (_) {}

    const data = JSON.parse(rawData);
    if (!data.analysisVulnerabilities) return [];

    let issues = data.analysisVulnerabilities.map((v) => {
      const vuln = v.vulnerabilities;

      // Take only the first line of details, then strip Horusec noise prefixes.
      const rawDesc = vuln.details.split("\n")[0];
      const description = cleanDescription(rawDesc);

      return {
        engine:      name,
        type:        vuln.rule_id || "CODE_VULNERABILITY",
        severity:    vuln.severity,
        confidence:  vuln.confidence,
        line:        vuln.line,
        file:        vuln.file.replace(/\\/g, "/"),
        description,
        evidence:    vuln.code,
      };
    });

    // When a single file was requested, restrict results to that file only.
    if (isFile && targetFileName) {
      issues = issues.filter((issue) => issue.file.endsWith(targetFileName));
    }

    // In --diff mode, post-filter to only the modified files.
    // Horusec doesn't support file-specific scanning natively, so we always
    // run the full directory scan and filter the output here.
    if (diffFiles && diffFiles.length > 0) {
      const diffSet = new Set(diffFiles.map((f) => f.replace(/\\/g, "/").toLowerCase()));
      issues = issues.filter((issue) => {
        const fp = String(issue.file || "").replace(/\\/g, "/").toLowerCase();
        // Match by suffix — handles both absolute and relative paths in output.
        return diffFiles.some((df) => fp.endsWith(df.replace(/\\/g, "/").toLowerCase()));
      });
      void diffSet; // suppress unused-var lint warning
    }

    return issues;
  } catch (e) {
    if (fs.existsSync(reportPath)) {
      try { fs.unlinkSync(reportPath); } catch (_) {}
    }
    return [];
  }
}

module.exports = { name, run };