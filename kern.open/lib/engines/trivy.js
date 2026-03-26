/**
 * lib/engines/trivy.js
 *
 * Parser plugin for the Trivy SCA (Software Composition Analysis) engine.
 *
 * Exports:
 *   name {string}                                    — unique engine identifier
 *   run(filePath, binPath, options) → Promise<Issue[]> — execute scan & normalise output
 *
 * To register this parser, ensure engines_manifest.js has an entry with:
 *   parser_path: "./engines/trivy.js"
 */

"use strict";

const { exec } = require("child_process");
const util = require("util");
const path = require("path");
const fs = require("fs");
const os = require("os");

const execPromise = util.promisify(exec);

/** Unique identifier — must match the `name` field in engines_manifest.js. */
const name = "trivy";

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

/**
 * Attempt to locate the line number of a package reference inside a manifest
 * file (e.g. package-lock.json).
 *
 * @param {string} filePath - Absolute path to the manifest file.
 * @param {string} pkgName  - Package name to search for.
 * @returns {string} 1-based line number, or "0" if not found.
 */
function findLineInFile(filePath, pkgName) {
  try {
    if (!fs.existsSync(filePath)) return "0";
    const content = fs.readFileSync(filePath, "utf8");
    const lines = content.split("\n");
    // Look for the package as a JSON key, e.g.  "tar":
    const index = lines.findIndex((l) => l.includes(`"${pkgName}":`));
    return index !== -1 ? (index + 1).toString() : "0";
  } catch (e) {
    return "0";
  }
}

/**
 * Run Trivy against `filePath` using the binary at `binPath`.
 *
 * @param {string}   filePath          - Absolute path to the file or directory to scan.
 * @param {string}   binPath           - Absolute path to the trivy binary.
 * @param {object}   [options]
 * @param {string[]} [options.ignoreList] - Directories to skip during the scan.
 * @returns {Promise<Issue[]>}
 */
async function run(filePath, binPath, options = {}) {
  const { ignoreList = [] } = options;
  const safeSource = fixPath(filePath);
  const safeBin = fixPath(binPath);

  // Trivy needs a writable cache directory to store its CVE database.
  // We keep it inside .kern_bin so it does not pollute the user's project.
  const cacheDir = fixPath(path.join(path.dirname(safeBin), "cache"));
  if (!fs.existsSync(cacheDir)) {
    try { fs.mkdirSync(cacheDir, { recursive: true }); } catch (_) {}
  }

  const reportPath = fixPath(
    path.join(os.tmpdir(), `trivy_res_${Date.now()}.json`),
  );

  // --scanners vuln  : only report dependency vulnerabilities (SCA), not
  //                    infrastructure misconfigurations.
  // --skip-dirs      : honour the ignore list.
  const ignoreArgs =
    ignoreList.length > 0
      ? `--skip-dirs "${ignoreList.join(",")}"`
      : "";

  const command =
    `"${safeBin}" fs "${safeSource}"` +
    ` --format json` +
    ` --output "${reportPath}"` +
    ` --cache-dir "${cacheDir}"` +
    ` --scanners vuln` +
    ` ${ignoreArgs}`;

  try {
    // Trivy exits 0 even when vulnerabilities are found (default behaviour).
    // It exits 1 only on a fatal error (e.g. DB download failure).
    // Increase maxBuffer because Trivy's JSON output can be very large.
    await execPromise(command, { maxBuffer: 50 * 1024 * 1024 });
  } catch (err) {
    if (!fs.existsSync(reportPath)) {
      return [
        {
          engine: name,
          type: "SYSTEM_ERROR",
          severity: "CRITICAL",
          description:
            `Trivy failed to run (Internet may be required for the first-run DB update): ${err.message}`,
        },
      ];
    }
  }

  if (!fs.existsSync(reportPath)) return [];

  try {
    const rawData = fs.readFileSync(reportPath, "utf8");
    try { fs.unlinkSync(reportPath); } catch (_) {}

    const data = JSON.parse(rawData);

    // Trivy returns a "Results" array — one entry per scanned target file
    // (e.g. package-lock.json, go.sum, etc.).
    if (!data.Results) return [];

    const issues = [];

    data.Results.forEach((result) => {
      if (!result.Vulnerabilities) return;

      // Build the full path to the target file for line-number lookup.
      const targetPath = path.join(safeSource, result.Target);

      result.Vulnerabilities.forEach((vuln) => {
        const confidence = vuln.Status === "fixed" ? "HIGH" : "MEDIUM";

        issues.push({
          engine: name,
          type: vuln.VulnerabilityID || "CVE-UNKNOWN",
          severity: vuln.Severity,
          confidence,
          file: result.Target,
          line: findLineInFile(targetPath, vuln.PkgName),
          description: `${vuln.PkgName}: ${vuln.Title || vuln.Description || "Unknown vulnerability"}`,
          suggested_fix: vuln.FixedVersion
            ? `Update ${vuln.PkgName} to version ${vuln.FixedVersion}`
            : "Check vendor advisories for mitigation.",
        });
      });
    });

    return issues;
  } catch (e) {
    if (fs.existsSync(reportPath)) {
      try { fs.unlinkSync(reportPath); } catch (_) {}
    }
    return [];
  }
}

module.exports = { name, run };