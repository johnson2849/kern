/**
 * lib/engines/gitleaks.js
 *
 * Parser plugin for the Gitleaks secret-scanning engine.
 *
 * Exports:
 *   name {string}                                    — unique engine identifier
 *   run(filePath, binPath, options) → Promise<Issue[]> — execute scan & normalise output
 *
 * To register this parser, ensure engines_manifest.js has an entry with:
 *   parser_path: "./engines/gitleaks.js"
 */

"use strict";

const { exec } = require("child_process");
const util = require("util");
const path = require("path");
const fs = require("fs");
const os = require("os");

const execPromise = util.promisify(exec);

/** Unique identifier — must match the `name` field in engines_manifest.js. */
const name = "gitleaks";

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
 * Run Gitleaks against `filePath` using the binary at `binPath`.
 *
 * @param {string}   filePath          - Absolute path to the file or directory to scan.
 * @param {string}   binPath           - Absolute path to the gitleaks binary.
 * @param {object}   [options]
 * @param {string[]} [options.ignoreList] - Paths/patterns to exclude from results.
 * @returns {Promise<Issue[]>}
 */
async function run(filePath, binPath, options = {}) {
  const { ignoreList = [] } = options;
  const safeSource = fixPath(filePath);
  const safeBin = fixPath(binPath);
  const reportPath = fixPath(
    path.join(os.tmpdir(), `gitleaks_res_${Date.now()}.json`),
  );

  try {
    // Run Gitleaks without a custom config to use its native ruleset.
    // --no-git  : scan files directly from disk (no git history required).
    // --exit-code=0 : always exit 0 so execPromise does not throw on findings.
    const command =
      `"${safeBin}" detect` +
      ` --source "${safeSource}"` +
      ` --no-git` +
      ` --report-format json` +
      ` --report-path "${reportPath}"` +
      ` --exit-code=0`;

    await execPromise(command);

    if (!fs.existsSync(reportPath)) return [];

    const fileContent = fs.readFileSync(reportPath, "utf8");
    if (!fileContent.trim()) return []; // Gitleaks outputs nothing when clean.

    const findings = JSON.parse(fileContent);

    // Post-process: filter out files that belong to an ignored path.
    return findings
      .filter((f) => {
        const normalizedFile = f.File.replace(/\\/g, "/");
        return !ignoreList.some((ignorePath) =>
          normalizedFile.includes(ignorePath),
        );
      })
      .map((f) => ({
        engine: name,
        type: "SECRET_LEAK",
        severity: "CRITICAL",
        confidence: "HIGH",
        file: f.File.replace(/\\/g, "/"),
        line: f.StartLine,
        description: `Secret detected: ${f.Description}`,
        evidence: f.Match,
        suggested_fix:
          "Remove the secret and use environment variables or a vault.",
      }));
  } catch (err) {
    return [
      {
        engine: name,
        type: "SYSTEM_ERROR",
        severity: "CRITICAL",
        description: `Gitleaks execution failed: ${err.message}`,
      },
    ];
  } finally {
    if (fs.existsSync(reportPath)) {
      try { fs.unlinkSync(reportPath); } catch (_) {}
    }
  }
}

module.exports = { name, run };