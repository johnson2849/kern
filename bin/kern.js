#!/usr/bin/env node
/**
 * bin/kern.js
 *
 * KERN CLI entry point.
 *
 * Commands:
 *   kern audit <path> [--engine <name>] [--silent] [--diff] [--json] [--format <fmt>]
 *   kern ignore add <pattern>
 *   kern ignore remove <pattern>
 *   kern ignore list
 *   kern list
 *   kern doctor
 *   kern setup
 *
 * --diff mode
 * -----------
 * When `kern audit --diff` is invoked, KERN uses `git diff --name-only` and
 * `git diff --cached --name-only` to collect the set of modified/staged files
 * relative to the repository root.  Only those files are passed to engines
 * that support file-specific scanning.  Engines that do not support it
 * (determined by the `supports_file_scan` flag in engines_manifest.js) are
 * skipped with an informational note.
 * This enables sub-500ms feedback loops for AI agents.
 *
 * --format sarif
 * --------------
 * Converts the fused issues into a valid SARIF v2.1.0 JSON document, suitable
 * for upload to GitHub Code Scanning.  All progress / warning logs are sent to
 * stderr so stdout contains only the SARIF payload.
 *
 * Clean stdout rule
 * -----------------
 * In --json, --format sarif, or --silent mode, NO non-payload text is written
 * to stdout.  All progress, warnings, and informational messages go to stderr.
 */

"use strict";

const path         = require("path");
const fs           = require("fs");
const { execSync } = require("child_process");

// Lazy-load heavy modules only when needed.
const KERN        = require("../lib/core");
const { getManifest } = require("../lib/engines_manifest");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** ANSI colour helpers (no external dep). */
const c = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  red:    "\x1b[31m",
  green:  "\x1b[32m",
  yellow: "\x1b[33m",
  cyan:   "\x1b[36m",
  grey:   "\x1b[90m",
};

const col = (colour, text) => `${colour}${text}${c.reset}`;

/** Map severity → colour. */
function severityColour(sev) {
  switch (String(sev).toUpperCase()) {
    case "CRITICAL": return c.red;
    case "HIGH":     return c.red;
    case "MEDIUM":   return c.yellow;
    case "LOW":      return c.cyan;
    default:         return c.grey;
  }
}

/** Print usage and exit. */
function usage(exitCode = 0) {
  process.stdout.write(`
${col(c.bold, "KERN")} — Security Orchestration CLI

${col(c.bold, "Usage:")}
  kern audit <path> [options]   Scan a file or directory
  kern list                     List registered engines
  kern doctor                   Check environment health
  kern setup                    Pre-download all engine binaries
  kern ignore <sub-cmd> [value] Manage .kernignore exclusions

${col(c.bold, "Audit options:")}
  --engine <name>       Run only the named engine
  --silent              Suppress progress output
  --json                Output raw JSON (machine-readable)
  --format <fmt>        Output format: text (default) | sarif
  --diff                Only scan git-modified files (fast mode for AI agents)

${col(c.bold, "Ignore sub-commands:")}
  kern ignore list
  kern ignore add <pattern>
  kern ignore remove <pattern>
`);
  process.exit(exitCode);
}

// ---------------------------------------------------------------------------
// Stderr-safe logger
// ---------------------------------------------------------------------------

/**
 * Write a progress/info message.
 * When machineOutput is true (--json or --format sarif), always writes to
 * stderr so stdout stays clean for the payload.
 *
 * @param {string}  msg
 * @param {boolean} machineOutput
 */
function logInfo(msg, machineOutput) {
  if (machineOutput) {
    process.stderr.write(msg + "\n");
  } else {
    process.stdout.write(msg + "\n");
  }
}

// ---------------------------------------------------------------------------
// --diff: collect modified files via git
// ---------------------------------------------------------------------------

/**
 * Run a git command and return its stdout as an array of non-empty trimmed lines.
 * Returns [] on any error (not a git repo, git not installed, etc.).
 *
 * @param {string} cmd
 * @param {string} cwd
 * @returns {string[]}
 */
function gitLines(cmd, cwd) {
  try {
    const out = execSync(cmd, { cwd, stdio: ["pipe", "pipe", "pipe"] })
      .toString()
      .trim();
    return out ? out.split("\n").map((l) => l.trim()).filter(Boolean) : [];
  } catch (_) {
    return [];
  }
}

/**
 * Collect the list of files modified in the working tree and/or staging area.
 * Paths are relative to the git repository root.
 *
 * @param {string} cwd - Directory to run git commands from.
 * @returns {{ files: string[], repoRoot: string } | null}
 *   Returns null when the directory is not inside a git repository.
 */
function getDiffFiles(cwd) {
  // Resolve the git repo root so we can make paths relative to it.
  const repoRootLines = gitLines("git rev-parse --show-toplevel", cwd);
  if (repoRootLines.length === 0) return null;

  const repoRoot = repoRootLines[0];

  // Unstaged changes.
  const unstaged = gitLines("git diff --name-only", cwd);
  // Staged (cached) changes.
  const staged   = gitLines("git diff --cached --name-only", cwd);
  // Untracked new files.
  const untracked = gitLines("git ls-files --others --exclude-standard", cwd);

  const all = [...new Set([...unstaged, ...staged, ...untracked])];

  // Filter to only files that actually exist on disk.
  const existing = all.filter((f) => {
    try {
      return fs.existsSync(path.join(repoRoot, f));
    } catch (_) {
      return false;
    }
  });

  return { files: existing, repoRoot };
}

// ---------------------------------------------------------------------------
// SARIF v2.1.0 conversion
// ---------------------------------------------------------------------------

/**
 * Convert a KERN audit result into a valid SARIF v2.1.0 document.
 *
 * Rules  : one rule per unique `type` value across all findings.
 * Results: one result per fused issue (SYSTEM_ERROR / CONFIG_ERROR excluded).
 *
 * Level mapping:
 *   CRITICAL / HIGH → "error"
 *   MEDIUM          → "warning"
 *   LOW / INFO / *  → "note"
 *
 * @param {object} auditResult - The object returned by KERN.audit().
 * @returns {object} SARIF v2.1.0 document.
 */
function toSarif(auditResult) {
  const issues = (auditResult.issues || []).filter(
    (i) => i.type !== "SYSTEM_ERROR" && i.type !== "CONFIG_ERROR",
  );

  // Build rules map: ruleId → rule object.
  const rulesMap = new Map();
  for (const issue of issues) {
    const id = String(issue.type || "UNKNOWN");
    if (!rulesMap.has(id)) {
      rulesMap.set(id, {
        id,
        name: id
          .split(/[_\-]/)
          .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
          .join(""),
        shortDescription: { text: id },
      });
    }
  }

  // Map severity → SARIF level.
  function sarifLevel(sev) {
    switch (String(sev).toUpperCase()) {
      case "CRITICAL":
      case "HIGH":   return "error";
      case "MEDIUM": return "warning";
      default:       return "note";
    }
  }

  // Build results array.
  const results = issues.map((issue) => {
    const ruleId = String(issue.type || "UNKNOWN");
    const result = {
      ruleId,
      level:   sarifLevel(issue.severity),
      message: { text: issue.description || ruleId },
    };

    // Physical location (file + line).
    if (issue.file) {
      const uri = issue.file.replace(/\\/g, "/");
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
            region: { startLine: Number(issue.line) || 1 },
          },
        },
      ];
    }

    // Engine tags.
    if (Array.isArray(issue.engines) && issue.engines.length > 0) {
      result.properties = { tags: issue.engines };
    }

    return result;
  });

  // Package version from package.json (best-effort).
  let kernVersion = "1.0.0";
  try {
    const pkgPath = path.resolve(__dirname, "../package.json");
    kernVersion = JSON.parse(fs.readFileSync(pkgPath, "utf8")).version || "1.0.0";
  } catch (_) { /* ignore */ }

  return {
    $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name:    "KERN",
            version: kernVersion,
            rules:   [...rulesMap.values()],
          },
        },
        results,
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/**
 * Pretty-print a single fused issue to stdout.
 * @param {object} issue
 * @param {number} idx
 */
function printIssue(issue, idx) {
  const sev    = String(issue.severity || "UNKNOWN").toUpperCase();
  const colour = severityColour(sev);
  const engStr = Array.isArray(issue.engines)
    ? issue.engines.join(", ")
    : (issue.engine || "?");

  process.stdout.write(
    `\n${col(c.bold, `#${idx + 1}`)} ${col(colour, sev)} ` +
    `[${col(c.cyan, issue.confidence || "?")}] ` +
    `${col(c.grey, `engines: ${engStr}`)}\n`,
  );
  if (issue.file) {
    const loc = issue.line ? `${issue.file}:${issue.line}` : issue.file;
    process.stdout.write(`   ${col(c.bold, "File:")} ${loc}\n`);
  }
  process.stdout.write(`   ${col(c.bold, "Type:")} ${issue.type || "?"}\n`);
  process.stdout.write(`   ${col(c.bold, "Desc:")} ${issue.description || ""}\n`);
  if (issue.suggested_fix) {
    process.stdout.write(`   ${col(c.bold, "Fix:")}  ${issue.suggested_fix}\n`);
  }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/** kern list */
async function cmdList() {
  const engines = getManifest();
  process.stdout.write(col(c.bold, "\nRegistered KERN engines:\n\n"));
  for (const e of engines) {
    const fsFlag = e.supports_file_scan ? col(c.green, "file+dir") : col(c.yellow, "dir-only");
    process.stdout.write(`  ${col(c.cyan, e.name.padEnd(12))} [${fsFlag}]  ${e.command_template}\n`);
  }
  process.stdout.write("\n");
}

/** kern doctor */
async function cmdDoctor() {
  const { runDoctor } = require("../lib/utils/doctor");
  await runDoctor();
}

/** kern setup */
async function cmdSetup() {
  const { runSetup } = require("../lib/utils/setup");
  await runSetup();
}

/** kern ignore <sub> [value] */
function cmdIgnore(sub, value, scanPath) {
  const root           = path.resolve(scanPath || ".");
  const ignoreFilePath = path.join(root, ".kernignore");

  if (sub === "list") {
    if (!fs.existsSync(ignoreFilePath)) {
      process.stdout.write("No .kernignore file found.\n");
      return;
    }
    const lines = fs.readFileSync(ignoreFilePath, "utf8").split(/\r?\n/);
    process.stdout.write(col(c.bold, "\n.kernignore contents:\n\n"));
    lines.forEach((l) => process.stdout.write("  " + l + "\n"));
    process.stdout.write("\n");
    return;
  }

  if (!value) {
    process.stderr.write(`kern ignore ${sub} requires a <pattern> argument.\n`);
    process.exit(1);
  }

  if (sub === "add") {
    const existing = fs.existsSync(ignoreFilePath)
      ? fs.readFileSync(ignoreFilePath, "utf8")
      : "";
    if (existing.split(/\r?\n/).some((l) => l.trim() === value)) {
      process.stdout.write(`Pattern "${value}" already exists in .kernignore.\n`);
      return;
    }
    fs.appendFileSync(ignoreFilePath, `\n${value}`, "utf8");
    process.stdout.write(`✅ Added "${value}" to .kernignore\n`);
    return;
  }

  if (sub === "remove") {
    if (!fs.existsSync(ignoreFilePath)) {
      process.stdout.write("No .kernignore file found.\n");
      return;
    }
    const lines   = fs.readFileSync(ignoreFilePath, "utf8").split(/\r?\n/);
    const updated = lines.filter((l) => l.trim() !== value).join("\n");
    fs.writeFileSync(ignoreFilePath, updated, "utf8");
    process.stdout.write(`✅ Removed "${value}" from .kernignore\n`);
    return;
  }

  process.stderr.write(`Unknown ignore sub-command: ${sub}\n`);
  process.exit(1);
}

/** kern audit <path> [options] */
async function cmdAudit(scanPath, opts) {
  const { engineFilter, silent, jsonOutput, sarifOutput, diffMode } = opts;

  // In machine-output modes, all progress logs must go to stderr.
  const machineOutput = jsonOutput || sarifOutput;

  // ── --diff mode: collect modified files ──────────────────────────────────
  let diffFiles = null;

  if (diffMode) {
    const cwd        = path.resolve(scanPath || ".");
    const diffResult = getDiffFiles(cwd);

    if (!diffResult) {
      process.stderr.write(
        col(c.yellow, "⚠️  --diff: not a git repository or git is not installed. " +
          "Falling back to full scan.") + "\n",
      );
    } else if (diffResult.files.length === 0) {
      logInfo(col(c.green, "✅ --diff: no modified files detected. Nothing to scan."), machineOutput);
      process.exit(0);
    } else {
      diffFiles = diffResult.files;

      if (!silent) {
        logInfo(
          col(c.bold, `\n🔍 KERN --diff mode: ${diffFiles.length} modified file(s)\n`),
          machineOutput,
        );
        diffFiles.forEach((f) => {
          if (machineOutput) {
            process.stderr.write(`   ${col(c.grey, f)}\n`);
          } else {
            process.stdout.write(`   ${col(c.grey, f)}\n`);
          }
        });
        if (machineOutput) process.stderr.write("\n");
        else process.stdout.write("\n");
      }

      // Note: engine skipping in --diff mode is now handled inside core.js
      // based on the supports_file_scan flag.
    }
  }

  // ── Run audit ─────────────────────────────────────────────────────────────
  const startMs = Date.now();

  let result;
  try {
    result = await KERN.audit(scanPath, {
      silent,
      engine:      engineFilter || null,
      diffFiles,
      quietStdout: machineOutput,
    });
  } catch (err) {
    process.stderr.write(col(c.red, `\n❌ KERN audit failed: ${err.message}`) + "\n");
    process.exit(1);
  }

  const elapsedMs = Date.now() - startMs;

  // ── Output: SARIF ─────────────────────────────────────────────────────────
  if (sarifOutput) {
    const sarif = toSarif(result);
    process.stdout.write(JSON.stringify(sarif, null, 2) + "\n");
    process.exit(result.vulnerable ? 1 : 0);
  }

  // ── Output: JSON ──────────────────────────────────────────────────────────
  if (jsonOutput) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    process.exit(result.vulnerable ? 1 : 0);
  }

  // ── Output: Human-readable ────────────────────────────────────────────────
  const issues = result.issues || [];
  const real   = issues.filter(
    (i) => i.type !== "SYSTEM_ERROR" && i.type !== "CONFIG_ERROR",
  );
  const errors = issues.filter(
    (i) => i.type === "SYSTEM_ERROR" || i.type === "CONFIG_ERROR",
  );

  process.stdout.write(
    col(c.bold, `\n📋 KERN Audit Report`) +
    col(c.grey, ` — ${result.filename} — ${result.timestamp}`) + "\n",
  );
  process.stdout.write(col(c.grey, `   Completed in ${elapsedMs}ms`) + "\n");

  if (real.length === 0 && errors.length === 0) {
    process.stdout.write(col(c.green, "\n✅ No issues found.\n\n"));
    process.exit(0);
  }

  if (real.length > 0) {
    process.stdout.write(
      col(c.bold, `\n⚠️  ${real.length} issue(s) found:\n\n`),
    );
    real.forEach((issue, i) => printIssue(issue, i));
  }

  if (errors.length > 0) {
    process.stdout.write(col(c.yellow, `\n⚙️  ${errors.length} engine error(s):\n\n`));
    errors.forEach((e) => {
      process.stdout.write(`  ${col(c.red, "✗")} ${e.description}\n`);
    });
  }

  process.stdout.write("\n");
  process.exit(result.vulnerable ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Argument parsing & dispatch
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    usage(0);
  }

  const command = args[0];

  switch (command) {
    case "list":
      await cmdList();
      break;

    case "doctor":
      await cmdDoctor();
      break;

    case "setup":
      await cmdSetup();
      break;

    case "ignore": {
      const sub      = args[1];
      const value    = args[2];
      const scanPath = args.find((a, i) => i > 2 && !a.startsWith("--")) || ".";
      if (!sub) { usage(1); }
      cmdIgnore(sub, value, scanPath);
      break;
    }

    case "audit": {
      // Find the scan path: first non-flag argument after "audit".
      let scanPath     = ".";
      let engineFilter = null;
      let silent       = false;
      let jsonOutput   = false;
      let sarifOutput  = false;
      let diffMode     = false;

      for (let i = 1; i < args.length; i++) {
        const a = args[i];
        if (a === "--silent" || a === "-s") {
          silent = true;
        } else if (a === "--json" || a === "-j") {
          jsonOutput = true;
        } else if (a === "--diff") {
          diffMode = true;
        } else if ((a === "--engine" || a === "-e") && args[i + 1]) {
          engineFilter = args[++i];
        } else if (a === "--format" && args[i + 1]) {
          const fmt = args[++i].toLowerCase();
          if (fmt === "sarif") {
            sarifOutput = true;
          } else if (fmt !== "text") {
            process.stderr.write(`Unknown --format value: ${fmt}. Supported: text, sarif\n`);
            process.exit(1);
          }
        } else if (!a.startsWith("--")) {
          scanPath = a;
        }
      }

      await cmdAudit(scanPath, { engineFilter, silent, jsonOutput, sarifOutput, diffMode });
      break;
    }

    default:
      process.stderr.write(col(c.red, `Unknown command: ${command}`) + "\n");
      usage(1);
  }
}

main().catch((err) => {
  process.stderr.write(col(c.red, `\nFatal: ${err.message}`) + "\n");
  process.exit(1);
});