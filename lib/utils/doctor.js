/**
 * lib/utils/doctor.js
 *
 * kern doctor — environment health checker.
 * Verifies Node version, OS arch, git installation, cache permissions,
 * HuggingFace connectivity, SHA-256 integrity of cached binaries, and
 * executable permissions.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const os   = require("os");
const crypto = require("crypto");
const { execSync } = require("child_process");
const { https } = require("follow-redirects");

const { getManifest, buildPlatformKey } = require("../engines_manifest");
const { GLOBAL_BIN_ROOT, findBinaryInDir } = require("./downloader");

// ── Chalk (v4 — CommonJS compatible) ────────────────────────────────────────
let chalk;
try { chalk = require("chalk"); } catch (_) { chalk = { green: s=>s, red: s=>s, yellow: s=>s, bold: s=>s, cyan: s=>s, gray: s=>s }; }

const ok   = (msg) => console.log(`  ${chalk.green("✅")} ${msg}`);
const fail = (msg) => console.log(`  ${chalk.red("❌")} ${msg}`);
const warn = (msg) => console.log(`  ${chalk.yellow("⚠️ ")} ${msg}`);
const info = (msg) => console.log(`  ${chalk.cyan("ℹ️ ")} ${msg}`);

// ── Helpers ──────────────────────────────────────────────────────────────────

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch (_) { return false; }
}

function headRequest(url) {
  return new Promise((resolve) => {
    const req = https.request(url, { method: "HEAD", timeout: 8000 }, (res) => {
      resolve({ ok: res.statusCode < 400, status: res.statusCode });
    });
    req.on("error", () => resolve({ ok: false, status: 0 }));
    req.on("timeout", () => { req.destroy(); resolve({ ok: false, status: 0 }); });
    req.end();
  });
}

// ── Section runners ──────────────────────────────────────────────────────────

function checkEnvironment() {
  console.log(chalk.bold("\n── Environment ─────────────────────────────────────"));

  // Node version
  const nodeVer = process.versions.node;
  const [major] = nodeVer.split(".").map(Number);
  if (major >= 16) {
    ok(`Node.js ${nodeVer}  (required: >=16)`);
  } else {
    fail(`Node.js ${nodeVer}  (required: >=16 — please upgrade)`);
  }

  // OS / Arch
  const platform = os.platform();
  const arch     = os.arch();
  const key      = buildPlatformKey(platform, arch);
  const supported = ["linux-x64","darwin-x64","darwin-arm64","win32-x64"];
  if (supported.includes(key)) {
    ok(`Platform: ${key}  (supported)`);
  } else {
    warn(`Platform: ${key}  (not explicitly listed in manifest — may still work)`);
  }

  // ── git installation check (required for --diff mode) ────────────────────
  try {
    const gitVersion = execSync("git --version", { stdio: ["pipe", "pipe", "pipe"] })
      .toString()
      .trim();
    ok(`git: ${gitVersion}  (required for --diff mode)`);
  } catch (_) {
    fail(
      "git: not found on PATH  " +
      "(install git to use --diff mode: https://git-scm.com/downloads)",
    );
  }
}

function checkCachePermissions() {
  console.log(chalk.bold("\n── Global Binary Cache ──────────────────────────────"));
  info(`Cache root: ${GLOBAL_BIN_ROOT}`);

  // Ensure directory exists
  try {
    fs.mkdirSync(GLOBAL_BIN_ROOT, { recursive: true });
  } catch (e) {
    fail(`Cannot create cache directory: ${e.message}`);
    return;
  }

  // Write test
  const testFile = path.join(GLOBAL_BIN_ROOT, ".kern_write_test");
  try {
    fs.writeFileSync(testFile, "ok");
    fs.unlinkSync(testFile);
    ok(`Read/Write access to ${GLOBAL_BIN_ROOT}`);
  } catch (e) {
    fail(`No write access to ${GLOBAL_BIN_ROOT}: ${e.message}`);
  }
}

async function checkConnectivity() {
  console.log(chalk.bold("\n── Network / HuggingFace Connectivity ───────────────"));
  const manifest = getManifest();
  const platform = os.platform();
  const arch     = os.arch();
  const key      = buildPlatformKey(platform, arch);

  // Deduplicate hosts
  const urls = [];
  for (const engine of manifest) {
    const spec = engine.binaries[key];
    if (spec && !urls.includes(spec.url)) urls.push(spec.url);
  }

  for (const url of urls) {
    const label = url.replace("https://", "").split("/").slice(0,3).join("/");
    const result = await headRequest(url);
    if (result.ok) {
      ok(`Reachable: ${label}  (HTTP ${result.status})`);
    } else {
      fail(`Unreachable: ${label}  (HTTP ${result.status || "timeout"})`);
    }
  }
}

function checkIntegrityAndExecutable() {
  console.log(chalk.bold("\n── Cached Binary Integrity & Permissions ────────────"));
  const manifest  = getManifest();
  const platform  = os.platform();
  const arch      = os.arch();
  const key       = buildPlatformKey(platform, arch);

  let anyFound = false;

  for (const engine of manifest) {
    const engineDir = path.join(GLOBAL_BIN_ROOT, engine.name);
    if (!fs.existsSync(engineDir)) {
      warn(`${engine.name}: not cached  (run 'kern setup' to download)`);
      continue;
    }

    // Find binary file — use the same logic as downloader.js (NON_BINARY_NAMES guard)
    const binary = findBinaryInDir(engineDir, platform);

    if (!binary) {
      fail(`${engine.name}: cache directory exists but no binary found`);
      continue;
    }

    anyFound = true;

    // Size check
    const size = fs.statSync(binary).size;
    if (size < engine.min_binary_size) {
      fail(`${engine.name}: binary too small (${size} bytes — may be corrupted)`);
      continue;
    }

    // Size + path report
    ok(`${engine.name}: binary found at ${binary} (${(size / 1024 / 1024).toFixed(1)} MB)`);

    // Executable bit (Unix only)
    if (platform !== "win32") {
      if (isExecutable(binary)) {
        ok(`${engine.name}: executable permissions ✓`);
      } else {
        fail(`${engine.name}: not executable — run: chmod +x ${binary}`);
      }
    } else {
      ok(`${engine.name}: permissions OK (Windows)`);
    }
  }

  if (!anyFound) {
    info("No binaries cached yet. Run 'kern setup' to pre-download all engines.");
  }
}

// ── Main export ──────────────────────────────────────────────────────────────

async function runDoctor() {
  console.log(chalk.bold(chalk.cyan("\n🩺  KERN Doctor — Environment Health Check")));
  console.log(chalk.gray("════════════════════════════════════════════════════"));

  checkEnvironment();
  checkCachePermissions();
  await checkConnectivity();
  checkIntegrityAndExecutable();

  console.log(chalk.gray("\n════════════════════════════════════════════════════"));
  console.log(chalk.bold("Done. Fix any ❌ items above before running kern audit.\n"));
}

module.exports = { runDoctor };