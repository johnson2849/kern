/**
 * lib/utils/setup.js
 *
 * kern setup — warm-up routine.
 * Pre-downloads all engine binaries for the current OS/Arch into the global
 * cache (~/.kern/bin), with integrity checks and clear progress output.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const os   = require("os");

const { getManifest, buildPlatformKey } = require("../engines_manifest");
const { getEngineBinary, GLOBAL_BIN_ROOT } = require("./downloader");

let chalk;
try { chalk = require("chalk"); } catch (_) { chalk = { green: s=>s, red: s=>s, yellow: s=>s, bold: s=>s, cyan: s=>s, gray: s=>s, white: s=>s }; }

// ── Simple progress bar ──────────────────────────────────────────────────────

function renderBar(current, total, width = 28) {
  const pct   = total === 0 ? 1 : current / total;
  const filled = Math.round(pct * width);
  const empty  = width - filled;
  const bar    = "█".repeat(filled) + "░".repeat(empty);
  const pctStr = String(Math.round(pct * 100)).padStart(3) + "%";
  return `[${bar}] ${pctStr}  (${current}/${total})`;
}

// ── Main export ──────────────────────────────────────────────────────────────

async function runSetup({ force = false } = {}) {
  const manifest   = getManifest();
  const platform   = os.platform();
  const arch       = os.arch();
  const platformKey = buildPlatformKey(platform, arch);

  console.log(chalk.bold(chalk.cyan("\n⚙️   KERN Setup — Binary Warm-up")));
  console.log(chalk.gray("════════════════════════════════════════════════════"));
  console.log(`  Platform : ${chalk.white(platformKey)}`);
  console.log(`  Cache    : ${chalk.white(GLOBAL_BIN_ROOT)}`);
  console.log(chalk.gray("════════════════════════════════════════════════════\n"));

  // Filter engines that have a binary for this platform
  const engines = manifest.filter(e => e.binaries[platformKey]);

  if (engines.length === 0) {
    console.log(chalk.yellow(`  ⚠️  No engines found for platform "${platformKey}". Check engines_manifest.js.`));
    return;
  }

  const results = { ok: [], skipped: [], failed: [] };
  const total   = engines.length;

  for (let i = 0; i < engines.length; i++) {
    const engine  = engines[i];
    const binDir  = path.join(GLOBAL_BIN_ROOT, engine.name);
    const already = fs.existsSync(binDir) && !force;

    // Progress header
    process.stdout.write(
      `\n  ${chalk.bold(`[${i + 1}/${total}]`)} ${chalk.cyan(engine.name.padEnd(12))}  ${renderBar(i, total)}\n`
    );

    if (already) {
      console.log(`         ${chalk.yellow("⚡ Already cached")} — skipping. Use --force to re-download.`);
      results.skipped.push(engine.name);
      continue;
    }

    try {
      console.log(`         ${chalk.gray("Downloading & verifying...")}`);
      const binPath = await getEngineBinary(engine.name, /* isQuiet= */ false);
      console.log(`         ${chalk.green("✅ Ready:")} ${binPath}`);
      results.ok.push(engine.name);
    } catch (err) {
      console.log(`         ${chalk.red("❌ Failed:")} ${err.message}`);
      results.failed.push(engine.name);
    }
  }

  // ── Final summary ──────────────────────────────────────────────────────────
  console.log(chalk.gray("\n════════════════════════════════════════════════════"));
  console.log(chalk.bold("  Setup Summary"));
  console.log(chalk.gray("────────────────────────────────────────────────────"));

  if (results.ok.length)      console.log(`  ${chalk.green("✅ Downloaded :")} ${results.ok.join(", ")}`);
  if (results.skipped.length) console.log(`  ${chalk.yellow("⚡ Skipped     :")} ${results.skipped.join(", ")}`);
  if (results.failed.length)  console.log(`  ${chalk.red("❌ Failed      :")} ${results.failed.join(", ")}`);

  if (results.failed.length === 0) {
    console.log(chalk.bold(chalk.green("\n  ✅ All engines ready. KERN is fully operational.\n")));
  } else {
    console.log(chalk.bold(chalk.red(`\n  ❌ ${results.failed.length} engine(s) failed. Run 'kern doctor' for details.\n`)));
    process.exitCode = 1;
  }
}

module.exports = { runSetup };
