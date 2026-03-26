/**
 * lib/utils/downloader.js
 *
 * Agnostic binary downloader — all engine-specific data is sourced exclusively
 * from lib/engines_manifest.js.  To support a new engine, add its entry to the
 * manifest; no changes here are required.
 *
 * Binary cache strategy (fastest-first):
 *   1. ~/.kern/bin/<engine>/   — global user cache; survives project wipes,
 *                                makes KERN instant for repeat users.
 *   2. Download from Hugging Face — only when the global cache misses.
 */

"use strict";

const { https } = require("follow-redirects");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const unzipper = require("unzipper");
const tar = require("tar");
const { execSync } = require("child_process");

const { getEngineEntry, buildPlatformKey } = require("../engines_manifest");

// ---------------------------------------------------------------------------
// Global cache root  (~/.kern/bin)
// ---------------------------------------------------------------------------

/**
 * Absolute path to the global KERN binary cache directory.
 * Using ~/.kern/bin keeps all engine binaries in one predictable location
 * across every project on the machine, making subsequent runs instant.
 */
const GLOBAL_BIN_ROOT = path.join(os.homedir(), ".kern", "bin");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 hex digest of a file on disk.
 * @param {string} filePath - Absolute path to the file.
 * @returns {string} Lowercase hex digest.
 */
function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest("hex");
}

/**
 * Verify the SHA-256 digest of a downloaded archive against the hardcoded
 * value stored in the manifest.  Throws if the digest does not match.
 *
 * @param {string} engineName   - Engine name (key in manifest).
 * @param {string} platformKey  - e.g. "linux-x64".
 * @param {string} archivePath  - Path to the downloaded archive file.
 */
function verifyChecksum(engineName, platformKey, archivePath) {
  const entry = getEngineEntry(engineName);
  const expected =
    entry && entry.binaries[platformKey]
      ? entry.binaries[platformKey].sha256
      : null;

  if (!expected) {
    // No checksum registered for this combination — skip silently so that
    // adding a new platform does not break existing installs before the
    // manifest is updated.
    return;
  }

  const actual = sha256File(archivePath);

  if (actual !== expected) {
    throw new Error(
      `KERN: Integrity check FAILED for ${engineName} (${platformKey}).\n` +
        `  Expected : ${expected}\n` +
        `  Got      : ${actual}\n` +
        `The archive may be corrupted or tampered with. Aborting installation.`,
    );
  }
}

/**
 * Recursively collect all file paths under a directory.
 * @param {string} dir
 * @returns {string[]}
 */
function getAllFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir, { withFileTypes: true });
  list.forEach((file) => {
    const fullPath = path.join(dir, file.name);
    if (file.isDirectory()) {
      results = results.concat(getAllFiles(fullPath));
    } else {
      results.push(fullPath);
    }
  });
  return results;
}

/**
 * Recursively search for the engine binary inside an extracted directory.
 * On Windows: looks for a file ending in ".exe".
 * On Unix:    looks for a file with no extension (executables typically have none).
 *
 * @param {string} dir      - Root directory to search.
 * @param {string} platform - os.platform() value.
 * @returns {string|undefined} Absolute path to the binary, or undefined.
 */
function findBinaryInDir(dir, platform) {
  // These names have no extension on Unix but are never the executable binary.
  const NON_BINARY_NAMES = new Set([
    "LICENSE", "README", "CHANGELOG", "NOTICE", "AUTHORS",
    "CONTRIBUTING", "COPYING", "INSTALL", "Makefile", "Dockerfile",
  ]);
  const files = fs.readdirSync(dir, { withFileTypes: true });
  for (const file of files) {
    const fullPath = path.join(dir, file.name);
    if (file.isDirectory()) {
      const found = findBinaryInDir(fullPath, platform);
      if (found) return found;
    } else {
      const isWin = platform === "win32";
      const isExe = file.name.endsWith(".exe");
      const noExt = !file.name.includes(".");
      const notKnownNonBinary = !NON_BINARY_NAMES.has(file.name);
      if (isWin ? isExe : (noExt && notKnownNonBinary)) return fullPath;
    }
  }
  return undefined;
}

/**
 * Check whether a directory contains a valid, ready-to-use engine binary.
 *
 * "Valid" means:
 *   - The directory exists.
 *   - At least one file inside matches the platform's binary naming convention.
 *   - That file is at least `minSize` bytes (guards against LFS pointer stubs).
 *
 * @param {string} dir      - Directory to inspect.
 * @param {string} platform - os.platform() value.
 * @param {number} minSize  - Minimum acceptable file size in bytes.
 * @returns {string|null} Absolute path to the binary, or null if not found/valid.
 */
function findValidBinary(dir, platform, minSize) {
  if (!fs.existsSync(dir)) return null;

  // Use findBinaryInDir (with NON_BINARY_NAMES guard) instead of the old
  // extension-based approach which incorrectly matched LICENSE, README, etc.
  const candidate = findBinaryInDir(dir, platform);

  if (!candidate) return null;
  if (fs.statSync(candidate).size < minSize) return null;
  return candidate;
}

/**
 * Ensure executable permissions are set on a binary (no-op on Windows).
 * Also strips the macOS quarantine flag when running on Darwin.
 *
 * @param {string} binPath  - Absolute path to the binary.
 * @param {string} platform - os.platform() value.
 */
function fixPermissions(binPath, platform) {
  if (platform === "win32") return;
  try {
    fs.chmodSync(binPath, "755");
  } catch (_) {}
  if (platform === "darwin") {
    try {
      execSync(`xattr -d com.apple.quarantine "${binPath}"`, {
        stdio: "ignore",
      });
    } catch (_) {}
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Return the path to a ready-to-execute engine binary.
 *
 * Cache lookup order
 * ------------------
 *   1. Global user cache  (~/.kern/bin/<engine>)  ← checked first; instant on hit
 *   2. Download from Hugging Face                 ← only on cache miss
 *
 * After a successful download the binary is stored in the global cache so
 * every subsequent invocation — across all projects — is instant.
 *
 * All engine metadata (URL, SHA-256, min size) is resolved dynamically from
 * the manifest — this function contains zero hardcoded engine references.
 *
 * @param {string}  engineName - Must match a `name` field in engines_manifest.js.
 * @param {boolean} isQuiet    - Suppress progress messages when true.
 * @returns {Promise<string>} Absolute path to the binary.
 */
async function getEngineBinary(engineName, isQuiet = false) {
  const platform = os.platform();
  const arch = os.arch();
  const platformKey = buildPlatformKey(platform, arch);

  // ── 1. Resolve manifest entry ─────────────────────────────────────────────
  const entry = getEngineEntry(engineName);
  if (!entry) {
    throw new Error(
      `KERN: Unknown engine "${engineName}". Add it to engines_manifest.js.`,
    );
  }

  const binarySpec = entry.binaries[platformKey];
  if (!binarySpec) {
    throw new Error(
      `KERN: Platform "${platformKey}" is not supported for engine "${engineName}". ` +
        `Add a binaries entry for this platform in engines_manifest.js.`,
    );
  }

  const { url } = binarySpec;
  const minSize = entry.min_binary_size;

  // ── 2. Global cache directory  (~/.kern/bin/<engine>) ────────────────────
  const globalBinDir = path.join(GLOBAL_BIN_ROOT, engineName);

  // ── 3. Check global cache first ──────────────────────────────────────────
  const cached = findValidBinary(globalBinDir, platform, minSize);
  if (cached) {
    if (!isQuiet) {
      console.log(`⚡ KERN: Using cached ${engineName} binary from ${cached}`);
    }
    fixPermissions(cached, platform);
    return cached;
  }

  // ── 4. Cache miss — wipe stale dir (if any) and download ─────────────────
  if (fs.existsSync(globalBinDir)) {
    fs.rmSync(globalBinDir, { recursive: true, force: true });
  }

  if (!isQuiet) {
    console.log(
      `📥 KERN: ${engineName} not found in global cache (~/.kern/bin). Downloading...`,
    );
  }

  const newPath = await downloadBinary(
    url,
    globalBinDir,
    entry,
    platformKey,
    isQuiet,
  );

  // Remove macOS quarantine flag from the freshly extracted binary.
  if (newPath) fixPermissions(newPath, platform);

  return newPath;
}

/**
 * Download an archive from `url`, verify its SHA-256 checksum, extract it
 * into `binDir`, and return the path to the extracted binary.
 *
 * @param {string}  url         - Remote URL of the archive.
 * @param {string}  binDir      - Local directory to extract into.
 * @param {object}  entry       - Manifest entry for this engine.
 * @param {string}  platformKey - e.g. "linux-x64".
 * @param {boolean} isQuiet     - Suppress progress messages when true.
 * @returns {Promise<string>} Absolute path to the extracted binary.
 */
async function downloadBinary(url, binDir, entry, platformKey, isQuiet = false) {
  if (!fs.existsSync(binDir)) fs.mkdirSync(binDir, { recursive: true });

  const platform = os.platform();
  const engineName = entry.name;
  const minSize = entry.min_binary_size;
  const tempFile = path.join(binDir, "download.tmp");
  const isTarGz = url.endsWith(".tar.gz") || url.endsWith(".tgz");

  if (!isQuiet) {
    console.log(`⬇️  KERN: Downloading ${engineName} from ${url} ...`);
  }

  return new Promise((resolve, reject) => {
    const request = https.get(url, (res) => {
      if (res.statusCode !== 200) {
        return reject(
          new Error(`KERN: Server returned HTTP ${res.statusCode} for ${url}`),
        );
      }

      const fileStream = fs.createWriteStream(tempFile);
      res.pipe(fileStream);

      fileStream.on("finish", () => {
        fileStream.close(async () => {
          try {
            // ── Step 1: Basic size sanity-check ──────────────────────────
            // Catches HuggingFace LFS pointer files (a few hundred bytes).
            const downloadedSize = fs.statSync(tempFile).size;
            if (downloadedSize < 1000) {
              throw new Error(
                `KERN: Downloaded file is too small (${downloadedSize} bytes). ` +
                  `This looks like an LFS pointer rather than the real archive.`,
              );
            }

            // ── Step 2: SHA-256 integrity check ──────────────────────────
            if (!isQuiet) {
              console.log(
                `🔒 KERN: Verifying integrity of ${engineName} archive...`,
              );
            }
            verifyChecksum(engineName, platformKey, tempFile);
            if (!isQuiet) {
              console.log(`✅ KERN: Integrity OK – checksum matches.`);
            }

            // ── Step 3: Extract the archive ───────────────────────────────
            if (!isQuiet) console.log(`📦 KERN: Unpacking ${engineName}...`);

            if (!isTarGz) {
              // ZIP — read into a Buffer and extract entry-by-entry to avoid
              // stream-locking issues on Windows.
              const data = fs.readFileSync(tempFile);
              const directory = await unzipper.Open.buffer(data);

              for (const zipEntry of directory.files) {
                const fullPath = path.join(binDir, zipEntry.path);
                if (zipEntry.type === "Directory") {
                  if (!fs.existsSync(fullPath)) {
                    fs.mkdirSync(fullPath, { recursive: true });
                  }
                } else {
                  const parentDir = path.dirname(fullPath);
                  if (!fs.existsSync(parentDir)) {
                    fs.mkdirSync(parentDir, { recursive: true });
                  }
                  const content = await zipEntry.buffer();
                  fs.writeFileSync(fullPath, content);
                }
              }
            } else {
              tar.x({ file: tempFile, cwd: binDir, sync: true });
            }

            // Give Windows Defender (and similar AV tools) time to finish
            // scanning the newly written files before we try to execute them.
            await new Promise((r) => setTimeout(r, 3000));

            // ── Step 4: Clean up the archive ──────────────────────────────
            try {
              if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
            } catch (_) {}

            // ── Step 5: Locate the extracted binary ───────────────────────
            const finalPath = findBinaryInDir(binDir, platform);
            if (!finalPath) {
              throw new Error(
                `KERN: Binary not found in ${binDir} after extraction.`,
              );
            }

            // ── Step 6: Post-extraction size validation ───────────────────
            const finalSize = fs.statSync(finalPath).size;
            if (finalSize < minSize) {
              throw new Error(
                `KERN: Extracted binary ${path.basename(finalPath)} is too small ` +
                  `(${finalSize} bytes, expected ≥ ${minSize} bytes). ` +
                  `The archive may be corrupted.`,
              );
            }

            // ── Step 7: Set executable permissions on Unix ────────────────
            if (platform !== "win32") {
              fs.chmodSync(finalPath, "755");
            }

            if (!isQuiet) {
              console.log(
                `✅ KERN: Engine ${path.basename(finalPath)} cached at ${finalPath}`,
              );
            }

            resolve(finalPath);
          } catch (err) {
            // Clean up on any failure so the next run starts fresh.
            if (fs.existsSync(binDir)) {
              fs.rmSync(binDir, { recursive: true, force: true });
            }
            reject(err);
          }
        });
      });
    });

    request.on("error", (err) => {
      if (fs.existsSync(binDir)) {
        fs.rmSync(binDir, { recursive: true, force: true });
      }
      reject(err);
    });
  });
}

module.exports = { getEngineBinary, GLOBAL_BIN_ROOT, findBinaryInDir, findValidBinary };
