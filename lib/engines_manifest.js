/**
 * lib/engines_manifest.js
 *
 * Single source of truth for all KERN security engines.
 *
 * ─── HOW TO ADD A NEW ENGINE ────────────────────────────────────────────────
 *  1. Add an entry to the ENGINES array below following the schema.
 *  2. Create a small parser file at the path you specify in `parser_path`.
 *     The parser must export: { name: string, run(filePath, binPath, opts): Promise<Issue[]> }
 *  3. That's it — no changes to core.js or downloader.js are required.
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Schema per engine entry:
 * {
 *   name            {string}  Unique identifier used as cache-dir name and log label.
 *   binaries        {object}  Platform → { url, sha256 } mapping.
 *                             Supported keys: win32-x64 | linux-x64 | darwin-x64 | darwin-arm64
 *   executable_name {string}  Filename inside the ZIP/tar that is the actual binary.
 *                             Do NOT include ".exe" here — downloader appends it on win32.
 *   min_binary_size {number}  Minimum acceptable size (bytes) of the extracted binary.
 *                             Used as a post-extraction sanity check.
 *   command_template {string} Shell command template. Tokens replaced at runtime:
 *                               {{bin}}    → absolute path to the binary
 *                               {{target}} → absolute path to the scan target
 *                             The parser's run() function builds its own command, so this
 *                             field is informational / used by generic runners.
 *   parser_path     {string}  Require-resolvable path (relative to THIS file's directory)
 *                             pointing to the dedicated parser module in lib/engines/.
 *   supports_file_scan {boolean}
 *                             Whether this engine can scan a single file directly.
 *                             true  → engine accepts a single-file path as target.
 *                             false → engine is directory-only; in --diff mode it is
 *                                     skipped (or its output post-filtered by the parser).
 * }
 */

"use strict";

/** @type {Array<EngineManifestEntry>} */
const ENGINES = [
  // ─── Gitleaks ─────────────────────────────────────────────────────────────
  {
    name: "gitleaks",
    supports_file_scan: true,   // gitleaks --no-git accepts a single file path
    binaries: {
      "win32-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/gitleaks/gitleaks-win.zip",
        sha256: "aa19543417c668b15e89b3357413099d81a75029a8ebbaec5034b7c8cc33c7e5",
      },
      "linux-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/gitleaks/gitleaks-linux.tar.gz",
        sha256: "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee",
      },
      "darwin-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/gitleaks/gitleaks-mac.tar.gz",
        sha256: "b2dc4f853128062856273d422e2f29791a036641c1655feb83192078970fbfc0",
      },
      "darwin-arm64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/gitleaks/gitleaks-mac.tar.gz",
        sha256: "b2dc4f853128062856273d422e2f29791a036641c1655feb83192078970fbfc0",
      },
    },
    executable_name: "gitleaks", // downloader appends ".exe" on win32 automatically
    min_binary_size: 1 * 1024 * 1024, // 1 MB
    command_template:
      '{{bin}} detect --source {{target}} --no-git --report-format json --exit-code=0',
    parser_path: "./engines/gitleaks.js",
  },

  // ─── Horusec ──────────────────────────────────────────────────────────────
  {
    name: "horusec",
    supports_file_scan: false,  // horusec requires a directory; parser post-filters results
    binaries: {
      "win32-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/horusec/horusec-win.zip",
        sha256: "f076955e035a53ba8c99e9e09a9b9730fa9d71a24bb106726476881e26eb83e1",
      },
      "linux-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/horusec/horusec-linux.zip",
        sha256: "632692635d1c4ed6a387bdfe6ee3ccbfb11fd48601578bbb3a4c32fe13b0d1ce",
      },
      "darwin-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/horusec/horusec-mac.zip",
        sha256: "c64d21129c2ffff9037f70fe68862b442a8ddfd23c70561db3c2d2a49535c5c9",
      },
      "darwin-arm64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/horusec/horusec-mac.zip",
        sha256: "c64d21129c2ffff9037f70fe68862b442a8ddfd23c70561db3c2d2a49535c5c9",
      },
    },
    executable_name: "horusec",
    min_binary_size: 5 * 1024 * 1024, // 5 MB
    command_template:
      '{{bin}} start -p {{target}} -o json --log-level error',
    parser_path: "./engines/horusec.js",
  },

  // ─── Trivy ────────────────────────────────────────────────────────────────
  {
    name: "trivy",
    supports_file_scan: true,   // trivy fs accepts individual files
    binaries: {
      "win32-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/trivy/trivy-win.zip",
        sha256: "611caadecfd1c5641bb476419f5555e454753543ec0f9813705748259e73dce0",
      },
      "linux-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/trivy/trivy-linux.tar.gz",
        sha256: "aa2c0ed6932ae70171b4f0f3fdb0403e29d9ce7e6fddad0ea08d440fdd695742",
      },
      "darwin-x64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/trivy/trivy-mac.tar.gz",
        sha256: "b0b5d63708bec5695eeceb77884709156c5d0449d7b455910a6d02e46b902ab9",
      },
      "darwin-arm64": {
        url: "https://huggingface.co/datasets/Bob-Potato/kernel-assets/resolve/main/trivy/trivy-mac.tar.gz",
        sha256: "b0b5d63708bec5695eeceb77884709156c5d0449d7b455910a6d02e46b902ab9",
      },
    },
    executable_name: "trivy",
    min_binary_size: 30 * 1024 * 1024, // 30 MB
    command_template:
      '{{bin}} fs {{target}} --format json --scanners vuln',
    parser_path: "./engines/trivy.js",
  },
];

// ---------------------------------------------------------------------------
// Helpers — used by downloader.js and core.js
// ---------------------------------------------------------------------------

/**
 * Build the platform key used to look up binaries in the manifest.
 * Combines os.platform() and os.arch() into the canonical key format.
 *
 * @param {string} platform - Value of os.platform() (e.g. "linux", "win32", "darwin").
 * @param {string} arch     - Value of os.arch()     (e.g. "x64", "arm64").
 * @returns {string} e.g. "linux-x64" | "darwin-arm64" | "win32-x64"
 */
function buildPlatformKey(platform, arch) {
  // Normalise arch: Node reports "arm64" on Apple Silicon, keep as-is.
  const normArch = arch === "x64" || arch === "arm64" ? arch : "x64";
  return `${platform}-${normArch}`;
}

/**
 * Return the full manifest array (all engines).
 * @returns {Array<EngineManifestEntry>}
 */
function getManifest() {
  return ENGINES;
}

/**
 * Look up a single engine entry by name.
 * @param {string} name
 * @returns {EngineManifestEntry|undefined}
 */
function getEngineEntry(name) {
  return ENGINES.find((e) => e.name === name);
}

module.exports = { getManifest, getEngineEntry, buildPlatformKey };