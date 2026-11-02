# How this snapshot was made

It was built by a script (not part of this snapshot: it carries the author's own personal-data scan patterns) from the author's working tree (about 2.7 TB), never in place: the script copies an allow-listed slice into a new directory, applies a short list of exact-match
patches, rewrites the author's home directory to a placeholder, scans every exported text file for secrets and personal data, and writes `MANIFEST.json` (sha256 of every file) and `EXPORT-REPORT.json`.

- **Left out on purpose:** the author's personal trial data and local trials, browser profiles, raw network captures, logs, build outputs (`target`, `cargo-home`), toolchains, compiled binaries, archives, and any
  environment file. Large state snapshots and helper binaries inside crate directories were skipped too.
- **Patches** (each asserted to match exactly once; the list is in `EXPORT-REPORT.json`): a path-independent lookup of one pinned fixture in the `checks.mjs` files and in `cleanup-checks.mjs`; reading the Node and validator locations from the environment
  instead of one machine's install paths. Nothing else in the sources was edited.
- **Rewritten:** the author's home directory (`/Users/<name>`) in provenance files became `<ZK9_ROOT>` / `<HOME>`. The sha256 values stored beside those paths still describe the original files and cannot be re-checked from here.
- **Generated at export time:** `PROGRAM-HASHES.json`, the sha256 of the four on-chain program binaries the local validator loaded (the binaries themselves are not published).
- **Scan:** no private keys, API tokens or e-mail addresses were found in the exported text. Test wallets use deterministic public fixture seeds by design.
- **Placeholders to fill before publishing** are listed in `EXPORT-REPORT.json` (`open_placeholders_to_fill_before_publishing`).
