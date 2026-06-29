# Changelog

All notable changes to **SafeRouter** (`safeproxy` crate; CLI: `sr`) are documented here.

Format: Keep a Changelog, adhere to SemVer.

---

## [1.0.0] — 2026-06-29

First stable release. Drops the old `carapace` name. Renames the CLI from `cape` to `sr` and the crate from `carapace` to `safeproxy`.

### Added

**9-layer defense model (replaces single-layer regex detection):**

- **Layer 0 — Decoy canaries** (`sr canary plant`): 11 planted decoys (~/.ssh/id_rsa, ~/.aws/credentials, ~/.kube/config, ~/.config/solana/id.json, ~/.docker/config.json, ~/.netrc, ~/.pypirc, ~/.npmrc, ~/.gnupg/secring.gpg, ~/.ssh/id_ed25519, ~/.aws/config). Any agent tool_use touching one of these paths = unconditional Block.
- **Layer 1 — Capability matrix**: `Source × Capability × AssetClass × Tainted → Allow / AllowWithAudit / Ask / Quarantine / Block`. Provider-induced Execute / NetworkPost always blocks. Writes to Temp/Executable from untrusted source Quarantine.
- **Layer 2 — Taint tracking** (sled-persistent): every artifact marked with Source. Taint propagates through parent artifact ids across sessions.
- **Layer 3 — Session graph**: 8 attack-chain patterns (`fetch→write→execute`, `read-secret→outbound`, `browse→extract→shell`, `mcp→shell/net`, `taint-leap`, `long-dwell`, `baseline-anomaly`, `capability-escalation`).
- **Layer 4 — Asset boundary**: 14 asset classes with hard-deny tiers (Credential, BrowserData, WalletData, Keychain, CloudMetadata).
- **Layer 5 — Quarantine pipeline**: SHA-256 intake, magic-byte sniffing (17 types: PE, ELF, Mach-O, ZIP, tar, gzip, bzip2, xz, 7z, RAR, PDF, shell/PowerShell/Python scripts, JSON, XML, text), ZIP & tar member listing. CLI: `sr quarantine list/release/purge/clear`.
- **Layer 6 — Egress control**: 35-domain allowlist, known-bad blocklist, Shannon entropy scan (≥ 7.5 bits/byte), sensitive-path-content sniff (28 file paths + 10 env-var tokens), block-unknown-POST mode.
- **Layer 7 — Behavioral baseline**: per-session capability + assetclass learning window (default 5 min, configurable). Anomaly scores 0..100.
- **Layer 8 — Regex detection + Unicode normalization**: 155 rules in 29 categories. New normalization layer folds Cyrillic/Greek homoglyphs, strips RTL/LTR overrides, collapses unicode whitespace, strips benign control chars. Closes 28 of 44 fuzz-found evasions.

**Adversarial fuzzer** (`sr fuzz`): 8 mutation operators (homoglyph, rtl-override, base64-split, unicode-ws, case-swap, comment-inj, control-char, tool-synonym). Auto-generates closing rules via `--apply`.

**Rules breakthrough**: 88 → 155 rules. New categories: indirect-injection (6), reverse-shell (7), cred-dump-windows (7), crypto-wallet (5), browser-token (6), clipboard-hijack (2), metadata-ssrf (5), history-read (3), wifi-creds (3), keyring-theft (4), env-leak (4), memory-dump (3), dropper (2), privesc-recon (3), vm-fingerprint (2).

**Red-team probes**: 30 → 41 probes across 17 categories.

**v2 inspect engine**: `DynamicRuleRegistry` with hot-reload (`RwLock`), `SeverityTier` (Info / Warn / Critical / Fatal), per-rule suppression list, rule IDs propagated through `Verdict`.

**CLI commands**:
- New: `sr fuzz`, `sr canary [plant|list|unplant]`, `sr quarantine [list|release|purge|clear]`.
- Existing: `sr proxy`, `sr scan`, `sr deep-scan`, `sr score`, `sr certify`, `sr verify`, `sr registry *`, `sr artifact`, `sr session *`, `sr policy`, `sr enforce`, `sr audit`, `sr sentinel`, `sr monitor`, `sr feed`, `sr web`, `sr keygen`, `sr demo-feed`.

**E2E integration test** (`tests/defense_e2e_chain.rs`): exercises the full 9-layer stack end-to-end at the `DefenseEngine` API level, simulating a 5-step grey-provider attack. Confirms the chain is broken at every step.

**Docs**: public README + `docs/ARCHITECTURE.md` (private internals, not auto-rendered on GitHub homepage).

### Removed

- Marketing / launch scaffolding markdown files: `V2_ROADMAP.md`, `VC.md`, `X_THREAD.md`, `HABR.md`, `SHOW_HN.md`, `LAUNCH_CHECKLIST.md`, `LAUNCH_RUNBOOK.md`, `RELEASE_NOTES_RC1.md`, `RELEASE_VALIDATION.md`. These were internal-only drafts that leaked into the repo early. Public surface is now README + LICENSE + SECURITY + CHANGELOG + docs/ARCHITECTURE.

### Security

- API keys wrapped in `zeroize::Secret`, never serialized.
- Forensics store at rest under XChaCha20-Poly1305.
- Canary decoys indistinguishable from real credentials (correct OpenSSH / AWS / Solana / Kube headers, decoy bodies that won't authenticate).
- Local-only by default (`127.0.0.1`).
- Memory-safe Rust core, no `unsafe` outside zeroize FFI.
- Fail-closed matrix: unrecognized combinations route to `Ask`, not `Allow`.

### Quality

- `cargo test --quiet` → 286 passing (was 35 in v1.0.0-rc1).
- `cargo clippy --all-targets -- -D warnings` → 0 warnings.
- `cargo run -- sr fuzz` → 16 evasions (down from 44 before normalization layer).

---

## Earlier development history

Pre-stable development under the working name `carapace` is summarized below. The crate name is now `safeproxy` and the binary is `sr`. Earlier versions below are not published to crates.io.

### v1.0.0-rc1

Initial public milestone. Wire-level proxy, SSE reassembly, behavioral regex rules, IoC blocklist, declared tool parsing, provider canary probe, signed threat-feed manifests, host IoC audit, sentinel host monitor, encrypted forensic storage, LLM-judge slow path.

### v0.1 - v0.9

Initial proxy / inspector / rules skeleton → encrypted forensics → sentinel → LLM judge → cargo-binstall metadata. Bumped declared-tool parsing. Added z.ai / DeepSeek / Kimi-aware adapter routing.