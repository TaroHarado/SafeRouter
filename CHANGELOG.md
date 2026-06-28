# Changelog

All notable changes to `carapace` are documented here.

The project follows a pragmatic pre-1.0 flow and will move to SemVer once the
first stable release lands.

---

## v1.0.0-rc1

First release candidate.

### Added

- Wire-level proxy (`cape proxy`) for Anthropic / OpenAI-compatible providers
- Streaming SSE reassembly before inspection
- Detection of unsolicited `tool_use`
- Behavioural RE2 rules (`curl | sh`, `irm | iex`, `schtasks`, anti-forensics, etc.)
- Built-in IoC blocklist
- Declared tool parsing for Anthropic / OpenAI request formats
- Provider canary probe (`cape scan`)
- Signed threat-feed manifest format + remote feed fetch (`cape feed`)
- Host IoC audit (`cape audit`)
- Background monitor (`cape sentinel`)
- Encrypted forensic storage
- LLM-judge slow-path for medium-confidence verdicts
- CI workflow (build/test/clippy on push/PR)
- Release workflow (cross-platform binaries on tags)

### Security

- API keys wrapped in `zeroize::Secret`
- High-severity injections substituted before they reach the client
- Full chunked-bypass defence validated in e2e tests

### Quality

- `cargo clippy --all-targets -- -D warnings` passes
- 35 unit tests + 2 e2e tests pass

### Licensing

- OSS core moved to Apache-2.0
- NOTICE file added
- trademark / badge stance documented separately

---

## v0.9

- LLM-judge module added
- `cape feed` CLI added
- CI/CD workflows added
- cargo-binstall metadata added

## v0.6-v0.8

- signed feed primitives
- host audit
- sentinel
- encrypted forensics
- z.ai / DeepSeek / Kimi-aware adapter routing

## v0.5

- `cape scan` canary probe
- threat-feed manifest primitives

## v0.4

- real `parse_declared_tools`
- false positives for legitimate tool calls reduced

## v0.3

- streaming forward path
- chunked injection e2e block

## v0.1

- initial proxy / inspector / rules skeleton
