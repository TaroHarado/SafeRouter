# carapace v1.0.0-rc1

First release candidate for `carapace`.

## What this release is

This is the first point where the project behaves like a real release
candidate, not a moving prototype:

- CLI surface matches runtime behaviour
- provider scan, host audit, sentinel, and feed fetch are all live
- encrypted forensics works
- CI + release workflows are wired
- clippy is clean under `-D warnings`
- test suite is green

## Included in this RC

### Core runtime

- `cape proxy`
- `cape scan`
- `cape audit`
- `cape sentinel`
- `cape feed`

### Detection & protocol

- Anthropic SSE parsing
- OpenAI-compatible SSE parsing
- z.ai / DeepSeek / Kimi-aware adapter selection
- unsolicited `tool_use` detection
- chunked payload reassembly before inspection
- behaviour rules + IoC blocklist

### Defensive extras

- signed threat-feed manifest verification
- encrypted forensic event capture
- host IoC checks for known malicious-reseller indicators
- optional LLM-judge slow path

## What is *not* guaranteed yet

- passive prompt theft detection
- full protocol coverage across every niche provider
- polished binary install UX on every platform until this release pipeline is smoke-tested

## Install

After artifacts land on the release page:

- Windows: `cape-x86_64-pc-windows-msvc.zip`
- Linux: `cape-x86_64-unknown-linux-gnu.tar.gz`
- macOS Intel: `cape-x86_64-apple-darwin.tar.gz`
- macOS ARM: `cape-aarch64-apple-darwin.tar.gz`

## Validation checklist after release

1. download one binary per family
2. run `cape --help`
3. run `cape scan` against a harmless local stub
4. run `cargo binstall carapace`
5. confirm GitHub release assets and checksums are sane
