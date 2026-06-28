# X / Twitter thread

1.
Cheap third-party "OpenAI-compatible" APIs are becoming a real attack surface for coding agents.

Not because the model is "bad".
Because the provider can inject tool calls / shell payloads into agent workflows.

I built a local guard for that.

2.
The project is `carapace` / SafeRouter.

It sits between your agent and the upstream provider and checks:

- model identity confidence
- agent safety
- tool-call risk
- latency / uptime
- drift over time

3.
It’s local-first.

No hosted key sink required.
Run the SafeRouter UI on localhost.

4.
Current pipeline:

- scan
- deep-scan
- score
- certify
- verify
- local trust registry
- signed feeds

5.
The key thing: we don’t just ask “is this endpoint good?”

We can now answer:

> Agent-safe / Chat-only / Do not use with auto-approve

That’s much more useful for real coding workflows.

6.
Repo:
https://github.com/TaroHarado/carapace

If people want it, I’ll publish a deeper breakdown of the agent-safety probe battery and how to evaluate grey LLM providers safely.
