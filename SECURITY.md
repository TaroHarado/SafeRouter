# Security Policy

## Reporting a vulnerability

Use GitHub Security Advisories / private reporting. Do not open a public issue for security bugs.

Include:

1. `sr --version` output.
2. The upstream the vulnerability was observed against (do **not** include
   credentials).
3. A minimal reproduction — ideally with `mockevil` or any local
   stub provider that returns the malicious chunk you used.
4. The alert line from the audit log if `sr` caught it, or the exact response
   that bypassed detection.
5. If you found the gap via `sr fuzz`, paste the evasion entry.

## Trust boundaries

SafeRouter (`sr`) runs as a local process with read access to your upstream API key.

It:

- forwards requests **verbatim**;
- never writes the upstream key anywhere (memory is `zeroize`d on drop);
- never writes request/response bodies to disk in plaintext — only alert
  metadata + a 512-byte snippet of the suspicious buffer (and, when
  `--forensics` is enabled, an encrypted envelope under XChaCha20-Poly1305);
- runs as a single static binary with **no** network egress except to the
  `--upstream` you configured and (optional) the LLM-judge endpoint;
- quarantine + provenance stores live under `~/.saferouter/` and contain
  no plaintext secrets (the decoy canary files are by design harmless).

If any of these properties break under audit, treat it as a critical
vulnerability.

## Decoy canary policy

`sr canary plant` writes fake credential files to standard paths under `$HOME`.
These files contain decoy content that will not authenticate to any real
service — verified by attempt (the OpenSSH private keys decode to a `CANARY
DECOY KEY - DO NOT USE` body, AWS keys are `AKIARCANARYDECOY000` formatted,
Solana id.json is a 64-byte seeded array with no on-chain balance).

`sr canary plant` will **never overwrite** an existing real file at a canary
path. If your `~/.ssh/id_rsa` already exists, the canary at that path is
skipped and logged.

Unplant via `sr canary unplant` removes only the files `sr canary plant`
wrote, by SHA-256 written into the canary registry.