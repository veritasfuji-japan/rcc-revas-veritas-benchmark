# Signed run, raw recipient and validity window for Native raw ingress

## Gap after #513

#513 integrates first raw HTTP archive with actual scripted Native/Bind, but its
fresh raw recipient and run label are root-enrolled outside the signed grant.
Add a separate `--local-https --raw-ingress success --raw-authority` fixture.
All existing unbound fixtures keep their old statements and remain required.

Before issuer or Custody startup, root enrolls a fresh run ID, raw archive
recipient public-key hash, local TLS leaf hash, exact API endpoint and a
300-second validity interval in an immutable public test context. The isolated
issuer includes that complete context under `raw_authority` in all eight
Ed25519-signed grants. Existing signed request hash, target, output cap and
inner public-fixture recipient fields are preserved. No signing key is exported.

Custody verifies the complete signature, context, enrolled raw recipient/run/
leaf and actual current wall clock **before consuming its SQLite row**. It
repeats the signed checks at dispatch entry and immediately before the actual
API POST. Not-before is inclusive; expiry is exclusive. Missing, extra,
non-integer/boolean time fields and intervals above 300 seconds fail closed.

## Required proof

The isolated Native driver captures its original first A0 SDK body once and
submits twelve invalid grants to the live Custody Unix socket, without
returning any response to the SDK:

| Candidate | Required Custody refusal |
| --- | --- |
| Run, recipient or expiry edited after signature | Invalid issuer signature |
| Validly signed other run | Run mismatch |
| Validly signed other raw recipient | Recipient mismatch |
| Validly signed other local TLS leaf | Leaf mismatch |
| Validly signed expired interval | Actual-clock expiry |
| Validly signed future interval | Actual-clock not-before |
| Validly signed changed interval | Enrolled-window mismatch |
| Validly signed old unbound statement | Raw authority required |
| Validly signed extra field / boolean expiry | Exact schema refusal |

These are deliberately invalid synthetic vectors signed by the test issuer,
not evidence of a malicious real issuer or a recovered past deployment. Native
also receives kernel permission failures when opening the authority context,
raw recipient key and raw plan for writing. Custody's rejection journal joins
the candidate hashes and reasons to Native IPC results. Real observation times
join expired/future claims. Before/after backend rows, consumption rows, POST,
raw event and TLS-event digests must remain identical; no invalid grant reaches
consumption, Bind, API TLS or the local scripted effect.

After all denials, the same server and Custody process complete the eight valid
original Native requests, eight actual Bind BLOCKED/COMMITTED pairs, eight raw
archives, private-owner recovery, inner AEAD, two Native terminals and detached
scorer calls. Eight immediate and eight post-Custody-restart replays remain
denied. Context validity does not restore consumed execution permission.

Forty successful context-validation records are expected: three checks for
each original request and one check per immediate/restart replay. They record
signed grant hash, UID/PID and the actual accepted clock reading. Replay
validation is not an admission or new API send. All readings must be inside the
signed interval and join the exact grant for that operation.

## Unchanged limitations

- The issuer permission is synthetic; the scope still contains the original
  eight fixed scripted requests and historic trial/model labels. A fresh
  run-bound raw archive context does not authorize adaptive research or spend.
- The raw recipient is a private ephemeral test key whose hash is now signed.
  Its owner approval, live enrollment, rotation and external custody remain
  unproved. The inner Native vault still uses its signed public reproducible
  fixture recipient; no real-data confidentiality is claimed.
- Root/kernel, issuer, Custody, backend, owner and source enrollment share one
  trusted CI VM. Wall-clock integrity/rollback resistance and independent
  administration are unproved. Root can change trusted files or the clock.
- Existing TLS fault, crash, concurrent, backend-restart and durable-issuer
  fixtures remain separate proofs; this new bound fixture demonstrates success,
  signed-context refusals and Custody restart only. No distributed CAS claim.
- Only the disconnected local API-shaped TLS route exists. Local test CA and
  hosts prove no public Provider identity. No live credential loader, paid
  workflow, real inference, external bank or administrative setting is touched.

Existing Actions requires 49 unit cases, the original 14 integrated raw-ingress
checks and 12 new authority checks, with source/evidence/JUnit validation and
zero skipped cases. Artifacts contain public signed statements, hashes, times
and sanitized receipts, not raw request/response bytes, keys, Bearers,
ciphertext or databases.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
