# Selected Native path: child-only synthetic signer

Base: merged #484, `8e415cbec57bd50dbdd3c239f92b4e86c39da0d2`.
Status: **OFFLINE RESEARCH / PROVIDER NO-GO / UTILITY UNSCORED**.

The new runner composes #484's pinned Native orchestration with a replacement
adapter. Historical files remain unchanged. The signer child generates an
Ed25519 private key after `spawn`; parent receives only its public key and signed
claims over a bounded JSON pipe. No private-key export or live-send opcode exists.
The inherited adapter constructor is not called, and parent Ed25519 generation
is tripwired while the selected Native path runs. The parent still owns the
synthetic response recipient key and its local database; neither is an issuer key.

The child checks exact #483 claim fields, frozen trial/case/model, false Provider
permission, A/B ordinal 0..3, and digest shape. It pins the first recipient, permits
one consume then one attach then one read for each request, and refuses scope
changes/reissuance. The parent verifies every returned signature. The custody
child independently verifies signatures and request/receipt/ciphertext binding.
Signer IPC uses `send_bytes`/`recv_bytes` with a size cap and bounded polls rather
than unpickling caller messages. Failure stops the run; no local signing fallback.

Native replay tests resend the **original consumed signed packet** after custody
restart. They do not request a fresh signature. Consequently a successful run
requires 24 signatures (eight per operation), eight cached replays, eight custody
replay refusals, and the same 32 protected socket connections as #484. There are
two custody startups, two scripted Native terminals/scorers and eight capped SDK
requests. Signer shutdown acknowledges counts and exits cleanly. Reports contain
hashes/counters, never keys, plaintext, signer PID, databases or sockets.

The signer rejects Python socket creation, connects/binds/DNS and ordinary process
launches. #484's parent and custody-child tripwires remain active; its offline SDK
metadata and IPv6 probe suppression remain unchanged. These are Python regression
observations, **not OS enforcement**, same-UID memory isolation or independent IAM.
Fresh interpreter startup/imports happen before the child installs its hook.

## Explicit limits

The parent supplies synthetic claims, including the first recipient and request
hash. The signer does not authenticate a real owner, read an independent approved
manifest, or verify that a receipt was actually issued by custody. Custody performs
the latter check. The signer has no durable state, expiry, revocation or cross-runner
consumption. Losing the signer stops this run; custody does not accept a replacement
issuer on restart. The protocol is not a production authorization service.

The parent is the offline SDK/request driver, **not a real Provider sender**. Process
separation here does not demonstrate independent credentials, egress controls,
independent approval or production-wide bypass resistance. Old entrypoints remain
available. All responses are scripted, real Provider posts and bank effects zero.
#321/#427 remain unresolved. No paid workflow, Secret, Environment, Ruleset or tag
is changed or executed.

## Validation

Unit tests cover exact-scope denial, operation order, binding and original-token
replay without resigning. A real spawned-signer test covers unsupported export/live
operations, repeat issuance, signature verification, clean stop and fail-closed
behavior after stop. Dedicated CI enables the full Native test, requires the exact
counts above, then executes a separate standalone report run. CI results must be
associated with the current HEAD and checked artifacts before any proof claim.
