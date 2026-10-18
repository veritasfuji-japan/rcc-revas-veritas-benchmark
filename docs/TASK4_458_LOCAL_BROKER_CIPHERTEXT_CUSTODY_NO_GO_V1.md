# Task4 #458 — One-shot allocation and ciphertext custody through a separate offline broker (NO-GO)

## One question

Can independently started client processes compete for **one broker-owned consume-before-capture record**, attach only authenticated ciphertext generated using the *existing #457 encryption primitive*, and recover it after the broker process restarts, without treating the experiment as a live Provider approval?

**This is local UNIX-socket research. It does NOT span distinct GitHub-hosted runners, prove a production remote CAS, or deploy an independent service.** The distinction matters: existing #327 already demonstrates one SQLite shared file across separate processes. #458 adds a separate IPC broker process owning the sole SQLite database, an explicit immutable ciphertext-only broker storage API, interruption/UNKNOWN handling and owner-key decryption after broker restart. It is not a true distributed trust boundary.

## Added files

- `scripts/task4_458_local_broker_once_ciphertext_v1.py` — independent broker process bound to a **private AF_UNIX socket**, never TCP/HTTP/OpenAI. Each client requests a claim for the frozen local-only Task4 synthetic trial / arm / ordinal. The broker uses SQLite `BEGIN IMMEDIATE`, the unique `PRIMARY KEY(trial,arm,ordinal)`, `synchronous=FULL` and `UNKNOWN_PERMANENTLY_CONSUMED` committed **before any synthetic response capture**. Any later claim, even with changed request SHA or after broker restart, is refused. Caller may attach one #457 X25519/HKDF/AES-256-GCM envelope with a matching hash/recipient/source; SQLite stores ciphertext blob once, in the same broker-owned durable file; query returns ciphertext only.
- `tests/test_task4_458_local_broker_once_ciphertext_v1.py` — explicit field allowlist, wrong scope/ordinal, retry conflict, tampered/plaintext attachment refusal, no secret/Provider sender, subprocess collision and UNKNOWN crash simulation.
- `.github/workflows/task4-458-local-broker-cryptographic-custody-deny.yml` — read-only PR-only single GitHub Runner, no protected Environment, no Secrets, no dispatch, no Provider. Test processes and a broker subprocess share the same one-job temp directory. Only non-sensitive receipt hashes/JUnit/summary are uploaded; never request/response plaintext, actual ciphertext, private recipient key, database or UNIX socket.
- This document.

## Scope and concrete acceptance

Twelve **separate worker processes**, six racing per A0 and B0 slot, must yield **two** successful consume+sealed-ciphertext results and ten denials. A thirteenth separate worker must commit an A1 consume and intentionally crash before attaching ciphertext. The broker is killed and independently restarted with its **same** private filesystem database; the original two ciphertext envelopes must be recovered by the original **ephemeral local recipient private key** (which the broker never held), and A1 must refuse retry even with no ciphertext. The broker itself has no authority to grant live sends: its reply is always `live_post:false`.

**No real Provider POST, bank effect, genuine final model text, native scorer, actual billable tokens or Utility recovery.** This test's encrypted payload is deliberately synthetic, not a provider HTTP response; the new test does NOT run the original #323/#456 Native scorer. Cryptographic AEAD integrity depends on the local test owner key, **not** externally verified Provider authenticity. No independent issuer, Cloudflare Durable Object, remote Key Management, remote immutable custody, per-run $ cost enforcement, or production IAM/egress boundary is provisioned.

## Security caveats and the next actual blocker

The broker and workers run on **one** GitHub-hosted job with shared filesystem and user account. AF_UNIX socket mode 0600 limits access on that host, but clients are not independently authenticated across organizations/identities. An owner/admin who can replace the SQLite file or the broker service can replay the trial; there is no independent tamper-evident external witness or durable off-host copy. SQLite `FULL` plus a clean broker restart tests local crash durability, **not** remote durable storage guarantees. `client exchange` failures/timeouts are never permission to retry: the server may have committed a permanent `UNKNOWN` state. No 'release' endpoint exists.

To fulfill Task4 #321 beyond this PR requires an **independently hosted and controlled, durable, non-reusable remote trial ledger** with fail-closed authority, separate production egress/IAM and tightly scoped restricted credential, managed public-key distribution and off-Runner encrypted evidence retention. Only then can the native real model path be wired for full independent same-run A/B from original authorized request through unchanged Native and official scorer. All past grants are consumed. Owner's $1 monthly OpenAI project stop is NOT exact per-run authorization or a cryptographic spending cap.

**Do not attach GitHub Environment secrets, real API keys, `workflow_dispatch`, or real outbound HTTP to this branch.** Issue #321 and Task1 #427 remain OPEN, genuine Provider research remains NO-GO, and no paid call is authorized.

Keep Draft pending full latest-HEAD CI and dedicated process collision/restart proof. Passing source tests means **local broker protocol rehearsal only**.
