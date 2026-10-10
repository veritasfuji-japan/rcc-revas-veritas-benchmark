# TASK15_DOCKER_REVOCATION_BOUNDARY_V1 — #284

**DRAFT / NOT PROVEN. 100% synthetic offline mock, zero real Provider effects.**

## Rule-of-One

This round integrates #283's SQLite revocation-with-claim atomicity into a
**separately running, networkless Docker Broker** that actually serves AF_UNIX
requests from isolated worker containers. The trusted CI host invokes a
separate Docker exec *inside the broker container* to commit a revocation.
Worker IPC exposes NO revocation command.

Frozen #283 merged main:
2c1eb0199b2828a08cfb9ab2140952bbb365810d.

A valid synthetic stolen key plus a copied, properly TEST-signed grant **MAY
WIN** the first claim before trusted revocation. There is no retroactive
rollback. All claims arriving *after* revocation commits must be denied,
because the revocation check and dispatch claim insert share the SAME
SQLite writer transaction protected by BEGIN IMMEDIATE.

## Two independently executed Docker scenarios

**Scenario A — Revoke first (zero mock effects):**
1. Same-UID forged key attempt -> INVALID_SESSION_CHALLENGE_RESPONSE.
2. Trusted host executes revocation in the broker container.
3. Separate worker with copied actual synthetic key + valid test grant ->
   TRUSTED_BROKER_REQUEST_REVOKED.
4. Wrong host UID -> UNTRUSTED_UNIX_PEER_UID_GID.

**Scenario B — Claim first (one mock effect):**
1. Attacker with the stolen session key + valid signed TEST grant obtains
   the ONE permitted mock effect, before revocation.
2. Trusted host executes revocation inside this broker container.
3. Attacker repeats key+grant -> TRUSTED_BROKER_REQUEST_REVOKED.
4. Legitimate key holder requests after revocation -> same rejection.

The total across two separate brokers is six AF_UNIX requests, two Docker
admin revocations, two independently readable SQLite archives, and exactly
one mock sink call. Dedicated JUnit contains 16 exact runtime assertions.

## Frozen host/broker assumptions

Both sides run with network=none, read-only root, non-root UID, all
capabilities dropped and no-new-privileges; broker alone mounts writable
/private (contains mock-only credential, synthetic worker key, SQLite) and
writable /ipc to create the Unix socket. Worker containers mount read-only
/worker.py, /ipc, and ONLY in keyed worker cases, a read-only synthetic
session key file. Docker inspect and test signer public root are archived.

Trusted Docker exec is not a proof of independent enterprise operator
authorization. An administrator or compromised Docker daemon/host can
exfiltrate synthetic secrets or alter the ledger. Revocation is not a
release-safe way to abort already claimed actions.

No full native AgentDojo model wire, actual Provider secret, real OpenAI
HTTP, paid request, bank effect, third-party certification, or production
IAM/revocation identity is asserted. Source, exact SHA, two raw SQLite
integrity checks, signed TEST grant, receipt hashes and six peer event rows
must be independently checked. CI green alone is not PROVEN.

Reproduce (GitHub Actions Ubuntu 24.04, pinned Python and Docker base):

    python scripts/task15_docker_revocation_audit_v1.py --output-dir results

The image build may download *pinned* Python dependencies; the two
runtime Docker container classes cannot reach external networks.
No historical user consent to charge carries forward.
