# TASK15_UNIX_IPC_MOCK_BROKER_PROCESS_V1 — PR #280

**DRAFT / NOT PROVEN. Zero actual OpenAI Provider calls or bank effects.**

## Rule-of-One and exact predecessor

Frozen #279 merged-main SHA: 9dc4f661949e032198ecd132f1c99ce670c9f2c5.

This round binds the offline-only signed mock broker core from #279 to
a separately running host broker subprocess over AF_UNIX, called by the
Docker-isolated untrusted worker pattern introduced in #278.

The kernel-provided socket SO_PEERCRED UID/GID must match the pinned
untrusted-worker UID 65534 and GID 65534 BEFORE request JSON is parsed.
The broker independently verifies the TEST Ed25519 grant and consumes
its one-shot request SHA via SQLite before invoking a local mock sink.

## On-disk and OS isolation

The trusted broker subprocess runs as the GitHub runner user, with its
own private directory (mode 0700), ephemeral synthetic credential file
(mode 0600), and broker ledger. The worker runs in a separate Docker
container as UID/GID 65534:65534 with --network=none, read-only root,
no Linux capabilities and no-new-privileges.

Only two explicitly audited read-only bind mounts are visible in the worker:
- /worker.py: this stdlib-only negative test client
- /ipc: a socket and public signed TEST grant fixture

The host-only synthetic credential, ledger, and pinned test operator public
root are not mounted in the worker container. There is no real API key.

## Four-request bounded trace

1. Worker presents exact signed TEST grant: broker accepts one local mock.
2. Worker replays same signed grant: durable SQLite uniqueness rejects.
3. Worker alters target hostname: frozen request scope rejects.
4. Host process (non-worker UID) attempts socket access: SO_PEERCRED rejects
   BEFORE reading or parsing the untrusted request.

The worker additionally probes documentation-range TCP 192.0.2.1:443 and
requires ENETUNREACH or equivalent kernel network namespace denial.

The broker archives four peer UID/GID decision events. The independent
auditor should verify:
- exact PR HEAD / immutable Docker image digest
- raw docker inspect (network=none; read-only; no privilege or sensitive mounts)
- test-only Ed25519 grant against archived public root
- exact request and approval SHA-256
- SQLite PRAGMA integrity_check, one mock receipt, one durable claim
- one accepted, three denied; in particular host UID rejected
- no real Provider HTTP, API spend, or banking effects

## Reproduction

The dedicated CI runs Ubuntu 24.04, Python 3.11.16 and
cryptography==50.0.0, plus a pinned Python Docker image.

    python scripts/task15_unix_ipc_mock_broker_process_audit_v1.py --output-dir results

Never pass real OpenAI credentials. No external Provider URL is contacted
by the worker (reserved documentation address only). No live send helper
is re-enabled.

## Critical limitations

Peer UID/GID verifies a Linux identity, NOT exclusive possession of a
particular container. An attacker obtaining the same UID and access to the
shared Unix socket may also try to communicate, although it still needs a
valid broker-pinned signed grant. The socket mode is intentionally 0666
so the worker can connect; SO_PEERCRED and signed scope are required.

The broker subprocess runs on the host, so this does NOT establish
production-grade isolation from the host OS, its administrator, Docker
daemon, the Linux kernel, or same-user code. The proof does NOT show
long-term custody of real Provider credentials, enrollment of an external
human operator, a trusted clock source, replay-safe authenticated IPC
under full host compromise, actual native model wire authenticity,
allowlisted Provider egress, or any real API receipt.

**CI green is not independent PROVEN.** Manual merge only after artifact
audit and exact-head checks. Future proof rounds must address stronger
broker OS identity, secret custody, full payload binding, and externally
approved one-shot Provider access. No historical spending authorization
carries forward.
