# Task1 #450 — Linux cross-UID Executor / Ledger mock boundary V1

**Status: OFFLINE MOCK ONLY — PAID TASK1 NO-GO. Issue #427 remains OPEN.**

## Exact measured scope

This extends #448's separate-process mock Executor and #449's independent *local* shared-ledger service. On Linux, an ephemeral **root test supervisor** uses numerical kernel identities to run a ledger, an Executor and two simulated Runners under **four distinct Linux UIDs**. There is no new system account, GitHub secret, Provider key, remote host, or manual Actions dispatch. The root supervisor is explicitly trusted and **outside the threat model**; it creates short-lived root-owned UNIX listening sockets and a ledger-owned private directory, then drops child credentials with `setgroups([])`, `setgid`, `setuid`.

### Enforcement the test actually checks

- Ledger SQLite directory is owned by the real Ledger UID with mode `0700`; ledger file is `0600`. Real Runner and Executor UIDs cannot list, read, write, chmod, unlink or replace the ledger file: the test checks kernel DAC denials, not a fake permission flag.
- The separately launched Ledger service accepts requests only when the kernel `SO_PEERCRED` UID is the enrolled Executor UID. A deliberately forged request with the otherwise correct *test-only* HMAC still fails from a Runner UID. This is a bounded negative control; real key compromise is not being claimed as impossible.
- The Executor accepts only either of two specified Runner UIDs, checks the source-owned offline Ed25519 handoff and frozen research NO-GO evidence from earlier #437/#441, and contacts #449's SQLite ledger service before calling #442's fake Provider port.
- Two independent simulated Runner Linux UIDs race to consume the same A. Only one fake A may ACK; the other is denied. The ledger records `UNKNOWN_A` before a fake call. A dropped/corrupt ACK retains UNKNOWN, and restart of the services on the *same local database* denies A replay.
- The proof uses AF_UNIX only. The only send effect is a local `InMemoryFakeProviderPort.deliver` method call. **No Provider HTTPS**, no real banking write, no official Native scorer, no paid model call or API spending occurs.

## What this does NOT prove

The test uses one GitHub-hosted Linux runner/host, and the privileged root supervisor can read/modify all fixtures and start services, replace kernels/identities or rewrite the database. The simulated UIDs are local numeric identities, **not real GitHub** job IAM identities, cloud roles, human approvers, or independently enrolled external signing principals. This is **not cross-host durability**, not real credential vault isolation, not a proof of network egress blocking to a real Provider, and not a production no-bypass guarantee. The root supervisor retains the synthetic signature and mock HMAC capability; a real authorization issuer and executor still require separate identity enrollment and audit.

Different local or remote ledger databases can still accept the same signed fake A; a copied/replaced database can reset the local lease under an unauthorized root/operator. The production Provider secret remains available to the existing staged #423 path, which has **not** been integrated with this isolated fake Executor. Our tested OS DAC and peercred denials apply only to this local fixture and do not close #423's real Provider bypass.

## Change scope and acceptance

Exactly three **new** files: this document, `scripts/final128_task1_linux_crossuid_shared_ledger_offline_v1.py`, and `tests/test_final128_task1_linux_crossuid_shared_ledger_offline_v1.py`. **No changes** to `.github/workflows/**`, #423's sender, Secrets, Environments, tags, Rulesets, permissions, production auth, billing or source pins.

The normal existing Ubuntu PR CI executes the self-contained Linux experiment. It requires the hosted Runner's standard passwordless `sudo` privilege to launch an isolated proof supervisor; no manual workflow or Provider request is triggered. The script starts from a deliberately stripped environment, with no inherited API keys. On a non-Linux system or CI without sudo, this dedicated test fails, rather than silently reporting PROVEN from an unexecuted check.

Merge only after exact-head CI and review: dedicated OS proof must complete without failures or skips, all inherited checks green, 3 additive files only, and Issue #427 remains OPEN. **Paid Task1 is NO-GO**; PR creation/merge does not convey fresh human consent.

**Next real requirement:** independent machine/cloud identities and secret custody, shared remote atomic ledger across actual GitHub Runners, network controls preventing other direct Provider paths, real VERITAS Bind at the final HTTPS send boundary, and externally verified failure/consumption receipts.
