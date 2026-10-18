# Task1 — separate-process mock Executor and local service-owned ledger V1

**Status: LOCAL OFFLINE MOCK-ONLY / PAID Task1 NO-GO. Issue #427 stays OPEN.**

Following #447's inert acceptance contract, this contribution moves the **#446** signed fake-provider pre-send gate behind a real, separate Python OS process. Its only transport is a Linux **AF_UNIX** socket. Two child-process mock Runners can compete to request the same signed A attempt over the socket, while the Executor owns its instance of #446's SQLite reservation gate and #442's fake port. B is admitted only after a validated local A ACK. UNKNOWN is durably persisted before the local fake attempt and is never retried. The tests reuse the test-only Ed25519 signing checks of #437 and the frozen #441 evidence readback; they do not invent a new live authority.

## What is genuinely exercised

- Dedicated Executor OS **process**, different PID, which creates a Unix-domain socket and holds the fake Provider object and SQLite gate in its address space. Runner clients send bounded JSON frames, not a raw Python fake-port object or file handle.
- 0700 test-private folder, 0600 socket and SQLite file; real Linux `SO_PEERCRED` checks the **kernel** peer UID, not an untrusted JSON-provided UID. Tests that select a different enrolled UID are denied before the fake port is reached.
- Exact-schema, 32-KiB-bounded, duplicate-key-refusing JSON intake. Signed context and fake request digest are checked by the existing #446 gate, with no client-supplied `paid` or `authorization` override.
- Two separate **local mock Runner processes** contend for one A lease through one Executor; one ACK is expected and one DENIED. Repeated attempts, B-first, fake ACK errors and deliberate transport uncertainty fail closed.
- Stop/restart of the Executor **on the same local SQLite file** preserves the attempt record. A second standalone Executor with a **different** SQLite file can still accept the same signed fake A; that counterexample is explicitly tested.
- Executor contains no real Provider client, outbound network transport, secret environment reader, GitHub ref/token mutation or production workflow entrypoint. The tests require **no Provider network call**.

## Critical nonclaims and limitations

**This is not real GitHub Runner separation, remote durability, independent IAM or bypass-proof execution.** All spawned processes run as the **same UID** on one test host. An actor with that UID may access or replace the SQLite file, and a source-owning caller can instantiate `InMemoryFakeProviderPort` directly. The parent test supervisor controls the synthetic Ed25519 signer and launch arguments. The Linux UID gate rejects wrong-UID peers, but it is **not** a distinct enrolled issuer/sender identity. A restarted local service using a different DB can bypass the scope of the original file. There is no remote external key custody, non-forgeable GitHub OIDC job identity, production egress denial or cross-host atomic lease.

The #423 live sender is unchanged and is **not routed** through this socket. The existing #423 Workflow still combines tag issuance and Provider HTTPS sender authority. Neither this PR nor its green CI proves no-bypass. No real Bind-to-Provider integration, genuine model output, official score, paid limit or fresh consent is introduced. This design does not solve Task1 production safety or finish Issue #427.

## Acceptance criteria

1. Exactly three new files under `scripts/`, `tests/` and `docs/optimization/`; zero edits to `.github/workflows/**`, #423, Provider secrets, Environments, tags, Rulesets, billing or real transport code.
2. Ordinary PR CI dedicated tests show one winner for concurrent local mock Runners; no duplicate A/B after local service restart; UNKNOWN preserves rejection after restart.
3. Forged signed payload, self-declared peer UID, malformed/multiple JSON frames, wrong signer, B-first, altered fake digest and expired/invalid frozen preflight cannot reach the local fake port.
4. The tests show separate ledgers allow the same A, preserving the counterexample to remote global single-use. Same UID file access is documented, not described as a real enforcement boundary.
5. Issue #427 remains OPEN; **paid Task1 NO-GO**. No `workflow_dispatch`, tag modification, external Provider POST, bank effect, official scoring or fresh approval.

**Next required proof after #448:** independently controlled executor identity, shared remote atomic ledger across genuine GitHub Runners, external credential custody, real network/egress deny policy and a separately reviewed cutover of #423. Until then, this is a meaningful *local IPC integration*, not real authority isolation.
