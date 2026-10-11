# Task4 #328 — Localhost REST server emulates GitHub CreateRef CAS (OFFLINE ONLY)

## One central invariant

Sixteen **separate Python OS client processes**, without access to the server's SQLite file, send identical create-only requests for a frozen trial ref to a separately hosted localhost HTTP server. Exactly one remote-server insert wins; all other clients receive a duplicate refusal. A rebooted server continues refusing the same ref. A simulated lost HTTP response **after the server has committed** means UNKNOWN and no resend; the next independent client is rejected.

Pinned merged #327 parent main `c02d0ea4a198bfdc95ab1916f95a5036ebad299e`.

The server implements a restricted **emulation** of the GitHub REST endpoint `POST /repos/veritasfuji-japan/rcc-revas-veritas-benchmark/git/refs`, with exact `{"ref":"refs/heads/offline-test-ledger/...","sha":"<pinned main>"}` payload. It uses its own SQLite `PRIMARY KEY(ref)`, `BEGIN IMMEDIATE`, FULL synchronous commit, returns HTTP **201** for the first claim and HTTP **422** for duplicates. It rejects malformed bodies, scope drift, wrong auth, unknown methods, duplicate JSON keys, and replay. Clients may connect **only to 127.0.0.1** and use the literally fake `Bearer task4-328-public-no-privileges` header.

## The essential scope distinction

**This proof NEVER talks to api.github.com, creates an actual GitHub Git ref, grants GitHub Contents Write, uses GITHUB_TOKEN, invokes OpenAI, or runs live banking operations.**

It tests a client/server interaction **emulating** intended remote atomic create semantics, not actual GitHub server semantics. Separate GitHub Actions workflow runs/jobs with a shared real backend are **not** executed. Workers are separate OS processes inside **one** job and one host, and communicate through the server's loopback HTTP endpoint; only the server process accesses the SQLite store. The test shows correct protocol decisions against an isolated backend with atomic create; no guarantee of globally durable consume-once on production GitHub is asserted.

A real Git ref can be deleted or force-moved by users with sufficient permissions, so even GitHub CreateRef 201/422 by itself is not a permanently non-reusable, independently administered ledger. A protected ref namespace/immutable external CAS policy and hostile deletion/recreation audit are still needed.

## Actual experiment that would be needed later

After #328's mock simulation is reviewed, a **separate narrowly authorized** GitHub-only research proof would need to:

1. Obtain explicit consent to create a specifically named test Git ref in a safe isolated namespace, and choose a carefully scoped GitHub token permission; avoid privileged PR workflows and secrets exposed to fork code.
2. Launch at least **two independent GitHub Actions workflow runs**, both deriving the **same** frozen trial ref. Each attempts the create-only operation once, without retries. Confirm exactly one 201 and one server-side duplicate refusal (usually 422) with head SHA, run IDs, API response receipts.
3. Start a fresh third run to verify the ref stays consumed after a job restart and independently audit who can move/delete that ref. Treat a timeout after send as UNKNOWN, never retry.
4. Ensure the full real Provider execution boundary still has no ability to send, no Provider credentials, no cost, no real bank effects, and no implied consent reuse.

**That actual remote GitHub cross-run validation is not implemented or authorized by this PR.** Do not claim #328 alone proves GitHub-hosted runner cross-run atomicity. It is a design-validation precursor, not a substitute.

## CI and proof

Workflow runs automatically on PR/main with `contents: read` only and exact PR HEAD checkout, disables credential persistence, contains no `workflow_dispatch`, `secrets.*`, `GITHUB_TOKEN`, `pull_request_target`, protected Environment or API sender. Runs 16 independently invoked OS workers against an isolated subprocess mock server, separately tests server restart and lost HTTP reply, checks negative responses, emits signed JSON report, JUnit and SHA256 artifact. Real GitHub repository gets **only the normal PR branch/files**, not proof ledger refs.

All current source pins, model/CAS claims and original AgentDojo test harness remain untouched. **REAL_PROVIDER_DISPATCH = DENY**; new real inference = 0; new Final128 scores = 0.

See [Issue #321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321) for missing actual Provider authorization, cost and shared one-use controls.
