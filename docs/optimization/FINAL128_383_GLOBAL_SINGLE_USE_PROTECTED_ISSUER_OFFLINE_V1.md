# Final128 #383 — Task1 global single-use protected issuer protocol (offline)

## Scope and rationale

Task1 #377–#382 have source-owned read-only banking context, equal attacked
A/B source, mocked model continuity, concrete Responses API wire, and the
actual HTTP POST adapter *against locally injected fake connections*. No
Task1 genuine independent Provider A/B result or Native Scorer improvement
has been produced.

**#383 is a different security step: the prospective protected issuer.**
It specifies the exact trusted GitHub workflow/main/head/run/actor/
environment/model/case/price/call scope, freezes a **fixed globally
singleton** ref to consume, implements the GitHub REST `POST /git/refs`
request packet, exercises atomic creation and 422/replay/unknown-outcome
denial *within an exact-type thread-safe fake Git ref store*, and writes
a fsync'ed local hash-chained event record prior to simulated creation.

#351 previously proposed per-SHA/per-run tag names. Such names can allow
a new run or new commit to bypass a protocol-wide limit. #383 instead
uses the already defined #382 constant:
`refs/tags/final128-task1-first-two-real-responses-v1-consumed`

**A single protocol tag is not immutable just because it exists.** A
future approved trusted workflow must independently audit creation/update/
delete protections, bypass actors and deploy credentials, and verify
the ref was newly atomically CREATED, never overwritten/deleted or reused.
Tag creation succeeds once per protocol across all runs only if those
real GitHub ruleset and credential constraints are enforced. The local
in-memory test does not prove any of them.

## Important NONclaims

- **No live Provider API invocation, no real GitHub ref creation, no
  provider credentials or billing changes, no new scorer results.**
- **No GitHub Environment, ruleset, secret, or current model access was
  configured or verified**. Proposed environment
  `task1-real-model-pilot` is a name, not a protection guarantee.
- A supplied context, actor, "approved" bool, JSON payload or fake 201
  reply is not authenticated operator consent, a trusted runner, or
  independent AWS/GitHub/Provider provenance.
- The estimate from #350/#382 (two first calls
  `0.0104192 USD` at hardcoded assumed token rates) is not a
  real account spending limit, guarantee of current rates, token ceiling
  enforced by the Provider, or invoice.
- Local `fsync` plus `O_EXCL` prevents some accidental retries in one
  runner filesystem; it is not an immutable cross-run evidence system.
  Simulated tag creation is not a protected cross-workflow lease.
- No actual response Tool call ID from a genuine Task1 A/B Provider
  session, exact original frozen DirectAttack payload enrollment, final
  terminal capture, or official native User/Attack Scorer was observed.
- Nothing in #383 exposes a real GitHub API caller or releases the
  #382 HTTP adapter to a real Provider. `live_execution_gate()` always
  refuses, including when shown fake succeeded "tag creation" or older
  Task4/Task1 approval wording.

## Required before a separate, freshly authorized paid pilot

1. Independently check current protected environment/reviewers, exact
   main/ref/run attempt/actor and actual permissions for a dedicated
   least-privilege issuer. Protect the code and workflow against
   unreviewed modifications.
2. Verify the **fixed tag** cannot be moved/deleted or bypass-created by
   actors with credentials. A GitHub Actions concurrency group and
   regular repository tag creation alone are insufficient.
3. Validate account/project spending controls, model access/pricing,
   max two first-turn requests, zero retry on uncertain outcome, and
   fresh exact-case user approval. Never reuse past approval or USD 5
   permission.
4. Actually create the global protected ref atomically through the
   trusted GitHub API *before any potential real Provider POST*,
   and fail permanently on 422, unknown or timeout.
5. Have the trusted runner directly own TLS and restricted Provider
   credential; capture exact request/response/status/header/SHA lineage
   and immutable evidence separately from lower-trust data.
6. Audit original task, same attack bytes, independently owned A/B
   Native read, genuine Provider Tool-call IDs and two genuine terminal
   answers, then execute pinned Native User/Attack scorers.
7. Require IAM/network/credential bypass-proof and third-party review
   before claiming production authority enforcement.

The real issuer/workflow and paid send should be a **separate reviewed
change after these are actually verified**, not enabled by editing one
boolean. This PR's workflow has no `workflow_dispatch`, no write
permission, and no Provider environment secret. All CI is offline.

## CI & merge criteria

The #383 pinned GitHub Actions runner uses actual frozen AgentDojo source
for inherited #377–#382 regressions, plus #383 strict scope,
fixed-tag-vs-per-run drift, fake atomic-create competition, replay,
pre/post-write uncertainty, hash chain and rejected false grants.
Every test must pass, none skipped. Evidence is SHA/redacted-only,
contains exact HEAD, source pin and explicit zero real Provider,
zero GitHub tag, zero Scorer counts. Check ALL repository CI, the
artifact digest and changed files before recommending a Draft merge.

Historical Final128 V13 remains A Utility 93/128, B Utility 64/128,
B injection success 0/128; this PR is not a new measurement.
