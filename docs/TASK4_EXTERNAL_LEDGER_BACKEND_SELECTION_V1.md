# Task4 external ledger backend selection

Reviewed 2026-10-21 JST against main
[`1d2045a29ed0eb08d134f7851ff3910abbb8888e`](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/commit/1d2045a29ed0eb08d134f7851ff3910abbb8888e)
(merged [#518](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/518)).
This is a documentation-only architecture decision based on current official
GitHub documentation and repository source. No backend, ledger branch, service,
credential, workflow permission or administrative setting is provisioned here.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**

## Decision

Select **a dedicated GitHub state branch using GraphQL
`createCommitOnBranch(expectedHeadOid)` as the next research storage candidate**.
This is a conditional design selection, not an approved deployment, implemented
adapter, tested GitHub race, or completed #518 service. It keeps research within
the existing GitHub platform without selecting a paid external database or an
always-on host that has not been offered.

Do not select Actions artifacts, caches, job outputs, workspace SQLite or the
workflow concurrency scheduler as the authoritative ledger. Do not grant the
Native/scorer/ordinary-agent job a repository write token to make the candidate
work. The current read-only offline workflow remains unchanged.

**No reviewed end-to-end deployment currently meets all requirements.** In
particular, stable service signing-key custody, authenticated issuer/Custody
requests, writer isolation and anti-reset administration remain unresolved. A
GitHub commit or its Verified badge is not the #518 signed acknowledgement.
The default #518 client must continue to refuse operation without its reviewed
transport and pinned service key.

## Requirements and options

The authorization run ID must survive fresh jobs and retries. One authority
namespace must retain a registry of every enrolled run and its consumed slots;
changing a workspace, branch name, signing epoch or workflow run ID must not
create a new unused copy of the same authorization run. Updates need a server-side
conflict condition, and a caller must stop after an uncertain acknowledgement.
Retention must outlive all grants and any supported resume/recovery window.

| Candidate | State across fresh hosted jobs | Conflict/retention limitation | Selection |
| --- | --- | --- | --- |
| Workspace SQLite or `/run` | No shared retained location provided | #517 proves same enrolled host only | Keep for local proof, not cross-runner authority |
| Actions artifact | Can transfer a particular uploaded object | Expires; write users can delete it; deleting a run removes its artifacts; object upload is not the required shared-state transaction [S1] | Evidence export only |
| Actions cache | May be restored by another job | Inactivity/quota eviction; no authoritative run transaction [S2] | Dependencies only |
| `concurrency` group | Coordinates participating jobs | Scheduling is not a retained enrollment/consumption record; it does not govern other API writers [S3] | Optional scheduling aid only |
| Dedicated Git state branch | Repository state is outside the runner workspace | Expected-head update is available; branch deletion/rewrite, writer rights and receipt authentication still need controls [S4, S5] | Conditional research storage candidate |
| Operator-provided persistent host / transactional database | Possible if actually provisioned | No host, authenticated service, key custodian or independently reviewed retention has been supplied | Defer; do not presume free infrastructure or enroll a vendor |

Standard hosted jobs use disposable execution environments; a later job is not
an implicit reopen of the previous SQLite file [S6]. Neither workflow artifacts
nor a successful CI run should be promoted into a durable authority guarantee.

## Why the GitHub candidate is conditional

GitHub documents that `createCommitOnBranch` appends a commit and moves the branch,
with required `expectedHeadOid` identifying its prior head [S4]. This is the
documented primitive selected for an expected-head update. **Inference:** it is a
suitable candidate for a bounded optimistic-concurrency experiment. Actual
same-head contention, acknowledgement loss, later-run recovery and permission
denial still need to be tested against GitHub before crediting cross-runner CAS.

The REST update-ref endpoint instead exposes `sha` and `force`; `force: false`
checks fast-forward ancestry, not a caller-supplied exact old-head equality [S5].
A carefully constrained single-parent REST design may be possible, but it is not
selected here. A connector's extra `expected_sha` parameter must not be treated
as proof that GitHub's REST wire API performs that comparison atomically.

A future state branch would contain only bounded, reviewed metadata: approved
run bindings, revisions, operation/request/grant digests, conservative states and
transition identifiers. No model prompts, responses, database dumps, private
keys, bearer tokens or raw ciphertext archives belong in Git. Even hashes and
run identifiers disclose metadata on a public repository; the research fixture
must use synthetic material. This design is unsuitable for confidential live
records without a separate data/security decision.

The branch name, repository identity and initial enrollment commit must be pinned
by trusted deployment configuration. The branch is never derived from a caller's
working directory, a new `github.run_id`, arbitrary CLI input or model output.
A missing, renamed, deleted, inaccessible or non-descendant branch stops the
run. Supported clients must not bootstrap or repair it. An ancestry check can
detect a rewrite before a pinned checkpoint; it cannot detect every rollback to
a valid descendant without a separately retained monotonic witness. A repository
administrator able to rewrite registration/history remains trusted unless a
separate deployment proves otherwise. No rule protecting this proposed branch
has been created or verified.

## Proposed transaction and failure rules

These are design requirements for a future implementation, not executed evidence:

1. A trusted writer reads the exact configured ref at commit H, loads one bounded
   canonical state document at H, and verifies its schema, pinned enrollment and
   full registry invariants. No partial checkout, cache hit or newest artifact
   substitutes for this read.
2. Authenticate the requester and its approved issuer/Custody role, then validate
   the exact #518 binding, request/grant digest and allowed monotonic transition.
   The Native policy's history, recipient, expiry and budget checks remain
   separate and mandatory. A GitHub token identifies an API actor; it does not
   establish the #518 Ed25519 peer identity.
3. Construct the complete next registry from H, preserving all earlier run IDs
   and consumed slots, and submit one commit using `expectedHeadOid=H`. An
   enrollment adds a never-used approved authorization run ID; it never replaces
   an existing registry entry or creates a new branch to bypass a duplicate.
4. On conflict, stop that request. Do not merge stale state, refresh the revision
   and automatically retry a permission mutation. Any later request needs its
   own policy decision and must preserve the existing consumed record.
5. Verify the returned commit, parent, exact state and operation identity. For a
   #518-compatible service, return the fresh, exact service-signed receipt only
   after the backend commit is established; signing-key custody is still an open
   deployment gate. Do not replace signature verification with a UI badge or
   silently change the strict #518 receipt schema to accept a commit object.
6. A timeout, GraphQL error (including an HTTP 200 body containing `errors`),
   partial/null result, rate limit, unavailable ref or failed verification stops
   issuance/dispatch. A mutation may already have committed. Read-only
   reconciliation may record its outcome; it never authorizes a replacement
   grant or resend. A ref advance after the operation is not itself evidence
   that the operation was absent.

Git is the proposed metadata store, not an execution gate. Every program with
unrestricted write rights could bypass the state machine. The trusted writer
must keep the client-facing API narrower than the underlying GitHub credential.
That credential must not reach untrusted code, artifacts or the Native/scorer
execution environment.

## Permissions, signer and cost gates

Current source declares `contents: read`, empty `GITHUB_TOKEN`/`GH_TOKEN` shell
variables, and checkout with `persist-credentials: false` in both the Native
offline and kernel-boundary workflows. That source does not provide a ledger
writer. Empty shell variables also do **not** remove the token available to an
action through `github.token`; GitHub recommends minimum token permissions [S7].
Keep the read-only policy. Do not put a write token into the existing mixed
Native test job or let privileged code check out an untrusted PR head.

| Unresolved gate | Concrete deployment evidence required |
| --- | --- |
| Namespace and lifecycle | Approved repository/ref/genesis, one retained registry, run-ID enrollment authority, retirement/tombstone retention, deletion/restore policy |
| Isolated writer | Reviewed trusted source pin, dedicated job/service identity, narrow input protocol, actual denial for ordinary agent/Native/scorer/issuer/Custody direct Git mutations; actual protections or explicit trusted administrators |
| Stable signed acknowledgements | Non-public service signing-key custodian, authenticated public-key enrollment and rotation, restart continuity; GitHub's commit signing is not the #518 key/domain/nonce contract |
| Peer identity | Verified issuer and Custody request authentication; role strings or a shared repository bot token are insufficient |
| Availability and timing | API/rate-limit/read-size bounds, ambiguous-result stop, replay-safe read-only reconciliation; per-request workflow startup must not be assumed to fit the existing 300-second closed-local grant window |
| Actual cross-runner behavior | Different hosted jobs/workflow executions read the same enrolled registry; concurrent conflicts, committed/lost acknowledgement, missing/corrupt state and duplicate run enrollment tested with synthetic metadata |

An Actions-only synthetic metadata experiment could use a separate trusted
writer job and its job-scoped repository token after an explicit workflow review.
It would test a backend, **not provision the stable service signer or complete
Native integration**. A #518-compatible signed service additionally needs real
key custody and a transport; none is available by merely choosing Git storage.
Do not generate a fresh service key on each runner and call it restart continuity.

GitHub currently documents free Actions use for public repositories on standard
hosted runners [S8]. This supports exploring a small public/synthetic GitHub-only
experiment without selecting another paid service. It is not a guarantee about
account billing settings, larger runners, artifact/storage usage, unlimited API
access, private-repository quotas or future pricing. No billing configuration was
queried or changed, and no new paid resource is selected. A later concrete
experiment must review its own limits before execution.

## Next work and stopping point

The next implementation proposal should test the selected backend with a bounded
GitHub metadata protocol and a separate trusted writer, using synthetic state and
**zero Provider calls**. Its review must first name the exact state ref, allowed
writers, trusted workflow pin and permitted bootstrap. Do not add another local
SQLite fault matrix and label it cross-runner storage. Do not enable ledger
mutations in PR-triggered untrusted code.

If the necessary writer permissions or signer custody cannot be supplied, retain
the explicit **DEPLOYMENT_BLOCKED** outcome instead of relaxing receipts or
placing a write credential into Native. G2/G7 credential/egress/old-route review
can proceed independently, but G3 retained cross-runner authority remains open.
Actual research permission and production independence remain separate from this
backend decision. No remaining-PR estimate is reduced on the strength of this
document alone.

## Sources and verification scope

Official documentation read on 2026-10-21; links describe platform behavior,
not current repository administrative configuration. No authenticated GraphQL
mutation, backend race or administrative endpoint was exercised by this review.

- **S1:** [Removing workflow artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts).
- **S2:** [Dependency caching reference](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
- **S3:** [Workflow concurrency](https://docs.github.com/en/actions/concepts/workflows-and-actions/concurrency). Current docs include optional queuing; this decision does not rely on the outdated claim that all queuing is unordered.
- **S4:** [GraphQL commits: createCommitOnBranch and CreateCommitOnBranchInput](https://docs.github.com/en/graphql/reference/commits). The old generic input-objects URL currently redirects to the reference index; use the commits category for `expectedHeadOid`.
- **S5:** [REST Git references](https://docs.github.com/en/rest/git/refs#update-a-reference).
- **S6:** [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners).
- **S7:** [Authenticate with GITHUB_TOKEN](https://docs.github.com/actions/reference/authentication-in-a-workflow) and [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use).
- **S8:** [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Repository basis: [#518 contract](TASK4_EXTERNAL_LEDGER_CONTRACT_V1.md),
[#517 same-host retained authority](TASK4_NATIVE_RETAINED_AUTHORITY_V1.md),
and the [G1–G8 research gate audit](TASK4_PROVIDER_RESEARCH_RESTART_GAP_AUDIT_V1.md).
This document updates the storage decision only; it does not retroactively close
any live gate or change a historical proof's stated scope.
