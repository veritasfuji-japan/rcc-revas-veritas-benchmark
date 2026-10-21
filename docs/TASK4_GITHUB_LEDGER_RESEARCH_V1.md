# Manual cross-runner GitHub metadata ledger experiment

This increment implements the conditional storage proposal from
[#519](TASK4_EXTERNAL_LEDGER_BACKEND_SELECTION_V1.md). It supplies a
`workflow_dispatch`-only experiment with separate standard Ubuntu jobs and a real
GitHub API backend. **PR CI runs unit API models and workflow checks only; it does
not execute this remote experiment or prove cross-runner retention.** Record
actual manual run/job/commit/artifact identities after the workflow is merged,
bootstrapped and exercised. Until then the remote result is NOT_RUN.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Fixed deployment proposal

| Item | Exact proposed value |
| --- | --- |
| Repository | `veritasfuji-japan/rcc-revas-veritas-benchmark` |
| State branch | `refs/heads/research/task4-retained-ledger-v1` |
| Only state file | `ledger.json`, regular mode 100644 |
| Schema | `task4.github-metadata-ledger.v1` |
| Scope | `SYNTHETIC_METADATA_ONLY_NO_PROVIDER` |
| Genesis | Parentless metadata-only root commit; state pins reviewed #519 source base `477a8040eda988698642e51c804f9e6fcedddd55` |
| Execution source | Exact immutable `github.sha` of a manual dispatch on `refs/heads/main`; checked against checkout HEAD |
| Execution workflow | `.github/workflows/task4-github-ledger-research-v1.yml` on this repository's main |
| Administrative consent input | `SYNTHETIC_LEDGER_ONLY_NO_PROVIDER` |

The state branch is **not** this PR's source branch. It is not created by PR CI.
Only explicit manual `bootstrap` creates it, using a fresh tree containing the
empty registry, a parentless root commit, and create-ref. The separate root keeps
the state history independent of the source tree and its workflow files; the
reviewed source base is a fixed field of the registry. There is no
update-ref, force push, delete, repair, automatic alternate namespace or fallback.
The bootstrap prints its genesis OID and a proposed random authorization run ID.
The operator must review and reuse the exact genesis for later exercises; it is
not silently discovered from the latest artifact or new branch head. A lost
bootstrap acknowledgement requires read-only operator inspection, not a retry
that creates a replacement namespace. Failed bootstrap may leave unreachable Git
objects; they confer no permission and are not treated as an enrollment.

Every subsequent operation validates that approved genesis has the empty schema
and no parents, that the exact branch exists, that its current commit descends
from genesis, and that the snapshot has a single bounded canonical state blob
whose Git blob hash matches the content. Missing/malformed state stops execution.
Ancestry to genesis is **not a monotonic anti-rollback witness**: administrators
can restore a valid earlier descendant and remain trusted. No Ruleset or branch
protection is created or claimed. No wildcard record deletion or registry pruning
exists; 32 retained authorization runs is a hard stop requiring a separately
reviewed lifecycle decision, not an automatic new branch.

## Separate jobs and expected evidence

The `exercise` mode uses six distinct hosted jobs/VM boot witnesses:

1. **reserve (trusted writer, contents:write):** add an owner-approved unused
   64-hex authorization run ID and reserve one fixed synthetic request/grant.
   Enrollment and reservation occur in one expected-head commit. The record
   binds the dispatched source commit and diagnostic Actions execution ID.
2. **observe (contents:read):** on a fresh runner read that exact reservation,
   then attempt a same-state write probe with the read-only job token. Only an
   actual HTTP 403 / GraphQL FORBIDDEN, followed by unchanged state, counts as
   permission denial. Unexpected write success or another failure stops the
   experiment; it is not relabeled successful isolation.
3. **contenders 1 and 2 (trusted writers, contents:write):** each submits exactly
   one `createCommitOnBranch(expectedHeadOid=H)` against the *same* H from observe.
   A later-starting job still uses H even if its peer already won. Neither
   refreshes the expected head. The selected record moves only from RESERVED to
   CONSUMED_UNKNOWN and records the winning candidate. Final verification needs
   one retained commit and one server-rejected contender, not just two local
   function outcomes. Simultaneous scheduling is not promised; the experiment
   tests competing same-head updates across jobs, including a late contender.
4. **replay (fresh trusted writer, contents:write):** read the retained consumed
   state and refuse both duplicate enrollment and another consume in the trusted
   state machine, without submitting either mutation. A repository writer that
   bypasses this code remains outside the threat model.
5. **verify (contents:read):** join the five preceding reports with the exact
   live state, source hash, authorization run, genesis and previous/final
   commits. Require six distinct Linux boot-ID hashes including the verifier.
   These are attribution witnesses, not hardware attestation or independent
   administrators. Actual Actions job IDs and hosted-runner metadata must also
   be reviewed after the run.

The metadata registry has one operation per authorization run. Its fixed hashes
describe synthetic bytes, not an SDK request or a valid execution grant. It does
not implement the eight-slot #518 signed service or the actual Native history
policy. Other enrolled runs and consumed records are preserved in each snapshot.
A workflow rerun/re-dispatch using the same authorization ID must fail duplicate
enrollment rather than start fresh, even when `github.run_id` changes. The Actions
execution ID is diagnostic binding, not an automatically generated authorization
ID. Resuming a partially completed exercise is not implemented.

## Acknowledgement and failure behavior

Normal mode runs one **synthetic callback returning the integer 1** only after
the GitHub response nonce, commit parent, ref and persisted exact snapshot have
been verified. This is a callback count, not a network send, bank effect or
Native execution. The competing request must stop with no callback.

In `lost-ack` mode, the writer deliberately discards a successful-looking
mutation response before acknowledgement validation. Final read-only verification
must find one consumed record while both contenders report zero callbacks; the
winner reports ACK_DISCARDED_STOP and the loser reports a server error. This is
controlled response-discard injection, not an assertion that a real network
packet was lost. Both modes must be run with different approved authorization
IDs before claiming both outcomes have been observed.

The client makes no automatic mutation retries. Timeouts, redirects, bad/partial
JSON, GraphQL errors (including errors with HTTP 200), mismatched identities and
failed readback stop the callback. Ambiguous outcomes remain consumed or reserved
as found; they never authorize a replacement operation. A failed/unavailable run
does not become PASS merely because some state exists. A complete final report
and independently reviewed live state/job evidence are required. These metadata
rules do not establish Provider exactly-once semantics.

## Permissions and trust boundary

Workflow-level permissions are empty. Only bootstrap/reserve/contender/replay
jobs request repository contents write. Observe/verify request contents read.
The job token is passed only into the fixed script step; checkout uses a pinned
action at exact dispatch SHA with `persist-credentials: false`. No job checks out
a PR head, caller-provided ref, state branch source or code from an artifact.
Actions and scripts in writer jobs are trusted. The script independently rejects
other repositories, non-manual events, non-main refs, wrong workflow paths,
source mismatch and altered scope acknowledgement. API URLs are fixed to
GitHub, with proxies and redirects disabled and bounded reads/timeouts.

The existing Native/kernel workflows remain contents-read. The new protocol
uses only the built-in job-scoped token, no PAT, Provider key or new Secret. The
read-only write probe measures this experiment's job-token boundary, not every
historical workflow, arbitrary code holding a write token, IAM-wide isolation or
independent administration. Write credentials remain broad repository authority
inside trusted writer jobs. Repository administrators can change source,
workflow permissions, genesis approval and history; they remain trusted.

This experiment does **not** provision a stable #518 Ed25519 signing key, signed
service acknowledgement, issuer/Custody peer authentication or a Native
pre-dispatch gate. GitHub TLS authentication and a commit's Verified badge are not
substitutes for those contracts. No real recipient or archive is provisioned.
No paid host/database or larger runner is selected; standard public Ubuntu jobs
follow the reviewed cost basis in #519, subject to actual platform/account limits.

## Manual execution after review and merge

1. In Actions, select **Task4 GitHub Retained Metadata Ledger Research** and
   dispatch on **main**, mode **bootstrap**, with the exact acknowledgement.
   This is an explicit creation of the fixed research state branch. Do it only
   once; an existing namespace is an error. Review `bootstrap.json` or its
   sanitized log for the genesis OID. Do not guess a genesis if creation failed.
2. Dispatch **exercise**, fault **none**, with that approved genesis and a fresh
   owner-approved 64-hex authorization ID (the bootstrap's proposed ID may be
   used after review). Review all jobs and the final verified artifact.
3. For the fault case, dispatch **exercise**, fault **lost-ack**, with the same
   genesis and a different approved authorization ID. Do not reuse the first ID
   to bypass its retained consumption. Do not rerun failed jobs to obtain a new
   permission; inspect state read-only and keep incomplete runs NOT_PROVEN.

These instructions describe the concrete proposed experiment. This implementation
PR does not itself dispatch bootstrap/exercise, create the state branch, change
Secrets/Environments/Rulesets/tags, or claim that remote validation ran. The
operator's merge is followed by the separately observable manual experiment.
There are no public model API or real bank calls in any mode.

## Local/PR validation

61 unit tests model the REST/GraphQL shapes and cover exact namespace/state,
same-head contention including a late-starting runner, commit-before-callback,
discarded/lost/malformed acknowledgements, read-only permission errors,
duplicate/replay refusal, full registry stop, state integrity, source/event
admission and the manual-only workflow permission layout. The existing every-PR
Native offline workflow runs these with zero skips and emits a manual-plan
artifact explicitly marked remote_experiment_executed=false. Unit API models
are not remote GitHub evidence.

Platform references: [GraphQL commits and expectedHeadOid](https://docs.github.com/en/graphql/reference/commits),
[REST Git trees](https://docs.github.com/en/rest/git/trees),
[REST Git commits](https://docs.github.com/en/rest/git/commits),
[REST Git refs](https://docs.github.com/en/rest/git/refs), and
[workflow dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
All are design/API references, not repository administrative verification.

## First manual exercise failure and input-schema correction

Bootstrap [39584774958](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39584774958)
succeeded at source `813a4ef70f30113a587eb7d497c865262f303e85`, creating
genesis `e71487da54ce8d4096c68e836ea19956cec54d6d` on the fixed state branch.
Exercise [39585508504](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39585508504)
then failed in reserve job `119173285916` with GRAPHQL_ERRORS_STOP. The other
exercise jobs were skipped. Read-only inspection after failure found the branch
still at that genesis, revision 0, with an empty run registry. No callback or
Provider execution occurred. This is a failed experiment, not cross-runner proof.

The published [CommittableBranch input definition](https://docs.github.com/en/graphql/reference/git#committablebranch)
accepts `branchName`, `id` and `repositoryNameWithOwner`. The client incorrectly
sent `refName`, following wording in the mutation description instead of checking
the input type. The request therefore violates the documented schema. The
original sanitized log did not retain the server's exact validation message, so
that message is not reconstructed or quoted here. The correction changes the
wire field to `branchName`; expectedHeadOid, namespace, permissions, transitions,
acknowledgement validation and the no-retry rule remain enforced.

The API model now validates branch inputs against an independently documented
schema fixture **before** resolver permission checks. This prevents the old
model from accepting an invalid writer request or misclassifying the read-only
probe as a permission success. Regression cases reject the old field for both
writer and read-only tokens without committing. Errors continue to stop the
callback. Diagnostics now retain at most three type/message pairs, with bounded
messages, token redaction before truncation, no control characters and no raw
response, variables, extensions or headers. Existing malformed/lost response,
replay and callback-order tests remain required.

This correction PR does not retry the failed workflow, mutate the state branch
or create another namespace. After review/merge, inspect the retained state again
and use a fresh owner-approved authorization ID for a new manual exercise with
the **same approved genesis**. Do not bootstrap again or reset the registry.
Successful remote reservation/permission/contention/fault evidence remains open
until a complete, separately reviewed execution succeeds.
