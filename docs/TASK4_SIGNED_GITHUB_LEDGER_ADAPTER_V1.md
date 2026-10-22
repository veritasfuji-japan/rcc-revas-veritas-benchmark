# Eight-slot signed GitHub ledger adapter

This increment implements the missing bridge from the [#518 receipt contract](TASK4_EXTERNAL_LEDGER_CONTRACT_V1.md)
to a GitHub expected-head metadata backend. The [#523 loopback mTLS listener](TASK4_EXTERNAL_LEDGER_MTLS_V1.md)
can host the new service through an explicit trusted service injection point.
The listener still requires client certificates, two distinct pinned peers,
TLS 1.2 or later and loopback binding. No client JSON can choose a backend or role.

**CI uses an in-memory GitHub API model and real loopback TCP/TLS. It makes no
remote GitHub mutation.** The earlier [manual metadata evidence](TASK4_GITHUB_LEDGER_OBSERVED_EVIDENCE_V1.md)
does not prove this different eight-slot schema or signed-service path. No new
branch, genesis, key custodian, workflow dispatch, live credential, persistent
authority host or Native integration is deployed here.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Adapter and proposed namespace

`scripts/task4_signed_github_ledger_v1.py` supplies GitState and
SignedGitHubService. GitState requires an explicitly supplied API, owner-approved
genesis OID and service public-key digest; there is no default backend or API
connection. The adapter sends REST reads and GraphQL createCommitOnBranch with
the typed `branchName` field and exact expectedHeadOid. A deployed transport
would additionally need the reviewed fixed-GitHub API/credential boundary.
This module does not obtain a token or start a network connection itself.

| Proposed fixed item | Value |
| --- | --- |
| Repository | `veritasfuji-japan/rcc-revas-veritas-benchmark` |
| Branch | `research/task4-signed-ledger-v1` (not created by this increment) |
| File | `ledger.json`, regular mode 100644, at most 65,536 bytes |
| State schema | `task4.github-signed-ledger-state.v1` |
| Scope | `SYNTHETIC_SIGNED_LEDGER_ONLY_NO_PROVIDER` |
| Reviewed source base in state | `266f9add41daf94a778f247a6f3c0560318e2da2` |
| Ledger ID | SHA-256 of repository, colon, branch, colon, state schema |
| Enrollment root | Approved parentless empty registry including the pinned service public-key digest; no actual genesis selected yet |

The existing `research/task4-retained-ledger-v1` experiment is unchanged. Its
one-operation schema is incompatible with this signed eight-slot contract.
This proposed namespace is a separate synthetic experiment, not migration,
reset or a replacement authority for an existing run. Any future manual profile
needs explicit creation/enrollment review, fresh approved authorization IDs and
its own complete evidence. No client can select another namespace after a
conflict or ambiguous result. No automatic bootstrap/repair/pruning/key rotation
exists. All enrolled records remain in the registry; 32 runs, the blob-size bound
or the 544-commit ancestry bound stop progress rather than resetting state.

Each run stores the exact #518 binding and an eight-slot snapshot for A0-A3 and
B0-B3. Per-run revisions count reservation and consumption transitions (0-16).
The whole registry revision is enrolled-run count plus all per-run revisions.
Each mutation preserves other runs and uses one whole-registry expected-head
comparison; a conflict on any run stops that request without a refresh/retry.
Same-run re-enrollment is denied even with changed manifest or role key digests.
Enrollment is an explicit trusted service administration method, absent from
the client command schema. It is not a deployed owner-approval workflow.

## Commit/readback/signing order

For each command the service verifies the approved root, exact ref, descendant
relationship, single-file tree, bounded canonical blob/hash, signer, registry,
binding and transport-authenticated peer. Reserve is issuer-only, consume is
Custody-only, and either enrolled peer may view. A reserve creates a previously
absent slot. Consume requires its exact reserved request digest, binds the grant
digest and moves it to CONSUMED_UNKNOWN. There is no unused/reset transition.

A mutation constructs the complete next registry and submits one expected-head
GraphQL commit. Before signing, it requires the exact response nonce, ref, commit
OID and single expected parent, then reads that commit through the Git API and
checks its canonical state and parent against the proposed transition. Only
after that readback does it sign the unchanged #518 domain/statement fields:
schema, ledger ID, binding digest, command digest, command nonce, action and exact
per-run snapshot. The service key must match the digest pinned in the backend
configuration and approved root. No secret key is included in Git state.

A view signs the validated current snapshot; it does not authorize a callback.
LedgerClient still requires a fresh view followed by its own verified mutation
receipt. Timeout, API errors (including an errors-bearing HTTP 200 body), partial
response, identity mismatch, stale head or failed readback produce no mutation
signature and no callback. The mutation might already have committed. The
service does not reconstruct a successful acknowledgement from a later view,
retry, reissue a grant or resend. A fresh service object must observe retained
consumption and reject replay. A callback exception likewise cannot undo it.

Registry validation and ancestry checks do not protect against a trusted writer
or administrator deliberately replacing state with another valid descendant.
The signer, API transport, workflow/source, namespace approval and backend
administrators remain trusted. Durable anti-rollback, OS/IAM credential isolation,
key rotation/retirement and power-loss/restore behavior remain deployment gates.
Metadata in a public Git repository is public; only synthetic bindings/digests
are in scope. No confidential live record is authorized by this profile.

## Tests, rehearsal and remaining work

40 new cases cover all eight reserve/consume slots; commit-before-readback-before-
signing; uncertain committed results without a mutation signature/retry; wrong
nonce/parent/ref/OID; API and readback failures; stale head; role/binding failures;
changed duplicate enrollment; prior-run preservation; registry capacity and
corruption; missing/wrong ref, blob hash, extra files, ancestry and root parents;
missing default backend and changed signer; and the actual mTLS/model join.
The existing 34 mTLS cases still cover its original SQLite service and restarts.

The rehearsal creates synthetic TLS material in a temporary directory and hosts
the signed adapter behind the real loopback mTLS listener. Its API model commits
A0 normally, then commits B0 but raises a simulated API timeout. The B0 mutation
gets no service signature or callback; a fresh service object sharing the model
rejects its replay. Seven checks require two consumed slots at per-run revision 4,
one synthetic issue and one synthetic send callback, role denial and signature
ordering. These callbacks append integers. The model is memory-only: reconstructing
a service object does not prove process restart, external storage or separate
Runner retention. No CA, certificate, key, configuration or database is uploaded.

Existing Native offline CI runs all 40 cases with zero skips, exercises the
rehearsal and validates its source/commit hashes, counts, seven checks and false
remote/deployment/Native/production flags. It does not dispatch the manual workflow.

```sh
python -m pytest -q -o addopts= tests/test_task4_signed_github_ledger_v1.py
python -m scripts.task4_signed_github_ledger_rehearsal_v1 --output results/task4-signed-github-ledger
```

Next deployment work must supply an approved stable service-key custodian,
authenticated credential delivery and isolated GitHub writer, reviewed manual
root/enrollment lifecycle, bounded real API transport and complete remote
commit/signature/fault evidence. That requires a separately reviewed execution
profile before any branch mutation. Actual Native reservation-before-grant and
consumption-before-send remain later integration work. Existing Provider,
credential/egress, private-recipient, independent A/B and fresh-consent gates are
unchanged. This increment creates no paid resource or public service endpoint.

The [manual deployment preparation runbook](TASK4_SIGNED_LEDGER_MANUAL_DEPLOYMENT_RUNBOOK_V1.md)
records key custody, the public approval record, create-only root/enrollment
requirements, evidence boundaries and the current DEPLOYMENT_BLOCKED stopping
point. It is not an executable remote profile or permission to create resources.
