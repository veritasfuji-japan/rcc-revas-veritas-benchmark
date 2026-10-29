# Task4 Native selected fault phase checkpoint — through #573

Recorded 2026-10-29 JST at main
[`4cfbec4439dc3b19f2fec2434919ea48c17a5e6c`](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/commit/4cfbec4439dc3b19f2fec2434919ea48c17a5e6c).
This is a builder-maintained evidence index and a bounded phase completion
decision, not an independent audit, execution approval or production certification.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**

## Decision and stopping rule

The selected synthetic Native ingress/archive/acknowledgement fault phase is
complete against the acceptance conditions below. Keep its mandatory regressions.
Do not automatically add more crash permutations as prerequisites for Utility
analysis. Reopen this phase for a concrete defect, changed implementation or
threat model, or a named deployment requirement with a falsifiable acceptance
test. New testing must identify the requirement and missing evidence first.

This closes a finite engineering phase; it does not close every possible
interruption boundary. In particular, #573 stops before Native records the model
response or the SDK caller receives it. Crashes during later history updates,
SDK delivery, terminal/scorer completion or arbitrary instruction boundaries
remain outside that selected proof.

## Scope and evidence progression

The backend is a controlled local synthetic service. The selected path uses
the frozen Native SDK/driver, original Bind core, separate process UIDs, Unix
sockets, mutual TLS, signed external ledger receipts and retained local state
on a trusted disposable Linux CI runner. Root controls fixture enrollment and
keys. This is not an independently administered deployment.

| Boundary / reference | Observed scope | Practical limit |
| --- | --- | --- |
| [Bounded Unix integration](TASK4_NATIVE_BOUNDED_UNIX_EGRESS_V1.md), [backend loss](TASK4_NATIVE_BACKEND_RESPONSE_LOSS_V1.md), [restart](TASK4_NATIVE_BACKEND_RESTART_V1.md) | Original Native path, signed admission, local effects and read-only retained backend reopen | Local backend receipts do not establish real Provider idempotency |
| [Partial response](TASK4_NATIVE_PARTIAL_RESPONSE_V1.md), [timeout](TASK4_NATIVE_RESPONSE_TIMEOUT_V1.md), [total deadline](TASK4_NATIVE_TOTAL_DEADLINE_V1.md) | Selected incomplete, stalled and bounded receive paths retain uncertainty and deny retry | Fixed tested limits; no arbitrary network/failure coverage |
| [ID binding](TASK4_NATIVE_RESPONSE_ID_BINDING_V1.md), [ID guard](TASK4_NATIVE_RESPONSE_ID_GUARD_V1.md), [framing](TASK4_NATIVE_RESPONSE_FRAMING_GUARD_V1.md), [size](TASK4_NATIVE_SIZE_BOUNDARY_V1.md), [read count](TASK4_NATIVE_READ_COUNT_V1.md) | Selected malformed or ambiguous replies denied before Native continuation | Explicit guards, not a universal HTTP/parser proof |
| [Archive failures](TASK4_NATIVE_ARCHIVE_FAILURE_V1.md), [write](TASK4_NATIVE_ARCHIVE_WRITE_FAILURE_V1.md), [close](TASK4_NATIVE_ARCHIVE_CLOSE_FAILURE_V1.md), [crash](TASK4_NATIVE_ARCHIVE_CRASH_V1.md), #567–#570 | Injected API failures and actual selected Custody SIGKILLs retain the effect/consumption distinction | API injection and process death do not prove power-loss durability; silent successful short writes are not covered |
| [Handler acknowledgement loss](TASK4_NATIVE_REPLY_ACK_LOSS_V1.md), #571 | Custody dies after successful seal or handler return, before Native reply delivery | Completed archive/state does not prove caller delivery |
| [Partial IPC reply](TASK4_NATIVE_IPC_PREFIX_LOSS_V1.md), #572 | Real Unix send prefixes: one byte, mid-JSON and complete JSON without newline; receiver sees EOF and stops | Selected prefixes, not all socket failure modes |
| [Runtime acknowledgement crash](TASK4_NATIVE_RUNTIME_ACK_CRASH_V1.md), #573 | Complete parsed frame; Runtime SIGKILL after frame return or RPC return, before SDK response | Complete receipt is not committed Native history or permission to repeat |

Each profile is a separate controlled run. This table does not join all faults
into one uninterrupted trajectory or claim that the same state transition is
reached in every case. Per-profile documents and validators define exact
expected outcomes. Retain the historical
[#505 checkpoint](TASK4_NATIVE_PROOF_CHECKPOINT_V1.md) for its earlier scope.

## Finite acceptance conditions

| Condition | Evidence at this checkpoint | Status within selected scope |
| --- | --- | --- |
| Positive path still completes | #573 matching normal control: eight original SDK returns, eight model records, two terminal/scorer results, 16 signed mutations | Observed; scripted outputs remain UNSCORED |
| Actual selected process deaths | #570 Custody and #573 Runtime self-SIGKILL; supervisor checks exit -9 and subsequent retained-state reopen | Observed; no Python cleanup or power-loss inference |
| Sender and receiver are distinguished | #572 actual prefixes/EOF; #573 full 1,894-byte frame and parsed reply, actual socket close for after-rpc-return | Observed; no sendall-only delivery inference |
| Unknown outcome does not restore permission | Negative profiles refuse reissue/replay after reopen and preserve their expected ledger/local/backend state | Observed for declared cases; no automatic dispatch retry |
| A committed effect is not mistaken for a completed SDK call | Both #573 cases: one backend effect, external revision 2 CONSUMED_UNKNOWN, local MOCK_OBSERVED, issuer PENDING, zero SDK/Native returns | Observed; no exactly-once delivery claim |
| Evidence is internally joined | Validators check pins, signatures, bytes, identities, timing and retained-state relations; modified proofs rejected | Builder replay completed; independent review remains open |
| Existing regressions remain mandatory | #573 combined Native artifact: 153 JUnit XML files, zero failures/errors/skips; all 22 PR workflows succeeded | Observed on the frozen PR head/merge below |

The #573 negative paths return no SDK result, even though Custody has already
parsed the backend response, committed Bind, saved the archive/receipt and
returned from its handler. Do not read a legacy empty parser_events field as
evidence that parsing never occurred. Runtime events establish the selected
full-frame/parsed-reply boundary. Cross-process send-audit and receiver-audit
timestamps can race; their relative ordering is not an acceptance condition.

## Frozen #573 evidence

| Identity | Value |
| --- | --- |
| Final PR head | `9a9d5ef534f52c8c38186ad7378a4c62f7556169` |
| Tested virtual merge | `45f5e5f8111fdb71e431c6df9f649cdf789956a2` |
| Actual main merge | `4cfbec4439dc3b19f2fec2434919ea48c17a5e6c` |
| Head, tested merge and actual main tree | `a4dcc074aa2ffdfde6f0140e99d9090d56667bf2` |
| Native run / job | [40853403815](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/40853403815) / 123378235619 |
| Artifact | [12889809511](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/40853403815/artifacts/12889809511) |
| Downloaded ZIP | 2,257,665 bytes; SHA-256 `d54e859426d257d981a412bc46512a2f81918bf243a8a5177810e4a47bf75158` |
| General PR tests | 6,698 passed; 1,205 existing skips; 94 subtests |
| New portable tests | 76; caller/SDK markers are stand-ins, real pipes and child SIGKILL |
| New root integration checks | 21 normal + 24 after-frame-return + 24 after-rpc-return = 69; zero skips |
| Modified proofs rejected in builder replay | 74 normal + 97 after-frame-return + 100 after-rpc-return = 271 |

The full ZIP digest was checked before report extraction; report validators,
previous profile controls and tampered-proof rejection checks were replayed.
Artifact JUnit counts are not benchmark case counts. General-suite skips are
not skips in the mandatory Native proof. Main's post-merge `test` succeeded;
this does not assert that all PR-only workflows reran after merge.

| Extracted canonical report | Bytes | SHA-256 |
| --- | --- | --- |
| Normal | 649621 | `af7cc11274a358b5ba775d99c9223abf298903db37395d64fa78a72df821cef9` |
| after-frame-return | 205861 | `998c3acb97950d406d69f5ff52e89e6086ef199fe47714079b52d2e21b8cd9a9` |
| after-rpc-return | 207919 | `53d26a54e8eb1c372953792b482f215bda2c6c1e65f9339db7f91515061341f0` |

GitHub artifact retention is finite. If an artifact expires, rerun the frozen
workflow and record new run/commit/digest identities; do not claim that a newly
generated proof has the historical artifact's identity. Reproduction requires
the workflow's frozen dependencies and a disposable supported Linux runner
with unused fixture UIDs. Portable unit tests alone do not reproduce root,
real SDK, Unix socket, TLS or cross-UID evidence. No operator VM run is requested.

## Separate workstreams and remaining decisions

| Workstream | Next bounded action | Evidence required / current limit |
| --- | --- | --- |
| Selected synthetic Native fault phase | Maintain regressions; reopen only under the stopping rule above | Complete within this document's scope |
| Utility improvement | Analyze failed normal tasks, identify a concrete cause, then compare frozen independent A/B measurements after a targeted fix | Real measured utility and injection outcomes; no score inferred from scripted control success |
| Independent reproduction | Assign an external reviewer and a frozen disposable reproduction bundle | Reviewer-controlled run, provenance and signed/evidence review; not completed here |
| Real Provider research | Select one deployment and review its sender, credential/egress path, private custody, budget, outcome policy and exact fresh authorization | Still NO-GO; synthetic receipts and this document authorize zero requests/spending |
| Production assurance | Define independent control ownership and deployed credential/effect inventory, storage assumptions and recovery contract | Bypass resistance, privileged adversaries, rollback, reboot/power loss and cross-host behavior remain unproven |

Utility work can proceed independently now. Further trusted synthetic fault
permutations are not automatically prerequisites for diagnosing utility loss.
Measured safety and utility must be evaluated together without weakening
authority conditions. A green synthetic control cannot establish injection
success zero or Arm B utility at least Arm A on genuine model responses.

For real research and production, retain the distinct gates in the
[Provider restart gap audit](TASK4_PROVIDER_RESEARCH_RESTART_GAP_AUDIT_V1.md)
and the [historical checkpoint](TASK4_NATIVE_PROOF_CHECKPOINT_V1.md).
Those gates must be reassessed against a concrete current deployment; they
are not automatically discharged by this phase decision.

This checkpoint adds documentation only. It issues no execution permission,
changes no runtime/limits/credentials/host rules, and does not merge its own PR.

