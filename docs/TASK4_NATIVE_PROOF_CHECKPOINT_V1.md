# Task4 Native proof checkpoint and remaining gates

For the bounded phase decision through #573, evidence identities and separate
Utility/research workstreams, see the
[selected fault phase checkpoint](TASK4_NATIVE_SELECTED_FAULT_PHASE_CHECKPOINT_V1.md).
This link preserves the historical scope and acceptance statements below.


Historical #505 checkpoint. For later #507–#510 helper/TLS/durable-issuer progress
and the remaining live-research acceptance gates, see the
[Provider research restart gap audit](TASK4_PROVIDER_RESEARCH_RESTART_GAP_AUDIT_V1.md).
The fresh-key/issuer-persistence and next-step statements below describe #505;
they do not negate the later bounded integrations.

Reviewed on 2026-10-20 JST against main
[`38b89770c712a2cea9e6b4fcc339e765ea70bb4d`](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/commit/38b89770c712a2cea9e6b4fcc339e765ea70bb4d)
(merged [#505](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/505)).
This is a documentation checkpoint for the selected Task4 path, not a new
execution authorization, independent audit or repository-wide security proof.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**

The selected actual Native SDK path now exercises signed admission, OS-separated
Bind Custody, local HTTP effects, response encryption, process restart and
controlled two-process contention in the same implementation. Its backend is
scripted and local. The next work should close a named remaining gate with a
falsifiable test; further combinations of trusted local faults do not by
themselves establish production authority or genuine model utility.

## 1. Exact scope and trusted components

| Item | Scope at this checkpoint |
| --- | --- |
| Native case | `banking:user_task_4:injection_task_0:direct`; A/B, ordinals 0–3; eight frozen SDK requests |
| Model | Scripted response source with label `gpt-4.1-mini-2025-04-14`; no genuine inference |
| Request manifest SHA-256 | `ee33c0a2d768ad4c7ceb4699a1abb702f6eb8e2f1ca8e0a64ce6c1867f860309` |
| Output limit | `max_completion_tokens=256`; not an authoritative billed-input-token or cost cap |
| Recipient manifest SHA-256 | `18e3d1c2776f029a57012beae669ac25c9bf3c680fc5239b0ee851196bedb93c` |
| Recipient public key SHA-256 | `8f15bcc58f2ddb4f6d5e490191d96b84d1f67b5872f5ec3871afd2e33c3f6aa1` |
| External pins | AgentDojo `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`; RCC `1d3782d3aae5ff9c88036709c1a5642320cc53c2`; VERITAS `a1d66aef02262cf8a913295270c3aafd159c6adb` |
| Actual Bind core Git blob | `0f64201e2599495ce4e3991348aa320995716ffc` |
| Identities | Native UID 61101, backend 61103, issuer 61105, Custody 61106; both competing Custodies share UID, credential, ledger and vault |
| Infrastructure | One trusted disposable Linux CI VM/kernel; Native/issuer loopback-only namespace; private local backend network; UID-enforced mock destination egress |
| Trusted authority | Root/kernel, source and key enrollment, issuer, Custody and backend; no independently administered deployment |

The Ed25519 signer generates a fresh private key inside its isolated process.
The X25519 recipient private key is a different key and is **publicly
reproducible synthetic test material**. It must never be promoted as confidential
custody for real data. Issuer persistence, owner approval, key rotation and
revocation are not established by this fixture.

## 2. What the latest evidence establishes

All rows below refer to separate runs of the same current adapter. They are
not one uninterrupted trajectory combining every interruption.

| Run / introducing PR | Required observations | Effects / consumed rows / ciphertexts | Replay refusals and result |
| --- | --- | --- | --- |
| Normal eight-request path / #499 | 22 | 8 / 8 / 8 | 8 normal + 8 after Custody restart; actual SDK parser, two Native terminals and two detached scorer calls; utility still UNSCORED |
| Three first-request fault runs / #500 | 21 each | after-consume: 0 / 1 / 0; response-lost: 1 / 1 / 0; after-sealed: 1 / 1 / 1 | 4 each; backend remains alive during Custody restart |
| Same three faults, both services restart / #501 | 28 each | Same counts as preceding row | 6 each, plus backend 403; unavailable reconciliation preserves state; backend returns retained receipts only |
| Two-Custody controlled overlap / #502 | 23 | 1 / 1 / 1 | One initial loser, then 8 replays refused; one returned SDK response; stop before forwarding A1 |
| Consumed winner exits before Bind / #503 | 26 | 0 / 1 / 0 | One lost IPC response and one initial refusal; 6 subsequent refusals; original loser remains alive |
| Concurrent winner loses response after backend commit / #504 | 29 | 1 / 1 / 0 | 10 subsequent refusals; winner restarts with backend alive; effect confirmation without raw response or completed Bind receipt |
| Same response loss plus backend SIGKILL/restart / #505 | 37 | 1 / 1 / 0 | 14 subsequent refusals plus backend 403; winner restarts while backend is unavailable; original loser remains alive |

The fault/concurrent-crash runs return zero SDK responses, complete zero Native
terminal arms and invoke zero scorers. The successful #502 overlap returns one
response but does not complete a terminal/scorer run. No row is a new Final128
measurement or a proof of Arm B utility recovery.

The OS path validates kernel peer identity, issuer signature, fixed bytes,
target, cap and recipient before consumption. A shared SQLite unique operation
insert admits one winner in the tested overlap. Normal admitted requests use
actual pinned Bind: denied authority has zero apply calls; permitted synthetic
authority has one apply call and a joined local backend receipt. Native cannot
read the tested private credentials/ledgers/signer key, mutate enrolled sources
or trust key, or use the tested direct/child network routes. These are real
bounded OS checks, not merely mocked application denials.

### Recovery semantics

| Evidence available | Permitted reconciliation result | What remains forbidden |
| --- | --- | --- |
| Backend unavailable | Preserve consumed ledger unchanged | Reset, reissue or retry |
| Authenticated absence after consumption | Remain `CONSUMED_UNKNOWN` | Claim NO_EFFECT or restore permission |
| Matching committed effect, response missing | `MOCK_EFFECT_CONFIRMED_NO_RESPONSE` | Reconstruct response, invent Bind COMMIT or resend |
| Previously sealed and observed response | Retain `MOCK_OBSERVED` and matching hashes | Replace confirmed response/receipt with another hash-valid pair |

Two GET-only reconciliations must be idempotent. Missing evidence cannot erase
prior confirmation. Restarted backends in the recovery fixtures open retained
SQLite read-only, validate the expected rows and refuse effect POSTs. They do
not reconstruct scripted dialogue state or accept fresh completion dispatches.
Process recovery with retained files is not VM/power-loss, storage rollback,
cross-host recovery or distributed CAS. A local receipt confirms only the
trusted local backend's effect; it is not a real Provider receipt.

## 3. Frozen evidence index

The latest complete evidence is the final #505 PR head
`bff52301019a2583cf68fe58ef50f00cb526b45f`, with 19/19 PR workflows successful.
Native ran GitHub's synthetic merge `d1f260565ea1849fa44a21471d72e83b1f3132a3`;
its tree `3629fdd24e0822f56c87ace8b5b549c4aa77dbe2` equals the PR head and the
merged #505 baseline. Kernel regression checked the PR head directly. This
does not assert that every PR-only workflow reran after merge.

| Evidence | Run / job | Artifact ID | Downloaded ZIP SHA-256 |
| --- | --- | --- | --- |
| Native integration and all 11 OS runs | [39380329516](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39380329516) / 118487748054 | [12244752700](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39380329516/artifacts/12244752700) | `a740957791e1ae1b8e4b78c617074aa99a98c6f832158451735d3dd26d836a41` |
| Earlier counter/kernel regressions, all nine runs | [39380329455](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39380329455) / 118487747771 | [12245087478](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39380329455/artifacts/12245087478) | `69293ec5c5eb4a225119ab9c7efaf789acd64d4161e202018009bb02f9d059e7` |

For #505, both ZIPs were downloaded and checked against API metadata and upload
log digests; ZIP CRC/path checks passed. Verified source hashes, nine historical
Native blob pins, three external commit pins, JUnit and request/response/receipt,
normal Bind/lineage and concurrent PID/barrier/outcome joins. Inspected proof
JUnit contained no skips/failures/errors. Native unit tests: 65; legacy selected
recipient integration: 13; kernel unit tests: 32. These are distinct suites,
not additional benchmark cases. The first #505 head stopped on a stale expected
unit count of 56; the final head requires all 65 and reran all workflows.

New #505 recovery observation: winner PID 3874 → 3884, original survivor 3875,
backend 3873 → 3887. Retained backend database SHA-256
`f20e4f5ec0eb69609a1e9b481cc29a6d6663cf8a3f95f0c4377a27e16abc1a3f`
was unchanged; exactly one effect remained. These PIDs are observations from
that run, not constants a reproducer must match.

Artifacts are sanitized evidence: no raw request/response bodies, grants,
private keys, credentials, ciphertext bytes or SQLite files. GitHub artifact
retention is finite; if unavailable, rerun the frozen offline workflow and
record new identities/digests rather than claim the old ZIP was reverified.

## 4. What changed since the earlier audit

| Earlier gap | Progress at this checkpoint | Still open |
| --- | --- | --- |
| Selected Native CI can miss dependency changes | #489 runs the selected offline workflow on every PR and requires its dedicated 13-case no-skip gate | Workflow enablement, event restrictions and independently protected change control |
| Selected Native path and OS/Bind mock proof were separate | #499 integrates actual frozen SDK bytes with separate-UID Custody, actual Bind and local HTTP effects | Real Provider adapter, credentials and independently administered enforcement |
| Crash/restart/concurrency were only separate counter experiments | #500–#505 exercise these bounded cases in the Native adapter itself | Cross-runner admission, issuer restart/reissue, hostile Custody, storage rollback and real Provider ambiguity |
| Historical paths are reachable | #490 provides source review and a fresh candidate inventory is produced by offline CI | Exhaustive deployed credential/effect coverage and external denial evidence |

The old #458 Broker remains synthetic NO_SEND code. Its callable operations do
not demonstrate a successful real Provider bypass. Separately, source inspection
at this baseline still finds default `HTTPSConnection` helpers supplied a key
by their caller: `send_exactly_once` in
[`task4_live_first_two_call_capture_oneuse_v1.py`](../scripts/task4_live_first_two_call_capture_oneuse_v1.py),
`once` in [`task4_live_second_two_call_capture_oneuse_v1.py`](../scripts/task4_live_second_two_call_capture_oneuse_v1.py),
and `one_post` in [`task4_live_third_two_call_capture_oneuse_v1.py`](../scripts/task4_live_third_two_call_capture_oneuse_v1.py).
Their outer CLI checks do not establish independent enforcement for any process
already holding a valid key and matching payload. Key availability, accepted
requests, billing and current workflow states were not tested.

The #423 workflow remains source-stopped at preflight and sender; its standard
sender requires an injected connection factory and has no default HTTPS path.
Do not classify it as an active default bypass. The 15 historical manual
Provider workflow disablement candidates remain an **administrative state
UNKNOWN** item; a source scan is not a GitHub enable/disable-state readback.
The three historical Task4 Environment declarations do not prove protection
settings. No setting was inspected or changed by this checkpoint. Static route
inventory is a candidate index, not a complete Python call graph; dynamic code,
aliases, external sources and credential consumers require further review.

## 5. Remaining gates and required closure evidence

Owners below are roles to assign, not people who have agreed to approve or
operate a deployment. No host, account, secret, external administrator or
reviewer is enrolled by this document.

### Research-only real-model gate — currently NO-GO

| ID / proposed responsible role | Required evidence before a fresh research attempt |
| --- | --- |
| R1 experiment owner + spending approver | Freeze exact source, case/model, independent A/B starts, execution ID, request/attempt limits, input/output limits, cost stop and maximum budget; obtain fresh explicit consent for that exact plan. Old approvals and current CI cannot be reused. |
| R2 sender/infrastructure operator | Review one concrete Provider sender deployment and its full credential/egress path; connect pre-dispatch admission to the actual sender; demonstrate unauthorized/alternate helper and subprocess attempts denied using a disposable no-cost sink first. No injected arbitrary forwarding fallback. |
| R3 authority/storage operator | Define durable consumption and run binding for the declared deployment, including issuer restart/reissue and ambiguous sends; retain unknown outcomes and prohibit automatic retry/new-grant reset; test the declared crash/concurrency cases. Do not infer Provider exactly-once behavior from local SQLite. |
| R4 key/evidence operator | Review non-public recipient provisioning/enrollment and pre-parser raw-response custody for the live path; prove redacted artifacts and authorized recovery. Never promote the public fixture key to protect real data. |
| R5 experiment reviewer | Confirm independent A/B inputs and response provenance through actual Native terminal/scorer; allow only the disposable bank simulator and zero real bank endpoints; incomplete runs remain UNSCORED. Review the current relevant workflow/credential state and any residual live routes. |

These are required closure records, not a statement that a live adapter exists
or that passing this document authorizes dispatch. Research consent is distinct
from production readiness: a narrowly scoped research experiment need not close
every production assurance below, but must have verified guardrails for its
declared threat model and fresh exact spending approval. This checkpoint grants
zero Provider requests and zero spending.

### Production independent-authority gate — not proven

| ID / proposed responsible role | Falsifiable acceptance evidence |
| --- | --- |
| P1 issuer/approval and deployment administrators | Independently protected identities, source/image/policy/key enrollment and approval; agent/ordinary PR cannot alter them, assume executor identity or acquire effect credentials. A second process alone is insufficient. |
| P2 credential/network administrator | Full deployed sender/tool-effect/credential inventory, including historical refs, workflows, reusable jobs, secret aliases and external grants; OS/IAM/egress denies same-UID agent code, retained helpers, alternate clients and child processes. Independently attest actual controls and denied sink-side observations. |
| P3 ledger and backend operators | Atomic admission for every supported runner; no sender/issuer reset or unreviewed reissue; tested crash/lost-ACK/restart and declared storage failure policy. Reconcile backend-authoritative outcomes. If backend lacks durable idempotency or receipts, state the limit and deny exactly-once claims. |
| P4 key/custody operator | Non-public recipient custody, authenticated versioned enrollment, rotation/revocation, retention and owner recovery; protect raw responses before validation/parser failure. |
| P5 independent reviewer | Reproduce the frozen positive/negative bundle on separately controlled disposable infrastructure, review deployed policy and backend receipts, and explicitly attest only the tested scope. No third-party verification has been completed by this PR. |

Utility restoration is a separate experiment: genuine independent A/B model
responses, frozen scorer/treatment and held-out measurements must show injection
resistance and utility without weakened authority conditions. No utility score
or completion-date estimate is inferred from the number of merged PRs.

## 6. Next implementation and reproduction

First choose one remaining gate, deployment and operator, then freeze its threat
model and acceptance test. The recommended next target is **R2/P2 for one
disposable executor boundary**: actual retained helper/alternate-client attempts
must fail outside application monkeypatches, and the authenticated sink must
corroborate zero unauthorized effects. Existing UID/netns fixtures are reusable
building blocks; another trusted local fixture alone does not close independent
administration. Use no real credentials or Provider calls for that first test.

For reproduction, start with the pinned #505 tree and the complete environment
and dependency setup in the existing
[`task4-native-frozen-recipient-offline.yml`](../.github/workflows/task4-native-frozen-recipient-offline.yml).
Use a disposable supported Linux runner: the proof creates network namespaces,
UID firewall rules and isolated processes under trusted root. Do not run the
privileged fixture on an ordinary production host. The dedicated job runs the
normal path and all ten additional modes; running only the unit file is not a
substitute. The new recovery mode is:

```sh
sudo -n "$(command -v python)" -m scripts.task4_native_os_custody_v1 \
  --run --concurrent --concurrent-response-loss --restart-both \
  --output results/task4-native-concurrent-backend-restart
```

The earlier counter/kernel regressions run separately in
[`ci-mock-executor-authority-boundary-v1.yml`](../.github/workflows/ci-mock-executor-authority-boundary-v1.yml).
Verify actual source/tree/checkout identities, external pins, all mandatory
checks, zero-skip JUnit, receipt/lineage joins and API/upload/download artifact
digests. Regenerated keys/PIDs are expected to differ. No reproduction or
independent review is claimed merely by publishing these instructions.

Related historical scope documents:
[original gap register](TASK4_488_EVIDENCE_TO_PRODUCTION_GAP_REGISTER_V1.md),
[route review and proposed deployment](EXECUTION_AUTHORITY_ROUTE_REVIEW_AND_SEPARATION_V1.md),
[dependency/CI coverage](TASK4_NATIVE_DEPENDENCY_CI_AUDIT_V1.md),
[original OS integration](TASK4_NATIVE_OS_CUSTODY_V1.md),
[faults](TASK4_NATIVE_OS_CUSTODY_FAULTS_V1.md),
[both-service restart](TASK4_NATIVE_BOTH_RESTART_V1.md),
[concurrency](TASK4_NATIVE_CONCURRENT_CONSUMPTION_V1.md),
[winner crash](TASK4_NATIVE_CONCURRENT_WINNER_CRASH_V1.md),
[response loss](TASK4_NATIVE_CONCURRENT_RESPONSE_LOSS_V1.md),
[concurrent backend restart](TASK4_NATIVE_CONCURRENT_BACKEND_RESTART_V1.md).

This checkpoint changes documentation only. It does not change execution code,
workflow permissions, pins, secrets, Environments, Rulesets, tags, paid workflows
or administrative state, and does not authorize a merge.
