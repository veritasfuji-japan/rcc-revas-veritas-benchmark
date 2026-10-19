# Task4 evidence-to-production gap register (offline, non-executing)

**Baseline:** main `64f69d04c748a0a88d6cb1dd849b1e5e70a804b0` (merged PR #487). **Status:** documentation-only; no new authorization, no live Provider calls, no production proof.

## Evidence ledger (PR HEAD validation; not production claims)

| PR | Boundary established in selected offline path | Dedicated run / job / artifact | Dedicated CI | Artifact ZIP SHA256 |
| --- | --- | --- | --- | --- |
| [#482](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/482) | Static reachability audit: 762 Python files, 30 direct call sites, 36 import-closure candidates, 18 workflow references; old #458 remains transitively reachable in historical entrypoints | Not recorded here | 16/16 PR workflows per handoff | Not recorded |
| [#483](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/483) | AF_UNIX signed ciphertext custody, SQLite consume/attach single-use, restart/readback | 39265737435 / 118104709863 / 12193820695 | 25 PASS | a1f7a21fc2fa97410738da50a5010b931724ac637ba8d6c448bb5f0aed4e8f90 |
| [#484](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/484) | Selected scripted Native SDK path routed through protected custody; eight requests and 32 protected connections | 39288455274 / 118182550161 / 12205605489 | 17 PASS | 098b8967e2e3ae873fb77d4cfca7a4eeaeefa8375d778c5dd8982d198667b1a9 |
| [#485](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/485) | Fresh spawned signer holds random Ed25519 private key; 24 signatures; cached replay rejection | 39290083693 / 118188156160 / 12205515951 | 15 PASS | 5fbf53ccbaca8611bec253405ee40e038ff93473247b6bbd65de95dda7cd5b78 |
| [#486](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/486) | Eight frozen scripted request digests enforced inside signer | 39292836677 / 118197631982 / 12205659593 | 13 PASS | e95032b3f1151412b1ed163b69433c209e7368166f943c70ad7539ffd22945c4 |
| [#487](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/487) | Frozen synthetic X25519 recipient before first consume; request scope unchanged | 39293913529 / 118201377215 / 12206487943 | 13 PASS | 231820d90bd5d8de8eceef2da828464778ac9cced7299bb829aac4a997107cb6 |

The #483–#487 dedicated runs are successful PR-HEAD runs, and their listed ZIP digests match GitHub artifact metadata. #487's PR HEAD had 18/18 successful workflows. Post-merge main `64f69d04c748a0a88d6cb1dd849b1e5e70a804b0` has a successful **CI** push run [39341331949](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39341331949); this does not imply every dedicated PR workflow reran on main.

## Scope and explicit non-claims

Frozen case `banking:user_task_4:injection_task_0:direct`, model **label** `gpt-4.1-mini-2025-04-14`, A/B ordinals 0–3, eight capped SDK requests, output cap 256. Responses were scripted: **no genuine model response, real bank effect, independently scored Utility, or production bypass-resistance test**. The #486 request manifest SHA256 is `ee33c0a2d768ad4c7ceb4699a1abb702f6eb8e2f1ca8e0a64ce6c1867f860309`. The #487 recipient manifest SHA256 is `18e3d1c2776f029a57012beae669ac25c9bf3c680fc5239b0ee851196bedb93c`; recipient public key SHA256 is `8f15bcc58f2ddb4f6d5e490191d96b84d1f67b5872f5ec3871afd2e33c3f6aa1`.

**Critical:** the #487 X25519 recipient private key is publicly reproducible from a synthetic label. It is **not confidential and must never protect real data**. The random child-only Ed25519 signing key is separate. Same-UID parent/code/DB/pin replacement remains outside this proof. Historical callable entrypoints remain. Signer state is not durable across restarts; read capability can be replayed; cross-runner atomicity and independent owner authorization are unproven.

## Gap-to-closure matrix

| Priority | Unresolved requirement | Required independent evidence / acceptance criteria | Work class |
| --- | --- | --- | --- |
| P0 | Eliminate bypass through historical entrypoints and alternate Provider clients | Enumerate every reachable sender, tool-effect path and credential route; negative attempts show unauthorized effect/egress impossible; no residual callable privileged bypass | Code + deployment review |
| P0 | Independent authority boundary | Distinctly administered issuer/approval, secret broker, IAM and network egress rules; demonstrate denial from unauthorized same-UID code and runners | External environment + adversarial review |
| P0 | Production-grade recipient custody | Independently provisioned non-public recipient key, authenticated enrollment/rotation/revocation, secret isolation, end-to-end AEAD owner recovery; never promote fixture key | External environment + cryptographic review |
| P0 | Durable single-use / uncertain-send semantics | Atomic shared CAS across runners; survive process crash/restart, lost ACK and ambiguous Provider outcomes; deny repeat send and preserve receipts | Code + external ledger |
| P0 | Protected change control | Pin reviewed workflow/code/policy; demonstrate no unauthorized modification of issuer, egress, rules or pins by an actor inside stated threat model | External administration |
| P1 | Prospective genuine-model research | Independent A/B model starts, bounded attempts/tokens, zero real bank endpoints, complete Native terminal/scorer provenance; explicit UNSCORED on incomplete runs | Offline dry-run, then separately authorized paid research |
| P1 | Independent reproducibility | Third party independently checks exact source pins, artifacts, adversarial cases and observed limits; no automatic promotion from CI green | External reviewer |
| P1 | Utility restoration without authority weakening | Pre-register scorer and treatment, score genuinely independent held-out A/B; compare injection successes and utility to same-version baseline | Experiment |

**Do not confuse gates:** A narrowly scoped disposable-bank real-model *research* experiment does not require every production-independent assurance to be completed, but **does require fresh exact spending consent and verified research guardrails**. A production no-bypass claim requires independent enforcement and adversarial evidence. See [#321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321) for Task4 prospective research NO-GO and [#427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427) for separate Task1 paid dispatch NO-GO. Both remain open.

## Proposed next work, before any new implementation

1. Audit *all* current sender/credential/effect entrypoints, not only the selected #487 runner; publish a concrete bypass inventory with owners and negative tests.
2. Define two explicit gate checklists: **research-only Provider A/B** versus **production independent authority**; record each missing external control and who can attest it.
3. Choose a P0 gap with a falsifiable acceptance test and exact threat model before coding; avoid accumulating additional scripted fixtures without closing a gap.
4. After a no-cost dry-run of the research-only sender, ask for **fresh** approval specifying case, model, exact commit, max attempts/tokens, budget and execution ID. No old approval is reusable.
5. Seek asynchronous independent review of a frozen evidence bundle; no reviewer role or approval is assumed.

## Default-deny operating conditions

`REAL_PROVIDER_NO_GO` · `UTILITY_UNSCORED` · `PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`.

This document authorizes **zero** Provider POSTs, **zero** spending, **zero** real bank effects, and **no** changes to Secrets, Environments, Rulesets, tags or paid workflows. It does not authorize a merge. Any future PR must be reviewed and merged manually.
