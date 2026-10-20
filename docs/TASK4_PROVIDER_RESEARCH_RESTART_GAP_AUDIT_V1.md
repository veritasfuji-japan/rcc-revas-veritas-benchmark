# Task4 Provider research restart: source audit and remaining acceptance gates

Reviewed 2026-10-21 JST against main
[`3634d554e9056bc7770b710bee4b69c54a42f64e`](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/commit/3634d554e9056bc7770b710bee4b69c54a42f64e)
(merged [#510](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/pull/510)).
This is a documentation-only source audit and implementation plan. It performs
no Provider request, credential read, administrative change or new experiment.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**

## Decision

The selected Native path has substantial real local OS/TLS/Bind/restart evidence.
It is not a ready-to-enable public Provider sender. Keep dispatch disabled and
close the named gaps below before proposing any new paid attempt. Do not add
more combinations of scripted faults without identifying which gap they close.

The next implementation should be a **Provider-shaped, source-neutral request and
raw-response boundary exercised only against closed local TLS**. Its review must
include the proposed credential/deployment contract, run-bound admission, archive
ordering and failure policy. No real secret loader, public egress or paid trigger
is authorized by this audit. Later live deployment and fresh consent are separate.

## What changed after the #505 checkpoint

These are separate bounded fixtures, not one trajectory combining every fault.

| PR | Verified local progress | Boundary still outside the proof |
| --- | --- | --- |
| #507 | Three unchanged historical helpers plus alternate clients/child routes: 12 network denials and six backend 403s; same-run eight Native effects and response/scorer joins | Helpers use an injected local HTTP transport in this fixture |
| #508 | Three unchanged default HTTPS helpers, six OS denials, three actual TLS/403s, bad-CA-before-HTTP control; actual Bind counter positive | Local hosts/CA enrollment; positive is a synthetic counter, not the Native trajectory |
| #509 | Eight actual frozen Native requests through Custody/Bind/local TLS, durable response encryption and original Native/scorer lineage; same backend denies bypasses | Transport is a signed packet to `/effect`, with a scripted backend |
| #510 | Separate durable issuer, SIGKILL/new PID, same key/epoch/eight issued grants; cached re-export refused before/after Custody restart; missing/truncated/replacement-key startup refusal | One trusted root/kernel/issuer/Custody/backend; no distributed CAS, host reboot, rollback or independent administration |

The #510 final head was `3c893463b04b2c3e1d6ee9b6ca06cdd799f1824d`,
with 19/19 PR workflows successful on the first head without retries. Native
audited synthetic merge `d7ba3eb13e825edf8461bcb0c91b1564e32837a1`, whose
tree `38bf879f165bc147298f6788c544d6326b86c443` equals the head and merged
baseline tree. Kernel evidence checks the head directly. These are PR validation
results, not a claim that all PR-only workflows reran after merge.

| Frozen evidence | Run / job | Artifact | Downloaded ZIP SHA-256 |
| --- | --- | --- | --- |
| Native, TLS and durable issuer | [39469576474](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39469576474) / 118789792876 | 12287271171 | `43bea6f03259958193ee8fc3016d2efdeff34a02005d281d90c49b13107e3b7f` |
| Kernel/counter regressions | [39469576254](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/39469576254) / 118789791966 | 12285858088 | `3219c1e9921c64a1ef60f692a968f4e59a4586b2ff58402ed8bb4b7359cdce3a` |

Both archives were downloaded and matched to API/upload/download digests, source
identities, CRC/path checks and zero-skip JUnit during #510 review. They contain
35 JUnit files / 1,033 cases, not 1,033 benchmark tasks. Issuer fixture: 16 issuer,
16 TLS and 22 normal Native checks; eight effects/consumptions; 32 replay denials
including 16 cached re-export attempts. Its 64 Custody TLS connections and 12
backend POST records remain unchanged across issuer restart/re-export/failure.
Artifacts expire; if missing, reproduce the pinned offline workflow and record
new identities/digests rather than claiming the old ZIP was downloaded again.

## Actual send and receive boundaries at this baseline

| Boundary | Source observation | Consequence for live research |
| --- | --- | --- |
| Native admission | `task4_native_os_custody_v1.statement/verify/custody`: exact signed scope, arm/ordinal, frozen request SHA, mock target, cap and public fixture recipient; SQLite operation IDs such as A0 | Not a fresh experiment ID/expiry/budget policy. The retained issuer epoch is anchored local state, not a field in each historical signed grant. |
| TLS outbound | `task4_native_local_https_v1.call`: standard verified HTTPS to the namespace-enrolled local peer; canonical signed packet and private `X-Mock-Auth`; `/effect` selected by `bind_post` | This is not the raw SDK JSON plus Provider Bearer authentication at `/v1/chat/completions`. Local HMAC/key/CA cannot be substituted for public Provider credentials/identity. |
| Backend response | `task4_native_os_custody_v1.backend`: GuardedMock local callable generates original scripted completion bytes; wraps them with `response_b64` and a local receipt | The backend receipt is not Provider accounting/idempotency evidence or a genuine response attestation. |
| TLS receive | `task4_native_local_https_v1.call` reads bounded bytes and JSON-parses the outer wrapper; `bind_post` checks status/receipt and decoded response hashes | Errors at this outer HTTP/wrapper boundary are not necessarily preserved by the later inner-response archive. |
| Native pre-parser archive | `task4_native_os_custody_v1.custody` recovers inner bytes, invokes `SealedLocalVault.commit_before_parser`, then returns ciphertext to Native | Valid proof of inner scripted response encryption before the Native SDK parser; not proof that every malformed/non-200/partial real HTTP response is sealed at first ingress. |
| Existing source-neutral ingress | `task4_461_sdk_response_ingress_no_go_v1.SDKResponseIngress.after_response` invokes a seal callback before status/JSON checks within its bounded response contract | Reusable ordering logic, not an installed sender or independently verified archive. Its callback receipt is a claim; it does not establish Provider origin/custody. |

All source paths in this audit are under `scripts/` unless stated otherwise and
refer to the pinned baseline above. The complete current path is documented in
[Native local HTTPS](TASK4_NATIVE_LOCAL_HTTPS_V1.md) and
[durable issuer restart](TASK4_DURABLE_ISSUER_RESTART_V1.md). Earlier
[source-neutral ingress](TASK4_461_SDK_RESPONSE_INGRESS_NO_GO_V1.md) and
[real-model readiness](TASK4_460_REAL_MODEL_READINESS_NO_GO_V1.md) remain useful
contracts; their historical counts/estimates are not current spending permission.

## Research acceptance register — every live gate remains open

Owners are proposed roles, not enrolled people or approvals. Each closure record
must name the exact source/image, deployment, operator, threat model and evidence.
Local progress is credited below without promoting a whole live gate to PASS.

| Gate / responsible role | Remaining implementation or operational decision | Falsifiable acceptance evidence before live research |
| --- | --- | --- |
| G1 Provider wire / sender implementer | Separate raw SDK request/response handling from the signed local control envelope; fixed endpoint/method/header policy; no arbitrary URL/proxy/factory fallback | Closed local TLS sink receives exact original SDK bytes at the reviewed Provider-shaped path with only a synthetic dedicated credential. Deny target/path/body/header mutation, redirects, alternate clients and child routes; preserve request/response identity through the real SDK parser. No public endpoint involved. |
| G2 credential and egress / infrastructure operator | Declare one concrete sender identity and private key delivery path; deny Native, issuer, scorer and untrusted jobs access to the Provider credential or sender identity | First use synthetic credentials and verify actual OS/IAM/network denial plus sink-side zero unauthorized effects. Then separately review proposed live provisioning and current protected source/workflow state without exposing a key. A job Environment or second Python process alone is insufficient. |
| G3 run-bound admission / authority and storage operator | Bind fresh execution ID, trusted before-first-request task/date/target/scope, request SHA, arm/slot, recipient, expiry and attempt policy to actual send. Define permitted adaptive continuation and retained storage for the declared deployment | No switch to a new temp directory, issuer epoch, runner or process may reset the same authorized attempt. Test pre-send consume, concurrent duplicate, ambiguous write/read, missing/corrupt state and restart/re-export. Unknown stays consumed; no automatic resend or new-grant reset. Do not claim Provider exactly-once semantics. |
| G4 first-ingress evidence / archive implementer | Seal raw HTTP status/header/body evidence before semantic validation or SDK parsing, using a separately reviewed live-capable archive contract | Inject non-200, malformed JSON, missing IDs, size limit, truncated read, timeout, archive failure and crash. Show durable ciphertext/hash joins for bytes actually observed, no retry/continuation on ambiguity, and no plaintext artifact. Distinguish sealed partial/prefix evidence from a complete response; never invent unreceived bytes. |
| G5 non-public recipient / key operator | Provision and authenticate an appropriate non-public recipient, authorize recovery and retention; preserve raw evidence confidentiality | Demonstrate recipient enrollment before first consume, rejected key substitution and authorized recovery with disposable private test material first. Review live provisioning separately. Never use the public/reproducible #487 fixture key for confidential evidence or relabel synthetic #457 metadata as Provider-authenticated. |
| G6 fresh scope/cost consent / experiment owner and spending approver | Choose experiment type, exact model availability/version, input/output/attempt limits, current prices, stop policy, max budget and fresh execution ID; protect those choices from model output | No-cost rehearsal produces the exact reviewed manifest and cost calculation. Verify whether each external account control is an actual enforcement limit or only an alert and its latency. Obtain fresh explicit approval only after concrete code/guardrails are reviewable. No inherited approval, historical dollar estimate or 256-token output cap establishes a total billing ceiling. |
| G7 deployment route review / infrastructure operator and reviewer | Review relevant enabled workflows, secret aliases, old refs, reusable jobs, key consumers and proposed deployment protections; resolve actual administrative unknowns | Read-only authorized state evidence and complete concrete credential/egress route review, or explicit unresolved NO-GO. Do not infer protection from YAML declarations or a source candidate scan. No administrative setting is changed by this audit. |
| G8 genuine independent A/B / experiment reviewer | Freeze treatment/scorer and fresh independent starts; preserve exact tool-return/next-request provenance and legitimate task authority | First no-cost source-neutral rehearsal, then separately authorized genuine model responses in the disposable bank simulator only. Full same-run terminal/scorer evidence is required for Utility; incomplete/first-call capture remains UNSCORED. No real bank endpoint or authority relaxation. |

### Fixed replay is not adaptive live authorization

The eight #486/#509 requests are frozen scripted A/B ordinals 0–3. The exact hash
of a later model query depends on the preceding genuine response and actual Native
tool results. Replacing GuardedMock with a live client will not preserve those
hashes or make the fixed eight-slot issuer a general conversation authority.
Do not disable byte checks or sign arbitrary follow-on messages to make it run.
Use the actual Native-generated next request and a separately reviewed bounded
admission policy, with the original legitimate task/date/target fixed before the
first query. A model-generated date or target never becomes issuer authority.

Two distinct proposals are possible: a bounded first-request A/B capture that
does not claim terminal Utility, or a bounded independent A/B continuation with
declared per-arm attempt limits and complete terminal/scorer requirements. This
audit chooses neither a request count nor a budget. Historical five-per-arm/ten
total planning and prior USD amounts are not a new approval or guarantee.

### Credential and old-route observations

The three historical helpers `send_exactly_once`, `once`, and `one_post` in
`task4_live_first_two_call_capture_oneuse_v1.py`,
`task4_live_second_two_call_capture_oneuse_v1.py`, and
`task4_live_third_two_call_capture_oneuse_v1.py` still have default public HTTPS
connectors and accept a caller-supplied key. Their outer CLIs check approvals and
consumed refs; those checks are not independent enforcement inside the helper.
The first/second/third manual workflows declare separate Environments and pass
`${{ secrets.TASK4_OPENAI_API_KEY }}` to sender steps. That is source evidence of
a credential route, not evidence that any key currently exists or is usable.
The current selected offline workflow instead blanks Provider key variables and
uses private synthetic HMAC credentials. It has no live Provider-key loader.

#507–#510 show bounded denial of tested helpers/routes under local controls. They
do not establish denial for arbitrary code already holding a valid live key on
an independently uncontrolled runner. The old #458 Broker remains synthetic
NO_SEND; its reachability is not a successful real Provider exploit.

The #423 Task1 workflow is source-stopped at preflight and sender, and its standard
send path has no default connection factory. Do not classify it as an active
default HTTPS bypass. Fifteen historical manual workflow disablement candidates
remain an administrative **UNKNOWN**; current enablement, Environment protection,
key availability and Ruleset state were not retrieved here. Refer to the
[historical route review](EXECUTION_AUTHORITY_ROUTE_REVIEW_AND_SEPARATION_V1.md)
and [quarantine audit](optimization/FINAL128_387_LEGACY_MANUAL_PROVIDER_QUARANTINE_V1.md).
Those indexes are not exhaustive deployed credential inventories.

The three historical helpers parse/check received responses before returning raw
evidence to their caller. They do not supply the required new first-ingress archive
merely because they prohibit retries. Post-response usage/cost checks cannot undo
charges already incurred. Provider request IDs and local receipt hashes alone do
not prove absence, billing, cryptographic Provider origin or safe resend.

## Ordered delivery and release record

1. Implement/review G1 + G4 against closed local TLS with synthetic-only
   credentials; specify G2/G3/G5/G6 interfaces before implementation. Keep all
   existing frozen proofs and default-deny behavior. Reuse source-neutral ingress
   where appropriate; do not rewrite historical pins or relabel scripted evidence.
2. Review the concrete deployment and live key/recipient provisioning plan,
   run-bound admission/storage and full A/B experiment scope. Close the applicable
   no-cost negative/fault tests and record G2/G3/G5/G7 attestations for the declared
   research threat model. No independently privileged reviewer is assumed.
3. Only when the above is concrete and reviewable, verify current model/prices
   and spending controls, then request fresh G6 owner consent for the exact commit,
   model, execution ID, maximum requests/tokens/cost and stop/recovery policy.
4. A later authorized execution may produce G8 evidence. No Utility result may be
   asserted in advance; early stops remain UNSCORED. No research pass promotes
   production readiness or authorizes another experiment.

| Release record | Current value |
| --- | --- |
| Reviewed proposed live sender/deployment | NOT SELECTED / NOT IMPLEMENTED IN THIS AUDIT |
| Research manifest / execution ID / budget | NOT ISSUED / NOT APPROVED |
| New real Provider requests / spend authorized | 0 / 0 |
| Key/recipient/egress operational attestation | NOT ATTESTED |
| Independent reviewer / operator acceptance | NOT ASSIGNED |
| Applicable live gates closed | NONE PROMOTED BY THIS DOCUMENT |

Issue [#321](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/321)
(Task4 research) and separate Task1 issue
[#427](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/issues/427)
were read back as open on 2026-10-21 JST. No issue state was changed. Their prior
approvals, keys, tags or experiments are not reusable permission.

Research may use a narrowly declared trusted infrastructure model with verified
guardrails and fresh consent; it need not prove every production property first.
Production still requires independently administered identities/change control,
full deployed credential/effect coverage, declared multi-runner storage semantics,
non-public key lifecycle and independent reproduction. A same-VM root anchor,
local CA or third-party-looking report is not that independent assurance.

This PR changes documentation only. No runtime, workflows, pins, secret or
Environment/Ruleset/tag/admin state, public egress, paid execution or automatic
merge is enabled. The historical
[Native proof checkpoint](TASK4_NATIVE_PROOF_CHECKPOINT_V1.md) remains a #505
snapshot; this document records the later #510 progress and live-research gaps.
