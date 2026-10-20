# Execution-authority route review and independent separation plan

Reviewed baseline: `cfcbb8bf06a165151d0797db2f8f3b0ca7964857` (merged #489).
Disposition: SOURCE REVIEW / NON-DEPLOYED DESIGN / REAL_PROVIDER_NO_GO /
UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN.

## Findings that determine the next implementation

1. Historical #458 custody is synthetic and NO_SEND. Its callable raw operations
   are not evidence of a successful real OpenAI dispatch. #487's selected runner
   uses protected custody while retaining historical helper imports and pins.
2. There are also distinct, real-network-capable historical Task4 helpers:
   `send_exactly_once` in `scripts/task4_live_first_two_call_capture_oneuse_v1.py`
   (127–144), `once` in `scripts/task4_live_second_two_call_capture_oneuse_v1.py`
   (163–178), and `one_post` in `scripts/task4_live_third_two_call_capture_oneuse_v1.py`
   (224–241). Each checks fixed request identity/size and uses a caller-supplied
   key; its default transport constructs HTTPSConnection to api.openai.com.
   Approval/consumed-ref environment checks are in the outer CLI, not these
   helper functions. A process already holding a valid key, matching fixed
   payload and required arguments is therefore a separate source-level route
   to review. No key availability, live invocation, accepted request, billing,
   current workflow enablement or successful exploit was tested here.
3. #423 is different: preflight is literal-false gated, issuer depends on that
   preflight, and sender is literal false. Its standard CLI `send` refuses before
   payload reconstruction/secret reads unless a connection factory is injected;
   `one_post` itself also requires an injected factory. There is no default real
   HTTPS connector there. Injected factories are not an enrolled external identity;
   an attacker already holding credentials and arbitrary code remains outside
   this local guard. Do not report the stopped CLI as an active default sender.
4. Real OS/network controls already exist in bounded mock harnesses (#278/#281,
   #370, #412). The remaining production gap is their integration with actual
   secret custody, independently administered identities, endpoints and change
   control. It would be inaccurate to say there is no OS-level isolation code.

## Scan coverage and reproducibility

At the baseline, `git archive` contains 1,780 regular files. The new source-only
inventory scans 1,194 UTF-8 sources: 495 non-test Python, 280 test Python, 409
workflow YAML, and 10 SQL/Docker/other selected sources. Six broad pattern classes
produce 1,111 candidate files. These are review candidates, NOT 1,111 senders or
exploits. No selected non-UTF-8 source was encountered at this baseline.

The inventory emits path, source SHA256, category and line numbers, never source
line contents or credential values. It does not import targets, read environment
values or contact any endpoint. The #489 every-PR offline workflow stores a fresh
inventory for its exact checkout commit beside the selected Native evidence.
Checkout may be GitHub's synthetic merge commit; use `audited_commit`, not an
assumed PR HEAD, when interpreting file hashes/lines.

```sh
python -m scripts.execution_authority_route_inventory_v1 --ref cfcbb8bf06a165151d0797db2f8f3b0ca7964857
python -m pytest -q -o addopts= tests/test_execution_authority_route_inventory_v1.py
```

Patterns cover Provider clients/endpoints, general network clients, credential
and environment references, tool/Bind effects, DB/consumption, and subprocess/
control-plane routes. Comments, mocks and dead code match too. Obfuscated or
aliased code, dynamic imports, generated programs, arbitrary file suffixes, JSON
contracts and code in externally pinned repositories are not exhaustively
resolved. This review reads relevant contracts/documentation separately; the
automated scan is not a complete call graph or credential-consumer proof.

## Manually reviewed route families

Paths below are relative to the baseline commit; associated candidate artifact
provides exact source hashes and line locations. A family row is not an assertion
that every variant or caller has been dynamically verified.

| Route | Source evidence | Credential/effect boundary and disposition |
|---|---|---|
| Historical Task4 first capture | `scripts/task4_live_first_two_call_capture_oneuse_v1.py:127–144,198–219`; `.github/workflows/task4-real-first-two-call-capture-v1.yml` | Direct default HTTPS helper, passed key; outer CLI checks approval/ref; workflow declares protected Environment, actual protection unknown |
| Historical Task4 second capture | `scripts/task4_live_second_two_call_capture_oneuse_v1.py:163–178,232–242`; `.github/workflows/task4-second-two-real-provider-v1.yml` | Same separation of lower HTTPS helper and CLI checks; actual key/approval/consumed-ref state unverified |
| Historical Task4 third capture | `scripts/task4_live_third_two_call_capture_oneuse_v1.py:224–241,288–306`; `.github/workflows/task4-third-two-real-provider-v1.yml` | Same lower-helper risk conditional on key + exact payload; no new consent inferred |
| Canonical Native SDK runner | `scripts/agentdojo_clean_ab_canonical_final_runner_v2_8.py:259–300,819,981–997` and historical runner variants | Reads OPENAI_API_KEY and builds normal SDK; budget wrapper reserves/commits usage; local wrappers are not independent IAM/egress enforcement |
| V13 two-phase wrapper | `scripts/final_128_real_provider_wrapper_v11.py:181–255,269–300`; `.github/workflows/final-128-v13-manual-dispatch-template.yml:75–89` | PostgreSQL consume/readback then subprocess runner; phase 2 receives both DB URL and Provider key in one job; grant rights and secret isolation unverified |
| Historical manual workflows | `scripts/final128_387_legacy_manual_provider_quarantine_audit_v1.py`; see exact list below | Known-name detector finds 15 without source-level static stop and 3 declaring protected Environments; enablement and secret validity unknown |
| Task1 stopped sender/issuer | `scripts/final128_423_task1_protected_first_native_chat_sender_v1.py:170–203,328–338`; `.github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml:24–25,110–125,183–185` | TASK1 key/capture key aliases; stopped preflight prevents dependent issuer; sender false; default connector removed; injected test interface remains |
| Task15 old direct helper | `task15_one_shot_openai_model_capture_gate_v1.py:156–173` | DirectOpenAIHTTPSOnce constructor/send permanently deny; arbitrary replacement client with a stolen key is a different route |
| Task4 staging | `scripts/task4_455_research_native_sender_hard_nogo_v1.py`; `scripts/task4_463_research_sender_broker_hard_nogo_v1.py` | Offline deny transports and local custody; no live forwarding; not a future production sender merely because named sender |
| Legacy local Broker | `scripts/task4_458_local_broker_once_ciphertext_v1.py`; #471 start/restart; #479 negative fixture | Raw AF_UNIX/SQLite operations remain; synthetic NO_SEND; preserve frozen historical sources pending migration/change review |
| Selected Native #483–#487 | `scripts/task4_native_frozen_recipient_v1.py` through scope/signer/protected custody modules | Eight frozen requests, child-only issuer key, publicly reproducible recipient; same-UID code/DB changes and production egress not independently excluded |
| Tool runtime and Bind | `task4_trusted_execution_date_runner_integration_v1.py:209,249,370`; `task15_refund_profile_controlled_runner_v1.py:269,306,445`; `scripts/agentdojo_final_runner_integration_v0_1.py` | Native runtime mutation and Bind hooks; reviewed environments are benchmark state, not evidence of real bank integration; an actual backend must independently reject alternate clients |
| Durable DB and SQL | `scripts/canonical_dispatch_atomic_consumption_v1.py:20–45`; `sql/task4_310_offline_postgres_consume_v1.sql`; `sql/task4_311_committed_receipt_handoff_ci_v1.sql` | DB writes/consume and grants are effects too; possession of DB/admin credentials and reset/reissue rights must be independently constrained |
| GitHub readback | `scripts/final128_354_task1_live_ruleset_fetch_v1.py`; `scripts/final128_390_environment_approval_readback_v1.py`; `scripts/final128_393_task1_tag_denial_evidence_readback_v1.py` | GET/readback routes, not Provider sends; may use GitHub credentials; no execution authority follows from a readback |
| GitHub write probe/issuer | `scripts/final128_357_task1_isolated_tag_negative_probe_v1.py:26–86`; stopped #423 issuer job | #357 can POST/PATCH/DELETE an isolated run-bound tag after explicit consent; issuer can create consumed ref when enabled; do not run during this audit |
| Process and deployment controls | `run_joint_benchmark.py`; Docker audit scripts; #412 supervisor/workflow | subprocess and Docker/root/NET_ADMIN are privileged control paths, not necessarily Provider sends; build-time network and runtime authority need different identities |
| Reference architecture | `scripts/task4_protected_issuer_credential_egress_architecture_v1.py`; `contracts/TASK4_PROTECTED_ISSUER_CREDENTIAL_EGRESS_ARCHITECTURE_V1.json` | #312 already models separate issuer/sender/ledger/vault/egress; model-checking a declared graph is not deployment attestation |

## Workflow and credential administration remains unknown

Re-running #387's source auditor on all 409 workflow files yields 18 matches for
its three known Provider Secret names: 15 administrative-disable candidates,
plus the three Task4 protected-Environment declarations above. This detector
does not exhaust aliases such as TASK1_OPENAI_API_KEY, inherited/reusable workflow
secrets, dynamic secret indexing, external OIDC grants or repository/organization
credential consumers. The new broad source index includes such references as
candidates; no actual secret values, existence or scopes were retrieved.

The 15 historical candidates are:

```text
agentdojo-clean-ab-canonical-final-v1.yml
agentdojo-clean-ab-final-v0_1.yml
agentdojo-task12-development-validation-v1.yml
agentdojo-task13-development-validation-v1.yml
agentdojo-task15-development-validation-v1.yml
agentdojo-task2-development-validation-v1.yml
final-128-v10-manual-dispatch.yml
final-128-v11-manual-dispatch-template.yml
final-128-v12-manual-dispatch-template.yml
final-128-v13-manual-dispatch-template.yml
final-128-v4-single-use-manual-dispatch.yml
final-128-v5-manual-dispatch.yml
final-128-v7-manual-dispatch-v2.yml
final-128-v7-manual-dispatch.yml
final-128-v8-manual-dispatch.yml
```

A read-only attempt to fetch the V13 workflow administration resource through
the connected GitHub fetch API was rejected as an unsupported endpoint on
2026-10-20 JST. This is an access limitation, not evidence of disabled state.
No administration setting was changed. An authorized admin must separately
attest current workflow states, historical-ref execution, reusable workflows,
secret consumers, OIDC trust, repository write tokens and independent billing
controls. Preserve frozen historical sources; do not silently rewrite their pins.

## Independent boundary: deployment specification building on #312

Threat model: an attacker controls agent code, ordinary PR code or a same-UID
process inside the agent sandbox. The attacker can invoke any retained helper,
use another HTTP client, spawn children and submit arbitrary requests. The
attacker must not hold host root, Docker control, sender identity, policy-admin
rights or independent approver rights. Privileged administrators remain an
explicit trust/attack surface requiring separate change control and audit.

| Component / proposed operator role (unassigned) | Required authority | Forbidden authority / required independent boundary |
|---|---|---|
| Agent and ordinary CI / application operator | Submit untrusted candidate and view redacted receipts | No Provider/backend keys, DB mutation, issuer identity, Docker socket, host mounts, credential-service access or direct effect egress |
| Issuer / independent approval operator | Issue narrowly scoped signed grants after fresh approval | No Provider key or Provider/backend send capability; reviewer/admin independence must be attested, not inferred from a second process |
| Shared ledger / storage operator | Atomically consume scoped attempt, expose committed receipt | Sender cannot mint/reset grants; issuer cannot erase consumption; admin recovery/reissue requires separately audited policy |
| Executor gateway / execution operator | Verify workload identity and exact reviewed request; verify grant and consume receipt; perform one approved action | No grant issuance, arbitrary endpoint/payload forwarding, caller-selected transport, credential export, dynamic code mount or bypass of backend authentication |
| Vault and network policy / infrastructure operator | Release scoped short-lived credentials only to enrolled executor; enforce destination/method/protocol and workload policy | Agent/PR cannot read vault or modify egress; endpoint allowlisting alone is insufficient if an untrusted agent can reach that endpoint with a key |
| Effect backend and evidence / backend operator + reviewer | Authenticate executor, enforce operation identity/idempotency where supported, persist authoritative outcome/receipts | No unsigned/direct mutation fallback; independent audit must reconcile attempted requests with backend-observed effects, including denied probes |

Proposed flow: agent submits exact bytes -> independently approved grant ->
executor verifies canonical request digest, recipient/key version, target,
operation, subject, expiry/revocation, execution ID and prestate -> ledger
commits unique consumption -> executor obtains scoped credential and sends ->
backend records authoritative effect -> evidence reconciliation. These are
proposed deployment requirements, not newly implemented or observed behavior.

One protected executor may contain both pre-send verification and network I/O,
provided its identity/code is protected from the agent and no arbitrary forwarding
API exists. A process split alone supplies no independent authority. On ambiguous
send/ACK, retain CONSUMED_UNKNOWN and require reconciliation; do not auto-retry or
issue a new grant. If the real backend has no durable idempotency/receipt API,
document that limitation and deny an exactly-once-effect claim.

The #487 public recipient must be replaced, never promoted: independently
provision a non-public recipient, authenticate enrollment/version, isolate owner
recovery, define rotation/revocation and validate AEAD on owner recovery. Do not
put plaintext/private keys in CI artifacts. Reuse the existing fixture only for
the explicit synthetic offline tests.

## Falsifiable acceptance conditions for a future implementation

| ID | Required attempt / evidence | Pass condition |
|---|---|---|
| A1 identity and credential denial | Agent same-UID arbitrary Python, direct historical helper, alternate HTTP library, subprocess and credential-service probes using synthetic credentials first | OS/service denies private key/token/ledger access; denied service requests and policy snapshot corroborate agent logs |
| A2 egress closure | IPv4/IPv6, DNS/IP, redirects, proxies, alternate ports, direct backend and retained SDK/helper routes | Only enrolled executor can reach authenticated effect service; agent cannot widen routes or assume that identity; controls enforced outside application patches |
| A3 protected verification | Unsigned/wrong issuer, modified bytes, wrong target/recipient/prestate, stale/revoked grant, extra fields, caller-selected transport | Reject before credential release/consumption where appropriate; no unauthorized backend effect or unbound arbitrary forwarding |
| A4 durable uncertainty | Concurrent attempts on two independent runners, process crashes before/after CAS/send, lost ACK, restart and replay | One durable admission; consumed/unknown cannot be reset/reissued by sender; no repeated send; authoritative outcome reconciliation, no exactly-once inference from SQLite alone |
| A5 backend and Bind | Signed admitted operation through real pinned Bind path and authenticated disposable external sink; negative direct/replay attempts | Backend-owned receipt/poststate shows one scoped positive effect and zero unauthorized effects; issuer signature, Bind and transport are integrated in the same run |
| A6 change/administration | Agent/PR attempt to mutate reviewed image, workflow, egress, vault policy, trust root, old refs, token scopes or ledger admin path | Independent administration rejects; exact image/policy/workload IDs and backend logs available to reviewer; privileged breakglass explicitly audited |
| A7 independent reproduction | Reviewer reruns frozen positive/negative bundle with their own disposable infrastructure | Source/image/policy identifiers, request/receipt hashes and denied probes match; reviewer conclusions remain scoped to tested deployment |

Existing #278/#281/#370/#412 give bounded building blocks for A1/A2/A5. Their
documents describe real Docker/UID/netns/mTLS tests with trusted host/root and
synthetic sinks. #412 explicitly says signed issuer regressions are separate
from its mTLS backend fixture; do not combine separate green checks into a
single integrated authority proof. This PR does not rerun those historical
Docker/root suites or claim their prior artifacts independently reverified.

Next implementation should select **A1+A2 for one disposable external mock
executor**, pin a concrete deployment and independent administrator, and reuse
the historical direct-helper shapes as denied attempts without real credentials.
No host/account/provider/platform has been selected or provisioned here; that
choice and necessary external access are prerequisites, not implied authority.
Until then, the current repo-wide scan and selected Native CI remain research
evidence only. A paid real-model research experiment has its own fresh scoped
consent gate; production assurance and research-only consent are distinct.

## Validation boundary

New scanner tests verify classification, nonexecution, source-hash/line output,
no source/credential-value disclosure and explicit scan exclusions. Every-PR
CI also retains #487's mandatory 13-case no-skip Native test gate and standalone
no-send report assertions. Actual PR HEAD/Run/Job/Artifact verification belongs
in the PR description. This document itself grants zero Provider calls, spending,
bank effects, setting changes, new credentials or merge authority.
