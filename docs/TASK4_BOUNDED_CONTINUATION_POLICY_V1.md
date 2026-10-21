# Bounded continuation policy: synthetic SDK contract rehearsal

## Selected increment after #514

#514 binds a fresh run, raw recipient and expiry into eight fixed Native grant
hashes. A genuine response will change the next Native request hash. This first
increment defines and exercises a bounded signing policy for such changing
request bodies without relaxing the existing frozen proofs.

**This new policy is not wired into Native, Custody, actual Bind, raw TLS or the
bank/scorer.** The original integrated proofs still run unchanged in the same
Actions job. This is a real pinned SDK serialization/parsing rehearsal using
synthetic in-memory responses and tool results, not adaptive Native execution,
genuine inference or Utility. Next work must connect the policy to those actual
boundaries and authenticate their observations under separated identities.

## Trusted contract and exact request admission

Enroll a fixed manifest before the first request. It commits to a #514-shaped
closed-local execution context, run/recipient/endpoint/validity, observer public
key, task identity, historic trusted task date and legitimate target, original
SDK parameters/tools, initial message hash and per-arm limits. The current
synthetic fixture permits three requests per arm, 64,000 bytes per request,
128,000 cumulative request bytes per arm, one tool call per step and the original
256-token output request cap. These are rehearsal choices, not a proposed live
budget or complete billing ceiling. The historic Task4 date 2031-07-08 and model
label are test material, not fresh research scope or current model selection.

For each step, validate the exact fixed SDK parameter hash and the complete
expected message history. No new trusted role, changed task/date/target/tool
schema/model/output cap or fabricated tool history is accepted. Model text
proposing a different date remains lower-trust assistant data; it cannot rewrite
the initial developer/user messages or manifest authority.

Each grant signs the exact current SDK request byte hash and length, arm,
issuer-controlled ordinal, manifest digest, run, raw recipient, endpoint,
validity and prior observer-receipt hash. Different response histories produce
different next request hashes; there is no pre-enumerated future-hash list and
no arbitrary follow-on signing API. A/B have independent history roots and
counters and start from the same original public first-request parameters.

## Observations, consumption and ambiguity

Before the rehearsal returns a synthetic completion to the SDK, a synchronous
FULL SQLite transaction reserves the attempt as CONSUMED_UNKNOWN and marks its
arm PENDING. The grant alone is not a reusable external dispatch capability:
there is no transport consumer or production single-use delivery proof here.

Continuation requires a cryptographically authenticated observer receipt that
joins run/manifest/arm/ordinal/request, exact response bytes and tool-result hash.
The policy checks the assistant/tool-call shape and matches the tool result ID
before appending those exact messages. The fixture's only simulated tool is
`get_balance`; no bank endpoint, tool executor or actual Bind is called. Valid
tool suggestions or a signed history receipt never grant banking effect authority.

The observer origin is explicitly SYNTHETIC_SDK_REHEARSAL_NO_TLS_NO_ARCHIVE_ATTESTATION.
These receipts are not raw archive attestations or Provider-origin evidence.
The issuer and observer keys are distinct but remain in one trusted test
process. They do not demonstrate OS isolation or an independently administered
observer. That interface must later join #514's actual Custody/archive and
authenticated Native tool-return path.

Forged/mismatched observations cannot advance PENDING. A correctly authenticated
but malformed response or mismatched tool history marks the arm UNKNOWN and
prevents any further grant. A complete terminal marks it TERMINAL. No duplicate
observation or exhausted arm can issue another grant. An ordinary late valid
observation may finish a still-pending attempt without resending it; any later
grant still checks the execution clock. No recovery path resets a consumed row.

## Storage and limits of this increment

The retained file must exist, be regular/non-symlink, belong to the process and
be mode 0600. Explicit fresh creation is exclusive, SQLite uses synchronous FULL,
and enrollment pins the manifest and issuer public key. Reopen refuses a changed
run/key, missing/corrupt file or pending/terminal reissue. Report snapshots join
every grant, observed response, receipt, arm head and cumulative byte count.

This proves reopening the **same retained file**, not global run enrollment.
A trusted caller can still create another file/directory; cross-directory,
runner, rollback and distributed reset resistance are explicitly unproved.
Trusted storage placement, private key provisioning, observed-data encryption
and authority service deployment remain later work. No live key loader or
privileged execution endpoint is introduced by this module.

## Required verification

Existing Actions adds 37 unit cases and 12 SDK rehearsal checks, zero skipped
cases required in the dedicated job. The minimal common CI may skip only the
SDK-specific test if its optional SDK dependencies are absent. Dedicated CI
installs OpenAI 1.109.1/httpx 0.28.1 and requires all cases.

Six actual SDK requests/completions run through the explicitly supplied local
transport with a synthetic placeholder credential, max_retries=0 and trust_env=False.
DNS and ordinary socket connection APIs are guarded to fail if used. This is
an in-process no-network rehearsal, not an OS egress proof. Existing OS/TLS
proofs are separate required gates. Reopen must retain six observed attempts,
two terminal arms and exact signed response-parent chains; pending/missing
state cannot reset. Artifacts contain signed public metadata/hashes and JUnit,
not raw bodies, private keys, ciphertext or databases.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
