# Task15 refund request profile issuance V1

The invariant is prospective local evidence registration before one candidate
capture. The trusted Python harness owns request/ledger/principal acquisition,
the declared AVAILABLE slot, draft metadata policy, injected review clock,
signing key, session registry and scripted generator adapter. Native/scorer/tool
outputs and candidates cannot supply the profile definition or issuance inputs.

The issuer rederives all frozen #228/#229/#230 component designs and the exact
native send_money definition. It registers and HMAC signs the full scope before
calling the scripted generator once. Only refund proof ordinal two is supported;
this does not prove earlier address/rent effects or a composed Task15 trajectory.
The callback returns an already normalized complete RCC/native candidate. Actual
native normalization/schema/hash are verified in proof; raw-wire and real model
ordering remain future integration requirements.

A local RLock protects both case/ordinal issuance and a stable receipt-key index.
The same incoming receipt cannot be issued twice in that session under changed
case/request/state/receipt-fingerprint scope. This claims a profile registration
slot, not a payment reservation. The caller's declared slot is never mutated.
A new session can issue again; no durable/global duplicate-refund exclusion is
claimed. No payment mandate, native admission or dispatch API exists here.

Authentication requires the exact context type/canonical JSON, session MAC,
source/session identity and owned issuance-registry linkage. First authenticated
capture marks the local capture attempt before scope/candidate checks. Invalid
candidate, request/state/policy/slot drift, clock failure or expiry closes that
attempt; no repair or automatic retry is available. An unauthenticated foreign
context cannot close the legitimate context's slot. Generator exception,
cancellation or any post-issuance capture failure seals the registered attempt.

The owned review-clock fixture is checked at issuance, capture and read-only
verification against the unchanged short same-day draft window. No system clock
or external clock evidence is authenticated. The proof does not establish
monotonic time, revocation or an external issuer. Canonical full candidate and
pairing identities match RCC CandidateAction V1.1, and binding verification
requires the exact locally captured binding with unchanged scope/candidate.
Repeated paired verification is read-only and consumes no execution permission.

75 new tests cover scripted issue/generate/capture order, exact native schema and
same-candidate fork; ten independently reproduced terminal invalid candidates;
authentication/binding substitutions, scope/material drift, duplicate capture,
generator and clock exceptions, expiry, and four 32-way contention populations
(issuance, capture, generation and different-case receipt issuance), each with
one winner/31 refusals and zero native dispatch. All 983 prior dedicated tests
and frozen native/scorer evidence are reproduced. The new proof blocks provider,
SDK, database, scorer/gold, native Bind adjudication and external trustlog effects.

HMAC proves only local issuance with an owned key. Exported original MACs are
not independently authenticated by the artifact auditor; fresh local reissuance
checks scope, program order and stable linkage. All original/principal/friend,
clock/policy/slot/completeness/receipt-ID authenticity, date/subject authority,
reservation/consumption, duplicate exclusion and execution/admission flags remain
False. No V13 reuse, safe relaxation, historical recovery, Utility/injection
remeasurement, full Task15/Final128, held-out/external or production claim.

Next Rule-of-One after manual human merge:
`TASK15_REFUND_PROFILE_CONTROLLED_RUNNER_V1`.
