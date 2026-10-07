# Task15 standing-order original-request authority design V1

This is an offline design assessment for the next Task15 goal. It adds no
context issuer, execution grant, Bind override, runner integration, repair,
refund/date/password authority, or later trajectory effects. Every design
observation leaves execution_permission, runtime_admission_activated and
full_action_admissible false. A matching candidate is review evidence only.

## Central invariant

Only the independently owned complete original Task15 request supplies the new
landlord account and rent amount. Only the independently owned current native
state supplies the target existing rent record. The normalized candidate must
bind that exact ID, recipient and amount, preserving subject, next date and
recurring status via null defaults or exact current values. Tool output prose,
model candidates and scorer/ground-truth results never supply authority.

The complete existing bounded Task15 request grammar is reused. Recipient is
matched exactly with no case conversion or account aliasing. Rent must be
positive and round-trip from the explicit decimal text to the native float
representation. This is the pinned benchmark's numeric model, not proof of
currency mandate, beneficiary authenticity or production monetary accuracy.

The owned snapshot must have the exact native environment/bank/user/filesystem
shape and finite, typed records. This conservative V1 supports bounded ASCII
record strings, canonical calendar dates, positive transaction amounts, and at
most 10,000 records per ledger. IDs are nonnegative integers, never booleans or
floats. The target has exactly Rent/rent/RENT as its subject, with one matching
record and no duplicate scheduled IDs. Its sender must equal the owned account.
More general rent classification or ambiguous schedules require separate proof.

The rent label is a selection rule over an assumed independently owned ledger,
not an authenticity verifier. The application must establish account ownership,
ledger provenance and rent classification before activating a runtime profile.
A copied JSON snapshot, label, source blob, hash or design projection cannot
establish those facts or become an authenticated payment mandate.

## Native semantics and protected optional fields

Pinned update_scheduled_transaction selects the first matching scheduled ID.
Duplicate IDs can therefore redirect an update even if only one record is marked
Rent. V1 refuses every duplicate scheduled ID rather than selecting by scorer ID,
array position, first/last match or model proposal.

Native recipient/amount/subject/date/recurring assignments are truthy-only. Date
and recurring are material schedule fields, not harmless execution metadata.
The default Rent record has recurring=false. Passing true changes it, and is
refused. Passing false when the current flag is true is natively inert, but also
refused as an unrequested divergent argument. Empty optional text differs from
current state and is refused even where native code treats it as inert. Native
truthiness must not broaden inferred authority. The original validator's checks
are recorded for comparison and remain unchanged.

The caller must supply the complete Pydantic-normalized six-field argument
object in the full five-field RCC CandidateAction. The design never normalizes
or repairs a proposal. Native schema normalization and V1.1 candidate/prestate
hash identity are independently checked in the dedicated proof. Future capture
must also reject unknown raw arguments before normalization, as the address
runner already does; ignored extra arguments cannot disappear into a grant.

## Proof and boundary

73 tests cover the candidate-independent projection; all null/current combinations
of optional fields; malformed/substituted candidates, request and prestate;
ambiguous rent and duplicate IDs; sender mismatch; strict scalar types; unknown
fields; altered date/recurring/subject; and exact same-candidate/prestate identity.
Untrusted file instructions target another schedule and never alter selection.

Two detached native probes execute the unmodified tool on cloned environments.
They establish that false preserves the default flag while true changes it,
with only the selected recipient/amount and requested native flag changing.
The original snapshot stays unchanged. These semantic probes are not governed
Arm A/B runs, profile issuance or activation of the live execution sink.

The previous 28 observer / 32 wire / 40 trajectory / 65 runner / 101 profile /
91 mapping tests and deterministic reports are reproduced. Earlier native scorer
observations remain downstream diagnostic evidence; they are never fed into
this design. New design tests forbid scorer, ground_truth, provider/SDK/network,
database, native Bind adjudication and external evidence writes.

Unresolved activation requirements include authenticated acquisition/principal
and ledger classification, prospective registered issuance before generation,
complete candidate/prestate control binding, final native sink checks, RCC/Bind
Authority/Constraint/Risk integration, per-arm single use/revocation/failure
ownership, and multi-goal continuation with separate refund authority.
Historical recoveries=0; safe-to-relax existing runner now=0. No utility recovery,
injection-success remeasurement, held-out/external validation or production
readiness is claimed. V13 stays consumed and closed.

Next Rule-of-One: TASK15_STANDING_ORDER_REQUEST_PROFILE_ISSUANCE_V1.
Only after this design is frozen should prospective issuance and immutable
capture be proved; issuance itself must still grant no native dispatch permission.
