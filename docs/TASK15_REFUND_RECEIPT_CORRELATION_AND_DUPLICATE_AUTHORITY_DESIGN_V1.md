# Task15 refund receipt correlation and duplicate authority design V1

The invariant is candidate-independent, stable receipt identity without inferred
consumption permission. The draft correlation key hashes the pinned native
ledger namespace, owned account reference and typed incoming receipt ID. It
excludes request wording, case, proposal ordinal, candidate arguments, balance,
files, receipt amount/subject and other mutable state. Material receipt changes
cannot reset the key; an old slot fingerprint is rejected. External namespace,
account/receipt identity and non-recycling of native IDs remain unproven.

The exact slot draft must bind the receipt fingerprint/key/account/namespace,
have DRAFT_UNAUTHENTICATED status and declare AVAILABLE. RESERVED, CONSUMED,
UNKNOWN, invalid state, scope substitution and extra self-attestation fields are
refused. AVAILABLE is an unverified declaration, never atomic reservation,
consumption, authenticated absence of a prior refund or execution authority.

The complete #228 refund and #229 metadata projections are rederived first.
Any own transaction or scheduled transaction to the receipt sender with exactly
the original requested amount is conservatively unresolved and refused,
regardless of date, subject or recurrence. This check intentionally observes
only exact full-amount records: other amounts do not authenticate absence of
partial, grouped, unrecorded, backdated or external refunds. The default native
ledger contains a prior 200-unit New year gift to that sender. It is not classified
as a proven refund, nor treated as proof of no refund. No historical labels are
used to select or repair candidates.

Native Transaction has only id/sender/recipient/amount/subject/date/recurring;
send_money accepts recipient/amount/subject/date and carries no original receipt
ID or correlation key. A missing field cannot be reconstructed as authenticated
correlation from a memo. The stable key is a proposed auxiliary authority-store
identity, not a change to native tool schemas. No existing file is modified.

Assessment keeps the unchanged complete RCC/native candidate and exact metadata
review. Even a matching candidate and AVAILABLE slot have execution/admission,
duplicate exclusion, slot authenticity, ledger completeness, ID non-recycling,
reservation and consumption all False. Repeated pure review is repeatable and
cannot establish single-use. No storage, registry issuer, mutation, dispatch,
provider, scoring or consumption API is introduced.

42 new tests cover same-candidate fork, candidate-independent key stability,
changed fingerprints, unavailable/unknown slots, ledger transactions/schedules,
other amounts without an exclusion claim, malformed/self-attested scope, four
unrepaired candidate refusals and the actual native schema. All 941 prior
provider-free dedicated tests and detached native probes are reproduced. The
new proof uses the frozen no-provider/scorer/database/native Bind/external effect
guard. Prior completed diagnostic scoring never feeds this design.

Trusted Python harness acquisitions are explicit assumptions, not external
identity evidence. No V13 reuse, safe relaxation, historical recovery, real-model
Utility recovery, injection remeasurement, composed Task15/Final128, independent
external/held-out validation or production claim. Durable atomic receipt
reservation/consumption, UNKNOWN reconciliation, revocation/drift and native RCC
Bind/final sink integration remain future requirements.

Next Rule-of-One after manual merge:
`TASK15_REFUND_REQUEST_PROFILE_ISSUANCE_V1`.
