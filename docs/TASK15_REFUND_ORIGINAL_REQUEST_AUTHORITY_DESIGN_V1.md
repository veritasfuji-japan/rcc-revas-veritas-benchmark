# Task15 refund original-request authority design V1

The single invariant is candidate-independent recipient/amount design without
execution permission: the original bounded user request supplies the refund
amount, and the caller-owned current ledger supplies a uniquely selected
incoming receipt. Candidate arguments, file text, scorer/gold, receipt subject
or a convenient outgoing date cannot create a refund mandate.

`derive_refund_design` requires the complete existing Task15 request grammar,
an explicit declared owned-ledger recipient reference, exact native full state,
finite typed records and unique IDs across both transaction collections. The
scope reference is restricted to the owned account IBAN or the pinned native
benchmark placeholder `me`. The explicit declaration is not authentication of
that mapping. Arbitrary other aliases are rejected.

The draft policy selects one incoming receipt with exactly the requested
positive amount. It must also be the sole latest incoming receipt by canonical
ledger date, have a nonrecurring flag and a bounded uppercase counterparty
reference. Ambiguous amounts/latest dates, later unrelated receipts, self or
outgoing transactions, malformed records and principal/state/request drift are
rejected. This selection is review material: it does not authenticate a friend
relationship, freshness, account ownership or external ledger provenance.

`assess_refund_design` checks the complete RCC CandidateAction V1.1 and all four
actual normalized native send_money fields. Recipient must equal the selected
receipt sender; amount must be the original request's exact normalized float.
Subject/date are checked only as native strings, never marked authorized. No
candidate is normalized or repaired by this pure assessment. A core match is
explicitly a partial component match; every execution/admission/mandate flag
remains False. The unchanged original-request validator still returns
send_money supported_profile=False and date_authority_present=False.

The date of the incoming receipt is not outgoing execution-date authority.
Receipt subject text is not trusted friend identity or outgoing subject
permission. An existing matching outgoing refund does not establish reusable
permission; duplicate-refund exclusion remains unproven. Receipt correlation,
registered context, exact capture, drift/revocation, single-use native Bind/final
sink and composed continuation all remain unresolved requirements.

The proof derives a projection before seeing the candidate, verifies identical
RCC candidate hashes for a forked pair, and retains 11 malformed/mismatched
candidates without repair. Two explicitly unauthorized detached semantic probes
use different arbitrary date/subject strings. The actual native function accepts
both, appends next_id=max(transaction and schedule IDs)+1, uses the account IBAN
as sender and recurring=False, and leaves balance unchanged. These are cloned
native semantic invocations, not governed dispatch, real settlement or an
accounting guarantee. Arbitrary accepted metadata does not become permission.

All 822 prior dedicated tests are reproduced. The new proof blocks provider/SDK,
database/scorer/ground-truth access, native Bind adjudication and external
trustlog effects. Previous post-completion diagnostic scoring belongs to the
frozen prior proof and never feeds this design. No live provider run, V13 reuse,
historical candidate recovery, safe relaxation, Utility recovery, composed
Task15/Final128 execution, held-out/external validation or production claim.

Owned request/current state/acquisition and declared mapping are trusted Python
harness assumptions, not authenticated real-world evidence. Hashes and dataclass
immutability do not authenticate them. There is no issuer, mandate, execution
API or enabled runtime gate in this new design. Existing files remain unchanged.

Next Rule-of-One after manual human merge:
`TASK15_REFUND_EXECUTION_METADATA_AUTHORITY_DESIGN_V1`.
