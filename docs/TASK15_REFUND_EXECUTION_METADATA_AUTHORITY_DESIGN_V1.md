# Task15 refund execution metadata authority design V1

The invariant is prospective, candidate-independent metadata review with no
permission escalation. The draft proposes the UTC calendar day of a caller-owned
review fixture and the fixed task-role literal `Refund`. It never selects a date
or subject from the candidate, receipt text, filesystem, scorer or gold.

The new pure module first rederives the complete frozen #228 refund projection.
An exact policy draft binds that projection digest, a bounded unverified review
reference and a positive validity window of at most 300 seconds. Review requires
second-precision UTC, start inclusive/end exclusive and no UTC day rollover.
An incoming receipt dated after the review day is refused. This is a relative
calendar check, not authenticated recency or freshness. No system clock is read.

The subject is a versioned draft policy literal naming the requested task role.
It is not proof of friendship, settlement, harmless content or user approval of
a payment memo. The outgoing date is a draft clock-policy value, not the incoming
receipt date or a utility target. Policy activation, issuer authentication,
authenticated clock and original request/ledger/principal acquisition remain
unresolved. Reference syntax, hashes and dataclass immutability authenticate none
of them. Start/end and policy constants cannot be expanded by a candidate.

Assessment rederives the projection at an explicitly supplied review time and
checks the unchanged full RCC/native candidate, receipt-bound recipient,
request-bound amount and exact proposed date/subject. It never repairs candidate
arguments. A metadata design match is only a partial review result. Effective
date/subject are None and all date/subject authority, execution/admission,
principal/friend authentication, duplicate exclusion and mandate flags are False.
The unchanged original-request send_money validator still rejects the tool.

The native function persists date and subject in a new transaction and leaves
balance unchanged. Two detached cloned-environment probes reproduce those exact
semantics: one design match and one arbitrary metadata mismatch. Both are
explicitly unauthorized. They prove neither metadata is inert in the record nor
that downstream tools, external banks or production treat it as harmless. They
are not a same-candidate treatment comparison, governed dispatch or settlement.

56 new tests retain 13 mismatched candidates without repair, reject malformed
policy/window/time, rollover, future receipt dates and scope/policy drift; all
885 prior dedicated tests are reproduced. The provider/scorer/database/native
Bind/external effect guard from the frozen pure design proof remains active.
Earlier native scoring remains downstream diagnostic evidence only. No provider
execution, V13 reuse, historical recovery, safe relaxation, full Task15/Final128,
Utility recovery, injection remeasurement, held-out/external or production claim.

There is no issuer, credential, mandate, runtime gate or execution API. Review is
stateless and repeatable, not a consumption proof. Receipt/refund correlation,
duplicate single-use, revocation, prospective registration before capture,
native RCC Bind/final sink and composed partial-effect continuation still need
proof. The next Rule-of-One is
`TASK15_REFUND_RECEIPT_CORRELATION_AND_DUPLICATE_AUTHORITY_DESIGN_V1`.
