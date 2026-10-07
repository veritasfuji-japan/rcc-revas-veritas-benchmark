# Task6 first-due-date policy design V1

The exact Task6 request authorizes the specified recipient, recurring intent,
the request's subscription purpose, and a unique trusted Spotify-derived amount.
It contains no first due date, timezone, cadence, or delegated date-selection
rule. Native `schedule_transaction.date` means the next date of the transaction
and is persisted in a scheduled record. Native acceptance of any string does
not supply authority. The Task4 immediate-refund clock profile cannot supply
this missing scheduling instruction.

## Proposed bounded policy

`task6-explicit-first-due-date.v1` requires an independently authenticated,
request-scoped scheduling mandate that **explicitly names the first due date**.
The proposed date rule is `EXPLICIT_MANDATE_DATE`; there is no implicit current
date, next month, historical merchant date, or model-selected default. UTC is
the sole supported calendar basis in this V1 proposal. Another timezone or a
delegated default rule needs its own authority analysis and reviewed version.

This PR reviews a design only. Policy review/merge, a valid draft, a reference
string, an issuer name, HMAC local issuance, or `approved: true` cannot create
the mandate. There is no active policy, configured mandate issuer, signing key,
effective due date, context issuer, or dispatch path in this change.

| Decision | Proposed requirement | Current status |
| --- | --- | --- |
| Date source | Explicit first due date in an independently authenticated principal's scheduling mandate | No mandate in original request |
| Calendar and format | Gregorian UTC date, exact `YYYY-MM-DD`, real calendar date | Review syntax only |
| Scope | Pinned banking Task6, native tool, exact request digest, case, proposal ordinal, immediate pre-state | Draft scope linted |
| Recurrence | Preserve explicit `recurring=true` intent in one native record | No cadence or recurrence executor authorized |
| Validity | UTC `[not_before, expires_at)`, at most 300 seconds, no backdated first due date | Proposed bound, fixture checks only |
| Rollover | Reject if issuance/verification crosses UTC day; no date rewrite or retry in consumed slot | Future owned-clock/session requirement |
| Activation | Separate reviewed policy registry and independently authenticated grant, bound before generation | Not implemented |
| Effect | One pinned native scheduled-record append, no immediate payment | No effect dispatched by this PR |

The 300-second limit is a conservative proposed context lifetime, not evidence
of an existing enterprise policy. The first due date may be today or a future
date **only if the independent mandate explicitly selects it**. The supplied
UTC fixture only tests draft consistency. It does not choose the due date or
authenticate the clock.

## Future authority and context boundary

Before any future date admission, all of these must be established:

1. A separately configured verifier authenticates the principal, mandate issuer,
   mandate identity/version, exact selected date and policy version. Grant
   acquisition and the trust/approval registry stay outside model/tool access.
   A reference or harness HMAC cannot substitute for real grant authentication.
2. A prospective context binds mandate digest, policy digest/version, source and
   session IDs, original-request digest, Task6 case/proposal, native source pin,
   immediate pre-state SHA-256, UTC calendar/date, issuance and expiry. Acquire
   it before the first candidate query; no candidate, gold, scorer, replay row,
   history date or tool prose can fill an authority field.
3. An owned clock and monotonic registry check expiry, rollback, day rollover,
   policy/mandate revocation and current registration before capture and at the
   actual sink. Reissuance cannot silently repair a rejected first proposal.
4. Capture one complete Pydantic-normalized RCC candidate once. Candidate date
   must equal the independently authorized date; recipient, amount, purpose and
   recurring intent must still satisfy the request profile. Never rewrite the
   candidate to the mandate, scorer target or a rollover date.
5. Preserve the same candidate/pre-state and V1.1 pairing identity for A/B.
   Bind the request and date contexts to that identity and exact full candidate
   hash. Keep RCC and native Bind checks. Use one sink attempt per arm with
   independent cloned state and final current authority/state checks; reject
   further effects and retries. Read-only verification is not consumption.
6. Prove the pinned native append only. A live banking standing order would
   need an independently specified cadence, payment limits, cancellation,
   recurrence executor and product authorization. This design does not prove
   those features.

The reference linter does not implement these six requirements. Its output
always has `effective_first_due_date=null`, `mandate_authenticated=false`,
`policy_activated=false`, `date_authority_present=false`,
`full_action_admissible=false` and `execution_permit=false`, even when every
draft field is structurally valid. No output is connected to the frozen
resolver, native Bind, replay harness or Final128 runner.

## Corpus and next work

All eight historical Task6 candidates remain unresolved; seven purpose labels
lexically match the request and one does not. Candidate dates cannot be used
to issue a retrospective mandate. No safe relaxation is established.

Adding a new explicit mandate adds authority to the workload. A prospective
mandate-assisted development experiment must be declared separately and
cannot be reported as recovery on the unchanged V13 corpus. Review/merge of
this design neither approves a date for that corpus nor upgrades development
evidence to held-out or production validation.

The immediate optimization path therefore proceeds to
`CONTROLLED_CANDIDATE_BINDING_MISMATCH_CAUSE_DECOMPOSITION_V1`, the 22 binding
mismatches already isolated in #205. Task6 date admission remains blocked
unless separate independent authority and context proof becomes available.
