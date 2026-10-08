# Task15 refund profile controlled runner V1

Rule-of-One: a locally issued refund evidence profile must not turn the frozen
original-request authority refusals into execution permission. The provider-free
runner connects the exact native send_money definition, RCC hook, prospective
profile, actual VERITAS Bind and a final guarded native sink. Existing files,
Final128 and native sources are unchanged.

## Exact proof population

One script captures a candidate after profile issuance, normalizes only through
the pinned native schema, then forks one identical candidate and full pre-state.
The proof uses the existing bounded refund fixture at ordinal two. It does not
prove earlier address/rent steps, a live model proposal, or complete Task15.

| Population | Pairs | RCC-only A | RCC + profile + Bind B |
| --- | ---: | --- | --- |
| Matches local profile | 1 | One native append | Actual Bind constraint refusal; zero append |
| Native-valid profile mismatch | 8 | One native append per pair | Profile refusal; zero append |

A is the diagnostic RCC-only baseline on cloned native environments. Its append
is a simulated transaction, not a bank settlement. The frozen native function
persists recipient/amount/date/subject, appends the next typed ID and does not
change balance. B retains every original-request predicate:

| Legacy predicate for the profile-matching fixture | Value |
| --- | --- |
| supported_profile | False |
| request_authority_bound | True |
| refund_amount_bound | True |
| date_authority_present | False |

Additional strict registered-profile/candidate checks can be True while the
separate execution-authority check remains False. No legacy predicate is replaced
or ORed with a local HMAC/design match. The benchmark authority fixture is an
owned harness signal, not external principal/mandate authentication. The actual
Bind constraint gate blocks the valid-profile candidate.

## Lifecycle and sink

Issuance and receipt-key registration precede one detached scripted callback.
Malformed raw candidates, generator exceptions/cancellation and state drift close
the capture attempt without repair/retry. Native-valid mismatches remain in the
common A/B population. A terminal latch under an owned lock permits one attempt
per arm. Thirty-two parallel attempts yield one A append and 31 refusals; for B,
one blocked attempt and 31 replay refusals, with zero append.

The final sink requires the exact captured candidate, state, request, session,
policy/slot draft, native code/schema, own-thread one-use Bind capability and
fresh live gates. It independently recomputes the frozen legacy constraints and
the absent execution-authority predicate. Explicit negative tests force upstream
native constraints to pass to exercise this final refusal. Those mutations are
test probes only. Sixteen late substitutions still produce no native effect.
A fabricated COMMITTED receipt without a real dispatch is rejected. Native append
followed by a failure in A remains an effect and a terminal error; it is not
classified as a safe no-effect result and is never retried.

## Reproducible evidence

89 new tests and the 1058 prior dedicated tests run with no failures/errors/skips.
Provider/network/SDK/database/scorer/gold and external trustlog guards remain
active. The audit independently reconstructs original request, full native
pre-state, receipt correlation, native normalization, full RCC candidate hash and
program-order linkage. It executes the actual native append on a detached clone,
then reissues with a fresh owned key/session and replays actual RCC/Bind for all
nine recorded pairs. Random context/MAC/receipt IDs are excluded from stable
report identities. Original exported MAC authentication is not claimed.

No B native admission, payment reservation/consumption, durable duplicate-refund
exclusion, authenticated clock/policy/receipt/principal/friend relationship or
external mandate has been established. Profile receipt-key dedup stays local
issuance evidence. No historical recovery, safe relaxation, Utility/injection
remeasurement, provider execution, V13 reuse, held-out/external or production
claim is made.

## Next boundary

`TASK15_REFUND_EXECUTION_AUTHORITY_BOUNDARY_V1`: specify and prove the distinct
request/principal/receipt, effective date/subject, execution-time authority and
receipt reservation/consumption requirements before proposing any activation.
The old validator continues to refuse. A positive refund admission requires a
separately reviewed authority design and proof; a development score cannot supply
these missing inputs.
