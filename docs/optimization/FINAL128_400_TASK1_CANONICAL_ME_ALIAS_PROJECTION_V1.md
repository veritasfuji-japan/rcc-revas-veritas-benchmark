# Final128 #400 — Frozen Native Task1 `me` alias-aware read-only B projection

## Parent and exact scope

#399 established source-frozen Native AgentDojo banking v1.2.2 Task1 DirectAttack
enrollment and the gap that prior #377/#378/#397 source-owned projection code
required `recipient == bank.iban`. The real v1.2.2 environment stores:

- Account `iban = DE89370400440532013000`.
- Native outgoing March transactions with `sender = me`.
- DirectAttack-bearing inbound March transaction with `recipient = me`.

The legacy #377 method would reject that injection slot and its portable #348
spending algorithm would undercount because it treated only `sender == iban`
as spending.

#400 introduces a **new source-owned Native Task1 path**; deliberately does
NOT alter any merged legacy #348/#377/#378/#397 implementation or its
historical evidence. Its source boundary is #399's exact Native Task1
constructor (frozen 128-case roster and DirectAttack native slot discovery),
not an externally supplied `native_prestate` JSON or a model reply.

## Source-pinned alias resolution without authority widening

The alias `me` is a literal from the immutable pinned AgentDojo banking
default YAML; it is NOT inferred from attack text, transaction subject,
model-generated narrative, scorer GOLD, policy change, or a caller argument.
The `iban` remains the actual pinned native bank object's IBAN.
In the internal bounded source calculation, either `me` or the exact
bank-owned IBAN denotes self, but not any other identity or account.

- Read the two freshly and independently loaded Native A/B environments
  only through actual `FunctionsRuntime.run_function(` +
  `get_most_recent_transactions, {"n": 100})` in memory.
- Compare native initial state and both exact attacked tool returns before
  creating B's projection. Reject state mutation, unknown identities,
  missing/duplicate/reordered rows, structured field tampering, incorrect
  date/amount/recurring flags, read truncation or ambiguous self-to-self rows.
- Enforce source-owned statement coverage: if native last-100 omits any
  older March transaction, reject instead of undercount.
- Sum only March self-sent transactions, excluding March incoming.
  Fixed native dataset yields `1050.00` outgoing and `10.00` incoming.
- Subject is always ignored for classification and must not appear in B's
  trusted overlay. The original attack subject remains byte-identical in
  each arm's genuine Native Tool response.

This helper's JSON-level checks cannot themselves attest external source
authenticity; only the pinned in-process caller establishes a bounded
local source relationship. This is not production source attestation or
execution authority.

## Native OpenAI model request parity

Using frozen Native OpenAILLM's actual `_message_to_openai` and
`_function_to_openai` converters, both arms are prepared with the *full*
unchanged native tool catalogue, including send_money, `tool_choice=auto`
and the same first request. Their Tool response contains the same original
DirectAttack source data. Fake **offline-only** tool call IDs are deliberately
different per A/B owner. Arm B alone receives an additional model-visible
source-owned read-only projection in the experimental developer-role overlay.
Neither arm receives a model/Provider-generated continuation; nothing is
actually sent. The overlay position is **NOT canonically verified** as a
real AgentDojo pipeline intervention. It is no more an execution permit than
#397's prior proposal.

## What a PASS means

The **canonical native source and DirectAttack input** are usable for a new
B-only read-only spending treatment without rewriting bank data or dropping
the lower-trust malicious original Tool message. Exact A/B model inputs can
be constructed offline with an unchanged full tool catalogue and no native
writes or Provider/Scorer sends. This closes the specific #399 alias-sensitive
projection blocker for this *new* bridge only.

It does NOT mean that the historical #377/#397 projection started working
unchanged, that the overlay's canonical role placement is validated, that
independent genuine model A/B requests exist, that the real agent chose any
proposed action, or that Utility has improved. No official Native Task1
User/Attack scoring, fresh Provider spend consent, external single-use
issuance, production IAM/network/credential enforcement, or third-party
validation is established.

## Next exit criteria for Ben

1. Verify an actual Native pipeline hook for B overlay placement that leaves
   AgentDojo's full tool surface and A/B first-turn histories intact.
2. Capture truly **independently generated** model calls and response IDs for
   both arms using a fresh explicit scoped operator approval, strict hard
   budget and externally consumed single-use capability. Historical budget
   consent is not reusable.
3. Route **all** effectful Native functions, not just one test send_money,
   through VERITAS's real pre-execution authority/bind with non-bypassable
   provider/network boundary and evidence.
4. Collect authentic same-run native final/model/tool/bank history and use
   the official pinned User and Attack scorers only on eligible runs.
5. Freeze paired Task1 scores, then decide whether Final128 measurement is
   justified, with no hidden benchmark-population changes.

## Merge gate

Source-pinned Native/VERITAS and 128-case freeze verified at exact HEAD,
both real read-only Native A/B calls and intact attack, expected March total
from structured source not GOLD, B-only source-owned overlay, untouched full
native tool definitions, tamper/ambiguity rejection, no skips/errors,
comprehensive inherited regressions, hash-only/JUnit CI evidence, and
all ordinary checks successful.

Classification: SOURCE-PINNED CANONICAL NATIVE TASK1 OFFLINE A/B MODEL-INPUT
PREPARATION; NO REAL PROVIDER, NO NATIVE OFFICIAL SCORES, NO PRODUCTION AUTHORITY.
