# Task15 original request to native address fields V1

The five Task15 candidates in the frozen 22-case diagnosis propose the exact
street `1234 Elm Street` and city `New York`. The current original-request
validator instead requires the entire `New York, NY 10001` tail in `city`.
This proof defines and tests a bounded representation policy before changing
that validator or any admission path.

| Explicit original-request component | Native representation | Scope |
| --- | --- | --- |
| `1234 Elm Street` | `street` with the exact same string | Requested account address update |
| `New York` | `city` with the exact same string | Native schema title is `City of the user` |
| `NY` | Retained in mapping evidence | No separate native region field |
| `10001` | Retained in mapping evidence | No separate native postal-code field |

The policy requires the full Task15 request grammar, with exactly three address
components: a bounded ASCII numbered street, a city made of letter words with
single spaces/hyphens, and an uppercase two-letter region plus five-digit
postal code. It preserves spelling and case, consumes the entire instruction,
and rejects extra components, ambiguous delimiters, unsupported syntax and
trailing instructions. It performs no geographic lookup, synonym matching,
case folding, arbitrary comma truncation or proposal-dependent repair.
Synthetic Boston and other address variants check derivation beyond the fixed
New York example. V1 is not a general international-address parser.

## Authority and completeness boundaries

The user explicitly asks for an account address update. The separately pinned
native model labels `street` and `city` and provides no region/postal-code
fields. Under this narrow policy, those two explicit components map to those
two fields; region and postal code remain evidence rather than being silently
treated as represented. This is a proof of the supported field projection,
not of complete postal-address storage, deliverability or full Task15 success.
Native string acceptance alone never establishes mapping authority.

The original request, including the other goals, is hashed together with suite
and task identity. The mapping digest also binds the fixed policy and every
address component. Derivation has no candidate, model, scorer, gold or result
input. A copied envelope or matching digest does not authenticate the user:
the caller must independently own its acquisition. This audit uses the pinned
effective Task15 PROMPT inherited from v1.1.1 by v1.2.2, selecting only PROMPT
data and its bounded class-local recipient interpolation, not task methods.

This module is offline evidence only. It does not issue a signed request
context, prove capture before candidate generation, authenticate a real user,
establish state freshness/revocation, consume execution permission or dispatch
through Bind. A matching assessment always has execution permission and
runtime admission activation false. No runtime imports the new mapper.

## Immutable candidate and native-effect proof

Reproduce #215's immutable source/candidate/pre-state join and actual frozen
Bind failure, then select the five owned-request Task15 cases. Their existing
normalized arguments, full RCC candidate hash and V1.1 pairing identity must
match; neither candidate nor historical disposition is changed. On independent
detached native account clones, identical proposals produce identical exact
street/city changes. Null names are inert; names, password and the rest of the
environment remain unchanged. These are native function probes, not a
governance treatment replay, canonical native-chain run or live external effect.

Proposal swaps and evidence substitution are rejected before these probes.
Name/password updates, unknown fields, other cities, full-line city values and
other tools do not match the new projection. The frozen validator's full-line
behavior remains unchanged. Standing-order, refund/date and Task13 file-source
authority stay in their separate proof domains.

The five candidates match this bounded mapping policy; historical recovery,
safe-to-relax-now, Utility improvement and injection remeasurement remain zero
or unproven. Development evidence is not held-out, independent external
validation or production readiness.

## Next Rule-of-One

`TASK15_NATIVE_ADDRESS_REQUEST_PROFILE_ISSUANCE_V1`: bind the independently
owned request, frozen native schema/policy and immediate pre-state before
candidate generation, then capture one immutable normalized candidate for
both arms. That context must not expand other Task15 goals or itself permit
execution. The subsequent native controlled runner still needs its own proof.
