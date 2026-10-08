# Task15 controlled multi-effect composed admission runner V1

## Status and proof scope

Proposed, **NOT PROVEN** until exact-head Actions, all predecessor tests,
new test population and artifact reconstruction have completed. This is a
provider-free, trusted-process, deterministic local-native proof harness;
never treat it as production execution authority or an external payment.

The implementation composes the existing single-operation address, rent and
refund RCC/VERITAS Bind/final-sink runners without modifying their source.
The new wrapper does not introduce new authority issuers, source-derived
permits, relaxed policies or any live provider execution.

## Actual ordered treatment

1. Maintain separately owned A and B complete local native states.
2. Acquire equal immediate pre-states. Issue both original prospective scopes
   before exactly one candidate generator is invoked.
3. Capture the same full CandidateAction for both arms at actual generation
   ordinal **3, 9 or 14** and recheck its live #244/#245 registered scope.
4. Independently derive the immutable #245 read-only boundary for each arm.
   Every obligation remains REQUIRED_UNPROVEN there.
5. Have trusted code construct precisely the frozen address, rent or controlled
   refund runner, pinned to native AgentDojo/RCC/VERITAS implementations.
6. Feed the already-captured candidate to that runner's own issuance/capture.
   Its legacy proof-slot ordinal is **0, 1 or 2**; compare its proof-slot
   pairing identity to the separately computed #245 identity. It is never
   silently substituted for the actual generation-ordinal identity.
7. Execute both arms against separately cloned native states using the real
   per-step RCC hook, Bind (B only), independent native final sink and local
   single-use token. Record real local results; do not accept supplied
   COMMITTED labels as authority.
8. Verify real journals, candidate/pre-state hashes, one native dispatch at
   most per arm, and exact local post-states. Persist each arm's detached native
   result immediately, before the paired arm can raise; unresolved attempts
   expose an UNKNOWN/PARTIAL observation rather than dropping A-side evidence.
9. For refund B, verify the owned receipt consumed before the native call
   and left terminal UNKNOWN without reopen/retry.
10. Preserve earlier local effect observations. If any arm refuses or
    diverges, close both lineages without acquiring a later candidate.
    On interruption before refund B returns, close the original unconsumed
    reservation, or retain a consumed reservation terminal UNKNOWN. Exceptions
    preserve the in-flight result and remain terminal UNKNOWN / failed:
    no retry, no rollback, no NO_EFFECT authentication or compensation.

The factory, original request, root/principal mapping, complete native reader,
metadata reviewer, process and clock are trusted harness assumptions. They
are **not** authenticated independent external inputs. The process cannot
sandbox arbitrary trusted Python code.

## Explicit limitations

The controlled runner does not prove that all three native operations reach
COMMITTED in both arms unless an exact recorded test observation shows that
terminal state. It does not prove real-model proposal chronology,
independent external root/ledger/principal authentication, cross-process
durable receipt exclusion, restart recovery, external settlement, production
bypass resistance, Utility recovery, new injection measurements, held-out
generalization or third-party independent validation.

V13's previously executed Final 128 is immutable and no V13 authorization
is reused. No OpenAI key, external provider, live database, production tool
or native scorer is used here. Even a three-step local COMMITTED result is
not a new scored Final 128.

## Verification

The dedicated workflow runs the frozen #245 recursive audit (2209 dedicated
previous tests) before 15 new provider-free integration tests, including two interruption probes.
A separate audit inspects the partial-effect records and refund-store closure. It uses exact
predecessor native SHA pins and artifact hashes. A new contract pins the
composition implementation, new tests, original proof dependencies and
explicit claim boundaries. Failure in either chain must fail the job.

## Next work

Only after independent evidence review should a separate Rule-of-One address
the complete native conversation/scorer trajectory and a newly authorized
provider evaluation. Do not represent this PR as a production or Utility
proof merely because all CI steps succeed.
