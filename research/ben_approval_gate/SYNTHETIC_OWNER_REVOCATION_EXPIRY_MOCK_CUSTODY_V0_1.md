# Ben synthetic Owner Approval: revocation and bounded interval at mock Custody

**Research-only. No actual owner, trusted real-time clock, provider or production policy.**

## Extension to merged #585

This change adds signed `valid_from_tick` and `valid_until_tick` to the
root-generated synthetic Owner statement and makes the isolated mock Custody
read a root-owned `trust/owner-current-validity.json` on every initial
(unconsumed) request. That file contains an exact schema, a synthetic logical
`clock_tick`, and a list of revoked statement SHA-256 digests.

The current validity test is strict:

- the signed interval uses integers (not booleans), with
  `0 <= valid_from_tick < valid_until_tick <= 1_000_000`;
- an approval is current only if
  `valid_from_tick <= clock_tick < valid_until_tick`;
- a previously valid statement is refused when its exact digest appears
  in the root-enrolled revocation list;
- malformed, missing, duplicate or oversized validity documents fail closed;
- Agent UID 61101 cannot rewrite the root-owned validity file;
- invalid signatures, revoked statements, expired statements and
  not-yet-effective statements are denied by the real mock Custody **before**
  the durable consumption insert;
- after each denied attempt the supervisor checks both backend effects and
  Custody consumption records remain zero; a restored valid state then
  permits the pre-existing pinned VERITAS Bind / one mock effect / receipt join.

These new negative controls run in the same PR CI integration as the
previous owner gate. They are isolated from all real providers and banking.

## Fundamental limits

1. **Clock simulation, not time attestation.** The current tick is supplied by
   the trusted CI root; it is NOT a wall-clock timestamp, independent secure
   clock, monotonic distributed time source, or externally verifiable time.
2. **Revocation simulation, not independent policy authority.** The same trusted
   root controls synthetic owner enrollment and the revocation list. This proves
   behavior when the local trusted source changes, not authority provenance,
   correctness of human consent, or security against root/Custody compromise.
3. **Pre-consumption, not atomic real-world dispatch.** Time and revocation are
   checked before the Custody SQLite consumption row; they are NOT rechecked
   atomically with the later sink effect. Races after that check, clock
   rollback, revocation propagation delays, lost acknowledgments and
   multi-node consumption are not covered by these new checks.
4. **No combined fault or concurrent owner claims.** The opt-in mock owner
   mode still refuses synthetic fault/concurrent combinations. The established
   separate non-owner fault and concurrency tests remain unchanged.
5. **No actual provider effect.** `REAL_PROVIDER_NO_GO`,
   `UTILITY_UNSCORED`, and `production_bypass_resistance_proven=false`
   remain unchanged.

## Acceptance evidence

The pinned Linux CI job must show the new unit negatives, three separate
real-Custody rejections (revoked / expired / future) each with *zero*
consumption/effect, untrusted write refusal, one valid synthetic effect
through pinned Bind, and unchanged existing workflows.

Further research: independent owner issuer/clock trust sources, signed
revocation epoch handling, and a dispatch-time check at the actual effect sink
under concurrent fault injection.
