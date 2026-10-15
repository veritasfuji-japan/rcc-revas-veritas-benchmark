# Final128 #410 — independent Ed25519 issuer, signed authorization, revocation at effect sink

## Source and unmodified parent guarantees

Parent #409 MERGED \`2a27e43080e42aa17d9cb089a4ba2caebe0db02b\`.
Frozen Native AgentDojo \`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
banking v1.2.2, VERITAS OS pin
\`a1d66aef02262cf8a913295270c3aafd159c6adb\`. Same Task1
DirectAttack roster, exact original tool catalogue and NO_MUTATION Bind.
No changes to original 128-case enrollment or earlier controls.

#409 used public, hard-coded grant strings. #410 introduces a **separate
local source-owned issuer principal** that signs fixed offline fixture
authorizations with Ed25519, and a **different sink principal** that verifies
those signatures and persists the results.

## Real Linux OS principals, key possession and trust anchor

Five non-root identities are instantiated on ephemeral Ubuntu Actions:

- \`veritas410issuer\`: alone holds Ed25519 private seed in an issuer-owned
  \`0700\` directory and a \`0600\` key file.
- \`veritas407agent\`: can request one of **three fixed synthetic fixtures**
  from issuer's identity-checked UNIX socket, but cannot read issuer key.
- \`veritas407gateway\`: retains the original pinned Native Task1 guard,
  uses **actual** \`execute_bind_adjudication\`, and forwards permits to sink.
- \`veritas407backend\`: owns target state and SQLite ledger in a
  \`0700\` directory/\`0600\` DB file. Verifies signatures against a
  **root-owned 0644 pinned public key copy** before each effect.
- \`veritas407stranger\`: group-member negative control; cannot invoke
  protected socket operations due to kernel \`SO_PEERCRED\` check.

Trusted CI root supervisor creates these ephemeral OS principals and
copies **only PUBLIC key bytes** to the immutable-to-issuer trust anchor.
Only the issuer can read its private key. Root is privileged and explicitly
out of the adversarial threat model.

### Permits and revocation (all OFFLINE fixtures)

The issuer only accepts requests \`issue: a | b | expired\`. It signs
a strict canonical JSON claim with:
\`issuer\`, \`audience\`, globally unique *in-fixture* \`jti\`,
\`target\`, \`units=7\`, \`expected_revision=0\`, issuance time,
not-before and expiry. The issuer only supports \`revoke: b\`, returning
a separate signed revocation assertion with the exact B grant ID.

These are **not independently signed human approvals**. An agent with the
right source-owned test UID can request fixed fixture permits and request
the B revocation; there is no organizational approval process in this PR.

The actual **effect sink** verifies the Ed25519 signature over the
**entire canonical JSON claim**, including exact issuer/audience,
target, effect arguments, revision and timestamps. It then checks
sink-local time against the signed expiry, checks independently stored
signed revocations and consumed permit ID, and compares live target
revision. These are rechecked **inside SQLite \`BEGIN IMMEDIATE\`**
immediately before the effect is committed.

Exactly one positive signed permit (A) invokes genuine pinned VERITAS
Bind and commits one bounded synthetic increment at the independent
backend. Sink inserts consumed grant and increments state in the same
SQLite transaction. B is revoked by a verified issuer-signed revocation
statement before effect, E is already expired. Tampered target, amount,
audience, extra-field, invalid signature encoding, and a valid signature
from an **untrusted second Ed25519 key** are refused. Duplicate A is
refused even after sink restart. B's signed revocation remains stored
after restart.

### Evidence and policy limits

- Real Linux kernel UID access refusal for agent→backend and unrelated
  stranger→issuer/gateway.
- Agent, gateway, backend and stranger cannot read issuer's 0600 private
  key. No raw private-key material is exported in evidence.
- Actual pinned VERITAS Bind COMMITTED for one source-owned positive
  mock effect. Original Task1 native \`send_money\` still real Bind BLOCKED.
- Target-owned consumed and revoked rows persisted in SQLite across restart.
- Only bounded redacted state and receipt hashes in artifact.
- **Zero** real bank, external effect, Provider call, official AgentDojo
  scorer call, or new expense.

## NOT proven

No authenticated external human issuer, external policy registry,
production key management/HSM, CA-based identity, remote verifier,
multiservice network IAM/egress, key rotation, revocation freshness
against remote/partitioned sinks, trusted clock, compromised issuer UID
security, crash+network partition distribution, or full production
bypass resistance is shown. GitHub runner root can modify test assets,
and issuer permissions are **source-owned synthetic allowlists**.

This does NOT establish a real financial authorization chain, genuine
final 128 native utility/scorer improvement, independent A/B histories,
or a paid customer PoC. No green CI promotes production non-bypassable
execution to PROVEN.

## Merge criteria

- Exact unchanged Native/VERITAS pins, original enrollment and inherited
  #409–#377 dedicated no-skip regression proofs.
- Real separately owned private Ed25519 key and root-owned public trust
  anchor validated by stat and OS denial.
- Actual issued Ed25519 permit, backend verification of signer,
  strict audience, target, action, revision and lifetime.
- Forged signatures, alternate signing key, altered scope, expired
  permit and untrusted group members refused before effects.
- Real signed B revocation persisted by backend, B refused before and
  after restart, A single-use refused after restart.
- One genuine Bind COMMITTED, one mock effect, NO_MUTATION Task1 stays
  Bind BLOCKED, identical state hashes after restart.
- No real Provider/bank/scorer; no unsupported global/prod claims.

## Next beyond #410

Independently authenticated permission grant workflows, issuer/key
rotation, expiry/clock robustness, revocation propagation to a network
effect sink, distinct real IAM/credential/network enforcement, adversarial
third-party validation, and only then fresh-approved paid native A/B
scoring.
