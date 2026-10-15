# Final128 #411 — signing-key rotation, retired keys and stale-authority fail-closed

## Exact source

Parent #410 MERGED \`0050e8cda8f613ac8045c1915f801d5e307c780f\`.
Unmodified original frozen AgentDojo v1.2.2
\`a75aba7631d3ca5fb7ab938965c97ead2f9ff84b\`,
VERITAS \`a1d66aef02262cf8a913295270c3aafd159c6adb\`,
Native Task1 DirectAttack and original 128-case enrollment.

The dedicated workflow includes *all* #410–#377 tests, including
native NO_MUTATION, Linux DAC, real Bind, durable backend crash recovery,
concurrency, source-owned signed authorization and signed revocation.

## Why #411

#410 demonstrated one fixed Ed25519 signing issuer and persisted
revocation. It did **not** show old signing keys being retired,
monotone key-registry updates or that a once-valid signature would stop
working when an issuer became unreachable and freshness expired.

#411 uses four distinct non-root Linux OS principal identities:
issuer, agent, gateway and effect sink, plus stranger negative control.
The issuer UID alone holds **three different Ed25519 private seeds**:
one control-plane authority signing key, one **old** permit signer and
one **new** permit signer. Each is a \`0600\` raw seed inside a \`0700\`
issuer-owned directory inaccessible to the other principals. A
root-owned \`0644\` public key anchors trust in the control-plane
authority, while signed key-policy assertions bind old and new public
keys to source-owned policy epochs.

### Three source-owned signed policy epochs

| Epoch | Active signing key | Retired/revoked | Signed policy freshness |
|---|---|---|---|
| 1 | old | none | 90s |
| 2 | new | old | 90s |
| 3 | new | old | 2s (test-only forced expiry) |

The issuer can issue *only* fixed synthetic A/B/C permits with signed
target, audience, expiry, not-before, expected revision and exact
increment-7 action. These are **not actual human approvals**.
Signed control-plane updates include exact issuer/audience,
strict key identifiers and public keys, monotone epoch,
explicit retired key set, issuance and expiration timestamps.
The sink verifies the control-plane Ed25519 signature against its
independently root-pinned control public key, validates policy scope
and monotone sequence, and persists the accepted epoch and key states
in its own SQLite database.

The backend never accepts a client-provided key as trust authority.
For **every single effect attempt** it checks, inside
\`BEGIN IMMEDIATE\`, that the target-owned policy exists and is still
fresh by sink clock, that the permit was signed by the currently active,
non-revoked leaf public key, that signed target/action/expected revision
and permit window match, and that the permit ID is unconsumed.
Only then does it atomically increment the synthetic counter and persist
the consumed permit and effect receipt.

### Negative and positive observations

1. A forged policy signed with a separate valid Ed25519 private key,
   altered signed active-key field, replayed epoch and skipped epoch
   are refused by the effect sink without promoting trust.
2. Epoch 1 allows one old-key A permit to COMMIT through **actual pinned**
   \`execute_bind_adjudication\` and the independent mock sink.
3. Epoch 2 rotates to new key and retires old key. A **valid, untampered
   old-key B permit** is rejected, not merely a malformed signature.
   An authentic new-key B permit produces a separate actual Bind
   COMMITTED with one and only one synthetic effect on B.
4. Tampered leaf signature, wrong leaf key and repeated consumed JTI
   are rejected with no extra effect.
5. Epoch 3 is a **real signed 2-second freshness lease**. The issuer
   service process is explicitly stopped and is unreachable to the
   client. After its lease expires under the sink's own clock, a
   cryptographically valid, unspent new-key C permit is **rejected at
   the sink**, even though its own signed 10-minute permit lifetime
   remains valid. The gateway cannot treat issuer outage or a
   previously cached successful verification as execution authority.
6. Backend is restarted using its prior owner-only SQLite file; epoch 3,
   retired old key, two effects and all receipt hashes remain intact.
   Policy remains stale and permits continue to fail closed.
7. Original pinned Native Task1 \`send_money\` still returns **actual**
   VERITAS Bind BLOCKED. No original bank state is modified.

## Scope and nonclaims

**This is an offline local issuer and local simulated counter**;
the policy control signer, both leaf keys, and the policy sequence
are all source-owned test fixtures. The parent GitHub runner has sudo
and can replace the test trust anchor; root, CAP_DAC_OVERRIDE, host
compromise, HSM/PKI trust, independent human approval, remote proof
of issuer outage, internet/network partition, remote revocation freshness,
cluster failover, distributed clock synchronization and real effect
backend IAM/egress are **not** proven.

The policy lease uses **sink-local wall clock** and a controlled 2-second
expiry; it does not prove monotonic-clock protection against rollback,
long-running production key rotation, malicious issuer controls or
cross-organization signed approvals. A valid issuer UID can issue the
specific source-owned fixture permits. No paid model Provider, external
bank effect, official AgentDojo scorer, independent real model A/B
utility or production non-bypassable execution is measured by this PR.
No status promoted to PROVEN.

## Merge gate

- Exact pinned source hash/frozen enrollment retained.
- Three distinct private Ed25519 seeds with 0600 DAC, root-only public
  trust anchor and four separate real Linux UIDs.
- Actual control Ed25519 signatures verified at sink and stored
  monotone epochs; forged/altered/rollback policy rejected.
- Valid old signer COMMITTED in epoch 1, valid same old signer rejected
  in epoch 2, newly active signer COMMITTED in epoch 2.
- Expired policy from stopped issuer causes backend fail-closed for
  valid unconsumed new-signer permit.
- Backend restart retains state, receipts, old-key retirement and
  fail-closed status.
- Original Native Task1 never gains write permission.
- Dedicated zero-skip, inherited #410–#377 and all exact-HEAD CI green.
- Redacted SHA+JUnit only, no key seed, Provider, banking effect,
  scorer or unsupported IAM/network/prod claim.

## Next

Independent trusted issuer/key-change authorization, key compromise
recovery and signed external policy distribution, sink-anchored
freshness proofs, monotone/rollback-resistant clock, remote network
partition tests and third-party adversarial verification.
