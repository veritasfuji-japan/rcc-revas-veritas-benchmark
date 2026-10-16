# Final128 #417 — Canonical-to-IAM source-bound admission: deny an unearned join

**Status: DRAFT / negative gap audit. NOT one uninterrupted canonical-to-IAM execution.**

## Reviewed evidence (two genuinely different source-boundary runs)

The original #416 CI artifact, `11960108900`, ZIP SHA-256
`163a4acf2ddec1d64da2922eb6d94728846c2ac55162b3dcbd2fa4c63dfea353`,
records one **local benchmark counter** COMMITTED outcome plus six blocked
cases under VERITAS reviewed SHA `73b73a75c5605aaf779ea291436722fae52ed1a7`.

The #2382 CI artifact, `12049616382`, ZIP SHA-256
`651ac609add37c99dfc0599d1a079556d7b8df8012bf17cca8643f6269671168`,
records a separate **synthetic IAM role grant** with native approval,
durable PostgreSQL consumption, signed target mTLS acknowledgement, challenge
`ISSUED -> CONSUMED` and `EFFECT_UNKNOWN -> CONFIRMED_EFFECT`. The
tested PR workflow merge SHA is `7c1551a2cf6d95e103395fcd3dd1f5a66876571d`,
*not* the subsequently merged OS-main SHA
`5af56051cdc5b88c1705f0afe876aa6ba4858371`.

**The native `request_id` and `execution_intent_id` are different in those
observed runs. More fundamentally, the OS #2382 issuer has no independently
verified #416 original-request digest or RCC candidate hash at issuance.**
The action classes themselves are different. **An earlier approval to increment
a local counter cannot authorize granting an IAM role.** No report join,
hash rewrite, cosmetic ID equality or checker adaptation may grant execution.

## This PR's exact, limited work

- Check in an explicitly **non-authorizing reviewed gap contract** with
  exact artifact reference IDs, SHA-256 and select non-secret lineage.
- Add optional *actual ZIP* checking with SHA-256 of the archive and every
  per-file `manifest.sha256` record; reject altered native lineage, missing
  signatures-as-reported, changed #2382 PostgreSQL count, duplicate effects
  and state transition anomalies. This is artifact integrity and reported
  outcome revalidation, **not independent cryptographic key custody**.
- Add offline negative tests that refuse substituted source hashes, false
  production claims, mutation of refusal cases, claimed source-binding,
  tampered target/nonce evidence or forged cross-repository ID equality.
- Emit a redacted `NOT_ADMITTED_NEEDS_SOURCE_BOUND_NATIVE_ISSUER` report.
  The default lightweight CI checks the *reviewed metadata snapshot*, and
  explicitly writes `real_both_artifact_zip_hashes_checked_this_run=false`.
  If both actual downloaded ZIPs are supplied, the same tool rechecks their
  immutable bytes and only then sets that field to `true`.
- No original #416 fixture or #2382 OS source changes, no action execution,
  no private credentials, no Provider calls, no AgentDojo score and no
  unsupported reconciliation promotion.

Run optional actual downloaded artifact audit locally:

```bash
python -m scripts.final128_417_canonical_iam_join_admission_v1 \
  --canonical-zip /path/to/reviewed-416.zip \
  --iam-zip /path/to/reviewed-2382.zip \
  --output /tmp/final128-417-audited
cd /tmp/final128-417-audited && sha256sum --check manifest.sha256
```

## Actual next boundary needed for genuine integration (separate implementation)

1. **Canonical IAM-scope candidate**: use RCC/REVAS original request and
   exact candidate digest for an IAM operation, not the existing test-only
   `local-counter` candidate. No re-dispatch of an already committed action.
2. **Authority at issuance**: VERITAS must independently verify the
   original-request and candidate hashes, identity and exact IAM target,
   action, resource, scope, expected pre-state and expiry. A fresh signed
   Human Approval for the IAM operation is necessary; counter permission
   cannot be translated into an IAM grant.
3. **Native source-bound bridging receipt**: a trusted OS issuer signs an
   exact mapping from RCC identity to native `request_id`,
   `execution_intent_id`, authorization ID and immutable hashes.
   Preserve both namespaces instead of rewriting their values.
4. **Execution boundary**: original signed one-use consumption in PostgreSQL,
   permit tied to exact mapped action, one real isolated Docker/mTLS IAM
   mutation, target-owned signed receipt, challenge freshness and single-use
   reconciliation.
5. **Independent end-to-end proof**: same *fresh*, controlled candidate in
   one trace, negative substitutions at each boundary, lost ACK/restart
   bounded checks, no scorer/gold authority, no unapproved IAM effect,
   no duplicate execution; redacted reproducible artifacts and pinned
   source hashes. Cross-host independent signer/reader remains separate.
6. **Real performance**: only after authority proof, preserve paired native
   model terminal/scorer and measure actual matched Final128 Arm A/B Utility
   and injection success; do not claim recovery from this test.

## Merge and reporting rules

CI green for #417 means the **false-join admission refusal is implemented**,
not that an IAM-scope candidate has been executed by VERITAS. Do not use
`PROVEN`, `production-ready`, `paired Utility restored`, `independent
operator verified` or `Ben's complete integration` for this PR.

Source references: RCC PR #416, VERITAS OS PR #2382. No paid API authorization
or production IAM action is requested.
