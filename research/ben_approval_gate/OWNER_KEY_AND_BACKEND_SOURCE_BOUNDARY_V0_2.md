# Ben synthetic Owner Approval — distinct keys and source-backed state v0.2

**RESEARCH-ONLY / OFFLINE / NO AUTHORITY / NO PROVIDER DISPATCH**

Follow-up to #583. The existing synthetic preflight checks Owner Approval and
an independent issuer grant. This change adds two negative controls to that
*preflight*, not a claim that the mock Custody or production sink enforces them.

## What is now checked

1. Even if both Ed25519 signatures verify, the enrolled owner and issuer
   public keys MUST differ. Key inequality alone cannot prove that different
   humans or organizations control those keys.
2. `trusted_backend_snapshot(connection)` reads a coherent transaction-scoped
   snapshot from a caller-supplied **read-only SQLite connection** with the mock
   backend's exact state/spent schema. It rejects malformed counter, receipt,
   missing spent or orphan spent records. The wrapper
   `preflight_from_trusted_backend(..., backend_connection)` no longer takes
   a caller-provided prestate dict. Its result remains
   `SYNTHETIC_PREFLIGHT_ACCEPTED_NOT_EXECUTED`, with
   `execution_authority=false` and `provider_dispatch=DENY`.

## Trust conditions and limits

- **Critical caller obligation:** only a trusted Custody/controller may choose
  and open the actual backend database. A read-only SQLite handle or correct
  schema is NOT independent backend provenance; a caller could supply a forged
  database. No provenance key, independent runtime attestation or trusted root
  is established here.
- The read transaction ends before preflight returns. This does **not** bind
  the snapshot to the final dispatch: post-preflight drift, revocation, and
  trusted clock still require dispatch-time validation.
- The production Bind Custody program has **not** been wired to call this
  wrapper. No egress, provider endpoint, owner credential, live issuer, real
  funds, durable owner permit, new single-use proof or independently verified
  external effect is introduced.
- Existing mock Custody kernel/network and atomic-consumption tests remain
  separately scoped. This PR must not be presented as end-to-end Owner
  Approval → Bind → effect enforcement.

Next: independently enroll source/issuer/owner trust anchors under Custody,
bind source proof to a nonce and permit, install the check at the sink boundary,
then run exact negative and replay/concurrency tests in the isolated mock
environment before making any wider claim.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED`
