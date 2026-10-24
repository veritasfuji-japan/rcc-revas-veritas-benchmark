# Source audit: signed-ledger integration into Native issuance and Custody

Prepared 2026-10-24 JST against main
`98640673e85fc9a6bce39159d22a6d292b52e520` (merged #533).
This audit locates the next implementation boundary; it does not connect or
run the retained service. The [machine-readable source record](../evidence/task4_signed_ledger_native_integration_source_audit_v1.json)
contains 12 byte-exact source/file pins, 33 AST symbol anchors and the fixed
request-digest comparison. Git blob SHA-1 and SHA-256 were checked locally;
repository modules were not imported or executed by that check.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## Decision

Use the existing **bounded Native continuation** path as the primary integration
candidate. It already verifies exact observed history, signed archive/tool
observations, per-arm parents, limits and current execution context. Do not
reimplement those controls or describe them as absent. They remain synthetic,
same-host controls rather than live Provider permission.

Do not wire the fixed manual client's run() into Native. Its eight synthetic
request/grant digests are not Native request/grant digests, and its successful
callback is only a list marker. Preserve its deployed approval and the #533
evidence as a separate experiment. An integrated research profile needs a
separately reviewed binding to the Native manifest/run and role identities;
this document does not authorize creating or enrolling that run.

The first code increment should be an explicitly required, synthetic-only
integration profile: source-neutral signed-ledger client logic, durable local
intent records, verified receipt retention and hooks at the actual issuer and
Custody boundaries. No caller-selected fallback, public endpoint, new key/root,
automatic repair, real credential loader or paid switch belongs in it.

## Exact current connection points

| Boundary | Pinned source | Current behavior and required integration position |
| --- | --- | --- |
| Bounded issuance | [NativePolicy.authorize](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_bounded_continuation_v1.py#L154-L169) | Validate fixed parameters/history/parent/budget, sign grant, write attempt and PENDING state in a local SQLite transaction. A verified remote reservation must precede new signing/export, after eligibility checks. |
| Issuer RPC | [issuer](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_bounded_continuation_v1.py#L225-L255) | Only trusted runtime UID can authorize/complete. Preserve SO_PEERCRED and exact request schema; ordinary Native/model data cannot select ledger binding, transport or role. |
| Independent grant checks | [verify_packet](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_bounded_continuation_v1.py#L258-L266) and [verify_grant](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_bounded_continuation_v1.py#L67-L73) | Validate grant signature, exact manifest/request/arm/ordinal/parent and current context. Keep these before claiming permission to consume. |
| Bounded consumption | [custody](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_bounded_continuation_v1.py#L269-L316) | Check peer/grant/history, insert local CONSUMED_UNKNOWN, then call Bind. Add verified remote consumption and retained receipt before any possible effect path. A failed receipt never reaches Bind/apply. |
| Actual effect boundary | [bind_post](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_os_custody_v1.py#L356-L434) | Pinned real Bind runs BLOCKED/zero apply then synthetic COMMITTED/one apply; keep exact request/prestate and postconditions. Never replace this with a post-send ledger counter. |
| Continuation observation | [NativePolicy.complete](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_bounded_continuation_v1.py#L171-L184) and [verify_observation](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_bounded_continuation_v1.py#L107-L124) | Both archive and runtime observations must match before an arm advances. A ledger snapshot is not an archive/tool observation and cannot advance history. |
| Retained local enrollment | [admit](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_retained_authority_v1.py#L73-L85) and [guard_policy](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_retained_authority_v1.py#L88-L94) | Enforce registered directory/database/key identities and no create-on-start. Remote storage adds a required barrier; it does not replace these checks with a disposable database. |
| Cached first grant | [cached_grant](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_retained_authority_v1.py#L220-L227) | Existing same-host fixture can reuse a privately retained original A0 grant after issuer crash. Do not infer equivalent remote recovery permission from a view. Define the new profile's stop/recovery rules explicitly. |
| Legacy pre-issued fixture | [state_value](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_durable_issuer_restart_v1.py#L33-L44) and [serve](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_durable_issuer_restart_v1.py#L118-L157) | state_value signs all eight fixed grants before export. Gating only export-existing is too late for reservation-before-signing. Keep this fixture separate. |
| Manual client | [manifest](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_signed_ledger_client_v1.py#L30-L36), [prepare](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_signed_ledger_client_v1.py#L39-L85) and [run](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_signed_ledger_client_v1.py#L119-L154) | Enforces its fixed synthetic manifest and uses list-only markers; not a source-neutral Native adapter. Do not relax its existing checks. |
| Reusable receipt verifier | [LedgerClient.exchange](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_external_ledger_contract_v1.py#L219-L245) and [LedgerClient.gate](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_external_ledger_contract_v1.py#L247-L251) | Fresh view/mutation, exact receipt signature/nonce/binding/state/revision, no mutation retry. These primitives are not yet called by the selected Native entrypoints. |
| Server-side state transition | [SignedGitHubService.exchange](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_signed_github_ledger_v1.py#L138-L171) | TLS-supplied peer identity, revision compare, RESERVED/CONSUMED_UNKNOWN transitions, backend readback then signature. It does not verify Native grants/history or actual callback effects. |

The older frozen [issue](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_os_custody_v1.py#L191-L215) also signs all grants in advance.
Its [custody](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/blob/98640673e85fc9a6bce39159d22a6d292b52e520/scripts/task4_native_os_custody_v1.py#L459-L569) has a separate local-consume path and dispatches to
bounded.custody when that profile is active. Audit both paths; do not treat a
hook added only to one as repository-wide coverage.

## Static compatibility findings

1. **Manual hashes differ from Native hashes.** Manual manifest digest
   `ff4180c808fb30e7c3f5c9cfe6f2ccff6be0c35bfed6ec42ab6a90c0dd866f6d`
   commits to SHA-256 of TASK4_SYNTHETIC_REQUEST_V1:<slot> and matching
   synthetic-grant labels. All eight request hashes differ from the pinned
   frozen Native request fixture. Bounded Native computes later hashes from
   actual SDK bytes. Reuse the service protocol, not the manual payload profile.
2. **Eight slot names are structurally compatible, not authority.** The protocol
   permits A0-A3/B0-B3 and revision 0-16. Bounded Native permits four requests
   per arm. Matching labels do not make run/manifest/key bindings interchangeable.
   Reserve must use SHA-256 of exact validated SDK bytes; consume must use the
   same request digest and canonical digest of the complete verified Native
   grant. No caller-supplied digest or operation may bypass eligibility checks.
3. **The server binds a manifest digest but does not interpret its policy.**
   It accepts structurally valid request hashes under an enrolled binding.
   Native scope/history/expiry/recipient/budget checks remain mandatory.
4. **Two durable stores do not form one transaction.** NativePolicy currently
   signs and advances SQLite in one local transaction. An external reservation
   can commit while its response or local commit is lost. Merely adding a
   network call inside a rollbackable transaction leaves the local arm READY
   after an unknown remote outcome. Do not claim atomicity across these stores.
5. **Identity and network enrollment differ.** The existing Native fixtures
   generate role keys under reserved UIDs; the operator service has separately
   approved TLS certificate-to-authority mappings. Equality must be explicitly
   enrolled and verified. No key copy or automatic remapping is authorized.
   A loopback listener in one network namespace is not reachable as the same
   localhost service in another. Keep egress isolation and use only an
   explicitly reviewed closed-local transport in the first integrated test.
6. **The selected modules have no direct signed-ledger imports or LedgerClient
   construction.** AST inspection covered the four named Native entrypoints.
   This is a scoped static observation, not transitive repository-wide
   reachability, deployed-route closure or dynamic bypass-resistance proof.

## Required ordering for the new synthetic profile

These are proposed acceptance requirements, not implemented runtime behavior.

### Issuer

1. Verify trusted enrollment, Native manifest/run/key identity and exact
   eligibility (history, parent, parameters, slot, limits and current validity).
2. Exclusively and durably record a local per-run/slot issuance intent **before**
   any remote mutation; block concurrent or restarted issuance from that intent.
   A rollback of later work must not erase or reset this consumed attempt.
3. Obtain a fresh signed view, reserve the exact request once with its expected
   revision, then verify and durably retain the exact reservation receipt.
4. Recheck validity after the potentially slow exchange. Only then sign and
   durably retain the original grant together with the reservation identity,
   and expose it through the existing trusted RPC. A signing/journal/export
   failure stays pending/unknown and must not produce a replacement grant.
5. Keep successful response/tool observation as the only way to advance the
   existing Native arm. A view, local missing file or new process is not recovery
   authorization. Initial integrated implementation should fail closed on
   unresolved issuance rather than silently use the legacy cached-grant path.

### Custody

1. Preserve peer, grant signature, exact wire, context, validity and contiguous
   observed-history checks. Require the exact trusted ledger/run/manifest role
   mapping and reservation/request match.
2. Durably record the local consumption attempt before external mutation.
   Then request remote consume once, binding the exact full grant digest.
3. Verify and durably retain the receipt before any Bind/effect path; recheck
   current validity immediately before possible dispatch. Every failure stays
   consumed/unknown. A valid old receipt or read-only snapshot is not a new gate.
4. Preserve actual Bind, first-ingress AEAD/fsync ordering, response joins and
   signed archive/tool history. No local-success fallback if the remote gate
   is unavailable, stale, wrong, unsigned or ambiguous.

Do not hold an uncommitted local intent as the only duplicate barrier while a
remote write may commit. Define lock/intent/schema migration and state-evidence
joins in the implementation; do not invent a distributed two-phase commit.
Favour conservative stop over automatic rollback, retry, re-enrollment or a
replacement namespace. Active required enrollment must not be downgraded to
an old profile simply by omitting a flag or marker.

## Minimum acceptance matrix for the implementation

| Case | Required observable outcome |
| --- | --- |
| Valid actual SDK request | Verified reservation before signing/export; verified consumption before Bind/effect; exact remote/local/request/grant joins |
| Invalid history, scope, recipient, signature or expired grant | No newly issued grant or effect; rejection occurs under existing controls |
| Reserve committed, response discarded | No new signature/export; durable intent retained; read-only remote snapshot shows reservation |
| Reservation verified, local record/sign/export fails | No replacement signature or automatic export on restart; ambiguity retained |
| Consume committed, response discarded | No Bind/apply/callback; remote and local consumed/unknown retained |
| Verified consume then crash before effect | No resend on a fresh process; zero or unknown effect remains explicitly distinguished |
| Bad signature, nonce, binding, digest or stale revision | No permission and no callback; bounded public evidence, no raw exception export |
| Concurrent duplicate in each role | Only one supported attempt can proceed; all losers stop without reissue/resend |
| Missing/corrupt/replaced journal, key, enrollment or remote state | Fail closed without create/repair/fallback |
| Expiry during remote exchange | Stop before signing/sending even if the earlier entry-time check passed |
| View/replayed receipt/cached legacy grant | Cannot authorize a fresh effect or bypass the required new-profile gate |
| Alternative caller/role/network route | Actual tested OS/TLS/credential denials plus a working positive control; no broad route-closure claim |

Use a disposable local signed service/model backend and closed TLS first, with
separate test roles. Preserve existing frozen and bounded CI fixtures unchanged.
A later actual GitHub-backed Native exercise requires separate reviewed
provisioning/approval and must preserve all existing evidence; it is not
authorized by this plan.

## Ordered follow-up

1. Implement the explicit source-neutral adapter, required enrollment and
   durable local intent/receipt contract; validate it without Provider egress.
2. Connect it at NativePolicy.authorize and bounded Custody's pre-Bind boundary,
   and run the matrix on that same actual Native/Bind/closed-TLS trajectory.
   Contract-only fake callbacks do not close this step.
3. Review deployment/run retention, credential/egress, remote identity and
   existing-route coverage for a declared research configuration before any
   newly approved real-service or real-Provider execution.

There is no new real Provider approval, run enrollment, budget or current model
selection in this PR. #533 remains bounded operator evidence, not proof that this
integration already exists. Full backend history, independent administration,
live private recipient lifecycle, independent genuine A/B scoring and Final128
remain separate open gates.
