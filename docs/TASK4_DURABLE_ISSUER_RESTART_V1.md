# Durable synthetic issuer restart on the Native local TLS path

## Required result

Retain the same issuer key, fixed eight-slot issuance ledger and epoch across an
actual issuer SIGKILL and a new process. Re-exporting already issued grants does
not mint new authorization, restore consumed permission or add TLS calls/effects.
Missing, truncated or otherwise valid replacement-key state must refuse startup
without generating a new key, reconstructing the ledger or exposing an endpoint.

Run the existing Native local HTTPS fixture with both `--local-https` and
`--durable-issuer`. The new mode requires disposable trusted CI root. Historical
HTTP/fault/concurrency modes and #509's independent TLS mode continue separately
with their existing assertions. The old ephemeral `issue` helper remains historical
fixture code; the new mode explicitly starts a separate durable issuer service.

## Persisted state and enrollment

Issuer UID 61105 has a private 0700 directory. A single exclusive 0600 regular file
contains its random Ed25519 private key, public key, random local epoch, all eight
exact signed grants, frozen scope and recipient identifiers, and issued_count=8.
The key and complete ledger are written together; fsync file and parent before
the first export. A crash during initial writing leaves unusable partial state
that restart refuses. Initialization never replaces existing state and is forbidden
after an enrollment anchor exists, even when the private state file is absent.

Trusted root receives the initial public export over an issuer-private UNIX socket,
then enrolls read-only public key/grants and a root-owned exact state hash anchor
before starting Custody/backend or permitting any consumption. The private key
never crosses the socket. SO_PEERCRED admits only the trusted root supervisor;
the issuer cannot read Custody/backend credentials or either execution ledger.

On restart, open the retained regular file with O_NOFOLLOW; require exact owner,
0600 permissions, one hard link, private directory, canonical bounded JSON,
consistent key/public pair, exact eight-slot schema and signatures. Require its
complete state hash, public key, grant set and epoch to match root enrollment.
The anchor is a checkpoint in this trusted fixture, not an independent owner or
anti-rollback service. The random epoch is not a new field in the historical
grant wire format; it binds the retained local state through the root hash anchor.

`export-existing` revalidates and returns only the same stored grants and public
hash metadata. It does not sign. `issue-again` explicitly refuses with
DENIED_ALREADY_ISSUED/new_grants=0. There is no scope extension or fresh grant API.
The initial pre-enrollment export is allowed once; every later export requires
the root anchor. Restart always requires enrollment before opening its socket.

## Same-run proof

1. Complete the existing eight-request Native → Custody → actual pinned Bind →
   closed local TLS → scripted response → pre-parser AEAD → Native/scorer path.
   Retain all default-helper OS/TLS negatives and normal 22/TLS 16 checks.
2. Snapshot exact consumed/effect rows, both execution database byte hashes,
   issuer state/anchor hashes and all backend POST/Custody TLS observations.
3. SIGKILL issuer, observe exit -9, start a different PID with the same UID and
   retained state. Require identical public key, epoch, grants and state bytes.
   Deny fresh issuance and re-present all eight cached re-exported grants to the
   still-running Custody: eight REPLAY_DENIED, no additional TLS call or POST.
4. Restart Custody with its original ledger. Keep the original eight restart replay
   checks, then re-present the same re-exported grants again: eight more denials.
   Every snapshot field must remain exactly equal; effects/consumptions stay eight.
5. Stop issuer again. Trusted root injects three separate startup faults: missing
   state, a truncated state file, and a fully valid state signed by a different key.
   Three distinct issuer-UID processes must refuse before ready/socket creation;
   absent/bad bytes remain untouched and no execution/TLS state changes.
6. Root restores only the exact original private bytes between fault injections.
   A final different issuer PID must load the original state and export identical
   public metadata. This is explicitly root-controlled fault restoration, not
   issuer self-repair or authorization recovery.

The original Native replay checks plus both cached re-export phases total 32
denials. The same live TLS backend has exactly four denied POSTs followed by
eight authorized scripted effects, with no POST or TLS connection added by any
issuer restart/re-export/failure. Each slot retains BLOCKED/apply=0 and
COMMITTED/apply=1 Bind records and its request/response/ledger/ciphertext/scorer
joins. Re-export denial is not evidence that a malicious independently privileged
issuer could never sign: execution still relies on the enrolled key, root-owned
public state and retained Custody consumption.

## Evidence and limits

The existing Actions workflow adds 38 unit cases and a separate 16-check issuer
report/JUnit linked by digest to the unchanged normal/TLS report schemas. Artifacts
contain public hashes, PIDs, UIDs, bounded receipt rows and decisions; private key,
persisted state, raw packets, credentials, databases and certificates stay ephemeral.

One trusted CI root/kernel/issuer/source enrollment/Custody/backend and locally
enrolled CA. No real Provider, external bank effect, new model inference or genuine
Utility measurement. Public/reproducible recipient keys remain synthetic. Issuer
rotation/revocation, independent administration, multiple concurrent issuers,
distributed CAS, storage rollback, power-loss behavior, host reboot recovery and
exhaustive production routes remain unproven. Fault/concurrency execution modes
remain separate historical HTTP proofs. Root can replace both state and anchor;
this fixture does not claim resistance to that trusted administrator.

**REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN**
