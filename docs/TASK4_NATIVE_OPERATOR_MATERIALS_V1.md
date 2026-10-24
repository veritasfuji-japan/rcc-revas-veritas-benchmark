# Task4 operator preparation materials v1

## Problem and resulting behavior

The retained-signer public profile accepts a Native manifest and public TLS
certificates, but neither the old manual manifest nor CI fixture keys are valid
operator inputs. This tool creates separate, role-local preparation material
and joins its public exports to the already retained service identity and three
Native authority exports. It never starts a listener or Native execution.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remains unchanged.

## Administrative layout

Existing authority keys, the service configuration and the remote genesis are
never read, moved or changed by this tool. All new private files have mode 0600,
inside an exclusively claimed 0700 directory named
`native-materials-v1-<new-run-id>`. Existing, empty or partial directories burn
the claim. There is no reset, replacement, repair, resume or mutation retry.
A failure may leave usable keys without a completed public record; that is a
stop requiring separate review, not permission to remove the claim.

| Preparation role | UID:GID | Pre-provisioned home | Material |
| --- | --- | --- | --- |
| service | 109:110 | `/var/lib/veritas-ledger` | New P-256 ledger TLS key and CSR |
| issuer | 61105:61105 | `/var/lib/veritas-native-issuer` | New P-256 client TLS key and CSR |
| custody | 61106:61106 | `/var/lib/veritas-native-custody` | New P-256 client TLS key and CSR |
| backend | 61103:61103 | `/var/lib/veritas-native-backend` | New P-256 local scripted API TLS key and CSR |
| archive | 61107:61107 | `/var/lib/veritas-native-archive` | New X25519 response recipient key |
| ca | 0:0 | `/var/lib/veritas-native-tls-ca` | Separate P-256 synthetic root CA |
| reader | 61109:61109 | Existing readiness directory | Public assembly only; no new key |

Provisioning accounts and checking UID/GID collisions are separate administrator
steps. Every listed home must already be owned by its role and mode 0700. No
account, home or directory permission is provisioned by the CLI. UID/GID and
supplementary-group checks occur before key creation. Root cannot select a
nonroot role to silently create that role's key. The existing service's GID 110
is deliberate; its signing key stays in its original custody slot.

Backend UID 61103 and archive UID 61107 reflect the closed-local Native source
profile. They require independent VM provisioning; their presence and the live
runtime's use of their new material are not inferred from a public export.
Runtime authority UID 61108 gets no TLS/recipient key from this module.

## Staged handoff

Use a reviewed protected source/interpreter, `-I -B`, and the explicit namespace
bootstrap documented in [public approval preparation](TASK4_NATIVE_GITHUB_APPROVAL_PREPARATION_V1.md)
when an older regular `scripts` package is also installed. The following CLI
argument examples contain review placeholders, not executable digest discovery.

1. Review the new run ID, account layout and the separately retained public
   bundle byte digest. Do not initialize a new ledger authority key. The
   `native-public-bundle-14dd236.json` already prepared on the VM remains a
   public input; no key regeneration is needed.
2. Under **each of the five material owners**, invoke `initialize --role ROLE
   --run-id RUN --acknowledge-create-synthetic-material`. It exclusively claims
   the fixed slot, creates one key, saves private `private.key` and public-only
   `public.json`, fsyncs, then reopens and checks private/public correspondence.
   Stdout is a report with `public_record` and `public_record_sha256`; retain
   the latter separately. It contains no private key. `inspect --role ROLE
   --run-id RUN --expected-export-sha256 PIN` checks the saved record, UID,
   mode, single-link key, directory/file identities and key correspondence.
3. Transfer **only the five exact public records**, retaining each independent
   record digest. Assemble a public document with schema
   `task4.native-preparation-materials.v1`, this module's `scope`, `run_id` and
   `exports` containing exactly `service issuer custody backend archive`.
   Validate it with `validate_materials`, save canonical bytes exclusively and
   retain its byte SHA256. The root CA must receive a reviewed, root-owned
   public copy: reader-private files intentionally are not a distribution path
   to other roles. Public-input reading permits trusted root/effective-UID
   ancestors, an owned/root-owned single-link 0600 or 0644 file and a trusted
   parent; it requires an externally retained digest.
4. Under root, `issue-ca --materials FILE --expected-materials-sha256 PIN
   --acknowledge-create-synthetic-material` verifies all public records before
   claiming its separate CA slot. It creates one CA and four seven-day leaf
   certificates from the exact signed CSRs. Each CSR must have the exact
   role/run subject, P-256 public key, valid proof-of-possession signature and
   only the prescribed hostname extension. CA privileges, extra extensions,
   substituted roles and arbitrary hostnames are rejected. CA private bytes
   remain only in its root-private slot. Its public report has schema
   `task4.native-preparation-certificates.v1`, the canonical materials digest,
   exact run and five public PEM certificates.
5. Retain and separately pin that public certificate package. Each TLS owner
   can call `install-certificate --role ROLE --run-id RUN
   --expected-export-sha256 PIN --materials FILE
   --expected-materials-sha256 PIN --certificates FILE
   --expected-certificates-sha256 PIN`. It checks its retained private/public
   pair, the package/run/CSR joins, signatures, validity and distinct keys, then
   creates `certificate.pem` exclusively in **its own new slot**. Repeating the
   installation stops; it cannot overwrite a certificate. It does not install
   a CA, create a service config or reload any process.
6. Under reader UID 61109, use `assemble --public-bundle FILE
   --expected-public-bundle-sha256 PIN --materials FILE
   --expected-materials-sha256 PIN --certificates FILE
   --expected-certificates-sha256 PIN --execution-source COMMIT40
   --not-before UNIX_SECONDS --expires-at UNIX_SECONDS`. This opens only public
   documents. It validates the retained genesis/signer, three Native authority
   exports and the material package. `raw_recipient_sha256` is computed from
   the actual exported X25519 public bytes; `local_leaf_sha256` is computed
   from the local scripted API leaf DER. The ledger's own TLS certificate is
   **not** used as that API identity. The manifest uses the exact fixed Native
   synthetic task and unchanged request budgets (four per arm).
7. Save **only `public_record`** from the assembly report as the canonical
   retained-signer public-preparation input. It is accepted by the existing
   `candidate`, `review`, and explicit root `render-approval` sequence. Retain
   its byte digest, producer source digest and all upstream public documents
   as preparation evidence. Approval installation and a dedicated GET-only
   credential remain separate steps; this tool creates neither.

The CLI rejects missing and irrelevant options and uses a constant STOP error
without raw filesystem/key/exception text. All stdout records are public.
Use exclusive output creation and fsync when saving them; never redirect private
files or an entire private slot into a report or repository.

## Boundary and limitations

* The new CA can issue only these four prescribed synthetic role/host leafs in
  one create-once call. It is not installed in OS trust, OpenSSL environment,
  browser trust, `/etc/hosts`, DNS or a running server. The backend hostname is
  `api.openai.com` because that is the existing **isolated local scripted**
  fixture's name; this certificate does not establish public Provider identity
  or authorize contact with the real hostname. No connection is made.
* X25519 recipient and TLS keys are distinct algorithms from all Ed25519
  application authority keys. All five TLS public keys (CA and four leaves)
  must also differ. The archive owner remains separate from custody/runtime.
* The explicit Native window is at most 300 seconds. Assembly preserves the
  exact timestamps; it does not choose, extend or refresh them. Read-only
  diagnostic candidates can describe an expired/future window. They are never
  execution permission. A later execution path must perform its existing
  execution-time checks and cannot interpret diagnostic readiness as ALLOW.
* `execution_source` is an operator-reviewed commit declaration; the producer
  cannot attest a Git checkout or installed interpreter. Existing readiness
  pins still cover 11 selected sources plus the retained profile's three, not
  all imported dependencies or the Python runtime. This new producer's hash
  is reported separately and retained with preparation evidence; it is not
  silently added to or represented as part of those 14 approval pins.
* Public record/CSR matches do not independently establish operator origin,
  role UID enforcement on another host or a live mTLS handshake. Owner-side
  inspection verifies a local pair but is not independent attestation.
* This change does not apply Native runtime profiles, provision journals,
  install grants, enroll a remote Native run or change the old service's bound
  manual run. It creates no socket, DNS lookup, GitHub request or Provider call.
* Same-UID replacement, root compromise, host rollback, independent clock
  trust, hardware power-loss durability, full PKIX/revocation and production
  deployment are outside this evidence. Root necessarily controls its own CA;
  its trust in public input still requires an independent review.

## Validation

The targeted suite exercises create-once claims, failure after private-key
persistence, pinned inspection, symlinks/hardlinks/modes, CSR signature and role
substitution, certificate/key/run joins, exact time retention, unchanged genesis
and service signer, and the existing candidate validator. Socket creation is
forbidden in the unit fixtures. A mandatory root-capable CI case creates keys
as their actual UIDs, issues the CA as root, installs four owner-matched leafs,
and verifies **25 actual PermissionError private-read denials** between the five
nonroot material owners and the other owners/root CA. It uses temporary homes,
not the VM's fixed `/var/lib` paths, and retains the JUnit evidence. No test uses
or asserts production deployment or real Provider permission.
