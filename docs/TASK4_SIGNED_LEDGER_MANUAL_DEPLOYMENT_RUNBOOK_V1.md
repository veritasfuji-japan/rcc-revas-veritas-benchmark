# Signed GitHub ledger: manual deployment preparation

Prepared against merged #524 source `85a659271a72538907c5d9462d57768772e68eac`.
This is a preparation runbook, not an executable deployment profile or approval
to create a ledger, generate a live key, issue a credential or dispatch a workflow.
The [adapter](TASK4_SIGNED_GITHUB_LEDGER_ADAPTER_V1.md) has only model-backed
GitHub evidence. Its remote result remains NOT_RUN.

**Current stopping point: DEPLOYMENT_BLOCKED.** Source now supplies
[create-once custody](TASK4_RECEIPT_KEY_CUSTODY_V1.md),
[retained startup](TASK4_RETAINED_SIGNED_LEDGER_SERVICE_V1.md),
[fixed HTTPS transport](TASK4_SIGNED_GITHUB_API_V1.md) and a
[manual existing-state entry point](TASK4_SIGNED_LEDGER_ENTRYPOINT_V1.md), plus
[create-only administration](TASK4_SIGNED_LEDGER_ADMIN_V1.md).
Actual isolated writer provisioning, approved root/enrollment, TLS/role custody,
protected runtime installation and remote evidence remain open gates. The existing manual workflow
`task4-github-ledger-research-v1.yml` runs the older one-operation metadata
experiment; it cannot execute this signed eight-slot service. Do not enter a
new key/root into that workflow or rerun its bootstrap for this purpose.

The [fixed synthetic manifest and manual role client](TASK4_SIGNED_LEDGER_CLIENT_V1.md)
now provide client-side preparation and explicit single-attempt operations after
separate source/identity/root/enrollment approval. Their tests use model storage;
they do not close actual deployment, remote reachability or independent enforcement gates.

`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN`

## 1. Establish a usable host before creating secrets

An operator-controlled Linux VM on an existing computer is a possible research
host, conditional on available storage, a supported virtualization setup and
reviewed access boundaries. No hypervisor/OS version has been selected or
installed by this runbook. A Mac can be assessed when available; do not erase or
repartition it as part of this preparation.

Record the VM/host owner, OS, available disk/RAM, private storage location,
service account and the period it can run during the experiment. It need not
run permanently: while unavailable, clients must stop. Sleep, network loss or a
VM shutdown is not evidence that an earlier mutation failed and never permits
automatic re-enrollment or resend.

The current listener accepts only loopback. A VM alone does not make it
reachable from a GitHub-hosted Runner. A remote endpoint, its hostname/CA/pin,
network exposure and client credential delivery require a later reviewed
implementation. Opening a router port or installing a tunnel/self-hosted Runner
is not a step authorized by this runbook.

## 2. Define custody and role ownership

The [create-once receipt custody utility](TASK4_RECEIPT_KEY_CUSTODY_V1.md)
provides explicit key initialization and pin-required reopen. The retained
startup and manual entry point explicitly use reopen only; initialization is
never part of startup. These interfaces do not remove the remaining deployment gates.

| Material | Intended holder | Public review value |
| --- | --- | --- |
| Stable Ed25519 service receipt key, raw 32 bytes | Dedicated authority-service account on retained private storage | Raw 32-byte public key and its SHA-256 |
| GitHub backend write credential | Authority service only | Repository, permission scope, identity, expiry/revocation plan; never token bytes |
| Issuer authority/grant key | Issuer service | Public-key SHA-256 in the approved run binding |
| Custody authority key | Custody service | Distinct public-key SHA-256 in the approved run binding |
| Service TLS key/certificate | Authority service | CA, approved hostname and full DER leaf-certificate SHA-256 |
| Issuer TLS key/certificate | Issuer service | Full DER certificate SHA-256 mapped to issuer authority digest |
| Custody TLS key/certificate | Custody service | Distinct full DER certificate SHA-256 mapped to Custody authority digest |
| Test CA signing key, if a private research CA is used | Trusted test administrator, outside client/runtime access | CA certificate and approved issuance/revocation policy |

Native/ordinary-agent/scorer processes must receive neither the receipt signer
nor backend write credential. TLS keys are distinct from authority/grant keys;
the administrator approves the mapping between their public identities. Client
JSON or a shared repository token cannot choose those mappings. The test fixtures
in the rehearsal scripts are temporary synthetic material, not deployed keys or
an enrollment mechanism.

Create service/client directories under trusted ancestors, outside every Git
checkout, workspace, artifact directory and cloud-synced folder. The current
reference loader requires each configured file to be a regular single-link file
owned by its runtime account, mode 0600, in an owned 0700 immediate parent.
Different roles need separate accounts/access, not only separate filenames.
Those filesystem metadata checks alone do not prove OS isolation or protection
against a privileged administrator replacing paths.

Generate the service receipt key once only after the host/custodian and exact
creation procedure are approved. Use exclusive creation; an existing path,
missing key, wrong mode, unreadable storage or changed public digest must stop.
Do not generate a new signer at service startup. Do not import CI fixture keys,
post private material in chat, or transfer it through logs/artifacts/Git.

A service process restart must reopen the same protected key. A VM snapshot or
backup contains sensitive material and may duplicate a signer; it is not a
monotonic authority witness. Backup/restore and rotation need an explicit trusted
administrator procedure preserving consumed records. If the key is lost or a
restore is uncertain, stop the experiment. Do not replace the signer/root or
start a new namespace to resume the same authorization.

## 3. Review public identities and an explicit approval record

Complete this record with actual values through a reviewed administration path.
UNSET is a blocking state, not a value to paste into GitHub. Public fingerprints
may be reviewed; secret key/certificate-key/token bytes must never appear here.

| Required field | Prepared value / current status |
| --- | --- |
| Exact execution source commit and reviewed file hashes | UNSET for remote execution; #524 is the model-tested implementation baseline |
| Repository | `veritasfuji-japan/rcc-revas-veritas-benchmark` |
| Proposed state branch | `refs/heads/research/task4-signed-ledger-v1` |
| State schema / scope | `task4.github-signed-ledger-state.v1` / `SYNTHETIC_SIGNED_LEDGER_ONLY_NO_PROVIDER` |
| Root state's reviewed_source_base field | Fixed by #524 as `266f9add41daf94a778f247a6f3c0560318e2da2`; this is metadata, not the future dispatch source |
| Ledger ID | Compute from the reviewed adapter's fixed repository/branch/schema; confirm with empty root and each binding |
| Receipt service public key and SHA-256 | UNSET; owner/custodian approval required before root creation |
| Namespace existence/read-only inspection | UNVERIFIED for deployment; an unexpected existing ref stops create-only bootstrap |
| Approved parentless genesis commit OID | UNSET; old experiment genesis is incompatible and must not be substituted |
| Issuer/Custody authority public-key digests | UNSET; distinct actual approved keys |
| TLS CA/hostname/server pin and two role mappings | UNSET; remote transport is not implemented |
| Host/service account and key/writer credential isolation evidence | UNSET |
| Synthetic manifest digest and fresh 64-hex authorization run ID | UNSET; do not reuse prior experiment IDs |
| Backend writer identity, permission and expiry/revocation | UNSET; broad repository writers/administrators remain trusted |
| Registry retention, rollback/restore assumptions and key retirement | UNSET; no automatic pruning/reset |
| Remote execution profile, operator and explicit approval | UNSET; no real-API command/workflow supplied by this document |

The service public-key digest means SHA-256 of raw Ed25519 public bytes. TLS pins
mean SHA-256 of the entire DER leaf certificate, not its PEM text, fingerprint
display string, CA certificate or subject name. Keep these representations
distinct when reviewing a future setup procedure.

## 4. Required create/enroll procedure for a future implementation

The create-only administration CLI now implements these root/enrollment
requirements in offline tests. Actual execution requires separate owner approval
and operator provisioning. The existing-state service entry point never performs them:

1. Perform read-only namespace/source/identity checks. Validate the approved
   fixed repository, ref, service signer and synthetic-only scope before making
   any mutation. Never discover a replacement root from a latest artifact.
2. On explicit owner-approved bootstrap only, create one tree containing the
   bounded canonical empty signed registry, a parentless commit and the fixed
   ref using create-only semantics. Require exact readback of the root and
   signer digest. No update-ref/force/delete/repair or alternate branch fallback.
3. Review and approve the actual genesis OID before enrolling an experiment.
   A lost bootstrap acknowledgement requires read-only inspection of the fixed
   namespace. Neither failure nor an existing ref authorizes another bootstrap.
4. Enroll the approved exact binding with a fresh authorization ID through
   dedicated administration. Preserve every prior run/tombstone; reject an ID
   already enrolled, even if manifest/keys/source changed. An ambiguous enrollment
   likewise requires read-only inspection, not automatic re-enrollment.
5. Start the signed service using only the approved source, root, existing key,
   TLS mappings and isolated backend credential. Ordinary clients expose only
   view/reserve/consume. Enrollment/key creation/root replacement are not client
   commands and must not run on startup.

The fixed registry has at most 32 runs, a 65,536-byte state bound and a 544-commit
ancestry bound. Whichever limit is reached first stops work. A separately
reviewed lifecycle decision must preserve rejection of old authorization IDs;
deleting records or changing epochs is not a capacity workaround.

## 5. Remote acceptance experiment and evidence requirements

Use synthetic material and list-append callbacks only. No SDK/Provider credential
or bank operation belongs in this experiment. Every remote test needs an exact
source, actual execution/job/host identity, approved root/binding, before/after
commits, signed receipt bytes/public verification and counts. Export bounded
public evidence only; keep keys, credentials, private configuration and raw
storage outside artifacts. A reviewed sanitizer/exporter is still needed.

The normal case must demonstrate real expected-head acceptance, commit readback
before the exact service signature, one permitted callback and a rejected
competitor. Verify issuer/Custody role crossing and a separate read-only writer
probe against the actual deployment, not only the model.

For committed-but-unverified API acknowledgement/readback, require no mutation
signature and no callback. For a committed service receipt lost in transport,
require no callback despite retained consumption. A fresh service/client must
see that state and refuse reissue/replay. Distinguish controlled response discard
from an actual network failure; evidence must say which boundary was injected.
Never rerun failed jobs or refresh/retry the same permission mutation to obtain
a successful-looking result. Read-only reconciliation cannot authorize a resend.

Separate fresh hosts/Runners, stable key reopening, real storage durability,
credential denial and privileged rollback assumptions need their own evidence.
Temporary keys, a fresh object sharing a memory model, VM cloning, a Verified
commit badge or a successful PR CI cannot stand in for those results.

## Stop and next action

Before real execution, prepare the protected module installation, dedicated
credential/access evidence and concrete public approval record. Preserve any
already-created receipt custody and its independent pin; do not repeat setup or
generate a replacement. If the host is unavailable, complete review and public
configuration planning only. No new mock fault matrix alone closes deployment.

Actual Native reservation-before-grant / consumption-before-send, Provider
credential/egress isolation, private archive/recipient lifecycle, independent A/B
measurement, current pricing and fresh owner consent remain separate gates in
the [restart audit](TASK4_PROVIDER_RESEARCH_RESTART_GAP_AUDIT_V1.md).
