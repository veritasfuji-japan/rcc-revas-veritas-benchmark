# PR #314 — Offline Infrastructure Candidate & Independent Evidence Plan V1

## Rule of One / frozen source

**A platform comparison cannot issue execution authority.** No candidate is
selected or provisioned by this PR; no developer-supplied cost claim, CI log,
GitHub environment reviewer, signed fixture, cloud documentation, or claimed
separate admin proves a deployed VERITAS execution boundary.

- #313 merged-main root: `221ca18c00effdacbfd8d6d4d74aa181860ae857`.
- The five #313 implementation blobs are pinned exactly and independently
  verified by the offline script.
- Previous one-use real Provider approval remains consumed at
  `95ff6be8c5875ed3827a00fe71fb54bd9de48130`.
- 12 external pre-send gates remain **NOT_ATTESTED**.
- 8 administrative responsibilities remain **UNASSIGNED / UNVERIFIED**.
- Provider egress, database superuser, vault, actual billing controls and
  cloud IAM are not externally inspected.
- No paid cloud service signup, protected account creation, deployment,
  network POST, key access, fresh approval, bank effect, or Final128 score.
- Live dispatch **DENY** unconditionally.

## Candidate comparison — examples, not a provider procurement decision

| Candidate | Useful now | Possible architecture | Unresolved critical limitation | Pricing status |
| --- | --- | --- | --- | --- |
| **A. Local Docker + PostgreSQL fixture** | **Yes**, zero *new cloud provisioning* for offline correctness and negative tests | Mock issuer/ledger/sender/denied socket and local DB fixtures | One local administrator can alter DB, process or network; not independent production evidence | Incremental cloud service charges **not created by #314**; actual local resource costs not audited |
| **B. GitHub Actions protected environment alone** | CI and release testing only | Environment approvals, protected workflow artifacts and restricted token permissions | An environment check by itself cannot physically enforce runtime egress, independently administered DB and Provider secrets; a privileged repository owner may still change controls | Plan-specific spend and limitations **not verified** |
| **C. Google Cloud separated services** | Architecture candidate only | Separate Cloud Run service identities, managed PostgreSQL, secret management, VPC egress, external audit | Effective tenant IAM, issuer vs sender identity, *all-traffic* VPC routing, firewall deny and independent admin must be tested; default outbound routes are not automatically isolated | Actual quote, baseline DB and network charges, billing hard-stop **unknown** |
| **D. AWS separated services** | Architecture candidate only | Separate IAM workload identities, Lambda/container sender, managed RDS/PostgreSQL, Secrets Manager, VPC egress, independent audit | Effective IAM, DB owner powers, secret grant path, NAT/proxy reachability, append-only audit outside DB control must be tested | Actual quote, DB, NAT/network, audit charges, billing hard-stop **unknown** |

**Recommendation for a zero-budget stage:** continue Option A for **non-production
tests only**; keep B for read-only CI; research C/D on paper. This does not
select A, B, C or D for production and does not authorize any external costs.
There is no credible fully independent production attestation with the
single-person setup currently documented. Obtain an external administrator or
independent operator agreement before claiming it; no hired employee is
required by this document, but a real independent control owner is.

## Official documentation consulted (not external verification)

- [GitHub deployment environments](https://docs.github.com/en/actions/concepts/workflows-and-actions/deployment-environments) — approval and secret-release behavior; not a firewall.
- [GitHub privileged pull-request triggers](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target) — untrusted code and secrets must remain separated.
- [Google Cloud Run service identity](https://docs.cloud.google.com/run/docs/securing/service-identity) — service and deployer identities are distinct, permissions require configuration.
- [Google Cloud Run network egress security](https://docs.cloud.google.com/run/docs/securing/security?hl=en) — internet routing without an expressly enforced VPC pathway.
- [Cloud Run Direct VPC egress](https://docs.cloud.google.com/run/docs/configuring/vpc-direct-vpc) — network routes must be specifically configured and observed.
- [Amazon RDS authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/database-authentication.html) — evaluate IAM-based DB auth and DB privileges separately from full administrative control.
- [AWS Secrets Manager and RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html) — secret rotation/management mechanism; not evidence of separation.

Official product guides explain possible features, **not actual effective
permissions** and **not an independent priced quotation**. Current
free-tier eligibility, regional availability, per-resource charges and
hard spending limits are explicitly **NOT VERIFIED** here.

## Eight accountable role domains (currently no owner assigned)

`human_approver`, `security_issuer_admin`, `ledger_data_admin`,
`secrets_admin`, `network_admin`, `sender_release_admin`,
`billing_admin`, `external_audit_admin`.

These are **control domains**, not a claim that eight employees are
required. A single person controlling root IAM, DB superuser, cloud audit
sink and bypass routes has not met independent administration regardless
of how many service accounts they create. Exact same-person/root-account
authority and breakglass paths must be independently assessed. The prior
#311 privileged DB-admin bypass remains open.

## Twelve individually attributable proof requests

| Owner domain | Gate IDs | Required evidence |
| --- | --- | --- |
| human_approver | NEW_HUMAN_SCOPED_APPROVAL | New signed exact request/model/expiry/max attempts/spend, not recycled permission |
| security_issuer_admin | ISSUER_WORKLOAD_IDENTITY; EXACT_REQUEST_ISSUER_TIME_AND_PRESTATE | Actual effective IAM denies from CI/agent to issuer; trusted time and immutable request context |
| ledger_data_admin | PROTECTED_LEDGER_CAS | Protected cross-run atomic consume and independently viewed committed receipt |
| external_audit_admin | DB_ADMIN_BREAKGLASS_RECONCILIATION; INDEPENDENT_AUDIT_AND_NO_REISSUE | DB privileged owner cannot silently restore grant; independent append-only evidence and alerts |
| secrets_admin | EPHEMERAL_PROVIDER_SECRET_BROKER | Actual privileged sender alone can receive short-lived credential; CI and forks denied |
| network_admin | NETWORK_EGRESS_ENFORCEMENT | Observed physical egress DENY for agent/CI and sender-only allowlisted path |
| sender_release_admin | PROTECTED_SENDER_CODE_INTEGRITY; COMMITTED_RECEIPT_BEFORE_SEND; UNKNOWN_REMOTE_STATE_NEVER_RETRY | Pinned deployment and identity, independent committed receipt before send, timeout leaves token consumed |
| billing_admin | FRESH_ACCOUNT_BILLING_ENFORCEMENT | Current signed pricing/quote, independently enforced real call/usage/spend ceiling |

Each gate must carry the real organization's tenant identity, independent
evidence producer, effective-permission observation, timestamp, source
artifact, immutable external hash and clear **PASS/FAIL/UNKNOWN**.
Source-controlled status fields may **not** be set to PASS based solely on a
simulator or CI-generated manifest. This PR records zero external evidence.

## Actual external negative tests needed later — NOT run by #314

1. Change ordinary PR/workflow contents and prove issuer impersonation,
   vault access, grant issuance and Provider egress are all refused.
2. Impersonate DB owner/breakglass admin; require independent append-only
   audit plus refusal of silent approval restoration.
3. Attempt unreviewed sender deployment and grant replay across jobs.
4. Crash immediately after consume; do not resend on unknown remote state.
5. Use a fake approved-cost screenshot; compare with actual billing and
   provider account enforcement.
6. Verify actual Provider request ID and usage only after separate consent.
7. Independently observe RCC/VERITAS Native Bind and held-out scoring
   after separately authorized provider-bound evaluation.

### Cost and operational stop rules

No free-tier claim is guaranteed. **No new costs are approved or incurred by
a cloud provisioning step in this PR** because there is no provisioning step.
Do not instantiate a billable service or real Provider call as part of
GitHub Actions validation. Do not place a live Provider key in a repository
workflow or logs. Pricing and admin independence are blockers, not
warnings. An owner must separately accept the chosen platform, independent
administrator structure and hard cost boundary before any production-bound
implementation.

### Merge gate

Keep PR #314 **Draft** until exact HEAD dedicated CI, existing full checks,
JUnit (zero failures), machine-readable audit and Artifact ZIP SHA-256 are
recorded. If successful, the only valid proof statement is:
`BLOCKED_NO_OWNER_INFRA_OR_EXTERNAL_PROOF`, **live dispatch DENY**.

The #313 merge was confirmed, but its **post-merge push CI was not
independently confirmed** by available commit-run retrieval at PR creation;
do not silently upgrade that status. This is separate from #314's
self-contained PR-head CI and must be reconciled before declaring the
full #313 post-merge record closed.
