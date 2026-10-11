# PR #312 — Protected Issuer, Credential & Egress Boundary Architecture V1

## Decision and scope

**Design decision:** A green Task4 PostgreSQL receipt is necessary evidence of
committed *test-only* consumption, **not** a sufficient execution permission.
Execution cannot be safely delegated to an agent, an ordinary PR workflow,
or the same process that creates its own approval.

This PR supplies a **non-deployed reference trust graph**, exact source pins
for #310 and #311, a negative-test attack-path verifier, and a concrete
production control evidence checklist. It does **not** deploy infrastructure,
inspect the organization's actual settings, obtain credentials, create
approvals, access OpenAI, perform a bank action, or score Final128.

A reference graph with zero attack paths proves only an internal property
*given the declared graph*. It cannot establish that all real world IAM,
network, vault, inherited privileges, service accounts or breakglass paths
have been enumerated.

## Five separate security identities

| Trust domain | What it may do in the proposed design | What it must never do |
|---|---|---|
| Agent, PR runner, ordinary CI, repository author | Produce untrusted action proposals and run mock/offline tests | Mint/consume production grants, load Provider credentials, assume protected sender role, access Provider egress |
| Fresh human approver + isolated issuer | Approve exact proposed request, case/model, expiry, one-call limit, spend conditions; issue a **separate immutable grant** | Use the Provider key, make Provider POSTs, unilaterally mark an external response as authentic |
| Independently administered grant ledger and breakglass admin | Store immutable scope, atomic consume-before-send + committed receipt and externally checkable audit | Allow silent privileged mutation, reset an already consumed grant, hand off fixture-only receipts as live authority |
| Protected sender and receipt verifier | Verify already committed exact grant and receive a short-lived credential via a separate broker; a proposed sender could submit only over an enforced egress proxy | Self-approve, issue/restore a grant, retry remotely ambiguous POSTs, bypass network/identity checks |
| Provider secret broker, egress proxy, billing owner, audit sink | Independently enforce workload identity, restricted egress, actual account controls, append-only evidence | Return usable secrets to a PR runner/agent, rely on a self-reported budget, trust a local hash as a production credential |

**Never merge roles merely to simplify a single-call test.** This reference
does not prove separation of a cloud administrator or a compromised database
superuser. #311 explicitly demonstrated a privileged database owner bypass.
A real deployment must address this with independent administrative
accountability and externally controlled event capture/alerting.

## Graph threat test and interpretation

The verifier models 19 principals/services and 19 declared capability
edges. Five untrusted source identities may touch only mock/public data.
The protected targets include the issuer, ledger, receipt verifier,
sender, vault, egress, Provider API, billing control, audit store and
breakglass administrator.

The suite injects bypass edges such as:

- agent → issuer: forged fresh approval;
- PR runner → protected sender: workload identity assumption;
- regular CI → egress proxy: direct Provider route;
- repository author → database breakglass admin: elevated mutation;
- mock executor → Provider API: unexpected real network transport;
- isolated issuer → Provider key: privilege co-location;
- protected sender → issuer: self-issuance and replay.

Reachability analysis plus an exact edge allowlist must reject each
unreviewed path. **The mock graph being safe is not a claim that the
current GitHub workflows or any production tenant are safe.**

## Proof gates before even one real prospective Provider request

Each item requires independently produced and attributed evidence,
not editable JSON claiming \`approved=true\`.

| # | Gate | Required evidence owner |
|---|---|---|
| 1 | New, narrowly scoped human approval, request hash, model, maximum one POST, expiry, spend | Human approver |
| 2 | Unforgeable issuer workload identity, separate from source author/CI/sender | Independent security admin |
| 3 | Protected cross-run immutable grant/ledger and atomic consume | Independent data admin |
| 4 | DB administrator breakglass paths audited outside that same DB | Independent security admin |
| 5 | Vault/broker exchanges a short-lived key only for attested protected sender | Secrets owner |
| 6 | Provider egress physically forbidden to PRs, agent and ordinary CI | Network owner |
| 7 | Reviewed sender artifact pin and protected deployment identity | Release owner |
| 8 | Fresh Provider model price/usage and independently enforced financial controls | Billing owner |
| 9 | Trusted current issuer clock + exact real request/context/native prestate | Trusted issuer |
| 10 | Independently read **committed** receipt before any network action | Sender owner |
| 11 | One attempt, transport retries disabled, unknown remote result remains spent | Sender owner |
| 12 | Durable externally reviewable audit record, no silent grant reissuance on rerun | Independent auditor |

All twelve statuses are **NOT_ATTESTED** in #312. The reference model
does not examine external configuration, so it cannot change a status
to proven. The previous real Provider consent is still consumed at
\`refs/tags/task4-third-two-real-provider-v1-consumed\`, target
\`95ff6be8c5875ed3827a00fe71fb54bd9de48130\`.

### After a separately authorized live call

Three further evidence gates can be checked *only after actual
observations*: Provider-origin request ID/model/usage and authenticated
correlation; real native RCC/VERITAS Bind, IAM/network bypass refusal and
effect reconciliation; and independent held-out model utility, injection
and scorer provenance. Pre-send safety must not be confused with
post-send scoring or a Final128 proof.

## Recommended deployable architecture decision for the next phase

The owner must first select a real infrastructure/security administrator
and a suitable protected backend. A possible architecture to evaluate is:

1. Separately managed approval API and identity provider, with signed
   immutable grants **created only after new scoped human authorization**.
2. Managed PostgreSQL with strict roles and an independent append-only
   receipt trail; use committed consumption before releasing a sender
   credential. Never reissue after a crash without external reconciliation.
3. Locked-down sender workload using provider-specific workload identity;
   vault access from that workload alone, no PR execution context.
4. Network egress through an independently enforced allowlist/proxy
   with deny-by-default routes for all ordinary runners and agents.
5. Out-of-band billing controls and auditable rate/token/call caps.
   An estimated $0.0044096 from a historic fixture is **not** a live
   Provider billing or project hard-stop guarantee.
6. Independent attack tests: alter GitHub workflow, compromise normal CI,
   replay a grant, mutate a DB receipt, abuse a privileged DB admin,
   access vault as a fork, bypass egress, timeout a Provider transport,
   rerun cancelled jobs, and test simultaneous send attempts.

**Do not implement these as publicly configured fixture passwords or
grant a GitHub Actions job the production Provider key.** Actual
cloud/project/service details, credentials and costs remain undecided.
The next implementation proposal requires a deployment choice,
separate infrastructure ownership and explicit cost approval.

## Exact bounded proof and stop conditions

Git pin root: merged PR #311 main
\`333e1b4d5e2a1b1bf5fb1d8717bea2d3599532f4\`.
Previous fixture SQL/script/workflow blobs are checked exactly; a
mismatch fails the dedicated audit.

Success means: deterministic local role-graph constraints and rejection
of unauthorized capability edges, fake attestations, changed source pins,
weakened invariants, removed controls and real-key environments.
It must report **BLOCKED_NOT_ATTESTED_NO_REAL_PROVIDER_DISPATCH** even
when every test is green.

No API client is instantiated. No secret is used, no actual approval is
issued, no request reaches a Provider, no banking effects occur, and no
official benchmark score changes. PR #312 must remain Draft until
latest-head CI, JUnit, evidence JSON and artifact digest are verified.
Do not auto-merge. A separate fresh, explicit scoped human approval
would be required for any later real paid Provider call.
