# PR #313 — External Control Readiness & Infrastructure Selection Preflight V1

## Exact scope / rule of one

**Rule of One:** A source-controlled plan, self-attested checklist, or apparent
infrastructure choice MUST NOT be promoted into execution authority. Keep every
pre-send production control **NOT_ATTESTED**, all eight infrastructure decisions
**UNDECIDED**, and live Provider dispatch **DENY** until the responsible owner
makes a separate decision and an independent operator supplies authentic
external evidence.

This is **offline / non-deployed**. No cloud provisioning, no new IAM identity,
no privileged database or network access, no secret, no real approval, no
OpenAI call, no bank effect, no Final128 evaluation. The previous real-Provider
approval remains **spent**; this PR neither renews it nor consumes another one.

Parent pinned #312 merged-main:
`a04ed01396e8d7a35ef82f437db1a93e28bd4762`.
Consumed historical permission tag target:
`95ff6be8c5875ed3827a00fe71fb54bd9de48130`.

## Decision prerequisites — not a deployment recommendation

The project owner must choose a real-world security boundary and explicitly
authorize any recurring resource cost before production-bound work. This PR
deliberately cannot make that choice or infer it from a passing CI job.
The candidate categories below are **patterns to assess**, not endorsements:

| Pattern | Possible use | Why it does not itself prove a safe execution boundary |
| --- | --- | --- |
| Local-only PostgreSQL / Docker with fake credentials | Cheap offline function and attack harness | Host and DB superuser can change grants; local tests do not establish an independent security or network boundary |
| Independently operated managed runtime, SQL ledger, vault and restricted egress | Candidate for later attested deployment | Must verify actual IAM policies, tenancy, credential use, network enforcement, costs and external audit |
| A protected CI environment with approvals | May help release engineering and artifact integrity | Approval workflow alone is not a separate issuer, protected sender, vault, independently administered ledger, or physically enforced outbound network block |

**Cost rule:** There is no approved paid budget or infrastructure contract
recorded in this PR. No provider pricing, free-tier availability, hard spending
ceiling or model-call price is certified. The safe default is to keep everything
offline and require a separate explicitly scoped owner decision before any
expense, service registration, or externally billable operation.

## Eight owner decisions outstanding

1. Identity provider and verifiable workload identities
2. Protected issuer runtime, inaccessible to PR/ordinary CI and agents
3. Independently administered ledger plus DB-superuser breakglass audit
4. Short-lived secret/token broker accessible only to protected sender
5. Protected sender workload and independently pinned build/deployment
6. Physically enforced deny-by-default Provider egress
7. Out-of-band append-only audit sink outside ledger admin control
8. Independently checked Provider pricing, token/attempt limits and billing

For each choice the owner must later identify actual tenant/account, product,
independent administrator, cost envelope, and separately attributable
evidence. Filling these cells in a Git commit does NOT constitute proof.

## Mandatory 12 external attestations

The full canonical gate set is pinned to #312. All remain
`NOT_ATTESTED`:

| Gate group | What an external verifier must substantiate |
| --- | --- |
| Fresh scoped approval and issuer identity | Signed owner authorization, exact request/model/cost/expiry; issuer cannot use sender or PR identity |
| Single-use ledger and committed receipt | Independently maintained immutable grant, atomic consume-before-send, durable committed receipt, no silent reissuance |
| Privileged DB-breakglass | Audited admin access and independent alert/evidence capture even when a DB owner is compromised |
| Secret broker and protected sender | Only attested sender gets short-lived credential, pinned release, sender cannot mint grants |
| Network and billing | Physical egress denial for agent/CI and independently audited financial/rate limits |
| Time/context, retry and audit | Trusted request/prestate and expiry; ambiguous Provider outcome stays spent; append-only externally visible audit |

**These are evidence *requests*, not attestations.** A self-signed JSON blob,
CI green, screenshot, invented URL, internal SHA, fixture receipt or owner
assertion cannot upgrade any status. External checks require independently
obtained IAM policy exports, effective-permission tests, network-deny
observations, ledger privilege audit, audit-store verification and real billing
configuration, attributed to the relevant administration authority.

## Negative-case acceptance

An auditor must DENY when:
- any of the 12 gates is absent or marked passed;
- any of the 8 decisions is omitted or falsely claimed selected;
- a GitHub contributor or CI job claims to be an independent admin;
- a fabricated audit URL or user-supplied JSON claims proof;
- parent #312 frozen Git blobs or the consumed-permission tag no longer match;
- a test environment tries to import a Provider credential;
- a DB owner can replace an already-consumed record without an external
  reviewable event (known unresolved privileged bypass);
- sender or network protection is implied by policy comments rather than
  witnessed enforcement;
- any request proposes live Provider sending or a new score.

### Stop conditions and PR merge rule

Merge **only after** exact PR HEAD dedicated checks + existing checks, JUnit,
structured audit JSON and artifact SHA-256 are reviewed. The only allowed
successful conclusion for this PR is:

`BLOCKED_AWAITING_OWNER_INFRA_AND_INDEPENDENT_ATTESTATION`
with `DENY` for any live action.

A green #313 report proves only that the source-pinned **offline preflight
contract remained fail-closed**, not that cloud IAM, network isolation, DB admin
controls, vault privileges or paid-call safety work in reality.

Next stage requires an owner-chosen platform, identified independent operator,
explicit expense boundary and **new** scoped human consent before *any*
production-bound sending. A separate PR should use a different proof rule to
collect real external evidence. No automatic approval carryover.
