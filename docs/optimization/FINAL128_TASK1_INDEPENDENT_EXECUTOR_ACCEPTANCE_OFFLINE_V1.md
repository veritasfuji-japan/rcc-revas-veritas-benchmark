# Task1 — Independent Executor acceptance contract V1 (OFFLINE / NO-GO)

**Status:** inert, source-owned architecture requirements only. **No deployed executor, no paid Task1 authorization. Issue #427 remains OPEN / NO-GO.**

## Scope of this PR

Four new files: this document, a strictly typed JSON trust-domain contract, a pure-data validator and 25 offline test cases (count from isolated local run). No modifications to existing .github/workflows, the #423 live sender, pinned benchmark inputs, secrets, GitHub Environment, production/research tags or Rulesets.

The acceptance contract separates issuer, untrusted GitHub Runner, independent Provider executor and independently controlled shared durable ledger. It lists exact deny-by-default behavior and hard blockers. The validator checks source-owned JSON integrity; self-asserted evidence flags can never authorize a paid call. Ordinary PR CI can run tests but no manual dispatch, Provider POST, billing or scoring is requested.

## Existing evidence and outstanding boundary

- #423 exposes the Provider HTTPS sender and production tag create/readback inside one manual Actions job with contents:write. No independent Provider egress gate is wired into that path.
- #405 and #410–#412 tested separate process, distinct Linux UID, issuer, mock mTLS/network boundary and real VERITAS Bind on synthetic effects; none is the live Provider endpoint or remote cross-Runner Task1 ledger.
- #437, #442 and #445 establish mock signed handoff, local fake Provider checks and an inert issuer/sender job blueprint. Caller-supplied Job IDs are not authentic GitHub OIDC evidence.
- #446 joins signed mock handoff, per-arm SQLite atomic reservation and local fake Provider calls, including separate OS process contention. The shared SQLite *file* does not survive independent ephemeral Runner stores, and the fake port can be called outside its in-process gate.

## Minimum future executor boundary — NOT IMPLEMENTED

1. **Issuer** must be an independently enrolled signing principal; cannot see Provider credentials or mutate the remote ledger. Actual issuer enrollment and permission issuance must be audited externally.
2. **GitHub Runner** remains an untrusted orchestrator: no Provider key, no issuer private key, no direct Provider egress, no ledger reset/delete permission. Permission declarations or job IDs alone are not enforcement.
3. **Executor** alone holds Provider credentials, authenticates the real caller and signed recipient-bound permit, independently verifies fresh human consent and executes real VERITAS Bind at the final send boundary. All alternative credentials and direct Provider egress paths must be denied by installed IAM/network controls.
4. **Remote shared ledger** must be independently controlled and atomically persist UNKNOWN before any attempted Provider POST. New Runs, retries, reordered B requests or different Runner machines cannot regain an already consumed arm. On ambiguous response, corrupted receipt, missing ledger, mismatched permit or remote outage: STOP, no automatic retry.
5. **Evidence review** must verify installed secret custody, identity, cross-Runner atomicity, denial of alternate network/credentials, crash/replay cases, provenance and provider billing controls. The #423 direct-send path must be cut over or disabled before claiming non-bypassability.

The model lease key deliberately excludes a GitHub Run ID: a new Run must not reset an approval/arm. The final uniqueness definition, approval digest collision scope, consent expiry, revocation and credential rotation require separate design review; JSON requirements are not an actual lease service or independent permission system.

## Current proof matrix

| Requirement | Status |
| --- | --- |
| Inert four-domain acceptance contract / local denial tests | Local design integrity only |
| #446 signed local fake-send + same-DB SQLite persistence | Already demonstrated locally |
| Enrolled issuer / independent executor actual IAM | **NOT PROVEN** |
| Shared remote atomic store across Runners | **NOT PROVEN** |
| Executor-exclusive API key and no-bypass egress | **NOT PROVEN** |
| Real Bind wired immediately before #423 Provider request | **NOT PROVEN** |
| Independently enforced Provider spending hard stop | **NOT PROVEN** |
| Fresh paid Task1 approval | **NOT GRANTED** |

## Merge criteria and restrictions

- Exactly four **new** non-workflow files; no edits to #423, tag or credential configuration.
- Local tests block external socket calls and clear common environment credentials. Existing normal PR checks must pass at the reviewed commit. Offline PASS is not an IAM or live-effect proof.
- Mutations allowing credential leakage, local-only ledger, weak replay key, post-UNKNOWN retry, fail-open on ledger outages, B-first send or a forged PROVEN status must be refused.
- Keep Issue #427 open and paid Task1 NO-GO; no workflow_dispatch, production ref consumption, Provider request, official utility/scoring or fresh consent inferred from PR creation or merge.

**Bottom line:** A machine-checkable architectural acceptance target, not an actual independent Executor deployment. The next operational proof requires separately managed identities, remote store, genuine egress enforcement and audited integration with #423, under a new scoped review.
