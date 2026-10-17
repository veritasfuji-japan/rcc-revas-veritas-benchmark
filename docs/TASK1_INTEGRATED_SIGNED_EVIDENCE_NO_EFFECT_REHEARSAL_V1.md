# Task1 signed-evidence integration rehearsal — NO-EFFECT V1

**Purpose**: a *single manual, no-cost-provider, synthetic* integration rehearsal connecting the offline Ed25519 candidate verifier from PR #430 to a fail-closed **non-authorizing** final boundary. It does not create or modify real Rulesets, refs, secrets, projects, or paid-provider requests.

## How to run AFTER reviewing and merging the draft PR

Actions → **Task1 Integrated Signed Evidence NO-EFFECT Dry Run V1** → Run workflow on `main`, exactly **once**. Do **not** select the existing **Task1 Native First Two Chat A/B PROTECTED MANUAL V1**, which is paid-capable and remains **NO-GO**. Do not retry the older failed paid Runs #39010798949 or #39018816423.

The new workflow is `workflow_dispatch`, bound to the repository owner, `main`, and first run attempt. It has `permissions: contents: read`, a pinned checkout and Python setup, no persisted checkout credentials, no Environment, no Provider API secrets, and no tag-create permission. It installs the sole offline Ed25519 verification dependency `cryptography==50.0.0` and runs offline tests + synthetic dry run. It does **not** expose `github.token` to the Python step or interact with GitHub REST at runtime.

GitHub Actions usage itself can count toward account runner minutes; this script does not incur OpenAI model usage.

## What is actually exercised

- The **synthetic, publicly known** fixed Ed25519 key constructs a made-up Ruleset snapshot. It is not a privileged GitHub Ruleset read and is never a production signing key.
- Each **manual** Actions Run binds its simulation to its own `GITHUB_SHA`, `GITHUB_RUN_ID`, and a new cryptographic random nonce (not logged).
- It invokes the **existing** `review_candidate_offline` from PR #430 and verifies a matching synthetic signature remains `EVIDENCE_VALID_OFFLINE_NOT_DISPATCH_AUTHORITY`.
- Adverse cases check post-signature tampering, stale evidence, omitted and nonempty bypass lists, mismatched run/SHA/nonce, no enrolled key, consumed or unknown singleton assertion, and changed/missing privileged Ruleset revision.
- The final **simulated** issuance decision is always `NO_GO_UNTRUSTED_SYNTHETIC_SIGNER_AND_NO_ATOMIC_POLICY_FENCE` on any syntactically valid offline evidence, or `DENY_NO_VALID_SIGNED_EVIDENCE` otherwise. There is no possible approval, Git ref write, or Provider dispatch branch.
- The run prints only coarse static labels, case outcomes, a count, and missing production prerequisites. It does not print the private key fixture, nonce, signatures, API token, or actors.
- Workflow success means the **expected refusals worked**. It is *not* the success of privileged attestation or a live A/B run.

## Real integration blockers that this drill explicitly leaves OPEN

| Missing production property | Why the dry run cannot satisfy it |
| --- | --- |
| Privileged Ruleset observation | No GitHub administration-authorized observer or real Ruleset GET with visible `bypass_actors` |
| Enrolled and revocable trusted signer | The signer is public synthetic fixture; nobody should trust it for real privilege |
| Independent fresh evidence | The Ruleset `updated_at` and tag absence are local **hypothetical** inputs, not authenticated readback |
| Administrative change/race control | Two REST GETs and a signature cannot prevent Ruleset edits between read and ref creation |
| Real immutable singleton tag issuance | No POST to GitHub, no tag rights, no readback, no retries |
| Paid Provider authorization | Prior consent is bound to superseded code; exact current SHA and spend require new explicit approval |

**Decision always: NO-GO.** Do not modify the existing paid-capable workflow, weaken Ruleset #24921425, change main protection settings implicitly, or manually create the singleton tag.

## Exit criteria for the *next* engineering phase

An independently reviewable privileged observer/key enrollment proposal must be real, appropriately permission-scoped and protected from the execution runner. A separately enforced method must bind fresh policy integrity through the issue-time ref write **without an unchecked Ruleset administration race**. Then demonstrate fail-closed behavior in a no-Provider/non-production-tag isolated environment. Only after that should a new paid dispatch approval be requested for a reviewed main SHA, model, case and billing risk.

Related: Issue #427, PRs #428–#430, `docs/TASK1_PRIVILEGED_RULESET_ATTESTATION_OFFLINE_V1.md`.
