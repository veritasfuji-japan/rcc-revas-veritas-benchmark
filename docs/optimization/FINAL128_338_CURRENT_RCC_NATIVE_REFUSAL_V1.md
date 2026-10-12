# #338 — Current RCC candidate at VERITAS native authority boundary: refusal only

## Purpose and claim boundary

#337 exercised current public upstream RCC main `353ad9e6a17cda8874a129493fe0f8f4fe4427bc` with 36 partner fixtures, producing 12 prepared requests and 24 withheld cases. **This PR selects exactly one actually released RCC candidate from a newly executed local run**, takes its unmodified candidate and request provenance to the **real VERITAS OS source** pinned at `299a3c4987668091f50ab3e45165bcccd1ae193f`, and proves that the RCC decision lock, RCC hash, and original evaluation prestate cannot mint a native Canonical Decision Artifact or execution authority.

**Only refusal and nonpromotion are in scope.** No real `POST /v1/decide` is executed in #338; there is no legitimate VERITAS canonical decision, no native permission issuance or consumption, and no actual protected action. The separate Bind-core call below is an **UNVERIFIED synthetic refusal probe**, not a direct chain from a CDA-promoted ExecutionIntent. The positive fully connected path remains explicitly NOT PROVEN.

## Exactly executed (dedicated CI, no API keys)

1. Read-only pinned checkouts of real RCC main and real VERITAS OS with immutable Git HEAD and source blob checks.
2. Run unchanged public RCC v0.1.0 commands: `preflight → register-takeshi → evaluate → verify-artifacts → prepare-veritas`. Confirm 36-case accounting, then choose lexically first released case (stable deterministic selection).
3. Recompute that case's candidate, source/object hashes, decision lock, originally selected candidate, label-free evaluation prestate and `/v1/decide` request bytes with the public RCC's **actual** `build_decide_request`.
4. Call VERITAS's **actual** `verify_canonical_decision_artifact` on RCC's decision-lock. It must reject (a valid RCC lock is **not** a native CDA).
5. Call actual VERITAS `validate_decision_candidate` with unchanged RCC candidate nested as *untrusted metadata only*. Do not infer actor, target, approval, authority or native policy from candidate text. It must explicitly report `DECISION_CANDIDATE_AUTHORITY_UNSPECIFIED`, fail closed.
6. Call actual `try_promote_verified_canonical_decision_candidate_to_execution_intent` with RCC's decision-lock incorrectly presented as native CDA. It must refuse, produce **no ExecutionIntent**, and report `CANONICAL_DECISION_ARTIFACT_INVALID`.
7. For an independent **negative-only probe**, create a clearly labeled unverified in-memory ExecutionIntent carrying the same RCC semantic candidate hash as *non-authoritative evidence reference*. Call VERITAS's real `execute_bind_adjudication` and real `ReferenceBindAdapter` with `authority_signal=False`, preventing application. Assert BLOCKED, zero calls to `apply`, unchanged state. **This deliberately is not the actual promoted candidate's execution path**, since step 6 prohibited promotion.
8. Enforce tamper tests, no signing, no post, no actual bank or model, no Dispatch, no scores.

This establishes that a current RCC approval cannot be promoted by treating its lock as a verified VERITAS decision, and that the native Bind adjudicator rejects a no-authority synthetic probe. It does **not** establish current RCC → real `POST /v1/decide` → CDA → Native v2 Authorization → consumed permission → Effect/receipt continuity.

## Engineering gate

```bash
# Source roots must contain the exact two frozen HEADs;
# CI checks them before any operation.
python scripts/final128_338_current_rcc_native_refusal_v1.py \
  --upstream-root current-rcc-upstream \
  --veritas-root veritas-source \
  --output-dir results/final128-338-current-rcc-native-refusal

FINAL128_338_UPSTREAM_ROOT="$PWD/current-rcc-upstream" \
FINAL128_338_VERITAS_ROOT="$PWD/veritas-source" \
python -m pytest -q -o addopts= tests/test_final128_338_current_rcc_native_refusal_v1.py
```

No model, bank or VERITAS API credential is supplied. The CI job is read-only for source repositories and writes only ephemeral local artifacts. No actual HTTP `/v1/decide` call occurs. The global PR CI skips upstream-dependent checks instead of pretending they were run; dedicated CI must pass.

**Do not merge** until dedicated + global CI SUCCESS and evidence source pins, run/job/artifact and per-case refusal are checked.

## What remains after this PR

1. A separately designed adapter must produce a **genuinely native verified CDA from an actual VERITAS `/v1/decide` execution**, with the same candidate and original request identity still bound. No replay of a historical synthetic permitted candidate.
2. Independent policy authority and any necessary human approval must be obtained from VERITAS-owned trusted sources, not RCC's adoption.
3. Native v2 Authorization → atomic consume → pre-effect ownership → exact dispatch permit → effect-state/reconciliation remains a separate controlled-sandbox success proof.
4. Only after that should model Provider A/B trials and Final128 be run under fresh explicitly bounded authorization and an unchanged scorer.

Historic scored V13 reference: **A=93/128, B=64/128, B-injection=0/128**. No new provider scoring or utility recovery in #338.
