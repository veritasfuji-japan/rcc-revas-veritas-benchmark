# #337 — actual RCC current-main release → source-bound VERITAS request

**Purpose:** replace an incorrect assumption ("the old RCC external-eval/v0.3.9 wrapper is still on Omar's current main") with an **executable, current-main pinned** compatibility boundary. This is *not* an assertion that full current canonical RCC → VERITAS Bind execution continuity is now proven.

## Relevant source divergence (2026-10-12)

- Ben/Omar historical reference line: `fdef6e4f7bfab4c49c366078c15b99a682e2d8da`, which diverges from the currently observed upstream main. A separate older benchmark integration uses `1d3782d3aae5ff9c88036709c1a5642320cc53c2`. **Do not silently alias or replace these sources.**
- Current `effacermonexistence/rcc-revas-veritas-benchmark` main pinned at `353ad9e6a17cda8874a129493fe0f8f4fe4427bc` publishes `rcc-revas-eval/v0.1.0/runtime`, `CURRENT=v0.1.0`.
- The old `external-eval/v0.3.9/src/rveval/integrations/agentdojo.py` path is **absent** from current main. The old integration may remain frozen as historic work; it cannot be advertised as if it were executed on current main.
- Current native module `rcc_revas_eval.native_veritas` explicitly supports **label-free original source and candidate → exact `POST /v1/decide` request preparation**, not actual native consumption, trusted physical bank prestate, VERITAS Bind or complete AgentDojo Final128.

## Actual execution in #337 (no model/bank/API)

A dedicated GitHub Actions CI (public standard runner, read-only checkout):
1. checks out **both** the benchmark PR HEAD and **actual upstream** `353ad9e...` in separate directories;
2. verifies upstream Git HEAD, `CURRENT`, seven immutable Git blob source hashes, and absence of the deprecated v0.3.9 path;
3. runs upstream's actual `python -m rcc_revas_eval preflight`;
4. runs upstream's `register-takeshi` for the original 36 partner fixture rows, then its `evaluate` with the registered pre-frozen plan and `verify-artifacts`;
5. runs upstream's **actual `prepare-veritas`** (no invoke / no HTTP), verifies full 36-case accounting (released candidates vs withheld) and re-runs the exact upstream `build_decide_request` code for every prepared candidate, checking the candidate's canonical hash, exact source artifact hash, decision identity, selected candidate, original label-free evaluation prestate and payload digest;
6. checks the upstream's **actual** echo-diagnostic implementation: matching echo returns `MATCHING_ECHO_ONLY`, tampered echo `MISMATCH`; neither equals native consumption;
7. tests wrong handoff candidate/source hashes, mutated prepared payload, rejected fake Bind/Utility claims. Emits explicit JUnit and a structured canonical SHA-256 report.

The upstream itself determines how many of the 36 cases release candidates and how many RCC correctly withholds. Neither number is fabricated or treated as 36 successful protected actions. The output is **development-only** RCC handoff/request preparation, not AgentDojo native case outcomes.

## Strict interpretation

| Claim | Before this PR | What #337 can actually establish after passing CI |
|---|---|---|
| The historical v0.3.9 adapter is present on current RCC main | Incorrect assumption | Pin check confirms absent |
| Current public RCC code can produce exact candidate/prestate-bound VERITAS requests | Not demonstrated in this benchmark at this current-main pin | **Actual code invoked for all released partner candidates** |
| Request-side candidate and synthetic evaluation prestate identity | Not measured on current main here | Source/bytes/hash checked against current release code |
| Upstream echo means server-side candidate consumption | Not supported | **Explicitly forbidden** by current upstream code |
| Production physical state / execution authority / real VERITAS Bind | Not established | **Not established** |
| Same candidate across current RCC → actual VERITAS Bind and final native effect | Not established | **Not established** |
| Final128 AgentDojo Utility ≥ 92/128, injection 0 after optimization | Unmeasured | **Unmeasured**; V13 93/64/0 unchanged |
| Paid model API or real banking operations | Not approved | **0 requested/executed** |

This is a *concrete current-source executable seam* for Omar's wrapper-continuity concern; it does **not** close the end-to-end claim. Next work requires an agreed current-source native execution adapter that consumes the same source-bound candidate and physical native prestate and generates a VERITAS-owned verified Bind receipt with final apply/deny continuity, then detached actual native scorer. Current upstream merely prepares `POST /v1/decide` requests.

## Run / evidence

```bash
# From benchmark checkout. The upstream repository must be locally cloned
# at the EXACT specified SHA (CI performs this read-only checkout).
PYTHONPATH=. python scripts/final128_337_current_rcc_main_request_boundary_v1.py \
  --upstream-root current-rcc-upstream \
  --output-dir results/final128-337-current-rcc-main
FINAL128_337_UPSTREAM_ROOT="$PWD/current-rcc-upstream" \
 PYTHONPATH=. python -m pytest -q -o addopts= \
  tests/test_final128_337_current_rcc_main_request_boundary_v1.py
```

Fresh outputs only, no environment containing model/bank credentials, no network dispatch of native VERITAS requests. Source retrieval uses GitHub read-only checkout, but there is no provider or bank network call. The generated report has 36-case accounting plus original source digest and verification stages; CI uploads JUnit, report, exact HEADs and SHA-256 manifest. **Do not merge** before dedicated and required checks pass and downloaded Artifact identities are reviewed.

**Score reference remains:** same-run V13 A=93/128, B=64/128, injection B=0/128. No new optimized treatment scores. Rule-of-One and nonpromotion from #335–#336 remain intact.
