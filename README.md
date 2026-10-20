# Joint Benchmark Runner / Evaluation Harness v0.1

**Status:** executable native-handoff treatment harness. The native VERITAS dry-run Bind Authorization gate is **not yet integrated**.

This package runs the preregistered synthetic governance dataset through the actual `CanonicalDecisionHandoff v1` validator from the pinned VERITAS OS repository and compares it with a transparent RCC/REVAS upstream-adoption baseline proxy.

## Pinned inputs

- VERITAS commit: `4a794e31b26c28e43eb1bb8e6a2474f511c5bd7c`
- Governance-labelled Evaluation Set: `v0.1.1`
- Dataset SHA-256: `1e6ea7f9366876b4cbf041cc0841ab72bd58d6f561ff78553deb6645e5bf2a88`
- Canonical Benchmark Contract v0.1 JSON SHA-256: `a1352dc3cea28da07ca4799e1587b45616376521021e88c724c753fb60738628`
- Benchmark Runtime Manifest v0.1 JSON SHA-256: `edefe64da6ab0980ff94fdc62086933b4ce79860e352472f92873d6e0ac310d8`
- RCC/REVAS -> VERITAS Field Contract v0.2 JSON SHA-256: `47de8bc99999d7f2d7791f51f6afa046e50f56b5777123374e1d43c00a4496fa`

## Why the dataset is v0.1.1

While implementing the native validator runner, the preregistration draft exposed four pre-freeze alignment corrections against the pinned VERITAS runtime/test vectors:

- missing target is `INVALID`, not `INCOMPLETE`;
- missing canonical action is `INVALID` with both `HANDOFF_ACTION_UNSPECIFIED` and `HANDOFF_AMBIGUOUS_ACTION`;
- stale policy lineage is `REVIEW_REQUIRED`, not `INVALID`;
- the current v1 READY path requires expected-state coverage.

No benchmark result was inspected before these corrections. See `fixtures/Governance_labelled_Evaluation_Set_v0.1.1_CHANGELOG.md`.

## What is actually executed

For each case, the runner:

1. loads the frozen RCC/REVAS-shaped upstream input;
2. records **Path A** as an upstream adoption proxy — not execution authority;
3. loads the pinned VERITAS `vector-01` READY handoff shape;
4. rewrites it deterministically with the case's typed actor/action/target/governance fixture;
5. applies only the preregistered fault/adversarial mutation;
6. constructs independent synthetic trusted assertions using the public VERITAS handoff contracts;
7. imports and calls the real pinned `validate_canonical_decision_handoff(...)` implementation;
8. scores native handoff status, reason codes and aggregate `ALLOW / HOLD / DENY` against the preregistered labels;
9. writes case-level results, summary, run manifest and reviewer report.

Optional `--run-decide-preflight` runs the repository's existing `scripts/run_decide_pipeline_poc.py` once. That proves the canonical `POST /v1/decide` ingress is runnable in the local environment; it is **not** substituted for per-case handoff treatment.

## Bind boundary

The v0.1 runner does **not** claim to execute `live_adapter_dry_run_bind_authorization_gate_review`.

- Default: Bind measurement = `NOT_EXECUTED`.
- `--bind-proxy`: derives a plumbing-only readiness proxy from the native handoff state. It is explicitly labeled `DERIVED_READINESS_PROXY_NOT_NATIVE_BIND_GATE` and must not be reported as native Bind evidence.

A future version must wire the actual deterministic dry-run Bind Authorization gate to satisfy the complete Contract v0.1 treatment chain.

## Quick start

```bash
# 1. Obtain the exact VERITAS source

git clone https://github.com/veritasfuji-japan/veritas_os.git
cd veritas_os
git checkout 4a794e31b26c28e43eb1bb8e6a2474f511c5bd7c
python -m venv .venv
source .venv/bin/activate
python -m pip install .

# 2. Check the benchmark package itself
python /path/to/joint_benchmark_runner_v0_1/run_joint_benchmark.py --self-check

# 3. Execute the native handoff treatment
python /path/to/joint_benchmark_runner_v0_1/run_joint_benchmark.py \
  --veritas-repo /absolute/path/to/veritas_os \
  --output-dir joint-benchmark-results \
  --run-decide-preflight
```

Development plumbing only:

```bash
python /path/to/joint_benchmark_runner_v0_1/run_joint_benchmark.py \
  --veritas-repo /absolute/path/to/veritas_os \
  --output-dir joint-benchmark-results \
  --bind-proxy
```

## Outputs

- `cases.jsonl` — per-case measured treatment results;
- `summary.json` — Path A / Path B metrics and Governance Delta;
- `run_manifest.json` — source, dataset, contract and result identities;
- `report.md` — reviewer summary;
- optional `decide_preflight_report.json`.

## Metrics

The harness reports:

- Path A and Path B aggregate accuracy;
- false-allow rate;
- false-stop and false-deny rate on expected-ALLOW cases;
- exact native handoff-status accuracy;
- exact reason-code accuracy;
- accuracy delta;
- false-allow-rate reduction;
- per-case treatment latency.

## Interpretation of Path A

Path A is intentionally labeled `UPSTREAM_ADOPTION_PROXY_NOT_EXECUTION_AUTHORITY`.

For the synthetic set, an upstream `candidate_adopted` + verifier pass is treated as a non-stopping baseline proxy. This lets the benchmark ask whether adding VERITAS catches missing/invalid authority, approval, lineage, target, state or policy conditions after an upstream candidate was already considered adoptable.

It must **not** be described as proof that RCC/REVAS itself grants or attempts real-world execution authority.

## Claim boundary

This is synthetic evaluation infrastructure. It does not establish production deployment, customer integration, regulatory certification, live-provider behavior, real execution authority, real Bind invocation, or external effects. Negative, neutral and positive measured results are all valid and must remain reportable.
