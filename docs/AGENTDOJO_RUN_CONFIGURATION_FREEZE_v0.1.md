# AgentDojo Clean A/B — Run Configuration Freeze v0.1

Status: **PARTIALLY FROZEN / ZERO-COST PREFLIGHT / EXECUTION GATE CLOSED**

This layer follows the merged mapping and pre-execution freezes. It freezes every
safe run-level invariant that can be fixed now without choosing a paid model or
observing a new benchmark result.

The current provider spend cap is exactly **USD 0**. Paid external model calls and
benchmark execution are prohibited by this version.

Frozen now: Banking user-task IDs 0–15, no selective removal/rerun/denominator
reduction, identical arm configuration requirements, no automatic retry, RCC/REVAS
and VERITAS source pins, authority separation, admissible task set 3/4/15, scorer
isolation, invalid-run conditions, and required evidence categories.

Eight items remain for the final execution freeze: exact attack enrollment,
RCC/REVAS runtime config, signed authority/revocation artifacts, deterministic
constraint resolver, scorer hashes/aggregation, exact model configuration, final
thresholds/stopping criteria, and immutable run/evidence workflow.

No clean A/B is authorized by this PR. A later reviewable commit must resolve all
eight items and explicitly open the execution gate before any result-bearing run.
