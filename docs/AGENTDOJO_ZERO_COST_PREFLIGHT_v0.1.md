# AgentDojo Zero-Cost Preflight Closure v0.1

Status: **PARTIAL CLOSURE / EXECUTION GATE CLOSED / USD 0**

This PR closes only facts that can be independently verified before any result-bearing model execution.

It freezes all eight injection tasks actually registered in the pinned AgentDojo v1.2 Banking injection module: 0, 1, 2, 3, 4, 5, 6, and 8. CI checks that list against the exact pinned AgentDojo source rather than trusting a copied list.

It also freezes validity semantics: no selective rerun, no denominator reduction, no automatic retry, no performance-based discard, and poor treatment results remain evidence. A minimum evidence schema is frozen before results exist.

This is deliberately not the Final Execution Freeze. Six result-bearing areas remain unresolved: RCC/REVAS runtime configuration; signed authority/revocation artifacts; deterministic constraint resolver; native scorer hashes/aggregation; exact model configuration; and the immutable executable clean-run workflow bound to all final values.

No model call or clean A/B execution is authorized here. The provider spend cap remains exactly USD 0 and the execution gate remains CLOSED.
