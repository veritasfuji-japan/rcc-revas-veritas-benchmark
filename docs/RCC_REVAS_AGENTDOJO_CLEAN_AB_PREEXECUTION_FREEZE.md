# RCC/REVAS × VERITAS — AgentDojo Clean A/B Pre-Execution Freeze

Status: **FREEZE CANDIDATE / EXECUTION GATE CLOSED**

This record is intentionally created before a new AgentDojo clean A/B result is
observed.

It binds the next evaluation to:

- Ben canonical RCC/REVAS package `1d3782d...`;
- current VERITAS pin `825e5c5...`;
- AgentDojo `v0.1.35` commit `a75aba7...`;
- benchmark `v1.2.2`, Banking;
- same enrolled case, same generated candidate, and same pre-state across arms;
- Arm A = RCC/REVAS baseline;
- Arm B = the same RCC/REVAS path plus VERITAS governance.

## Effect ownership

For a protected AgentDojo mutation, the candidate is captured immediately before
the native runtime would mutate state.

Arm A may execute that exact frozen candidate through the native AgentDojo
runtime.

Arm B may execute that exact frozen candidate only through
`AgentDojoBankingBindAdapter.apply` after native VERITAS Bind admits it.

The wrapper must not redispatch the operation after Bind.

## Governance separation

RCC `ADOPT` is not VERITAS execution authority.

The generated candidate is not authority.

The AgentDojo user prompt is not Human Approval.

Authority for the benchmark profile must come from a separately frozen,
benchmark-scoped source. Runtime constraints may use only the original request
and preregistered trusted structured state. Benchmark scorer/gold information is
forbidden from the runtime governance path.

The current pinned AgentDojo treatment policy admits protected mutation only for
user tasks 3, 4 and 15, subject to deterministic runtime constraint validation.
All other protected mutations fail closed.

## Why the execution gate is still closed

The structural boundary is now frozen as a candidate, but eight execution-level
items remain deliberately unresolved:

1. exact immutable AgentDojo case enrollment;
2. exact model/provider/version/temperature/tool configuration;
3. exact RCC/REVAS runtime configuration used identically across arms;
4. concrete benchmark Authority fixture and verification path;
5. deterministic task-specific constraint resolver implementation;
6. exact native AgentDojo scorer invocation/output schema;
7. final metrics and success/failure thresholds;
8. immutable clean-run workflow and evidence artifact schema.

No clean A/B should run until these are separately frozen.

## Claim boundary

This PR is not an AgentDojo result. It does not establish independent external
validation, production readiness, certification, or a real-bank effect.
