# V13_UTILITY_RECOVERY_CLAIM_GATE_V1 — PR #287

**Do not mistake source-data triage for a Utility improvement.**

## Central rule

The V13 result was **A Utility 93/128**, **B Utility 64/128**,
**A injection-task success 20/128**, **B injection-task success 0/128**.
Thirty cases succeeded in A and failed in B, but one case succeeded in
B and failed in A, producing the **net 29-case raw gap**.

Already-frozen case-level diagnosis partitions those 30 regressions:

| Class | Count | Why not automatically recovered |
| --- | ---: | --- |
| MODEL_OR_TRAJECTORY_VARIANCE | 3 | Different model/source histories do not establish policy false blocks |
| AUTHORITY_PROTECTIVE_BLOCK | 10 | Candidate may violate original request or trusted pre-state |
| SEND_MONEY_PARAMETER_AUTHORITY_UNRESOLVED | 10 | Date/recipient/amount authorization must be separately established |
| CONDITIONAL_PREDICATE_NOT_PREREGISTERED | 7 | No preregistered deterministic condition authority |

**Nine of the 30 regressions have the same raw protected call sequence,
21 have different sequences.** Even same sequence is not independent
permission evidence. The existing paired control holds exact candidate
and pre-state equal across arms for 81 mutation-relevant cases: 12 both
commit and 69 RCC-only commits while VERITAS refuses. None of those 69
are declared false positives solely because RCC committed them.

This PR adds an exact contract-crosschecking, deterministic,
READ-ONLY claim gate. No historic case is promoted to new measured
Utility or execution permission. All proposed recovery claims are
**refused** in this round. The gate records the next investigation
population without reading gold labels, calling a model, repairing an
agent candidate or changing VERITAS authorization semantics.

## Why prioritize these tasks

Historical A-success/B-failure concentration: Task4=8, Task14=8,
Task15=8, Task2=3, Task13=2, Task1=1. This is investigation order
by raw size, **not** predicted recoverable Utility. In particular,
Task4 send-money date metadata, Task14 conditional password authority,
and Task15 complete multi-action request each have separate unresolved
authority conditions; no blanket policy relaxation is admissible.

## Evidence / nonclaims

- Exact predecessor #286 merged main and Git blob SHA-1 of the existing
  baseline diagnosis, V13 final result boundary, and frozen controlled
  candidate attribution contract.
- 24 unit tests cross-check V13 scoring arithmetic, 30 exact case-ID
  partition and task histogram, 81 controlled candidates/69 governance
  refusals, source artifacts, and malicious changes to scores, IDs,
  classification, pairing, budget and false-promotion labels.
- New generated JSON output and JUnit only. No independent new model
  generation, no actual utility improvement, no new injection measurement,
  no proof that all 29 can be recovered.
- No V13 authorization reuse, Provider API client, OpenAI API keys,
  real banking effects or billable Provider calls.

## Next useful implementation

Rather than another generic security perimeter PR, select one
authority-valid Task4/Task14/Task15 cohort and produce **prospective
canonical independent A/B candidate/source trajectories** with exact
owned request and trusted pre-state, keeping all original refusal
semantics. Only then can an independently validated fresh scorer/run
support measured Utility improvement. Actual paid Provider calls
require **fresh explicit user authorization**. The earlier historical
$5 or $0.25 limit is not permission.

CI green != PROVEN. Manual merge only after exact-head all-CI and
independent artifact/evidence audit.
