# TASK15_OFFLINE_PAIRED_SCORER_INPUT_PROVENANCE_V1

## Status

**Implemented / NOT PROVEN** until exact-HEAD CI and evidence artifact.

## Rule-of-One

Extract, using the pinned **native AgentDojo** helper functions,
`model_output_from_messages` and `functions_stack_trace_from_messages`,
the terminal model-output content and exactly three original tool-call
`FunctionCall` entries from each of the two independently observed
offline A/B native terminal histories.

Read-only evidence also binds both projections to their **actual local
governed pre/post environments**, each native return, original source
tool-call ID, original owned user instruction, and the completed six
RCC/Bind native effects.

## Canonical enrollment exclusion

This Task15 local development harness uses the **noncanonical**
`banking:user_task_15:refund-design-v1` case identifier, not
`banking:user_task_15:injection_task_N:direct` from the Canonical Final
128. It also uses synthetic offline model replies.

Therefore:

- A successful projection is **not** a canonical Final128 enrollment.
- There are **zero actual native rubric/scorer calls** in this round.
- Utility and injection success are both **NOT MEASURED**.
- Even a seemingly valid case ID in a derived local artifact does not
  authenticate an external provider response or make it score-eligible.
- A/B source candidate queries used B-only native result history. A-side
  model candidate generation remains unproven as independent.

No scorer may influence the run, mint authority, dispatch an effect, or
rewrite the already committed outcomes.

## Exact acceptance

Replay full predecessor #255 proof chain (2,322 prior tests); validate
15 new tests (1 positive projection, 11 source/terminal/state forgeries,
2 invalid case-ID refusals and 1 noncanonical scope test). The audit
rehydrates `NativeScorerInput` for both arms and verifies their source
function-call ID lists, model-output fields and full typed environment
state hashes. The inputs are *projected, not scored*.

This is a narrow preparatory step toward a separately authorized,
canonically enrolled, actual-model, actual-AgentDojo-scorer proof.

Do not merge based on CI green alone; inspect exact-HEAD Artifact hashes
and the 13 negative-evidence rows.
