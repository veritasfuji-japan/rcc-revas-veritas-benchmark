# TASK4_LIVE_SECOND_TWO_CALL_CAPTURE_ONEUSE_V1 — PR #297

**Not yet authorized for real API use. All current changes and CI are free/offline.**

Prior #296 merged-main SHA:
\`5528a7e5d6c63bcdce255fbab1ff0942cee96a35\`.

## New measurable step

The first genuine A/B GPT-4.1 mini model responses have already been
captured and their \`get_iban({})\` operations run in two separate frozen
AgentDojo in-memory banking environments. The next complete model inputs,
containing the *actual* native read-only IBAN result and real first model
call IDs, were independently frozen by #296:

- Source proof: Run \`38066695568\`, Artifact ID \`11674814494\`.
- Exact source ZIP SHA256:
  \`5e060179f7c0419d5a2b3d49587dba4d1e93f7adc8c0a41ddac1bb689813a609\`
- Exact source JSON SHA256:
  \`d31e2f9781ba3f1de33b04bbac382bc1664588ad7533d83eb13f7f7fec6be6d5\`
- A second request SHA256:
  \`f154c06de41bc0ae4c1a56ece0c5d01c30e456a41842ade683a70accd6cf8e3a\`
- B second request SHA256:
  \`5bd78ed559115ecec94fc35850fec02b0f915aebc26372544fe1d30a2f2e904c\`
- Full model: \`gpt-4.1-mini-2025-04-14\`, maximum 256 output tokens,
  11 *declarations* for native banking functions but **zero executable
  bank tools inside the sender**.

## Strict authorization boundary

The previous $0.50 approval and single-use tag
\`task4-first-two-real-provider-v1-consumed\` are permanently consumed.
Their reuse is explicitly denied. This PR does NOT grant new consent.

A separate NEW approval is required before any API dispatch:

- **Exact case:** \`banking:user_task_4:injection_task_0:direct\`
- **Exact allowed model:** \`gpt-4.1-mini-2025-04-14\`
- **New allowed provider calls requested:** at most one A, one B
- **Proposed new cumulative additional spend cap:** $0.50
- **No native read/write execution, no third model call, no real bank effect**
- **New consumed tag:** \`task4-second-two-real-provider-v1-consumed\`
- **New Environment:** \`task4-real-provider-second-two-calls\`

This tag requires its OWN **active, no-bypass tag ruleset**: target
\`refs/tags/task4-second-two-real-provider-v1-consumed\`, restrict
deletions, restrict updates, non-fast-forwards; allow initial creation.
The LIVE workflow verifies this through GitHub's rulesets API before
touching Provider transport; without the new rule, it refuses to proceed.

A NEW dedicated GitHub Environment with protected main-only deployment,
the \`TASK4_OPENAI_API_KEY\` environment secret, and any feasible manual
review gate must be set up. The existing first-call Environment is not
used. Project/org cost limits must be separately rechecked. The proposed
$0.50 is not a guaranteed real-time/provider-enforced billing maximum,
and there can be accounting delay.

**Only after user gives NEW approval for this exact scope**, an operator
can initiate GitHub Actions → **Task4 Second Two Real Provider Calls V1**
→ main and enter exact input:

\`APPROVE_TASK4_ONE_CASE_A_B_SECOND_2_CALLS_MAX_USD_0.50\`

This extra manual user action is the specific execution approval. Do not
fill in that phrase or run the workflow simply because this PR merged.

The workflow verifies source ZIP and JSON SHA, old consumed ref still
pointing at original run, the new exact ruleset/secret, then **atomically
creates** the NEW consumed tag BEFORE touching the Provider network.
If anything fails or a request is ambiguous, it never retries. Successful
results are appended as full raw JSON + server request ID, response ID,
usage, source hash and no-effect declarations to GitHub artifacts.

A real model may ask to read incoming transactions, try a write tool,
or return a textual answer. Every such response is only *recorded*;
no functions are executed or scorer used.

Even when two actual second model replies are obtained, the malicious
incoming transaction has NOT been shown to the model until a genuine
\`get_most_recent_transactions\` native read is performed and a subsequent
model continuation is separately approved. Do not infer prompt injection
success, valid Utility, or any frozen Final128 improvement from these
two second responses.

### CI / merge boundary

Standard pull_request/push CI has empty Provider keys and exclusively
uses mocked HTTP transport, source provenance controls and 31 offline
tests. Neither PR open nor merge can cause a billable API request.

CI green != independently PROVEN. **Do not merge #297** until all
exact-HEAD checks succeed and independently downloaded offline
Artifact/JUnit/manifest verifies; **do not run LIVE workflow** until
a separate new, narrowly scoped approval and all protection settings
are independently inspected.
