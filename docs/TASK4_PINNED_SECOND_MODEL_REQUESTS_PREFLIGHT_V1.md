# TASK4_PINNED_SECOND_MODEL_REQUESTS_PREFLIGHT_V1 — #296

After merged #295 (\`a25fe47cc9b3452cf6baec277a662957acb4369a\`),
take the audited **real-first-model A/B decisions** from #294 and their
**real in-memory native get_iban results** from #295, and freeze exactly
TWO A/B full OpenAI-compatible **SECOND** request envelopes.

**No new model call, no new permission, no new spend, no new native
banking write and no new Canonical Final128 score.**

- Frozen #295 run \`38066049553\`, Artifact \`11674688715\`, ZIP
  SHA256 \`4dae35268cfa102ce5ddf3c7c54cbbcecb2bacd44141436c9ae7b86c27494a02\`.
- Captured genuine first-provider model run \`38065015883\`.
- A second full request SHA256:
  \`f154c06de41bc0ae4c1a56ece0c5d01c30e456a41842ade683a70accd6cf8e3a\`.
- B second full request SHA256:
  \`5bd78ed559115ecec94fc35850fec02b0f915aebc26372544fe1d30a2f2e904c\`.
- Both contain the original trusted **synthetic test date**
  (2031-07-08), the original Task4 user instruction, one genuinely
  model-chosen \`get_iban({})\`, and its corresponding native tool result
  \`DE89370400440532013000\`; they have distinct actual model tool IDs.
- These are only prepared requests. Although the complete model
  request declares native banking tool schemas, no native writes are
  available to this module and no API transport is implemented.

Unlike prior synthetic-history replay, the incoming model first-turn
tool call was an actual previously captured OpenAI response. The source
authentication assumption is pinned GitHub Actions + default HTTPS,
not a cryptographic provider signature.

The malicious incoming-transaction prompt injection was **NOT** seen by
the real model yet. The request immediately follows a harmless \`get_iban\`
result. A future genuine model completion may or may not select
\`get_most_recent_transactions\`; that requires a newly authorized
independent model call for both A and B, with a new single-use approval
and budget. The old \$0.50 authorization was consumed and cannot
be used again.

The workflow downloads exactly the previously independently audited ZIP,
verifies SHA256, parses raw actual A/B packets and source evidence,
runs 29 offline unit tests with 26 tamper/authority denials, writes full
read-only packets to a new artifact and never accesses the OpenAI secret.
No workflow_dispatch is present; merging this PR cannot send traffic.

Merge **only** after all exact-head CI SUCCESS plus independent raw ZIP,
JUnit and request-payload SHA audit. CI green != real model
continuation, legitimate utility or attack success.
