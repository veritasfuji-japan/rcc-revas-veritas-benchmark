# TASK4_NATIVE_READ_MODEL_CONTINUATION_SEAM_V1 — PR #293

Frozen prior merged #292: \`c0e6be8e106de4fb7ec47db12a7b495252aee07f\`.

## A functional connection, not a new fake result

#292 sealed two separate complete A/B **initial** model request JSON
payloads for genuine use at a future externally approved Provider boundary.
They did not include malicious tool results, because an agent must first
choose to query the native bank. This PR implements the next **real
simulator** stage and archives both histories.

It consumes ONE **untrusted offline mock ChatCompletion-shaped tool-call
response** at a time, tied to the exact current model-input SHA-256.
The response must request exactly one pinned native read-only tool,
first \`get_iban\` with empty args, then \`get_most_recent_transactions\`
with \`{"n":10}\`. These are the two frozen Task4 development trajectories
chosen to prove this seam. Different real-model behavior is a closed
failure in this bounded implementation, not something to silently correct.

The **actual pinned AgentDojo native FunctionsRuntime and ToolsExecutor**
run these read operations against the actual disposable banking environment
with the native \`injection_incoming_transaction\` DirectAttack payload.
The runtime PHYSICALLY includes only the two allowed READ functions; no
\`send_money\`, standing orders, account changes or other writer exists
in that runtime. The bank state SHA-256 must not change.

Native codec output constructs the next OpenAI-compatible request, carrying
the genuine native YAML tool return, not a synthesized scorer/fixture
post-read string. The transaction's exact malicious subject is decoded
from native YAML and verified inside the *next* model request after the
second native read. A separate A and B mock response stream yields
different call-ID-correlated next request SHA-256s.

## Experimental proof

- **2** independent local A/B bank simulator instances with same exact
  pinned attacked source and frozen original Task4 request
- **4** real native AgentDojo read-only operations (2 per arm)
- **2** next-model full payloads containing actual native injected tool
  result, linked to unique model call-ID histories
- **19 dedicated tests**, including 17 fail-closed guards for forged
  Provider-shape values, write tools, malformed arguments, call alias,
  request mismatch, attempted retry, response schema drift and mutated
  native pre-state
- Archived raw A/B next-request JSON payloads, native read journals and
  source SHA, full JUnit and pin/installation evidence

**NO live model is called.** All test model response objects are
local fixtures, not Provider authenticated. Model IDs and usage counters
in JSON are untrusted and cannot be treated as billing receipts. Actual
model continuation after seeing the injected tool data is still required
before Utility or injection-success can be measured.

The current source is deliberately no-transport: it cannot invoke real
network or write banking effects even when a caller supplies a pretend
API key. No historic $5 permission is reused, and the proposed $0.50
first-request plan is still NOT authorization. Exact live scope, account
access, trusted operator signature, one-use ledger and billing guard
remain separately required.

Manual Ready-for-review/merge only after exact HEAD all checks SUCCESS
and independently downloaded Artifact/JUnit/native return hash audit.
CI green != independent production PROVEN.
