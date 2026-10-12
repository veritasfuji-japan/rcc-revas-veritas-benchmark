# Task4 #367 — Real serialized SDK MockTransport bytes into one-use SQLite rehearsal

Runs the frozen #326 actual OpenAI SDK MockTransport A/B paths (4 local
intercepts per arm), pinned tiktoken 0.12.0 o200k_base, and feeds each
observed serialized raw request body into #366, using #365's
transactional local one-use ledger. Confirms raw SHA-256, byte length,
local BPE counts, separate A/B session IDs, replay rejection, and
irreversible failure on local token-limit denial.

Native SDK and original #326 audit tests run in the same pinned workflow.
This is a retrospective binding of intercepted local mock requests,
not a new pre-send integrated SDK sender; fake responses unlock local
continuation and are not independently generated LLM output. SQLite
is local-only, not an externally protected one-use authority. No real
provider API, secrets, billed tokens, bank effects, spending approval,
genuine model utility or production boundary proof is claimed.
