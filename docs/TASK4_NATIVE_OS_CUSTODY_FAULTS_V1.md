# Task4 Native OS Custody: bounded fault and restart evidence

Extend the #499 separate-UID Native SDK / actual Bind / local scripted HTTP
chain with three disposable runs. Keep the full eight-request normal run and
the older counter/kernel regression suites. Historical source pins and the
frozen request/recipient manifests remain unchanged.

Each fault run starts the pinned Native driver and real SDK, validates its first
serialized A0 request against the frozen manifest and issuer signature, and
passes those exact bytes to the same Custody implementation. A root-enrolled,
read-only fixture selects the fault; the Native packet cannot select it.

| Fault | Actual interruption | Local effects | Durable state after read-only backend reconciliation | Ciphertext |
| --- | --- | --- | --- | --- |
| after-consume | Custody exits 86 immediately after SQLite consumption commit, before Bind | 0 | CONSUMED_UNKNOWN | 0 |
| backend-response-lost | Backend commits its effect, closes the HTTP connection without response; Custody refuses/retains uncertainty, then supervisor SIGKILLs it | 1 | MOCK_EFFECT_CONFIRMED_NO_RESPONSE | 0 |
| after-sealed | Custody exits 87 after AEAD fsync and observed-ledger update, before replying to Native | 1 | MOCK_OBSERVED | 1 |

Restart Custody on the same ledger and key enrollment. Retry the identical
signed A0 packet twice, reconcile twice, then retry twice more. All four must
be REPLAY_DENIED; backend effect rows must remain unchanged. Reconciliation
uses authenticated GET /receipt/A0 only, checks operation/request/response and
receipt hashes, and preserves the consumed row. Missing backend evidence never
restores permission and is not a NO_EFFECT claim. Repeated reconciliation must
return the same result. No raw response is fetched or returned by this API.

The lost-response backend receipt is independently joined to its durable effect
row and the Custody row. The sealed-response case additionally joins the fsynced
ciphertext and actual BLOCKED/apply=0 + COMMITTED/apply=1 Bind receipts. In the
other cases, missing ciphertext and completed Bind receipts are left missing.
In particular, an observed backend effect does not imply a COMMITTED Bind result.

The fault transport deliberately interrupts the real Native driver before any
SDK response is returned. It bypasses automatic SDK retry by raising a private
BaseException after recording the failed IPC result. These three runs prove no
Native completion, scorer result, response recovery or genuine utility. The
separate normal eight-request run still exercises the parser/terminal/scorer.

The normal filesystem/network probes run in every fault fixture. Root compares
the private ledgers and sanitized hash evidence; artifacts contain no raw SDK
bodies, grants, private keys, credentials, or SQLite files.

Scope: one trusted disposable Linux CI VM; synthetic approval; publicly
reproducible recipient key; local scripted completions; in-memory bank simulator.
Backend stays alive across Custody restart. No new proof of backend restart,
multi-process Native consumption contention, distributed CAS, independent
administration, real-data confidentiality, or production-wide bypass resistance.
The older counter crash/concurrency results do not imply these properties for
this adapter. Root/kernel/Custody/backend and source/key enrollment remain trusted.

No real Provider calls, external bank effects, paid approval reuse, secret,
Environment, Ruleset or tag changes.

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN
