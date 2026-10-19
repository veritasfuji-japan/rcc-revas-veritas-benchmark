# Task4 PR #469 — actual offline SDK response transport adapter: encrypt before Native parser (NO-GO)

## Purpose
Build a **working transport-level adapter** for the unchanged pinned #323 *offline* Native SDK A/B run. This is the first step toward a reusable response-capture seam, **not** a live Provider Sender or genuine A/B study.

The original #459 joined broker, encrypted custody, Native and scorer by monkeypatching the source mock responder's `__call__`. **This PR moves capture/consume into the SDK's HTTP transport boundary** while leaving the original OneArmMock class and its method intact. The factory accepts only the exact pinned local `OneArmMock` type; the injected subclass of `httpx.BaseTransport` has no network forwarding method, no paid client, no configuration switch and no alternate origin.

## Execution order for every turn (A0–A3 and B0–B3)

1. Original #323 Native Task4 trajectory constructs the model request through the **real OpenAI SDK serializer**, targeted to the original SDK `httpx.Client`.
2. The constructor of `httpx.MockTransport` is locally replaced for the duration of the two frozen test runs, returning a **guarded `httpx.BaseTransport` instance**, not an `httpx.HTTPTransport`. Any wrong type/arm/second source is denied.
3. Guard checks the request method, path, host, dummy test key, request-byte bound and monotonically increasing ordinal; calls the unchanged #458 **local** Unix Broker to consume the unique (trial, arm, ordinal, request SHA) slot before requesting any mock response. A refusal consumes no Provider budget and there is **no retry**.
4. Calls only the exact pinned **#323 script-generated** `OneArmMock(request)` to get a local `httpx.Response`. There is no network transport. It must be the response for the *same* request object.
5. Calls #457 `SealedLocalVault.commit_before_parser`, which AEAD encrypts and fsyncs the *original raw HTTP bytes* in a 0700 local test directory. Broker attaches that ciphertext by immutable receipt, and #456 validates the unchanged local response ID, model, order, source and raw SHA.
6. Only **after** ciphertext and journal checks pass does the transport return the original local response object to the SDK parser. The same Native model history continues to the next SDK request; Native RCC/VERITAS Bind and the original post-only scorer remain unchanged.
7. After eight successful turns, verify original Native A/B terminal/scorer linkage, decrypt in memory with an ephemeral TEST recipient, restart the same-runner Broker and refuse consumption replay for all eight ordinals. Delete temporary ciphertext and SQLite when the test exits.

The transport permanently fails closed after any unsupported method, wrong endpoint/key, out-of-order request, local Broker duplicate, wrong response identity, corrupted ciphertext, attachment failure, journal failure or attempted fifth turn. The dedicated offline tests inject these failures in isolation and exercise the actual full Native SDK flow.

## Explicit limitations

- **Provider authenticated responses: zero.** Original #323 mock responses still originate in the same local process. This is a real SDK *response seam*, not real model intelligence.
- **Real Provider POSTs = zero.** No new Provider key, access to Secrets, HTTP/TCP Sender, DNS/egress, Env/Ruleset/tag change or paid workflow. Issue #321 and #427 remain OPEN/NO-GO.
- A local once-only broker + Unix socket + SQLite do not prove durable consumption or independent identity across GitHub runners. Cryptographic recipient keys and clock remain ephemeral/2031 synthetic.
- The official benchmark target refund amount is **10.0 in an unspecified currency**, not #465's synthetic 100 USD cents. Neither fixture grants actual payment authority.
- The scorer observes genuine *locally completed Native trajectories* with scripted replies; it does **not** establish genuinely generated Utility, injection success, Final128 results or production no-bypass.
- The `httpx.MockTransport` constructor interception is an **offline integration seam only**. For a future live research run a separately reviewed isolated true Sender, provider-origin receipts, encrypted external custody and fresh exact-owner cost approval will be necessary. This PR does not implement or enable that Sender.
- The test scaffold's injected fake Broker and fake Vault exercise refusal and call sequencing, not cryptographic security; the full dedicated Native test uses the real pinned #457/#458 primitives.

## Review plan

Only four additive files: this implementation, negative and integration tests, this document, and a PR-only read-only no-Provider CI workflow. Full test requires the exact pinned AgentDojo, RCC and VERITAS sources, Python/OpenAI SDK/httpx/crypto lock, and zero Provider credentials. The common CI runs the fast no-network checks and skips *only* the full environment-dependent Native test, while the dedicated workflow sets `TASK4_469_NATIVE_PROOF=1` and runs every test.

Review before manually merging:
- Dedicated Native test + negative tests PASS and original A/B terminal/scorer counts verified; no fake Utility promotion.
- All PR-head inherited checks PASS, exact 4-file additive diff, no modified #323/#455/#457/#458/#459.
- Sanitized SHA-only JUnit/artifacts, no raw prompts, account details, response plaintext, API keys or real bank data.
- Keep real Provider dispatch disabled; the next task is true research Sender/source/custody design pending new exact consent, not another fake scored run.
