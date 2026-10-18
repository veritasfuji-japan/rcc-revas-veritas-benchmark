# Task1 #453 — Remove default direct Provider HTTPS from real sender (HARD NO-GO)

## One actual source change

Following merged #452's **actual GitHub Actions** three-job split, we modify the actual #423 Python sender, not another simulated Executor. The default `http.client.HTTPSConnection("api.openai.com", 443)` direct transport is **removed** from `scripts/final128_423_task1_protected_first_native_chat_sender_v1.py`. Its executable `--mode send` CLI now fails immediately with `423_REAL_PROVIDER_DIRECT_HTTPS_DISABLED_EXTERNAL_EXECUTOR_REQUIRED` when no injected transport exists. This refusal is before Native packet construction, any environment API/AES secret validation, journal creation or network use.

The low-level `one_post(..., connection_factory=None)` likewise fails with `423_REAL_PROVIDER_DIRECT_HTTPS_DISABLED_EXTERNAL_EXECUTOR_REQUIRED`, instead of creating a live HTTPS connection. The existing *explicitly injected* connection factory is kept solely to preserve the offline regression testing of the old native packet, response encryption-first and unknown-no-retry code. A caller-controlled Python connection factory is **not an external Executor** or an authenticated Authority, and unrestricted code with the credential could still bypass it; no non-bypassable security claim follows from an in-process gate.

## What is actually hardened

A future operator merely editing #452's job-level `if: false` can no longer activate the default built-in direct sender. Both the actual Workflow and actual Python CLI are fail-closed by default. In contrast to earlier #442–#450 mock-only Executor proofs, **this patch changes the source that would otherwise perform a real Provider HTTPS POST**. The existing #452 split keeps preflight and sender hard-disabled; its issuer job depends on the disabled preflight, so neither GitHub production tag issuance nor Provider send is reachable through the declared normal manual job graph.

This is defense in depth and reduction of an exposed production-bound transport route, **not externally enforced control**. The source is still editable by privileged repository actors and the injected test transport could be replaced by arbitrary Python from the same trust domain. It does not independently govern all network routes, assign or authenticate an external issuer, protect the true Provider API credential outside untrusted runners, implement an atomic cross-Runner ledger or supply a trusted spend limiter. The code still contains its historical mock-test send logic for regression purposes; there is no production route to a new service.

## Next step requiring external trust

Deploy an **independently administered external Executor** with Provider credential custody, enforced network ingress/egress boundaries, authentic sender/issuer identity, a cross-Runner atomic per-arm consume-before-send ledger, failure/UNKNOWN no-retry and externally verifiable receipt/usage reconciliation. Only then should a separately reviewed new sender integration be added and its direct-send bypass tested from untrusted runners. Future real Provider operation requires fresh exact explicit human approval with spend controls and preserved original request/source/Native/Bind/scorer provenance.

Until such an independent trust root exists, **Issue #427 is OPEN; all paid Task1 and new Task4 Provider dispatch is NO-GO**. Old approval text, production/research Git ref state, source test signatures or CI success are not authorization.

## Bounded review and evidence

Three changed files: actual #423 Python sender, this document, and one new zero-network pytest file. No Workflow/Ruleset/Environment/Secret/tag, deployment, IAM, API use, cost or Native scorer is edited or executed. New tests require all of: actual `execute(mode="send")` without an injected test connection fails before source reconstruction or secret lookup; direct `one_post()` fails without a test connection; CLI rejects in a bare environment and leaks no secret text; explicit default HTTPS constructor and imports are absent; #452's job-level hard stops remain.

Legacy source-owned, offline fake-connection regression tests still must pass (they are NOT proof of deployed authority or new Utility). Keep Draft pending latest-head full and dedicated sender CI. Canonical Final128 V13 remains A=93/128, B=64/128, B injection success=0/128; **zero** new measured Utility improvements under Ben's goal.

## Critical security nonclaim

**Changing Python source is never equivalent to independently enforced credential and egress isolation.** Until Provider credentials are unavailable to runners and the independent Executor becomes the sole authorized sender, direct calls through other software or malicious modifications remain a separate bypass threat. This PR only shuts off the *existing default sender path*.
