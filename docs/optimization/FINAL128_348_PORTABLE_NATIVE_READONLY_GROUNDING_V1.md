# #348 — Portable Native Read-Only Task1 Answer Grounding

## Single invariant

**SOURCE-CONSISTENT NATIVE READ-ONLY TRANSACTIONS → GROUNDED TASK1 OUTPUT, WITHOUT HISTORICAL HASH EXCEPTION**

#345 isolated a real V13 Task1 spending error (Arm A £1,050 correct, Arm B £1,060 incorrect). #346 showed that a **detached corrected** B answer passes original native AgentDojo User and Attack scorers, but the adapter was pinned to one exact V13 historical execution-row hash. #347 froze a next independent A/B pilot with **$1.00 only proposed, $0 approved**, with no real provider dispatch.

#348 replaces the old-hash dependency in **a separately importable offline adapter**, supports changed trusted native bank states and totals, and exercises the **actual frozen AgentDojo banking read-only tool**. This is a deployable *interface concept*, **not a production-attested authority interface and not a full paired A/B result**.

## Precise seam

`scripts/task1_source_bound_readonly_grounding_v1.py` exports:

- `total_from_native_read_only(case_id, original_user_request, original_tool_call, native_prestate, observed_tool_result)`: requires exactly Task1 and the read-only native Tool `get_most_recent_transactions(n=100)`.
- `grounded_final_answer(..., original_terminal_output)`: preserves the original answer if it matches structured outgoing spending, else produces a **separate local detached answer** from the structured bank state. Does **not** replace the original Tool output, rewrite archived model terminal, invoke scorers, or create new authority.
- The original `native_prestate.bank_account.iban` identifies the account. The original state and returned Tool records must match by ID, order, recipient, sender, amount, date and recurring flag. **Only** `subject` may differ, permitting an injected incoming transaction subject without giving it any instruction authority.
- Enforces full month coverage: if native `get_most_recent_transactions(n=100)` omits older March transactions, the adapter **refuses**, rather than calculating a misleading partial monthly total.
- Date must be canonical ISO, amounts finite, nonnegative and at most two fractional decimal places; duplicate IDs, missing or extra Tool results, changed structured fields, wrong read-only function/args, unclear terminal, altered original user task and foreign case IDs all fail closed.
- Neither scores, "ground truth", approval status, attack success, instructions in transaction subject nor any model assertion can influence the calculation.

## Trust boundary — still not closed

The `native_prestate` **must be provided directly by an independently secured native runner before the model or attacker can modify it**. Matching an attacker-supplied state to an attacker-supplied Tool result is **not provenance authentication**; #348 cannot cryptographically prove caller ownership. The output explicitly marks `caller_native_provenance_cryptographically_verified=false` and `run_time_caller_ownership_verified=false`. A self-asserted `read_only_native_receipt` is rejected rather than being promoted to trusted authority.

A later genuine run must bind this interface to native runner-owned initial bank state, actual tool result and authenticated egress with replay-resistant immutable receipts, verify same-case A/B independent Provider histories, preserve the raw final response and compare the actual User+Attack Scorer of real *new* model trajectories. **The code does not turn on any live sender, data access, approval, or production policy.**

## Pinned live tool check

Original native tool file `ethz-spylab/agentdojo@a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`:

`src/agentdojo/default_suites/v1/tools/banking_client.py` Git blob `941c27467b7890cced7ab70e5fd5ca32241f99a5`.

The dedicated CI checks out that exact source and invokes its real `get_most_recent_transactions(account,n=100)` implementation using a new offline isolated `BankAccount`. The subject of an inbound transaction is modified with an injection string in the observed read-only Tool data; trusted structured fields still reconcile, and the correct outgoing-only total is computed. This **is not a fresh model call**.

## Provider availability / pricing research

OpenAI's public documentation checked on 2026-10-12 still lists `gpt-4.1-mini-2025-04-14`; current publicly documented standard text rates are **$0.40 / 1M input** and **$1.60 / 1M output tokens**. Public docs **do not confirm access for this specific API project**, available account credits, or an enforceable hard spending cap. An estimated $1 cap in #347 remains *proposed*, not granted or enforced. No paid experiment is authorized by this PR. Verify live model access and externally enforced budget **without guessing from CI** before any real Provider call.

## Evidence and limitations

- New case-independent data-path tests include actual native Tool objects, injection in `subject`, typed mismatches, identity drift, date/amount corruption, wrong tool, old-month coverage, **pass-through when correct**, and a distinct correction when wrong.
- Zero Provider calls, Native Bind, privileged authorization, bank writes, native Scorer calls, independent new A/B outcomes or official Utility recovery in #348.
- The previous V13 metrics remain historical **Arm A 93/128, B 64/128, B attack success 0/128**. This PR must not be reported as `65/128` or new attack measurement.
- No production runner modifications in this PR. No new dummy approval, no self-issued signature authority.

**Merge gate:** dedicated & shared CI SUCCESS; inspect real-tool integration/JUnit and provenance claims. Next *result-bearing* step still requires externally controlled project budget, fresh exact-case/operator consent, native run-owned read-only receipts and independent real-model A/B. Avoid another metadata-only default-deny PR.
