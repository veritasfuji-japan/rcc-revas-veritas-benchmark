# Final128 #424 — Validate Task1 protected secrets BEFORE one-use production tag

## Failure being fixed

Merged #423's manual protected `workflow_dispatch` checks only that `TASK1_OPENAI_API_KEY` and `TASK1_CAPTURE_AES256_KEY` are non-empty **before** the irreversible production singleton POST. The Python live sender validates API-secret syntax and decodes AES-256 key material only **after** that singleton is consumed. Thus an invalid Base64 string, short key or whitespace-containing API token could waste the one-use tag with **zero real Provider calls**.

## One scoped fix (no new sender or scoring code)

- Refactor the existing `check_live_runtime(*, require_consumed_tag=True)`. With `False`, it runs the exact protected GitHub run/ref/actor/first-attempt, fresh manual approval, Environment-name, operator billing review, API key syntax and **strict canonical Base64 decoded 32-byte AES key** checks **without** claiming a consumed production tag. The function is reused with `True` immediately before the actual existing sender path and then requires `TASK1_423_TAG_CONSUMED=1` and exact `TASK1_423_TAG_READBACK_SHA=GITHUB_SHA`. The after-tag check remains mandatory and unchanged in meaning.
- Extend the existing sender CLI by **one** `--mode secrets-preflight` mode. It rederives the source-owned pinned first A/B packets, checks the above context and credential syntax, and returns only a REDACTED, explicit `permission_to_send=false` status; it writes no journal, consumes no tag and opens no network connection.
- In `.github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml`, replace the non-empty-only secret check with `--mode secrets-preflight` **before** `Atomically consume exact no-bypass production once tag`. Both secrets remain injected via the Environment only for that step, with no printing or output, and are separately provided to the later sender. Existing manual-only trigger, single-use tag protection, no-retry, AES-GCM response encryption and native source checks are preserved.
- Add positive and negative tests in the existing #423 offline suite: missing/short/whitespace API token, invalid/noncanonical/wrong-length Base64 AES, outdated consent, wrong ref/actor/rerun, absence of tag in the valid precheck, required tag for actual sender, and static proof that validation appears before tag creation and provider send.

## Boundaries

This only prevents **obviously malformed secret configuration** from consuming the irreversible tag. Syntactically valid but revoked/unauthorized API credentials can still fail after tag consumption. A 32-byte key is correct AES-256-GCM *length*, not proof of secure generation, storage, rotation or independent custody. The Environment, actor and consent strings are runtime checks; no new independently operated approver or full IAM/credential/network bypass attestation is provided.

OpenAI project budget settings and local soft token estimates are **not** a provider-enforced USD hard spending stop. Do not manually dispatch any paid workflow from this PR/merge without separate authorization and verified financial-risk acceptance.

This PR makes **NO** actual GitHub tag POST, Provider call, bank effect, model output or Native scoring request. Historical A Utility 93/128, B Utility 64/128, B injection 0/128 unchanged. Newly recovered official Utility: **0**.

### Review criteria

Dedicated inherited #423 CI must run on the **exact PR HEAD**, real pinned offline Native source, full socket-blocked test suite and GitHub workflow ordering tests with JUnit failures/errors/skips=0. An already consumed tag must never be deleted, patched, reused or reset as part of validation. CI success alone does not grant paid dispatch permission.
