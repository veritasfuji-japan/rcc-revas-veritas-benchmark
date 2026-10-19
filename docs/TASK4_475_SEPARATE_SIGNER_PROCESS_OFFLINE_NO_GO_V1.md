# Task4 #475 — separate signer OS process, local synthetic NO-GO

This is a **bounded offline proof of OS-process separation**, not a production authority gate.

A child process generated with Python `multiprocessing` **spawn** holds an ephemeral Ed25519 private key. The parent verifier receives only the public key and a signed **synthetic no-send** claim. The parent rejects nine negative cases (replay, revocation, wrong signer, missing signature, request change, policy change, arm change, model change and forged send). A live-send opcode is explicitly denied. The CI is PR-only, read-only, without injected secrets, and writes hash-only evidence.

## Exact limitations

- Both processes share one GitHub Actions runner, operating-system account, inherited environment and trust domain. This is **not** independent IAM, OS user isolation, separate machine, credential boundary, network egress denial or remote signing authority.
- Signer key is ephemeral, **not** the user's authorized issuer key; no actual approval was given. Signer child is intentionally allowed to sign only synthetic NO_SEND fixtures.
- The child protocol uses a local multiprocessing Pipe. The verifier's consumed set and revocation flag are volatile, not a durable cross-runner or crash-safe authorization ledger.
- This is an isolated component test. **It is not wired into the full #474/#473/#472/#471 Native A/B pipeline** and does not prove the original SDK bytes pass a production issuer trust boundary.
- No real Provider request, real model utility, external bank effect, payment authorization, billing cap, real owner approval or production sender exists. Real Provider POSTs: **0**. Utility: **UNSCORED**. Task4 #321 and Task1 #427 remain **OPEN / NO-GO**.

Source base is merged PR #474 `b36110c8d8961f82c2053850e805b6fc92ac8ed0`. Four additive files. No GitHub Secrets, Environments, Rulesets, tags or paid workflow changes. Draft PR until CI and owner manual review.

## Next gap

Before claiming a genuinely independent execution boundary: independently operated signer/issuer, verifiable policy and revocation source, credential and network separation, durable cross-runner single-use storage, integration into the **original Native SDK wire** path, and explicit bounded owner consent before any paid Provider POST.
