# Task4 #318 — Genuine Third Model Proposal → Native Bind → Terminal Scorer Eligibility

## One invariant

**Two genuine, already-captured third-turn A/B model `send_money`
proposals may be replayed through unchanged pinned Native VERITAS Bind,
but they may NOT be labeled completed, utility-scored, recovered or
newly authorized when the actual captured histories stop at a
`finish_reason=tool_calls` message.**

This PR addresses the practical question: *Can we run a new,
zero-API-cost offline Native Utility score directly from the existing
real-model Task4 evidence?*

**Finding:** A bounded pre-dispatch refusal is reproducible free of new
API charges, but an authentic full-trajectory Native AgentDojo Utility
score **cannot** be obtained from the existing third-turn responses
alone. The genuine model never supplied the later tool-result
acknowledgement and final assistant message for these frozen runs.
The refusal itself contains no protected bank effect; faking a
terminal message to call the scorer would be invalid evidence.

## Provenance and exact inputs

- Parent: merged PR #317 main
  `f6fc6361f56dda8d0b5c1afae2b1955dd914a6e0`.
- PR #300 third real Provider capture:
  [run 38097049813](https://github.com/veritasfuji-japan/rcc-revas-veritas-benchmark/actions/runs/38097049813),
  Artifact `11686131074`, ZIP SHA-256
  `6d9842caa8c017ae2bd4426ee7d4b0f1c02f79252d82c96767c048c88f176ab2`.
- Genuine native read history: Artifact `11676881211`, ZIP SHA-256
  `bbc7ba1a16aaac67aed75bdbb7a5abc71bfa978599e1cfc42700779377e838f4`.
- Historical consumed grant remains at
  `95ff6be8c5875ed3827a00fe71fb54bd9de48130`.
- Immutable AgentDojo
  `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b`,
  VERITAS OS `a1d66aef02262cf8a913295270c3aafd159c6adb`.
- Existing #301 actual VERITAS Bind implementation, #317 provenance
  validator, scorer invocation helper, native scorer observer,
  both original source contracts are byte-pinned by Git blob SHA-1.

The dedicated CI downloads only the two archived ZIPs, hashes complete
bytes, verifies consumed grant, and clones two exact native source
trees. It then runs the **actual** #301 implementation of Native Bind
against the **original genuine** A and B third model proposals, without
mutating either model output. It does not call the real OpenAI API,
refresh a past approval, or operate real banking.

## Scope of new CI evidence

For each arm, the new checker requires:

1. Authentic-capture original response ID and canonical digest, exact
   third original request digest, one `send_money` proposal and
   `finish_reason=tool_calls`.
2. No final assistant text after the proposed effect and no native
   tool-result acknowledgement in this **captured third-call artifact**.
3. Existing pinned Native VERITAS Bind returns `BLOCKED` with
   `date_authority_present=false`. The independently constructed
   native prestate is unchanged, and apply attempts are zero.
4. No complete terminal model transcript or detached native
   post-execution scorer input is claimed, even though source proposals
   contain the expected legitimate recipient, amount and date text.
5. An actual AgentDojo scorer **is not invoked** on an invented
   message or an artificially credited partial history.
6. All labels, scores, new Provider budget, new real bank effects
   and production execution authority remain explicitly zero or
   unspecified (`null` where *not observed*), never set to a
   synthetic successful score.

Negative cases include altered real response, swapped arm, tampered
grant, forged terminal text, alleged Utility scoring, changed parent
pins, credential presence and reused spending consent.

## Distinguish three different claims

| Claim | Evidence status |
| --- | --- |
| Frozen genuine third model proposal exists in A and B | Captured and SHA-pinned, without new Provider |
| Native VERITAS Bind actually blocks both unqualified old proposals | Re-run using unchanged pinned code |
| Authentic **completed** Task4 model-to-Bind-to-native post-state-to-scorer Utility | **NOT_AVAILABLE_FROM_ARCHIVE**; no final model/tool continuation |

No scorer number is manufactured: `bound_utility_score=null`,
`bound_attack_success_score=null`. This is not an AgentDojo official
score of failure, and is not counted as one newly evaluated
injection-success trial.

V13 reference stays Arm A 93/128, Arm B 64/128,
B attack success 0/128. No new recoveries or Final128 run.

## Next practical development step

A future owner must **not** retroactively attach an
after-the-fact Task4 trusted date authorization to these genuine
historical tool calls. Two paths remain distinct:

1. For historical evidence only, obtain a freshly approved authentic
   continuation after the old model response and run native read-only
   tool return, final model answer and native detached scoring.
   Because the old third-call date authorization is missing,
   such continuation would still not prove Utility recovery under
   a newly preissued date authority.
2. To test **Utility recovery**, launch a **new** prospective,
   separately issued date-bound one-case A/B run from the first model
   request, with actual independent model generations, protected
   credentials/budget boundaries, unchanged RCC/Bind and actual native
   terminal scorer. This requires fresh explicit approval and the
   independent controls already identified by #313/#314/#317.

Do not spend any API money without fresh user approval. This
entire PR is offline and default DENY.

## Review gate

Keep Draft until latest HEAD dedicated and all ordinary workflows
SUCCESS, exact JUnit and audit JSON independently verified, artifact
ZIP digest matches, and both of the first two claims above are
conclusively reproduced. No score promotion even on green CI.
