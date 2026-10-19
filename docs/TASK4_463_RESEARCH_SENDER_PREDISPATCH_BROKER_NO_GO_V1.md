# Task4 #463 — Research Sender pre-dispatch bridge, Provider HARD NO-GO

## Narrow purpose
Connect the **real OpenAI SDK-serialized first Native Task4 request** from merged #455 to the **separate-process local one-use Unix Broker** from merged #458, and stop BEFORE any Provider network transmission. This creates a reviewable sender-side, consume-before-denial integration, not a deployable or authorized live Sender.

The original #455 and #458 source files are read-only, Git-blob-pinned inputs. No existing Native, Bind, Scorer, Environment, Secrets, Ruleset, tag, or historical workflow is modified. The code does not create a network client or obtain any Provider credential.

## Exactly what is checked
- Original pinned Native first request from Arm A and separately prepared Arm B, not inferred from model-generated replies.
- Actual SDK serialization into the #455 network-incapable `httpx` transport, exact case/model/date fixture/tool/byte/BPE checks retained.
- Before refusing that transport: one request-hash consumption per Arm through the actual #458 Unix-socket Broker's atomic local SQLite journal. Arm+ordinal=0 and the exact SDK request SHA must match the #455 observation.
- After the Broker process is stopped and restarted on the SAME local SQLite database, **repeat consumption of each first request is denied**. All audit outputs use hashes and fixed reason codes; no raw prompt, response text or credentials are saved.
- Failing or interrupted inspection must not authorize sending, nor falsely count success in the bridge report. Any incomplete A/B pair is rejected.
- Redacted local JUnit / hash-report artifacts only; PR-triggered read-only standard hosted Runner; no manual Provider trigger, paid Approval, Environment use or secrets.

## Crucial limits and what is NOT proven
- **Zero actual Provider POST**. This implementation intentionally cannot transmit to the model. It does not implement the final research Sender.
- The #455 execution date `2031-07-08` remains a synthetic fixture, **not a real trusted issuer date**. No final protected banking effect, complete genuine Native trajectory, Provider response or eligible authentic Utility score is produced.
- The #458 Broker uses **one Runner's local SQLite + Unix socket**. It does not provide cross-Runner/re-dispatch single-use enforcement or independently protected credential/egress control. The Broker consumes only a synthetic trial ID and never grants live dispatch.
- #463 covers **only the first model request of each Arm**. The proposed research limit of up to five model calls per Arm, and true multi-turn real-model continuation, is still not integrated into a protected live Sender.
- No external billing guarantee, input-token exact upper bound, authenticated Provider response, independently controlled issuer, off-Runner ciphertext custody or production bypass resistance is proven.
- A posted screenshot showing `VERITAS-Task4-Research` $0/$1 with `Limit enforced` and owner-reported model availability is not owner approval or a per-trial hard spend cap.
- Issue #321 (Task4) and #427 (Task1) remain **OPEN / BLOCKED or NO-GO**. Historical model-call permissions were consumed; no permission, consent or paid run is granted by merging this code.

## Next genuine research readiness requirements (separate scope)
1. Review exact prospective trial source SHA, approved case/model/tokens/calls/expiry/max-dollar risk, and genuinely **pre-first-request** owned date/recipient/amount/scope issuance (not the 2031 fixture).
2. Separate trusted research-only credential custodian and egress-permitted Sender from PR/fork inputs and non-sender actors. Review and independently test cancellation, malformed response, timeouts, lost replies, no retry, cross-runner duplicate denial and log/Artifact secret leakage.
3. Bind all prospective real A/B requests and original Provider responses into an independently attributable, preferably encrypted chain from first request to native tool results, final assistant answer and official detached scorer. Mark partial runs **UNSCORED**.
4. Confirm Provider account actual model/price/rate limits, cost protections, current API key isolation and protected Environment behavior; obtain **fresh explicit owner consent** to an exact reviewed experiment. Never infer this consent from "はい", CI green, historical grants or the monthly $1 project cap.

**Merge gate**: latest PR HEAD, exact four-file diff, dedicated Native first-send-denial JUnit success, hash-only artifact, all required inherited checks successful, owner's separate merge decision. Keep the PR Draft until verified.
