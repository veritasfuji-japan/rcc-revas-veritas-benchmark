# Task4 variable Native history / raw archive bridge

This increment connects PR #575's runner to an explicit **closed local research
deployment**. It is not an operator service installation or a public Provider
sender. No live credential, paid trigger or existing approval is changed.

## Execution

`seed_request(profile, suite)` derives the full pinned Native catalog and trusted
date/user messages. `ResearchArchiveCustody` enrolls that exact seed, profile,
archive recipient and receipt signer in a retained SQLite database. Model, date,
output cap, per-arm request count and serialized-byte limits come from the
explicit research profile. A/B start with separate retained history rows.

Before calling its receiver, Custody commits the attempted operation as UNKNOWN.
The receiver must be supplied explicitly. `UnixTLSReceiver` is the concrete local
transport: AF_UNIX only, kernel peer UID check, CA/hostname verification and
pinned leaf before POST, then the existing fixed total-deadline collector.
There is no DNS, IP socket, bearer loader or transport fallback in this receiver.
The URI on this local protocol is not permission to access a public endpoint.

Custody invokes the unchanged
`task4_provider_shaped_raw_ingress_v1.seal` before framing/JSON parsing. This
retains the actual bounded raw HTTP bytes in the original X25519/HKDF/AES-GCM
envelope, with file/directory fsync and create-only archive names. The unchanged
framing and occurrence-preserving response-ID guards then reject incomplete or
ambiguous responses. Only the new completion validator uses the configured
model; it does not change the old fixed-model parser.

Internal operation ID, upstream HTTP request ID and completion ID are separate
fields. None is overwritten to satisfy the old `native-local-<op>` convention.
Raw bytes and tool arguments are not repaired. Normal SDK nullable metadata is
accepted; substantive refusal/unsupported completion behavior remains incomplete.

`ArchivedResearchRun` verifies signed release/profile/request/body joins before
releasing a completion into the Native runner. At the next request it checks
the exact prior assistant and matching Native tool result, and Custody commits
and signs that observed history. Its exact signed receipt hash is required as
the next request's parent; knowing only the tool history cannot bypass a missing
observation acknowledgement. The final observation is committed before
scoring. Every released completion's request and Native assistant hashes must
join the actual immutable arm record. Only a complete chain reaches the existing
detached Native User/Attack scorer. Missing ACKs retain the Native record and
attempt count but return no score; retained UNKNOWN/PENDING/TERMINAL attempts
cannot be issued again from the same database.

## What is reused and what is not claimed

The runner still performs Native RCC reads and its existing real VERITAS Bind
adjudication on the simulator's protected action. This new custody service is a
research-specific bridge using the existing raw envelope, receive collector and
framing/ID guards. It does **not** retrofit the old four-step issuer, its fixed
manifest, inference POST Bind adapter, signed GitHub ledger or operator lease.
Those frozen files and proofs remain unchanged. No production authority is
issued by a research receipt.

The selected deployment is a local test backend and spawned Custody process with
a trusted Native runtime. Separate-process execution is tested; these tests use
the same OS user and do not prove separate-UID key confidentiality, independent
administration or cross-directory reset resistance. Test code provisions keys;
there is no executable production key/config loader or general RPC server.
Arbitrary Python in the trusted runtime/receiver is outside this proof. A real
operator deployment must provide its own authenticated admission and protected
retained state; replacing that requirement with these local receipts is invalid.

Local feasibility remains distinct from V13 recovery and a causal date-treatment
experiment. Official Utility is null, new measured recoveries are zero, and
`REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN` remain unchanged.

## Verification

The dedicated PR #575 workflow also invokes
`validation/task4_research_archive_native_checks.py`, with all selected tests
required and zero skips. Coverage includes one/two/four/six-response Native
histories, early incorrect terminal scoring, protected refund and read-after-
refund, independent arms, changed model/output cap, actual archive decryption,
retained terminal refusal, malformed/incomplete responses, altered release,
lost receiver/final ACK and normal SDK nullable metadata.

Two tests spawn a distinct Custody process and use actual verified TLS over a
Unix socket for two and six responses per arm. They require an environment that
permits Unix sockets. The managed authoring environment rejects socket creation
with EPERM, so these two tests must run in disposable GitHub CI; they are not
optional, skipped or replaced by simulated socket success. All other checks can
run locally with socket creation unavailable.
