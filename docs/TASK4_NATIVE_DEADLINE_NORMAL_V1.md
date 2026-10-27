# Normal Native continuation through the fixed total response deadline

This closed positive control applies the frozen PR #559 collector to every actual
changing-history Native POST in the frozen PR #553 full bounded exercise. The
previous fast GET only proved transport-level success; it did not demonstrate
that the Native SDK could consume the response and continue to its terminal.

The new explicit transport adapter delegates the original dispatch and replaces
only `raw.capture` with `task4_native_total_deadline_v1.bounded_capture`. It observes
connection closure, the original archive seal returning after file/directory
fsync, and the original parser returning. Its temporary dependencies are restored
in `finally`, including on failures. Signature checks, single-use consumption,
Bind, the SDK, tool execution, archive encryption, HTTP parsing, signed ledger and
scripted backend implementations are unchanged and source-pinned. No framing
repair, authority bypass, retry, cached grant or artificial callback is added.

Each response gets one two-second monotonic receive deadline, a maximum 0.7-second
inactivity wait, the existing byte limit and the frozen collector's read-count
limit. A new legitimate request starts a new deadline; receiving more bytes does
not reset the current response deadline. Only EOF strictly before that deadline
passes the existing capture gate. The earlier slow-drip header/body cases remain
mandatory CI steps and still stop without parsing or continuation.

## Mandatory disposable root CI

Run only on the workflow's disposable runner with unused fixture UIDs and no
existing retained fixture anchors. This command is not an operator VM procedure:

```bash
sudo -n "$(command -v python)" -m scripts.task4_native_deadline_normal_v1 \
  --run --output results/task4-native-deadline-normal \
  --acknowledge-isolated-deadline-normal-test
```

The root supervisor exports the tracked checkout and existing three exact
external Git pins to root-owned read-only files. It opens a new network namespace
whose live parent remains distinct, brings up only loopback and installs the
existing eight ordered UID-specific IPv4/IPv6 rejection rules there. Before and
after the Native sequence, actual actor UID probes must be rejected with matching
kernel counters. Root controls pass. Only the owned isolated table is removed;
the parent's namespace and table-name inventory must remain unchanged. This does
not establish privileged concurrent mutation safety or host deployment readiness.

The unchanged full exercise must produce:

- Eight actual SDK responses across four changing-history steps in each arm,
  followed by two original Native terminals and scorer calls.
- Sixteen signed model mutations with exact request, grant, nonce, revision and
  authenticated Unix mTLS receipt joins; the backend is a local GitHub API model.
- Eight original Bind `BLOCKED`/zero-returned-apply controls and eight `COMMITTED`
  results, eight durable effects and eight original archive/tool/parent chains.
- Fifty real negative issuer IPC requests and actual private-key/peer denials.
- Ledger and issuer SIGKILL/reopen at the same retained terminal state, followed
  by two terminal grant refusals. Custody is terminated/reopened using the original
  exercise and the sixteen total replay refusals cause no extra POST or event.
- Fresh archive-owner UID recovery of all eight encrypted raw archives.

The added report contains the complete original normal/integration/model reports
and a 32-event trace (capture, close, sealed, parsed for each operation). It joins
exact collected wire bytes, receive-call timestamps and allowed waits to the
backend's original wire digest/length, the recovered archive digest/length,
AEAD envelope digest, parser response digest and actual SDK response digest.
The original parser is replayed offline against those same bytes. Capture finishes
before connection closure, closure precedes seal completion and seal completion
precedes parsing. Both the actual socket and connection must be closed. The
original socket inactivity timeout must be restored. Every response must finish
before its fixed deadline, with only byte reads followed by EOF.

`normal` retains the existing report schemas and validators as reusable joins,
not as a claim that the old collector ran. The outer report explicitly declares
`capture_override`, pins both old profiles and the new adapter, hashes the entire
normal report and trace, and validates them together. Forty portable checks cover
changed deadlines, byte/digest/archive/parser joins, event order, ownership,
namespace and dependency restoration. The root command writes sixteen joined
JUnit checks only after full validation. All new portable and actual-root checks
are mandatory with zero skips; archived reports are complete canonical JSON.

## Limits

All response bytes and credentials are synthetic local fixture material. This is
not a public Provider call, remote GitHub run, operator deployment or fresh live
execution permission. It does not test normal backend restart, VM reboot, power
loss, hard real-time scheduling, independent administrators or full runtime
attestation. The existing operator service and expired approvals are outside
this fixture. Success does not change REAL_PROVIDER_NO_GO, UTILITY_UNSCORED or
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN.
