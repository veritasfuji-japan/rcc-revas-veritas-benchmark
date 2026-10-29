# Runtime crash after complete Native reply v1

REAL_PROVIDER_NO_GO / UTILITY_UNSCORED /
PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN.

This disposable-root synthetic profile follows the partial IPC reply cases. The
entire original newline-framed Custody reply now reaches Runtime. The frozen
framer successfully parses it, but the original SDK caller has not received it.

| Boundary | Actual stop point |
| --- | --- |
| after-frame-return | Original frame function returned; original RPC has not returned, socket is still open |
| after-rpc-return | Original RPC returned and its context closed the socket; wrapper has not returned to Native Proxy.call |

In both selected cases Runtime kills itself with SIGKILL. A complete wire or a
successful internal function return does not become permission to replay the
request after restart. This does not add a signature verifier to Runtime: the
original frame function performs newline framing and JSON parsing. Original
Custody signatures and their evidence joins are verified by the report validator.

## Original call path and observations

The observer delegates the original SDK adapter, original bounded Native driver,
original b.rpc and original n.frame. Replay/refusal replies delegate unchanged and
are not counted as successful model replies. It records SDK_CALL_ENTER, actual receive
sizes/bytes/hash and FRAME_RETURNED. In the second case it additionally observes
RPC_RETURNED and the actual socket object's closed fileno. It emits its own
RUNTIME_CRASH_INTENT and actually SIGKILLs the Runtime PID. There is no fabricated
boundary exception or SDK result, no Python unwind claim for the killed Runtime,
and no cached reply delivery after reopen.

The root supervisor waits for actual exit -9, captures empty Runtime stdout and
stderr, and verifies all four service processes are still alive. Only afterward
does it kill/reopen ledger, issuer, Custody and backend. Actual original Custody
has already committed Bind, saved its complete archive and signed receipt,
returned from its handler, and persisted MOCK_OBSERVED and the gate's
effect-returned marker. Its complete real Unix send is separately observed.

Sender and receiver events are both joined to exact original reply bytes, not
assumed from sendall alone. Their post-call timestamps need not be ordered across
processes: receiving can race with the sender's audit write. Each is checked
against the prior original handler return, and Runtime events are internally
ordered. No particular recv segmentation is required. All reads remain bounded
by the original 4096-byte frame receive call limit.

Evidence joins include the actual Runtime PID, signal, exit, original frozen
source pins, full frame and parsed reply, closed socket where applicable, sender
PID and wire, original successful parser/Bind/crypto/fsync events, signed ledger
receipts and backend readback. SDK_CALL_RETURNED and NATIVE_RETURNED must be absent
on the crashing path. The code boundary is before Native appends its model record
or returns an httpx response to the SDK. The retained issuer remains PENDING,
without a tool observation, response digest or new continuation grant.

After Runtime and four service restarts, issuer reissue is refused, Custody replay
is refused before another dispatch, the backend is read-only with one effect,
external ledger remains revision 2 CONSUMED_UNKNOWN, and Custody remains
MOCK_OBSERVED. Archive inode/bytes, backend identity, signed rows and attempt slots
are retained. Owner decryption and read-only reconciliation issue no permission.

The matching normal control uses the same observers for eight actual Native
steps. All eight frames, RPCs and original SDK calls return, followed by the
original Native result with two terminal/scorer results and 16 signed mutations.
Its original Custody TERM/reopen path remains unchanged.

## Validation

Portable tests use real pipes, the unchanged frame function and actual child
SIGKILL. Their caller/SDK markers are explicitly labelled stand-ins, not actual
SDK, socket or cross-UID evidence. Mandatory disposable-root CI runs the complete
original Native SDK and real Unix socket path with original handlers, separate
UIDs, mutual TLS, all-actor IPv4/IPv6 denial and the prior controls. It requires
21 normal checks and 24 per crash (69 total), zero skips. The combined workflow
budget remains 55 minutes; all per-operation receive limits remain unchanged.

Only run the root harness on a disposable Linux runner with the exact pinned
sources and unused fixture UIDs:

```bash
python -m pytest -q -o addopts= tests/test_task4_native_runtime_ack_crash_v1.py
sudo -n python -m scripts.task4_native_runtime_ack_normal_v1 \
  --run --output results/task4-native-runtime-ack-crash/normal \
  --acknowledge-isolated-runtime-ack-normal-test
for fault in after-frame-return after-rpc-return; do
  sudo -n python -m scripts.task4_native_runtime_ack_crash_v1 \
    --run --crash-point "$fault" --output "results/task4-native-runtime-ack-crash/$fault" \
    --acknowledge-isolated-runtime-ack-crash-test
done
```

These are two selected process-stop boundaries, not proof for all history-update
boundaries, power loss/reboot, privileged concurrency, independent operator
administration, full-runtime attestation or production bypass resistance. The
synthetic root controller knows fixture keys. No operator VM, credential, real
Provider, external backend, host firewall, OS trust store or live permission is
changed.
