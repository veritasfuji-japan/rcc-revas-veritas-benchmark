# Native IPC reply prefix loss v1

Scope: disposable-root synthetic CI only. REAL_PROVIDER_NO_GO /
UTILITY_UNSCORED / PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN.

The frozen Custody handler can finish its backend effect, Bind, parser, archive,
signature, local MOCK_OBSERVED update and gate effect-returned marker before its
caller receives a complete reply. Internal completion does not authorize Native
continuation. This profile follows the zero-byte reply loss profile with three
selected real Unix socket prefixes:

| Fault | Bytes sent before actual Custody SIGKILL |
| --- | --- |
| one-byte | First byte of the original canonical JSON plus newline wire |
| mid-json | First floor(full wire length / 2) bytes |
| without-newline | Entire canonical JSON, excluding its final newline |

The complete JSON case is deliberately not syntactically corrupt. The original
Native framing function still requires the final delimiter and refuses EOF. It
must not treat independently parseable partial framing as permission.

## Execution and evidence

The original Custody server loop, Unix peer credentials, packet verification,
consume handler, signed ledger, Bind, serializer and Native framing code remain
unchanged. A fixture wraps accepted connections only on the exact native.sock
path. Non-success responses (including replay denials) delegate unchanged. After
the original handler returns ARCHIVED_NATIVE_RESPONSE, the wrapper sends the
selected bytes using the real accepted socket's sendall, records SEND_RETURNED,
and kills its own actual Custody process with SIGKILL. sendall success is local
acceptance, not a delivery guarantee; Runtime separately records every actual
recv outcome and exact received prefix before BOUNDED_FRAME refusal.

Validation joins sender wire/hash/length and role/PID/namespace/time to the
original signed archive, handler reply, fsynced gate marker, committed local row,
real Runtime bytes/hash/length/read sizes and EOF, actual exit -9, and unchanged
retained storage. It does not require a particular segmentation of recv calls.
Every nonempty read is bounded by the original 4096-byte receive call limit.
The backend HTTP response was fully parsed successfully in all three cases;
Native IPC framing is the later failed boundary.

After all four roles restart, the same backend is reopened read-only, issuer
remains pending, external signed-ledger revision stays 2 CONSUMED_UNKNOWN, the
Custody row stays MOCK_OBSERVED and replay is refused. Exactly one backend effect
remains. Owner decryption and read-only reconciliation issue no permission.
No Native model response, tool observation, continuation or scoring is reported.
No attempt slot, row, key or archive is repaired or reset.

The matching positive control sends all eight original complete newline-framed
replies, observes eight real send returns, completes the original eight SDK steps
and two terminal/scorer results, and keeps the original 16 signed mutations.
Its frozen Custody TERM/reopen path is preserved; negative cases use four actual
SIGKILL/reopens.

## Running

Only in a disposable Linux root CI runner with the exact frozen dependencies and
unused fixture UIDs:

```bash
python -m pytest -q -o addopts= tests/test_task4_native_ipc_prefix_loss_v1.py
sudo -n python -m scripts.task4_native_ipc_prefix_normal_v1 \
  --run --output results/task4-native-ipc-prefix/normal \
  --acknowledge-isolated-ipc-prefix-normal-test
for fault in one-byte mid-json without-newline; do
  sudo -n python -m scripts.task4_native_ipc_prefix_loss_v1 \
    --run --crash-point "$fault" --output "results/task4-native-ipc-prefix/$fault" \
    --acknowledge-isolated-ipc-prefix-loss-test
done
```

Portable tests use real pipes and real child SIGKILL with explicitly labelled
same-UID role and SQLite handler stand-ins. They do not establish Unix socket,
original handler or cross-UID security. Mandatory root CI executes actual Unix
socket prefixes and original handlers with all-actor IP denial. Its reports
require 21 normal and 24 checks per negative, no skips. Prior controls stay
mandatory. Only the combined job budget increases from 50 to 55 minutes;
per-operation receive limits remain unchanged.

These selected process crashes do not prove all IPC byte boundaries, physical
power loss, reboot recovery, hostile privileged concurrency, independent operator
administration, full-runtime attestation or production bypass resistance. The
synthetic root controller knows fixture keys. No operator VM, credential, real
Provider, external backend, host firewall, OS trust store or live permission is
changed.
