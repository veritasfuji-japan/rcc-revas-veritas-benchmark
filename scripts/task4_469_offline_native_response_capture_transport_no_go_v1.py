#!/usr/bin/env python3
"""Task4 #469: actual Native SDK -> offline response transport -> local AEAD.

This is a *working response-transport adapter* for the unchanged #323
offline scripted responder. Unlike #459, this hooks the SDK's HTTP transport
rather than monkeypatching the source responder's __call__ method.

ONLY a pinned, exact OneArmMock class can originate bytes. NO external
Provider connection/credential, real authority, real score or live bank exists.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_469_NATIVE_SDK_TRANSPORT_PREPARSE_AEAD_NO_GO_V1"
CASE = "banking:user_task_4:injection_task_0:direct"
BASE_MAIN = "98c1be0e19d6cbf5baa2566d16b68eb1c70f4013"
ARMS = ("A", "B")
PER_ARM = 4
MAX_WIRE_BYTES = 64_000
PINS = {
    "scripts/task4_323_one_arm_local_sdk_v1.py":
        "9f66f472dea5317e687413131655ee0016f2703f",
    "scripts/task4_320_local_sdk_complete_native_v1.py":
        "b59b2c7d84f0f1ef42e7a7885a5c2f0d673f3271",
    "scripts/task4_456_raw_response_native_lineage_offline_v1.py":
        "f857de56e9ef9db866a456d403797014fa6cd6a2",
    "scripts/task4_457_local_response_aead_v1.py":
        "824beea3e3681c0447829fb7960a9f88a634b90f",
    "scripts/task4_458_local_broker_once_ciphertext_v1.py":
        "47edf6bc081b3475f34b84102af793117def56a0",
    "scripts/task4_459_native_broker_custody_join_v1.py":
        "56ea27e7cd0767b07c986a444efe34e507b8061c",
    "task4_323_single_arm_trajectory_v1.py":
        "a5e1803d6630785f065a8b466b8cf92a231505e2",
    "task4_323_single_arm_scorer_v1.py":
        "74ea71c3b76da9e1c06b7a5eaf4a0b7c85079925",
}
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN",
    "TASK4_469_PAID_APPROVAL",
)


class Denied(RuntimeError):
    """Static denial reason only."""


def need(value, reason):
    if value is not True:
        raise Denied(reason)


def sha(raw):
    return sha256(raw).hexdigest()


def git_blob(raw):
    from hashlib import sha1
    return sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def no_live():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "469_LIVE_SECRET_OR_PAID_GRANT_NOT_ADMITTED")


def verify_pins(root=ROOT):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), "469_ROOT_MUST_EXIST")
    result = []
    for rel, expected in PINS.items():
        file = root / rel
        need(file.is_file() and not file.is_symlink()
             and file.resolve().is_relative_to(root.resolve()),
             "469_PINNED_SOURCE_PATH_REQUIRED")
        got = git_blob(file.read_bytes())
        need(got == expected, "469_PINNED_SOURCE_CHANGED")
        result.append({"path": rel, "git_blob": got})
    return result


class CapturedLocalOnly:
    """Transport owner; require exact (not subclassed) offline Native mock.

    No sender/endpoint selection, imported Provider client or fallback path.
    Local broker consumes BEFORE mock response; original raw response is
    fsynced/encrypted and attached BEFORE it is returned to SDK parsing.
    """

    def __init__(self, *, arm, source, driver, sockpath, root,
                 recipient_vault, journal, broker):
        need(arm in ARMS and type(source) is driver.OneArmMock
             and source.origin_arm == arm and source.attempts == 0
             and not source.closed, "469_ONLY_EXACT_FROZEN_LOCAL_SOURCE")
        self.arm = arm
        self.source = source
        self.sockpath = sockpath
        self.root = root
        self.vault = recipient_vault
        self.journal = journal
        self.broker = broker
        self.records = []
        self.failed = False
        self.closed = False

    def close(self):
        self.closed = True

    def handle_request(self, request):
        need(not self.closed and not self.failed,
             "469_FAILED_OR_CLOSED_RESPONSE_SESSION")
        # Any failure permanently kills this test source (no retry/fallback).
        self.failed = True
        ordinal = len(self.records)
        need(ordinal < PER_ARM
             and self.source.attempts == ordinal
             and request.method == "POST"
             and request.url.scheme == "https"
             and request.url.host == "api.openai.com"
             and request.url.path == "/v1/chat/completions"
             and not request.url.query,
             "469_EXACT_NATIVE_ORDER_AND_TARGET_REQUIRED")
        from scripts.task4_320_local_sdk_complete_native_v1 import LOCAL_KEY
        need(request.headers.get("authorization") == "Bearer " + LOCAL_KEY,
             "469_LOCAL_DUMMY_KEY_ONLY")
        raw = request.content
        need(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE_BYTES,
             "469_NATIVE_WIRE_BYTE_LIMIT")
        key = {"trial": self.broker.SYNTHETIC_TRIAL,
               "arm": self.arm, "ordinal": ordinal}
        claimed = self.broker.exchange(self.sockpath, {
            "op": "consume", **key, "request_sha": sha(raw)})
        need(claimed.get("decision") == "LOCAL_CONSUMED_NO_SEND"
             and claimed.get("live_post") is False,
             "469_CONSUME_BEFORE_ANY_SOURCE_RESPONSE")
        # Exact unchanged #323 offline source callable only. No TCP transport.
        response = self.source(request)
        need(response.request is request
             and type(response.content) is bytes,
             "469_ONLY_ORIGINAL_LOCAL_HTTP_RESPONSE")
        # #457 commits original bytes (even malformed HTTP responses) BEFORE
        # the journal or SDK parser accesses JSON.
        sealed = self.vault.commit_before_parser(
            arm=self.arm, ordinal=ordinal, request=request, response=response)
        envelope = (self.root / sealed["envelope_filename"]).read_bytes()
        need(sha(envelope) == sealed["envelope_sha256"],
             "469_FSYNCD_RESPONSE_ENVELOPE_CHANGED")
        attached = self.broker.exchange(self.sockpath, {
            "op": "attach", **key, "receipt_sha": claimed["receipt_sha"],
            "envelope_b64": base64.b64encode(envelope).decode("ascii")})
        need(attached.get("decision") == "LOCAL_CIPHERTEXT_SEALED"
             and attached.get("sha256") == sealed["envelope_sha256"]
             and attached.get("live_post") is False,
             "469_BROKER_ATTACH_BEFORE_PARSER_REQUIRED")
        self.journal.observe(arm=self.arm, request=request, response=response)
        need(sha(response.content) == sealed["response_sha256"],
             "469_RESPONSE_CHANGED_AFTER_ENCRYPTION")
        self.records.append({
            "arm": self.arm, "ordinal": ordinal,
            "request_sha256": sealed["request_sha256"],
            "response_sha256": sealed["response_sha256"],
            "ciphertext_sha256": sealed["envelope_sha256"],
            "broker_receipt_sha256": claimed["receipt_sha"],
        })
        self.failed = False
        return response


def run_native_pair():
    """Actual offline Native SDK all-turn execution via guarded BaseTransport.

    Creates NO arbitrary response provider. The original local Model mock is
    the sole response origin, and output is NEVER real-score evidence.
    """
    no_live()
    source_pins = verify_pins()
    import httpx
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from scripts import task4_323_one_arm_local_sdk_v1 as driver
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    from scripts import task4_456_raw_response_native_lineage_offline_v1 as journal_mod
    from scripts import task4_457_local_response_aead_v1 as vault_mod
    from scripts import task4_458_local_broker_once_ciphertext_v1 as broker
    from scripts import task4_459_native_broker_custody_join_v1 as legacy

    for guard in (base.reject_live_context, journal_mod.deny_live_environment,
                  vault_mod.deny_live, broker.deny_live_context):
        guard()
    sys.path.insert(0, str(ROOT / "_pins/rcc/external-eval/v0.3.9/src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    recipient = X25519PrivateKey.generate()
    public_raw = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with tempfile.TemporaryDirectory(prefix="task4-469-local-no-provider-") as temp:
        root = Path(temp)
        db, socketpath = root / "slot.sqlite", root / "broker.sock"
        vault = vault_mod.SealedLocalVault(root, recipient.public_key())
        journal = journal_mod.RawResponseJournal()
        service = broker.spawn_server(db, socketpath, sha(public_raw))
        original_mock_transport = httpx.MockTransport
        transports = []
        try:
            class OfflineSDKCaptureTransport(httpx.BaseTransport):
                """Only route through CapturedLocalOnly; cannot forward network."""
                def __init__(self, guard):
                    self.guard = guard
                def handle_request(self, request):
                    return self.guard.handle_request(request)
                def close(self):
                    self.guard.close()

            def exact_local_transport_factory(handler):
                # This replaces MockTransport in the pinned #323 source with
                # an SDK-compatible BaseTransport; no dynamic network fallback.
                arm = getattr(handler, "origin_arm", None)
                need(type(handler) is driver.OneArmMock and arm in ARMS
                     and len(transports) < len(ARMS)
                     and arm == ARMS[len(transports)],
                     "469_TRANSPORT_FACTORY_LOCAL_ORIGIN_ONLY")
                guard = CapturedLocalOnly(
                    arm=arm, source=handler, driver=driver,
                    sockpath=socketpath, root=root, recipient_vault=vault,
                    journal=journal, broker=broker)
                transports.append(guard)
                return OfflineSDKCaptureTransport(guard)

            with patch.object(httpx, "MockTransport", exact_local_transport_factory):
                rows = [driver.run_source(arm) for arm in ARMS]
            native = journal.seal(rows)
            need(len(transports) == 2 and
                 all(g.closed and not g.failed and len(g.records) == PER_ARM
                     for g in transports),
                 "469_EIGHT_TRANSPORT_CAPTURED_TURNS_REQUIRED")
            all_records = [x for guard in transports for x in guard.records]
            need(legacy.audit_join(vault.receipts, native["response_receipts"], native),
                 "469_NATIVE_RESPONSE_AUDIT_JOIN_REQUIRED")
            need(vault.verify_local_recovery(recipient) is True,
                 "469_AEAD_LOCAL_RECOVERY_REQUIRED")
        finally:
            broker.stop_server(service, socketpath)
        restarted = broker.spawn_server(db, socketpath, sha(public_raw))
        try:
            for row in all_records:
                key = {"trial": broker.SYNTHETIC_TRIAL,
                       "arm": row["arm"], "ordinal": row["ordinal"]}
                found = broker.exchange(socketpath, {"op": "read", **key})
                need(found.get("decision") == "LOCAL_CIPHERTEXT_READ_ONLY"
                     and found.get("ciphertext_sha256") == row["ciphertext_sha256"]
                     and found.get("live_post") is False,
                     "469_ENCRYPTED_RESPONSE_MUST_SURVIVE_BROKER_RESTART")
                denied = broker.exchange(socketpath, {
                    "op": "consume", **key, "request_sha": row["request_sha256"]})
                need(denied.get("decision") == "DENY_ALREADY_CONSUMED"
                     and denied.get("live_post") is False,
                     "469_NO_REPLAY_AFTER_RESTART")
        finally:
            broker.stop_server(restarted, socketpath)
    return {
        "rule_of_one": RULE, "baseline_main": BASE_MAIN, "case_id": CASE,
        "source_pins_verified": source_pins,
        "adapter_path": "SDK_HTTPX_BASETRANSPORT_LOCAL_MOCK_ONLY",
        "legacy_mock_call_monkeypatched": False,
        "sdk_actual_native_response_turns": len(all_records),
        "native_completed_scripted_terminals": native["complete_native_terminals_locally"],
        "native_detached_scripted_scorer_calls": native["detached_native_scorer_calls_locally"],
        "all_responses_encrypted_before_sdk_parser": True,
        "broker_local_attempts_nonreplayable_after_restart": len(all_records),
        "response_receipts_hash_only": all_records,
        "real_provider_posts": 0, "external_bank_effects": 0,
        "independent_provider_response_origin_attested": False,
        "real_date_or_recipient_authority": False,
        "cross_runner_protected_custody": False,
        "genuine_native_utility": None,
        "score_status": "UNSCORED", "real_provider_dispatch": "DENY",
        "status": "FULL_NATIVE_SDK_LOCAL_CAPTURE_TRANSPORT_WIRED_NO_REAL_PROVIDER",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    no_live()
    out = (ROOT / args.output).resolve()
    need(out.is_relative_to(ROOT) and not out.exists()
         and not out.is_symlink(),
         "469_REPORT_CREATE_ONLY_INSIDE_REPOSITORY")
    result = run_native_pair()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                   encoding="utf-8")
    print("TASK4_469_OFFLINE_SDK_TRANSPORT_EIGHT_RESPONSE_AEAD_NATIVE_SCORER_NO_GO")


if __name__ == "__main__":
    main()
