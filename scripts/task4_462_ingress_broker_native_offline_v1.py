#!/usr/bin/env python3
"""#462: join the #461 ingress to #458 broker/#457 AEAD and #323 Native.

ONLY pinned scripted local SDK responses. The real OpenAI SDK serializes the
capped Native request through the existing #325 cap-only proxy. This script
has no real Provider transport, credentials, external bank access, or ability
to authorize spending. It explicitly records the lossless LOCAL cap-stripping
adaptation used by #323's frozen mock, never conflating those request hashes.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_462_SDK_INGRESS_TO_LOCAL_BROKER_AEAD_NATIVE_SCORER_NO_PROVIDER_V1"
ARMS = ("A", "B")
TRIAL_CASE = "banking:user_task_4:injection_task_0:direct"
OFFLINE_PER_ARM = 4
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "TASK4_462_PAID_APPROVAL",
    "TASK4_461_PAID_APPROVAL", "TASK4_455_LIVE_APPROVAL",
)
# Git blob SHA1 (not content SHA256), exact immutable source files at #461 merge.
EXTRA_SOURCE_BLOBS = {
    "scripts/task4_325_exact_sdk_wire_offline_v1.py": "b15099dcf158bfb1afab1eff7560fd45f31e7622",
    "scripts/task4_461_sdk_response_ingress_no_go_v1.py": "25bd9c0a531158dd6eb111d908d05272ec952664",
    "scripts/task4_323_one_arm_local_sdk_v1.py": "9f66f472dea5317e687413131655ee0016f2703f",
    "scripts/task4_456_raw_response_native_lineage_offline_v1.py": "f857de56e9ef9db866a456d403797014fa6cd6a2",
}

class Refused(RuntimeError):
    pass


def need(condition, reason):
    if condition is not True:
        raise Refused(reason)


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def deny_live_context():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "462_REAL_PROVIDER_SECRET_OR_APPROVAL_CONTEXT_DENIED")


def verify_extra_source_blobs(root=ROOT):
    checks = []
    for rel, expected in EXTRA_SOURCE_BLOBS.items():
        file = root / rel
        need(file.is_file() and not file.is_symlink() and
             file.resolve().is_relative_to(root.resolve()),
             "462_FROZEN_SOURCE_FILE_REQUIRED")
        data = file.read_bytes()
        blob_sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        need(blob_sha == expected, "462_FROZEN_SOURCE_CHANGED")
        checks.append({"path": rel, "git_blob_sha1": blob_sha})
    return checks


def verify_linkage(rows, journal_report, receipt_rows, ingress_rows, vault_rows):
    """Two distinct byte representations: actual capped SDK vs uncapped local mock."""
    expected = {(a, i) for a in ARMS for i in range(OFFLINE_PER_ARM)}
    for records, label in ((receipt_rows, "BROKER"), (ingress_rows, "INGRESS"),
                           (vault_rows, "VAULT"),
                           (journal_report["response_receipts"], "JOURNAL")):
        need(type(records) is list and len(records) == len(expected),
             "462_" + label + "_EXACT_EIGHT_REQUIRED")
        need({(x["arm"], x["ordinal"]) for x in records} == expected,
             "462_" + label + "_PAIRING_REQUIRED")
    broker_map = {(x["arm"], x["ordinal"]): x for x in receipt_rows}
    ingress_map = {(x["arm"], x["ordinal"]): x for x in ingress_rows}
    vault_map = {(x["arm"], x["ordinal"]): x for x in vault_rows}
    source_map = {(x["arm"], x["ordinal"]): x
                  for x in journal_report["response_receipts"]}
    need([x["origin_arm"] for x in rows] == ["A", "B"] and
         journal_report["complete_native_terminals_locally"] == 2 and
         journal_report["detached_native_scorer_calls_locally"] == 2 and
         journal_report["real_provider_calls"] == 0 and
         journal_report["new_genuine_native_utility_scores"] == 0,
         "462_SCRIPTED_NATIVE_TERMINAL_ONLY")
    for key in expected:
        b, i, v, j = (mapping[key] for mapping in
                      (broker_map, ingress_map, vault_map, source_map))
        need(b["sdk_request_sha256"] == i["request_sha256"] ==
             v["request_sha256"] and
             b["response_sha256"] == i["response_sha256"] ==
             v["response_sha256"] == j["original_response_raw_sha256"] and
             b["local_mock_request_sha256"] == j["original_request_raw_sha256"] and
             b["sdk_request_sha256"] != b["local_mock_request_sha256"] and
             v["external_provider_authenticated"] is False and
             i["provenance"] == "UNVERIFIED_RESPONSE_SUPPLIED_BY_CALLER" and
             j["source"] == "LOCAL_SCRIPTED_SDK_MOCK_NOT_REAL_PROVIDER",
             "462_TWO_RAW_REQUEST_SHAS_MUST_NOT_BE_SPLICED")
    return True


def run_local_direct_join():
    deny_live_context()
    verify_extra_source_blobs()
    sys.path.insert(0, str(ROOT / "scripts"))
    from importlib.metadata import version
    need(version("openai") == "1.109.1" and version("httpx") == "0.28.1",
         "462_PINNED_REAL_SDK_AND_HTTPX_REQUIRED")
    import httpx
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    from scripts import task4_323_one_arm_local_sdk_v1 as driver
    from scripts import task4_325_exact_sdk_wire_offline_v1 as capped
    from scripts import agentdojo_openai_frozen_adapter_v0_1 as adapter
    from scripts import task4_456_raw_response_native_lineage_offline_v1 as source_journal
    from scripts import task4_457_local_response_aead_v1 as vault_module
    from scripts import task4_458_local_broker_once_ciphertext_v1 as broker
    from scripts import task4_461_sdk_response_ingress_no_go_v1 as ingress_module
    import task4_frozen_provider_transport_date_context_binding_v1 as transport
    from scripts import task4_460_real_model_readiness_no_go_v1 as readiness

    for deny in (base.reject_live_context, source_journal.deny_live_environment,
                 vault_module.deny_live, broker.deny_live_context):
        deny()
    # #460's already merged eight-byte source contract still protects prior code.
    readiness.readiness()
    recipient = X25519PrivateKey.generate()
    public = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    journal = source_journal.RawResponseJournal()
    native_rows, records, actors = [], [], []
    with tempfile.TemporaryDirectory(prefix="task4-462-local-only-") as folder:
        root = Path(folder)
        vault = vault_module.SealedLocalVault(root, recipient.public_key())
        db, socket_path = root / "broker.sqlite", root / "broker.sock"
        broker_process = broker.spawn_server(db, socket_path, sha(public))
        original_adapter = adapter.create_completion_once

        def local_capped_sdk(*, client, messages, tools):
            return original_adapter(client=capped.CapOnlyOfflineSDKProxy(client),
                                    messages=messages, tools=tools)

        class LocalNativeIngressMock(driver.OneArmMock):
            """Original Native SDK/MockTransport, never any Provider socket."""
            def __init__(self, arm):
                super().__init__(arm)
                self.ingress = ingress_module.SDKResponseIngress(
                    arm=arm, trial_id=broker.SYNTHETIC_TRIAL)
                self.inspector = capped.WireInspector(arm)
                actors.append(self)

            def __call__(self, sdk_request):
                arm, ordinal = self.origin_arm, self.attempts
                need(ordinal < OFFLINE_PER_ARM, "462_ONLY_FROZEN_SOURCE_FOUR_RESPONSES")
                try:
                    # Every hash here describes the SDK's *capped* original.
                    full = self.inspector.inspect(sdk_request)

                    def consume(*, trial, arm, ordinal, request_sha):
                        return broker.exchange(socket_path, {
                            "op": "consume", "trial": trial, "arm": arm,
                            "ordinal": ordinal, "request_sha": request_sha})

                    admission = self.ingress.before_response(
                        ordinal=ordinal, request=sdk_request, claim=consume)
                    need(admission["provider_send_permission"] is False,
                         "462_INGRESS_CANNOT_AUTHORIZE_POST")
                    # Existing #323 mock accepts the historical 5-field body,
                    # not the 6-field capped SDK wire. This LOCAL-only adaptation
                    # remains explicitly different from the original SDK bytes.
                    stripped = {k: v for k, v in full.items()
                                if k != "max_completion_tokens"}
                    local_headers = dict(sdk_request.headers)
                    local_headers.pop("content-length", None)
                    local_request = httpx.Request(
                        sdk_request.method, sdk_request.url,
                        headers=local_headers, content=capped.canonical(stripped))
                    local_response = super().__call__(local_request)
                    sdk_response = httpx.Response(
                        local_response.status_code,
                        headers=local_response.headers,
                        content=local_response.content,
                        request=sdk_request)
                    need(local_response.content == sdk_response.content and
                         sdk_response.request is sdk_request,
                         "462_LOCAL_MOCK_RESPONSE_BYTES_CANNOT_CHANGE")

                    def archive(*, trial, arm, ordinal, request, response, receipt_sha):
                        v = vault.commit_before_parser(
                            arm=arm, ordinal=ordinal, request=request, response=response)
                        raw_envelope = (root / v["envelope_filename"]).read_bytes()
                        need(v["envelope_sha256"] == sha(raw_envelope),
                             "462_ENVELOPE_SHA_NOT_EQUAL")
                        attached = broker.exchange(socket_path, {
                            "op": "attach", "trial": trial, "arm": arm,
                            "ordinal": ordinal, "receipt_sha": receipt_sha,
                            "envelope_b64": base64.b64encode(raw_envelope).decode()})
                        need(attached["decision"] == "LOCAL_CIPHERTEXT_SEALED" and
                             attached["sha256"] == v["envelope_sha256"] and
                             attached["live_post"] is False,
                             "462_LOCAL_BROKER_ATTACH_BEFORE_SDK_PARSER_REQUIRED")
                        return v

                    unchanged = self.ingress.after_response(
                        response=sdk_response, seal=archive)
                    need(unchanged is sdk_response,
                         "462_INGRESS_SDK_OBJECT_IDENTITY_REQUIRED")
                    journal.observe(arm=arm, request=local_request,
                                    response=local_response)
                    records.append({
                        "arm": arm, "ordinal": ordinal,
                        "sdk_request_sha256": sha(sdk_request.content),
                        "local_mock_request_sha256": sha(local_request.content),
                        "response_sha256": sha(sdk_response.content),
                        "recipient_envelope_sha256": vault.receipts[-1]["envelope_sha256"],
                        "response_object_identity_preserved": unchanged is sdk_response,
                        "real_provider_post": False})
                    return unchanged
                except BaseException:
                    self.ingress.unknown()
                    raise

        try:
            with patch.object(driver, "OneArmMock", LocalNativeIngressMock), \
                 patch.object(transport, "create_completion_once", local_capped_sdk):
                native_rows = [driver.run_source(arm) for arm in ARMS]
            native = journal.seal(native_rows)
            ingress_receipts = [r for instance in actors
                               for r in instance.ingress.receipts]
            need(len(actors) == 2 and
                 all(len(a.inspector.records) == OFFLINE_PER_ARM and
                     a.ingress.report()["score_status"] == "UNSCORED" and
                     a.ingress.report()["real_provider_dispatch"] == "DENY" and
                     not a.ingress.poisoned for a in actors),
                 "462_TWO_FOUR_STEP_INDEPENDENT_LOCAL_SDK_INGRESS_SOURCES")
            need(verify_linkage(native_rows, native, records,
                                ingress_receipts, vault.receipts),
                 "462_NATIVE_LOCAL_SOURCE_LINKAGE_REQUIRED")
            need(vault.verify_local_recovery(recipient),
                 "462_LOCAL_AEAD_BYTES_RECOVERY_FAILED")
        finally:
            broker.stop_server(broker_process, socket_path)
        restarted = broker.spawn_server(db, socket_path, sha(public))
        try:
            for rec in records:
                key = {"trial": broker.SYNTHETIC_TRIAL,
                       "arm": rec["arm"], "ordinal": rec["ordinal"]}
                existing = broker.exchange(socket_path, {"op": "read", **key})
                need(existing["decision"] == "LOCAL_CIPHERTEXT_READ_ONLY" and
                     type(existing["envelope_b64"]) is str,
                     "462_BROKER_RESTART_CIPHERTEXT_NOT_DURABLE")
                blob = broker.b64decode(existing["envelope_b64"])
                need(sha(blob) == rec["recipient_envelope_sha256"] ==
                     existing["ciphertext_sha256"] and
                     sha(broker.recover_test_ciphertext(blob, recipient)) ==
                     rec["response_sha256"],
                     "462_RESTART_RECOVER_DIFFERENT_RESPONSE")
                retry = broker.exchange(socket_path, {
                    "op": "consume", **key,
                    "request_sha": rec["sdk_request_sha256"]})
                need(retry["decision"] == "DENY_ALREADY_CONSUMED" and
                     retry["live_post"] is False,
                     "462_BROKER_MUST_DENY_RETRY_AFTER_RESTART")
        finally:
            broker.stop_server(restarted, socket_path)
    return {
        "rule_of_one": RULE, "case_id": TRIAL_CASE,
        "baseline_main_sha": "32ead3c8835322589e1511660bc9b9aaa1a2db6b",
        "source_class": "LOCAL_SCRIPTED_SOURCE_NOT_REAL_PROVIDER",
        "source_mock_request_body_differs_from_original_capped_sdk_wire": True,
        "sdk_original_capped_requests": 8,
        "original_response_objects_preserved_after_ingress": 8,
        "local_aead_broker_attach_before_sdk_parser": 8,
        "broker_ciphertexts_recovered_after_restart": 8,
        "local_native_terminals": native["complete_native_terminals_locally"],
        "local_native_scorer_calls": native["detached_native_scorer_calls_locally"],
        "capped_sdk_vs_mock_uncapped_receipt_pairs": records,
        "true_utility": None, "true_injection": None,
        "score_status": "UNSCORED", "real_provider_posts": 0,
        "real_provider_dispatch": "DENY", "fresh_owner_paid_consent": False,
        "remote_atomic_ledger_proven": False,
        "external_provider_origin_authenticated": False,
        "off_runner_ciphertext_custody_proven": False,
        "production_bypass_resistance_proven": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    out = (ROOT / args.output).resolve()
    need(out.is_relative_to(ROOT) and not out.exists(),
         "462_CREATE_ONLY_HASH_ONLY_REPORT")
    report = run_local_direct_join()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                   encoding="utf8")
    print("TASK4_462_LOCAL_INGRESS_BROKER_AEAD_NATIVE_SCORER_NO_PROVIDER")


if __name__ == "__main__":
    main()