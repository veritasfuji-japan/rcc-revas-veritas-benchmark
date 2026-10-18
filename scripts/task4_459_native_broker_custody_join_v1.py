#!/usr/bin/env python3
"""Task4 #459: single-source LOCAL SDK -> broker consume -> AEAD -> native -> scorer.

Offline only. The unmodified #323 local scripted OneArmMock is the ONLY
response origin. Uses the unchanged #456 journal, #457 AEAD primitive and #458
separate-process broker. Never creates a real network transport or Provider
credentials; the broker NEVER grants a live send. Neither true Utility nor
cross-runner custody is proven.
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
RULE = "TASK4_459_SINGLE_LOCAL_NATIVE_SOURCE_BROKER_ENCRYPTED_CUSTODY_JOIN_NO_PROVIDER_V1"
CASE = "banking:user_task_4:injection_task_0:direct"
ARMS = ("A", "B")
PER_ARM = 4


class Refused(ValueError):
    pass


def need(condition, reason):
    if condition is not True:
        raise Refused(reason)


def sha(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def audit_join(cryptographic_receipts, native_receipts, native_report):
    """Pure provenance gate; never allows a synthetic report to be scored as real."""
    need(type(cryptographic_receipts) is list and
         type(native_receipts) is list and
         len(cryptographic_receipts) == len(native_receipts) == 8,
         "459_EXACT_EIGHT_SOURCE_BOUND_RESPONSES")
    sealed = {(r["arm"], r["ordinal"]): r for r in cryptographic_receipts}
    native = {(r["arm"], r["ordinal"]): r for r in native_receipts}
    expected = {(arm, ordinal) for arm in ARMS for ordinal in range(PER_ARM)}
    need(set(sealed) == set(native) == expected, "459_NO_CROSS_ARM_OR_ORDINAL_SPLICE")
    for key in expected:
        a, b = sealed[key], native[key]
        need(a["request_sha256"] == b["original_request_raw_sha256"] and
             a["response_sha256"] == b["original_response_raw_sha256"] and
             b["source"] == "LOCAL_SCRIPTED_SDK_MOCK_NOT_REAL_PROVIDER" and
             b["provider_authenticated"] is False and
             a["external_provider_authenticated"] is False and
             a["independent_durable_custody"] is False,
             "459_REQUEST_RESPONSE_NATIVE_SOURCE_NOT_EQUAL")
    need(native_report["distinct_raw_sdk_response_count"] == 8 and
         native_report["complete_native_terminals_locally"] == 2 and
         native_report["detached_native_scorer_calls_locally"] == 2 and
         native_report["real_provider_calls"] == 0 and
         native_report["new_genuine_native_utility_scores"] == 0 and
         native_report["live_provider_dispatch"] == "DENY",
         "459_NATIVE_SCORER_CANNOT_PROMOTE_SYNTHETIC_ORIGIN")
    return True


def run_local_join() -> dict:
    """One unchanged #323 local A/B source, 8 pre-consumed broker slots."""
    sys.path.insert(0, str(ROOT / "_pins/rcc/external-eval/v0.3.9/src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from scripts import task4_323_one_arm_local_sdk_v1 as driver
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    from scripts import task4_456_raw_response_native_lineage_offline_v1 as journal_mod
    from scripts import task4_457_local_response_aead_v1 as vault_mod
    from scripts import task4_458_local_broker_once_ciphertext_v1 as broker
    for f in (base.reject_live_context, journal_mod.deny_live_environment,
              vault_mod.deny_live, broker.deny_live_context):
        f()
    recipient = X25519PrivateKey.generate()
    recipient_public = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_sha = sha(recipient_public)
    with tempfile.TemporaryDirectory(prefix="task4-459-no-provider-") as folder:
        root = Path(folder)
        db, sockpath = root / "trial.sqlite", root / "owner.sock"
        vault = vault_mod.SealedLocalVault(root, recipient.public_key())
        journal = journal_mod.RawResponseJournal()
        records = []
        server = broker.spawn_server(db, sockpath, public_sha)
        original = driver.OneArmMock.__call__
        try:
            def observe(mock, request):
                # All bytes come from the source-owned local MockTransport.
                need(type(mock) is driver.OneArmMock and mock.origin_arm in ARMS,
                     "459_ONLY_PINNED_OFFLINE_RESPONSE_ORIGIN")
                arm, ordinal = mock.origin_arm, mock.attempts
                need(type(ordinal) is int and 0 <= ordinal < PER_ARM,
                     "459_ONLY_FOUR_NATIVE_REQUESTS_PER_ARM")
                request_raw = request.content
                need(type(request_raw) is bytes and bool(request_raw),
                     "459_NATIVE_REQUEST_BYTES_REQUIRED")
                claim = broker.exchange(sockpath, {
                    "op": "consume", "trial": broker.SYNTHETIC_TRIAL,
                    "arm": arm, "ordinal": ordinal, "request_sha": sha(request_raw)})
                need(claim["decision"] == "LOCAL_CONSUMED_NO_SEND" and
                     claim["live_post"] is False, "459_BROKER_CONSUME_BEFORE_CAPTURE")
                # The original transport generates only a deterministic local fixture.
                # If it fails after claim, the slot remains permanently UNKNOWN.
                response = original(mock, request)
                rec = vault.commit_before_parser(arm=arm, ordinal=ordinal,
                                                 request=request, response=response)
                sealed = (root / rec["envelope_filename"]).read_bytes()
                need(sha(sealed) == rec["envelope_sha256"],
                     "459_FSYNCED_CIPHERTEXT_CHANGED")
                attached = broker.exchange(sockpath, {
                    "op": "attach", "trial": broker.SYNTHETIC_TRIAL,
                    "arm": arm, "ordinal": ordinal,
                    "receipt_sha": claim["receipt_sha"],
                    "envelope_b64": base64.b64encode(sealed).decode("ascii")})
                need(attached["decision"] == "LOCAL_CIPHERTEXT_SEALED" and
                     attached["sha256"] == rec["envelope_sha256"] and
                     attached["live_post"] is False,
                     "459_CIPHERTEXT_NOT_SEALED_BEFORE_PARSER")
                # This source verifier inspects original local HTTP bytes.
                # Return exactly the source-owned SDK response object.
                journal.observe(arm=arm, request=request, response=response)
                records.append({"arm": arm, "ordinal": ordinal,
                                "request_sha256": rec["request_sha256"],
                                "response_sha256": rec["response_sha256"],
                                "ciphertext_sha256": rec["envelope_sha256"],
                                "broker_receipt_sha256": claim["receipt_sha"]})
                return response

            with patch.object(driver.OneArmMock, "__call__", observe):
                rows = [driver.run_source(arm) for arm in ARMS]
            report = journal.seal(rows)
            need(audit_join(vault.receipts, report["response_receipts"], report),
                 "459_SOURCE_JOIN_REFUSED")
            need(vault.verify_local_recovery(recipient),
                 "459_LOCAL_RECOVERY_FAILED")
        finally:
            broker.stop_server(server, sockpath)
        # New isolated broker process reopens the ORIGINAL SQLite file.
        restarted = broker.spawn_server(db, sockpath, public_sha)
        try:
            need(len(records) == 8, "459_INCOMPLETE_SOURCE_RECORDS")
            for item in records:
                key = {"trial": broker.SYNTHETIC_TRIAL,
                       "arm": item["arm"], "ordinal": item["ordinal"]}
                found = broker.exchange(sockpath, {"op": "read", **key})
                need(found["decision"] == "LOCAL_CIPHERTEXT_READ_ONLY" and
                     found["live_post"] is False and
                     type(found["envelope_b64"]) is str,
                     "459_CIPHERTEXT_NOT_DURABLE_ACROSS_BROKER_RESTART")
                blob = broker.b64decode(found["envelope_b64"])
                recovered = broker.recover_test_ciphertext(blob, recipient)
                need(sha(blob) == item["ciphertext_sha256"] ==
                     found["ciphertext_sha256"] and
                     sha(recovered) == item["response_sha256"],
                     "459_RECOVERED_SAME_SOURCE_RESPONSE_REQUIRED")
                attempt = broker.exchange(sockpath, {
                    "op": "consume", **key, "request_sha": item["request_sha256"]})
                need(attempt["decision"] == "DENY_ALREADY_CONSUMED" and
                     attempt["live_post"] is False,
                     "459_RESTART_MUST_NEVER_REISSUE")
        finally:
            broker.stop_server(restarted, sockpath)
    # No raw HTTP bytes, ciphertext, owner private key or local SQLite in report.
    return {"rule_of_one": RULE, "case_id": CASE,
            "source": "LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM",
            "native_model_requests_captured": 8,
            "encrypted_broker_slots_recovered_after_restart": 8,
            "source_native_terminals": report["complete_native_terminals_locally"],
            "source_detached_native_scorer_calls": report["detached_native_scorer_calls_locally"],
            "paired_arm_sources": list(ARMS),
            "hash_only_receipts": records,
            "real_provider_posts": 0, "new_genuine_utility": 0,
            "off_runner_custody_proven": False,
            "independent_cross_runner_cas_proven": False,
            "provider_authenticated": False,
            "real_execution_date_authority_proven": False,
            "live_dispatch": "DENY"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    out = (ROOT / args.output).resolve()
    need(out.is_relative_to(ROOT) and not out.exists(),
         "459_CREATE_ONLY_REDACTED_REPORT")
    result = run_local_join()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf8")
    print("TASK4_459_LOCAL_NATIVE_BROKER_AEAD_RESTART_SCORER_NO_PROVIDER")


if __name__ == "__main__":
    main()