#!/usr/bin/env python3
"""Task4 #463: real Native first SDK wire -> separate local Broker consume -> HARD DENY.

Research sender *pre-dispatch* prototype. No real Provider transport exists.
No credentials, billable calls, network forwarding, authority grant, or
automatic retry is available here. Only historical offline #455 SDK Native
first requests may be inspected; #458 records an irreversible LOCAL test
attempt in a separate process before every refused Provider-bound request.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_463_NATIVE_SDK_PREDISPATCH_SEPARATE_BROKER_HARD_DENY_V1"
FROZEN_MAIN = "c542e9b90c5b3650c5412b43ce21784807caf485"
ARMS = ("A", "B")
REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
RESEARCH_ENV = "task4-provider-protected"
SOURCE_PINS = {
    "scripts/task4_455_research_native_sender_hard_nogo_v1.py":
        "82f814da6f358dcb910b5e1b1fdc4d0b153b90ae",
    "scripts/task4_458_local_broker_once_ciphertext_v1.py":
        "47edf6bc081b3475f34b84102af793117def56a0",
}
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "OPENAI_BASE_URL",
    "ANTHROPIC_API_KEY", "VERITAS_DATABASE_URL", "TASK4_463_PAID_APPROVAL",
    "GITHUB_TOKEN", "GH_TOKEN",
)

class Denied(RuntimeError):
    """Fixed codes only; never print raw request, API secrets or model output."""

def need(ok, reason):
    if ok is not True:
        raise Denied(reason)

def sha(blob):
    return hashlib.sha256(blob).hexdigest()

def no_live_environment():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "463_CREDENTIAL_OR_LIVE_APPROVAL_CONTEXT_FORBIDDEN")

def verify_sources(root=ROOT):
    rows = []
    for rel, expected in SOURCE_PINS.items():
        path = root / rel
        need(path.is_file() and not path.is_symlink()
             and path.resolve().is_relative_to(root.resolve()),
             "463_SOURCE_PIN_PATH_REQUIRED")
        content = path.read_bytes()
        git_blob = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\x00" + content
        ).hexdigest()
        need(git_blob == expected, "463_FROZEN_455_458_SOURCE_DRIFT")
        rows.append({"path": rel, "git_blob": git_blob})
    return rows

def check_offline_bridge(legacy_report, consumption):
    """Require first-turn independent sources, not genuine Utility."""
    from scripts import task4_455_research_native_sender_hard_nogo_v1 as sdk
    need(type(legacy_report) is dict
         and legacy_report.get("rule_of_one") == sdk.RULE
         and legacy_report.get("case_id") == sdk.CASE
         and legacy_report.get("new_live_provider_dispatch") == "DENY"
         and legacy_report.get("actual_provider_calls") == 0
         and legacy_report.get("fresh_paid_permission") is False,
         "463_UPSTREAM_455_MUST_REMAIN_NO_GO")
    sources = legacy_report.get("arms")
    need(type(sources) is list and len(sources) == 2
         and [x.get("arm") for x in sources] == ["A", "B"]
         and all(x.get("provider_calls") == 0
                 and x.get("native_scorer_calls") == 0
                 and x.get("real_issuer_date_attested") is False
                 and x.get("real_provider_send_enabled") is False
                 and x.get("sdk_request", {}).get("provider_post_allowed") is False
                 and x.get("sdk_request", {}).get("date_trust")
                 == "OFFLINE_FIXTURE_NOT_REAL_ISSUER"
                 for x in sources),
         "463_TWO_NATIVE_FIRST_REQUESTS_BOTH_DENIED")
    need(type(consumption) is list and len(consumption) == 2
         and [x.get("arm") for x in consumption] == ["A", "B"]
         and all(x.get("ordinal") == 0
                 and x.get("decision") == "LOCAL_CONSUMED_NO_SEND"
                 and x.get("live_post") is False
                 and x.get("request_sha256")
                 == sources[i]["sdk_request"]["sdk_body_sha256"]
                 for i, x in enumerate(consumption)),
         "463_LOCAL_BROKER_MUST_PRECONSUME_EXACT_SDK_WIRE")
    return True

def review_native_first_pair():
    """Execute REAL SDK serializer and Native first-prompt preparation, no egress.

    The inherited #455 transport is network-incapable. Each first request is
    consumed by an actual #458 isolated Unix-socket Broker BEFORE HARD DENY.
    There is no 'send', 'enable', 'approve', or key-loading entry point.
    """
    no_live_environment()
    source_checks = verify_sources()
    from scripts import task4_455_research_native_sender_hard_nogo_v1 as sdk
    from scripts import task4_458_local_broker_once_ciphertext_v1 as broker

    for check in (sdk.deny_real_context, broker.deny_live_context):
        check()
    receipts = []
    recipient_fingerprint = sha(b"463-synthetic-broker-no-recipient-key")
    with tempfile.TemporaryDirectory(prefix="task4-463-no-provider-") as directory:
        folder = Path(directory)
        db, sock = folder / "trial.sqlite", folder / "broker.sock"
        service = broker.spawn_server(db, sock, recipient_fingerprint)
        parent = sdk.RejectingResearchWire

        class ReviewedDenyTransport(parent):
            def handle_request(self, request):
                need(not self.sealed and self.calls == 0,
                     "463_ONE_NATIVE_ATTEMPT_PER_ARM_ONLY")
                self.sealed = True
                self.calls += 1
                # Original #455 checks exact SDK-produced bytes, model,
                # native first messages, tool schema, and local BPE threshold.
                self.last = sdk.inspect_sdk_request(request)
                need(self.last["date_trust"] == "OFFLINE_FIXTURE_NOT_REAL_ISSUER"
                     and self.last["provider_post_allowed"] is False,
                     "463_ISSUER_OR_TRANSPORT_MUST_REMAIN_UNVERIFIED")
                request_sha = self.last["sdk_body_sha256"]
                consumed = broker.exchange(sock, {
                    "op": "consume", "trial": broker.SYNTHETIC_TRIAL,
                    "arm": self.arm, "ordinal": 0, "request_sha": request_sha})
                need(consumed.get("decision") == "LOCAL_CONSUMED_NO_SEND"
                     and consumed.get("live_post") is False,
                     "463_BROKER_NOT_CONSUMED_BEFORE_SENDER_DENY")
                receipts.append({"arm": self.arm, "ordinal": 0,
                                 "request_sha256": request_sha,
                                 "receipt_sha256": consumed["receipt_sha"],
                                 "decision": consumed["decision"],
                                 "live_post": False})
                raise sdk.Refused("463_BROKER_CONSUMED_NETWORK_TRANSPORT_ABSENT")

        try:
            with patch.object(sdk, "RejectingResearchWire", ReviewedDenyTransport):
                observed = sdk.stage_paired_native_ab()
            need(check_offline_bridge(observed, receipts),
                 "463_BROKER_SDK_BRIDGE_REFUSED")
        finally:
            broker.stop_server(service, sock)
        restarted = broker.spawn_server(db, sock, recipient_fingerprint)
        try:
            for receipt in receipts:
                probe = broker.exchange(sock, {
                    "op": "consume", "trial": broker.SYNTHETIC_TRIAL,
                    "arm": receipt["arm"], "ordinal": 0,
                    "request_sha": receipt["request_sha256"]})
                need(probe.get("decision") == "DENY_ALREADY_CONSUMED"
                     and probe.get("live_post") is False,
                     "463_DUPLICATE_MUST_STAY_DENIED_AFTER_RESTART")
        finally:
            broker.stop_server(restarted, sock)
    return {
        "rule_of_one": RULE, "baseline_main": FROZEN_MAIN, "repository": REPO,
        "research_environment": RESEARCH_ENV,
        "environment_accessed": False, "provider_secrets_present": False,
        "sender_external_transport_installed": False,
        "first_native_sdk_requests": 2,
        "local_broker_consumed_once": len(receipts),
        "broker_replay_refusals_after_restart": len(receipts),
        "source_pins_checked": source_checks,
        "hash_only_pre_dispatch_receipts": receipts,
        "trusted_real_date_authority_proven": False,
        "fresh_owner_paid_consent": False,
        "external_credential_egress_control_proven": False,
        "actual_provider_calls": 0, "native_tool_effects": 0,
        "genuine_utility": None, "genuine_injection": None,
        "score_status": "UNSCORED", "real_provider_dispatch": "DENY",
        "status": "OFFLINE_SENDER_PRE_DISPATCH_INTEGRATED_LIVE_NO_GO",
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    no_live_environment()
    output = (ROOT / args.output).resolve()
    need(output.is_relative_to(ROOT) and not output.exists(),
         "463_CREATE_ONLY_LOCAL_HASH_REPORT")
    report = review_native_first_pair()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                      encoding="utf8")
    print("TASK4_463_NATIVE_FIRST_BROKER_BEFORE_DENY_NO_PROVIDER")

if __name__ == "__main__":
    main()
