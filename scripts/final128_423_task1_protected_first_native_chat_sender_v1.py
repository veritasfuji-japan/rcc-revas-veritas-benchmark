#!/usr/bin/env python3
"""#423 staged first A/B Native Chat sender; NEVER invoked by PR CI or merge.

The only LIVE path is a separately, manually dispatched protected GitHub job
with fresh consent, source pins, immutable singleton consumption, environment
secret and operator-confirmed billing controls. No general chat-agent runner,
no tool dispatch, no second model turn, no Native scorer. Preflight is offline.
Caller/environment self-claims do not prove IAM isolation or a hard API cap.
"""
from __future__ import annotations

import argparse
import base64
from decimal import Decimal
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import sys

from scripts import final128_421_task1_native_first_pair_presend_v1 as first
from scripts import final128_422_task1_native_chat_http_capture_v1 as shape
from scripts import final128_403_task1_integrated_native_loop_bind_overlay_v1 as native
from scripts import final128_418_task1_native_measurement_gap_v1 as exit_gate
from scripts import final128_425_task1_environment_secret_diagnostic_v1 as secret_diag

CASE = "banking:user_task_1:injection_task_2:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
APPROVAL = "APPROVE_TASK1_FIRST_NATIVE_A_B_TWO_CALLS_MAX_USD_1"
PRODUCTION_TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
ENVIRONMENT = "task1-real-model-pilot"
ARMS = ("A", "B")
MAX_BODY_BYTES = shape.MAX_BODY_BYTES
RUN_RE = re.compile(r"^[1-9][0-9]{5,19}$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
PAYLOAD_MAX_BYTES = first.MAX_SERIALIZED_BYTES
# Restricting output tokens and request bytes does NOT independently prove a
# strict account/project spending cap or exact prompt token billing.
NO_RETRY = True
RULE = "FINAL128_423_TASK1_PROTECTED_FIRST_TWO_NATIVE_CHAT_POST_V1"


class Denied(RuntimeError):
    pass


def require(value, reason):
    if value is not True:
        raise Denied("423_" + reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return first.canonical(obj)


def source_pair():
    """Recreate native initial requests entirely IN PROCESS, never from JSON."""
    from agentdojo.task_suite.load_suites import get_suite
    enrollment = json.loads(native.source.ROSTER_FILE.read_text(encoding="utf8"))
    run = native.run_frozen_task1_integrated_native_ab(
        suite=get_suite("v1.2.2", "banking"), enrollment=enrollment,
        write_count=2)
    ledger = json.loads((exit_gate.ROOT / exit_gate.LEDGER).read_text(encoding="utf8"))
    ready = first.freeze_native_first_pair(source_run=run, ledger=ledger)
    require(ready["redacted_manifest"]["case_id"] == CASE
            and ready["redacted_manifest"]["number_of_proposed_first_chat_calls"] == 2
            and ready["redacted_manifest"]["provider_request_count"] == 0
            and ready["redacted_manifest"]["native_later_scripted_stages_sendable"] is False,
            "EXACT_TWO_INITIAL_NATIVE_REQUESTS")
    for arm in ARMS:
        first.validate_owned_presend_payload(
            prepared=ready, arm=arm,
            proposed_payload=ready["ephemeral_unsent_packets"][arm])
    return run, ledger, ready


def preflight_manifest(ready):
    m = ready["redacted_manifest"]
    return {
        "rule_of_one": RULE,
        "case_id": CASE,
        "model": MODEL,
        "status": "PRESEND_ONLY_NEVER_GRANTED_BY_PREFLIGHT",
        "first_AB_native_request_sha256": m["first_packet_SHA256_by_arm"],
        "native_catalog_sha256": m["native_full_tool_catalog_sha256"],
        "agentdojo_pin": m["agentdojo_pin"],
        "veritas_pin": m["veritas_pin"],
        "proposed_provider_calls": 2,
        "max_output_tokens_per_call": first.OUTPUT_LIMIT,
        "local_soft_cost_upper_estimate_usd": m["budget_upper_estimate_usd"],
        "proposed_spend_target_usd": "1.00",
        "enforced_provider_project_spend_cap_proven": False,
        "live_sender_called": False,
        "protected_approval_observed": False,
        "production_global_once_tag_consumed": False,
        "eligible_for_official_scoring": False,
        "new_genuine_utility_recoveries": 0,
    }


def check_live_runtime(*, require_consumed_tag=True):
    """Check protected runtime+secret formats; tag check only for real send.

    The manual workflow invokes this with require_consumed_tag=False BEFORE
    the irreversible singleton POST. Send invokes it again with True. Neither
    mode can establish actual Provider key validity or billing hard-stop.
    """
    e = os.environ
    require(type(require_consumed_tag) is bool,
            "EXACT_PRECONSUME_OR_LIVE_RUNTIME_PHASE_REQUIRED")
    require(e.get("GITHUB_ACTIONS") == "true"
            and e.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and e.get("GITHUB_REF") == "refs/heads/main"
            and e.get("GITHUB_REPOSITORY") == REPO
            and e.get("GITHUB_ACTOR") == "veritasfuji-japan"
            and e.get("GITHUB_RUN_ATTEMPT") == "1"
            and type(e.get("GITHUB_RUN_ID")) is str
            and RUN_RE.fullmatch(e["GITHUB_RUN_ID"]) is not None
            and type(e.get("GITHUB_SHA")) is str
            and SHA_RE.fullmatch(e["GITHUB_SHA"]) is not None,
            "EXACT_PROTECTED_MAIN_ONE_ATTEMPT_CONTEXT_REQUIRED")
    require(e.get("TASK1_423_APPROVAL") == APPROVAL
            and e.get("TASK1_423_ENVIRONMENT") == ENVIRONMENT,
            "FRESH_HUMAN_APPROVAL_PROTECTED_ENV_REQUIRED")
    if require_consumed_tag:
        require(e.get("TASK1_423_TAG_CONSUMED") == "1"
                and e.get("TASK1_423_TAG_READBACK_SHA") == e["GITHUB_SHA"],
                "POSTCONSUME_TAG_SHA_REQUIRED")
    # Operator-attested only; NOT independent verification of the account
    # billing system. Strong spend stop must be independently reviewed
    # before manually dispatching. The code never marks it PROVEN.
    require(e.get("TASK1_423_OPERATOR_BILLING_REVIEW") ==
            "I REVIEWED PROJECT BILLING AND APPROVE MAX USD 1",
            "FRESH_OPERATOR_BILLING_REVIEW_REQUIRED")
    key = e.get("TASK1_OPENAI_API_KEY")
    capture = e.get("TASK1_CAPTURE_AES256_KEY")
    # Exactly the same format predicate as the separate, zero-effect
    # #425 Environment-only diagnostic. Distinct from actual key validity.
    shape_status = secret_diag.classify_secret_shapes(
        api_key=key, capture_base64=capture)
    require(shape_status != "API_KEY_FORMAT",
            "DEDICATED_ENVIRONMENT_API_SECRET_MISSING")
    require(shape_status == "SHAPES_OK_NOT_A_PROVIDER_AUTHENTICATION",
            "ENCRYPTION_KEY_MUST_BE_CANONICAL_BASE64_OF_32_BYTES")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # Cryptography import above is required for the actual send path.
    return key, base64.b64decode(capture, validate=True)


def _durable_line(path: Path, event: dict):
    require(path.parent.is_dir() and not path.is_symlink()
            and type(event) is dict and "raw_response" not in event
            and "api_key" not in event and "authorization" not in event,
            "NO_PLAINTEXT_OR_SECRET_JOURNAL")
    with path.open("a", encoding="utf8") as out:
        os.chmod(path, 0o600)
        out.write(json.dumps(event, sort_keys=True, allow_nan=False) + "\n")
        out.flush()
        os.fsync(out.fileno())


def one_post(*, arm, payload, api_key, client_id, connection_factory=None):
    """One HTTPS POST ONLY. No retries after unknown HTTP/TLS outcome."""
    require(arm in ARMS and
            type(client_id) is str and
            shape.CLIENT_ID.fullmatch(client_id) is not None and
            shape.CLIENT_ID.fullmatch(client_id).group(1) == arm,
            "EXACT_BOUND_ARM_CLIENT_REQUEST_ID")
    require(type(api_key) is str and len(api_key) > 20,
            "MISSING_PROVIDER_KEY")
    raw = canonical(payload)
    require(len(raw) <= PAYLOAD_MAX_BYTES
            and payload.get("model") == MODEL
            and payload.get("max_completion_tokens") == 256
            and payload.get("store") is False
            and payload.get("stream") is False
            and payload.get("n") == 1
            and payload.get("tool_choice") == "auto",
            "EXACT_NATIVE_MODEL_CAP_AND_NO_STORE")
    connector = connection_factory or (lambda: http.client.HTTPSConnection(
        "api.openai.com", 443, timeout=25, context=ssl.create_default_context()))
    conn = connector()
    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "X-Client-Request-Id": client_id,
        "User-Agent": "veritas-task1-423-first-native-ab",
    }
    try:
        conn.request("POST", "/v1/chat/completions", body=raw, headers=headers)
        res = conn.getresponse()
        body = res.read(MAX_BODY_BYTES + 1)
        require(len(body) <= MAX_BODY_BYTES, "OVERSIZE_BODY_UNKNOWN_NO_RETRY")
        # Never silently retry 429, 5xx, timeout or any ambiguous result.
        require(type(res.status) is int and res.status == 200,
                "HTTP_UNKNOWN_OR_NON_200_NO_RETRY")
        rid = res.getheader("x-request-id")
        require(type(rid) is str and shape.SERVER_ID.fullmatch(rid) is not None,
                "NO_PROVIDER_SERVER_REQUEST_ID")
        return {
            "client_request_id": client_id,
            "response_status": res.status,
            "response_headers": {"x-request-id": rid},
            "raw_response": body,
        }
    finally:
        conn.close()


def _encrypt_capture(*, raw: bytes, key: bytes, arm: str,
                     run_id: str, request_sha: str):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BODY_BYTES
            and len(key) == 32 and arm in ARMS, "ENCRYPTED_CAPTURE_ONLY")
    nonce = os.urandom(12)
    aad = canonical({"case": CASE, "run": run_id,
                     "arm": arm, "request_sha256": request_sha})
    encrypted = AESGCM(key).encrypt(nonce, raw, aad)
    return {
        "format": "AES256_GCM",
        "nonce_base64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_base64": base64.b64encode(encrypted).decode("ascii"),
        "aad_sha256": digest(aad),
        "raw_sha256": digest(raw),
    }


def execute(*, mode, out_dir: Path, connection_factory=None):
    require(mode in ("preflight", "secrets-preflight", "send"),
            "MODE_ONLY_OFFLINE_PREFLIGHT_SECRETS_PREFLIGHT_OR_SEND")
    require(out_dir.is_dir() and not out_dir.is_symlink(), "EXISTING_OUTPUT_DIR")
    run, ledger, ready = source_pair()
    pre = preflight_manifest(ready)
    if mode == "preflight":
        p = out_dir / "task1-423-presend-status.json"
        require(not p.exists(), "NO_OVERWRITE_EVIDENCE")
        p.write_bytes(canonical(pre) + b"\n")
        return pre
    if mode == "secrets-preflight":
        # This MUST occur before the production singleton tag creation.
        # The process does not write any files or start any connection.
        # In particular, this validation is not a permission to dispatch.
        check_live_runtime(require_consumed_tag=False)
        return {
            "status": "SECRETS_SYNTAX_CHECKED_PRETAG_NOT_APPROVED_TO_SEND",
            "credentials_syntax_checked": True,
            "actual_provider_key_validity_proven": False,
            "enforced_provider_spend_stop_proven": False,
            "production_tag_consumed": False,
            "provider_requests_sent": 0,
            "permission_to_send": False,
        }
    require(not (out_dir / "task1-423-redacted-journal.jsonl").exists(),
            "NEVER_RESTART_OR_OVERWRITE_CAPTURE")
    key, encryption_key = check_live_runtime()
    run_id = os.environ["GITHUB_RUN_ID"]
    path = out_dir / "task1-423-redacted-journal.jsonl"
    _durable_line(path, {"event": "BEFORE_FIRST_PROVIDER_CALL_TAG_ALREADY_CONSUMED",
        "run": run_id, "sha": os.environ["GITHUB_SHA"],
        "request_sha256_by_arm": pre["first_AB_native_request_sha256"],
        "max_posts": 2, "no_retry": True, "project_hard_cap_proven": False})
    observations = {}
    for arm in ARMS:
        payload = ready["ephemeral_unsent_packets"][arm]
        first.validate_owned_presend_payload(
            prepared=ready, arm=arm, proposed_payload=payload)
        # #422 already demands the client request id legacy prefix.
        # Reuse it rather than modifying #422 to accept spoofed new IDs.
        client_id = "task1-422-" + arm + "-" + run_id
        _durable_line(path, {
            "event": "BEFORE_ONE_PROVIDER_POST_UNKNOWN_STOP_NO_RETRY",
            "arm": arm, "request_sha256": first.digest(payload),
            "client_id_sha256": first.digest(client_id),
            "may_have_billed_after_this_event": True})
        try:
            wire = one_post(arm=arm, payload=payload,
                            api_key=key, client_id=client_id,
                            connection_factory=connection_factory)
            checked = shape.capture_one(
                native_run=run, ledger=ledger, prepared=ready, arm=arm, **wire)
            enc = _encrypt_capture(
                raw=wire["raw_response"], key=encryption_key,
                arm=arm, run_id=run_id, request_sha=checked["request_sha256"])
            encrypted_path = out_dir / ("task1-423-" + arm + "-raw-chat.enc.json")
            require(not encrypted_path.exists(), "ENCRYPTED_FILE_REPLAY_FORBIDDEN")
            encrypted_path.write_bytes(canonical(enc) + b"\n")
            os.chmod(encrypted_path, 0o600)
            observations[arm] = checked
            _durable_line(path, {
                "event": "ONE_PROVIDER_RESPONSE_CAPTURED_ENCRYPTED",
                "arm": arm,
                "request_sha256": checked["request_sha256"],
                "raw_response_sha256": checked["raw_response_sha256"],
                "server_request_id_sha256": checked["server_request_id_sha256"],
                "response_id_sha256": checked["model_response_id_sha256"],
                "estimated_cost_usd_not_invoice":
                    checked["estimated_cost_usd_not_invoice"],
                "native_tools_dispatched": 0})
        except BaseException as exc:
            _durable_line(path, {
                "event": "UNKNOWN_PROVIDER_OUTCOME_STOP_NEVER_RETRY",
                "arm": arm, "error_class": type(exc).__name__,
                "possible_paid_call": True, "retry_permitted": False})
            raise
    for id_field in ("client_request_id_sha256", "server_request_id_sha256",
                     "model_response_id_sha256"):
        require(observations["A"][id_field] != observations["B"][id_field],
                "A_B_INDEPENDENT_PROVIDER_ID_COLLISION")
    total = sum((Decimal(observations[a]["estimated_cost_usd_not_invoice"])
                 for a in ARMS), Decimal(0))
    require(total <= first.BUDGET_PROPOSED_USD,
            "POSTCALL_LOCAL_ESTIMATE_ABOVE_USD_ONE")
    _durable_line(path, {
        "event": "FIRST_AB_PAIR_CAPTURED_ENCRYPTED_NOT_SCORED",
        "total_local_estimated_cost_usd_not_invoice": str(total),
        "actual_call_count": 2, "native_tool_dispatches": 0,
        "official_native_scorer_calls": 0, "new_utility_recoveries": 0,
        "provider_enforced_spend_cap_verified": False})
    return observations


# #425: A closed allowlist of NON-SECRET diagnostic categories.
# Do NOT emit actual exception text or environment values to Actions logs.
# This is classification of refusal only, never evidence of Provider identity,
# key acceptance, a spend hard-stop, or issuance of execution authority.
SAFE_PRETAG_REFUSAL_CATEGORIES = {
    "423_EXACT_PRECONSUME_OR_LIVE_RUNTIME_PHASE_REQUIRED":
        "INVALID_PREFLIGHT_PHASE",
    "423_EXACT_PROTECTED_MAIN_ONE_ATTEMPT_CONTEXT_REQUIRED":
        "GITHUB_RUNTIME_CONTEXT",
    "423_FRESH_HUMAN_APPROVAL_PROTECTED_ENV_REQUIRED":
        "APPROVAL_OR_ENVIRONMENT",
    "423_FRESH_OPERATOR_BILLING_REVIEW_REQUIRED":
        "BILLING_REVIEW",
    "423_DEDICATED_ENVIRONMENT_API_SECRET_MISSING":
        "API_KEY_FORMAT",
    "423_ENCRYPTION_KEY_MUST_BE_CANONICAL_BASE64_OF_32_BYTES":
        "AES_KEY_BASE64_OR_LENGTH",
    "423_NO_VALID_ENVIRONMENT_ENCRYPTION_KEY":
        "AES_KEY_BASE64_OR_LENGTH",
}


def safe_pretag_refusal_category(exc):
    """Never return any substring supplied by caller, secrets or exception."""
    if type(exc) is not Denied:
        return "OTHER_PRETAG_FAILURE"
    # Only our fixed, audited Denied reasons can select a fixed category.
    return SAFE_PRETAG_REFUSAL_CATEGORIES.get(str(exc),
                                            "OTHER_PRETAG_FAILURE")


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--mode", choices=("preflight", "secrets-preflight", "send"), required=True)
    cli.add_argument("--output-dir", type=Path, required=True)
    args = cli.parse_args()
    try:
        execute(mode=args.mode, out_dir=args.output_dir)
    except BaseException as exc:
        if args.mode == "secrets-preflight":
            print("TASK1_425_PRETAG_DENIAL_CATEGORY=" +
                  safe_pretag_refusal_category(exc), file=sys.stderr)
        else:
            print("TASK1_423_REFUSED_" + type(exc).__name__, file=sys.stderr)
        # Explicitly suppress traceback and exception causes: they might
        # contain secret-bearing third-party validation messages.
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
