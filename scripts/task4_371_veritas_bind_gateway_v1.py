#!/usr/bin/env python3
"""#371: pinned VERITAS OS bind-time evaluator inside a Docker mock gateway.

Imports EXACT upstream veritas_os/core/continuation_runtime/bind_admissibility.py
from a SHA-pinned veritas_os checkout copied by Docker build. This is a real
deterministic evaluator with synthetic host-trusted signals, NOT the full
VERITAS authorization issuance/production bind-consumption runtime.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path

import service as predecessor
from veritas_bind_admissibility import (
    AdmissibilityOutcome, BindAdmissibilityInput, evaluate_bind_admissibility,
)

CONTEXT_FILE=Path("/trusted-bind/contexts.json")
GATE_LOG=Path("/brokerdata/veritas-bind-evaluations.jsonl")
PINNED_SOURCE=Path("/app/veritas_bind_admissibility.py")
TRUST_DOMAIN=b"TASK4_371_HOST_TRUSTED_BIND_CONTEXT_V1\x00"
VERSION="task4-371-synthetic-veritas-bind-context-v1"
EXPECTED_SOURCE_SHA_ENV="TASK4_371_VERITAS_EVALUATOR_SHA256"

def exact_context(entry,statement,key):
    predecessor.insist(type(entry) is dict and
        set(entry)=={"version","statement_sha","authority_signal",
                     "constraints","live_fingerprint","expected_fingerprint",
                     "runtime_risk","ttl_expires_at","approval_expires_at",
                     "signature"},"TRUSTED_BIND_CONTEXT_SCHEMA_INVALID")
    unsigned={k:entry[k] for k in entry if k!="signature"}
    predecessor.insist(unsigned["version"]==VERSION and
        unsigned["statement_sha"]==predecessor.digest(statement),
        "TRUSTED_BIND_CONTEXT_SUBJECT_MISMATCH")
    signature=entry["signature"]
    predecessor.insist(type(signature) is str and len(signature)==64
        and hmac.compare_digest(
            predecessor.sign(key,TRUST_DOMAIN,unsigned),signature),
        "TRUSTED_BIND_CONTEXT_SIGNATURE_INVALID")
    constraints=unsigned["constraints"]
    predecessor.insist(type(constraints) is dict and
        set(constraints)=={"broker_credential_scoped","exact_sink_endpoint"}
        and all(type(v) is bool or v is None for v in constraints.values()),
        "TRUSTED_BIND_CONSTRAINT_SCHEMA_INVALID")
    for name in ("authority_signal","runtime_risk"):
        value=unsigned[name]
        predecessor.insist(type(value) is bool or value is None,
                           "TRUSTED_BIND_SIGNAL_SCHEMA_INVALID")
    for name in ("live_fingerprint","expected_fingerprint",
                 "ttl_expires_at","approval_expires_at"):
        value=unsigned[name]
        predecessor.insist(value is None or
            (type(value) is str and 0<len(value)<=128),
            "TRUSTED_BIND_FINGERPRINT_OR_EXPIRY_INVALID")
    return unsigned

def signed_context_for_statement(statement):
    key=predecessor.key_bytes()
    source_digest=hashlib.sha256(PINNED_SOURCE.read_bytes()).hexdigest()
    predecessor.insist(source_digest==os.environ.get(EXPECTED_SOURCE_SHA_ENV,""),
                       "PINNED_VERITAS_OS_SOURCE_DIGEST_REQUIRED")
    contents=CONTEXT_FILE.read_bytes()
    predecessor.insist(0<len(contents)<=8192,
                       "TRUSTED_BIND_PACKET_SIZE_INVALID")
    ctx=json.loads(contents,object_pairs_hook=predecessor.strict_object)
    predecessor.insist(type(ctx) is dict and set(ctx)=={"A","B"},
                       "TWO_TRUSTED_ARM_CONTEXTS_REQUIRED")
    return exact_context(ctx[statement["arm"]],statement,key),source_digest

def append_gate_record(row):
    predecessor.insist(GATE_LOG.parent.is_dir(),
                       "BROKER_GATE_EVIDENCE_STORAGE_MISSING")
    with GATE_LOG.open("ab") as fp:
        fp.write(predecessor.canonical(row)+b"\n")
        fp.flush()
        os.fsync(fp.fileno())

class VeritasBindHandler(predecessor.Handler):
    def broker_execute(self,body):
        # Host-signed Task4 statement is verified BEFORE interpreting its
        # separately host-controlled runtime-bind signals.
        predecessor.insist(type(body) is dict and set(body)=={"grant"},
                           "EXACT_SIGNED_GRANT_ENVELOPE")
        grant=body["grant"]
        predecessor.insist(type(grant) is dict and
                           set(grant)=={"statement","signature"},
                           "EXACT_SIGNED_GRANT_REQUIRED")
        statement=grant["statement"]
        predecessor.insist(predecessor.statement_is_exact(statement),
                           "EXACT_SYNTHETIC_TASK4_OPERATION_REQUIRED")
        predecessor.insist(type(grant["signature"]) is str and
            hmac.compare_digest(predecessor.sign(
                predecessor.key_bytes(),b"TASK4_370_GRANT_V1\x00",
                statement),grant["signature"]),
            "HOST_SIGNED_SYNTHETIC_GRANT_REQUIRED")

        context,source_sha=signed_context_for_statement(statement)
        now=datetime.now(timezone.utc).isoformat()
        bind_input=BindAdmissibilityInput(
            execution_intent=predecessor.digest(statement),
            current_timestamp=now,
            authority_signal=context["authority_signal"],
            constraint_signals=context["constraints"],
            live_state_fingerprint=context["live_fingerprint"],
            expected_state_fingerprint=context["expected_fingerprint"],
            runtime_risk_signal=context["runtime_risk"],
            drift_sensitive=True,
            ttl_required=True,
            approval_freshness_required=True,
            missing_signal_outcome=AdmissibilityOutcome.BLOCK,
            ttl_expires_at=context["ttl_expires_at"],
            approval_expires_at=context["approval_expires_at"],
        )
        result=evaluate_bind_admissibility(bind_input)
        is_eligible=(result.admissibility_result is True and
            result.recommended_outcome is AdmissibilityOutcome.ELIGIBLE_TO_COMMIT)
        # This recommendation is NOT execution authority on its own.
        # Both host grant verification and original #370 backend/sink
        # credential + SQLite one-use gate MUST still succeed.
        row={
            "arm":statement["arm"],
            "operation_id":statement["operation_id"],
            "statement_sha256":predecessor.digest(statement),
            "trusted_context_sha256":predecessor.digest(context),
            "veritas_os_evaluator_sha256":source_sha,
            "evaluated_at":now,
            "actual_pinned_veritas_bind_evaluator_invoked":True,
            "recommended_outcome":result.recommended_outcome.value,
            "admissible":result.admissibility_result,
            "reason_codes":list(result.reason_codes),
            "ready_to_attempt_existing_oneuse_sink":is_eligible,
            "full_veritas_os_authorization_issued":False,
            "trusted_signals_are_synthetic_fixtures":True,
            "real_provider_calls":0,
        }
        append_gate_record(row)
        if not is_eligible:
            raise ValueError("VERITAS_BIND_BLOCK:"+
                ",".join(result.reason_codes or ["NO_ELIGIBLE_OUTCOME"]))
        super().broker_execute(body)

def main():
    predecessor.Handler=VeritasBindHandler
    predecessor.main()

if __name__=="__main__":
    main()
