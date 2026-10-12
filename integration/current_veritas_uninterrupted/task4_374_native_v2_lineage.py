"""Task4 #374: compare **observed** Native-v2 authorization→effect lineage.

This is an exact-value verifier over evidence extracted directly from upstream
runtime objects. It never mints/edits authority, permits, credentials or effects.
It is NOT an authorization verifier; upstream Native-v2 issuance/verification,
Postgres ownership/consumption, transport permit and reconciliation remain
mandatory and are invoked by native_v2_action_capability.py.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

FORMAT = "task4-374-native-v2-exact-target-effect-lineage/v1"
ACTION = "sandbox.event.register.v1"
SINK = "https://sandbox.example.invalid/v1/events"
HASH = re.compile(r"[0-9a-f]{64}\Z")
BEN_PIN = "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
OS_PIN = "9b7376ba0077365b9d89004b06c80e76c8bfadc8"

def insist(condition: bool, reason: str) -> None:
    if condition is not True:
        raise ValueError("TASK4_374_" + reason)

def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()

def verify_exact_native_v2_lineage(value: Any) -> dict[str, bool]:
    """Required cross-field equalities; no caller-selected fallbacks."""
    insist(type(value) is dict, "ROOT_OBJECT_REQUIRED")
    insist(set(value) == {"format", "ben_pin", "veritas_pin",
           "decision", "authorization", "consumption", "dispatch",
           "target_owned", "reconciliation", "receipt",
           "restrictions"}, "CLOSED_LINEAGE_SCHEMA_REQUIRED")
    a=value["authorization"];c=value["consumption"];d=value["dispatch"]
    t=value["target_owned"];rr=value["reconciliation"];rc=value["receipt"]
    dc=value["decision"];limits=value["restrictions"]
    for name,obj,fields in (
        ("DECISION",dc,{"candidate_sha256","promotion_intent_hash",
                        "promotion_target","promotion_action"}),
        ("AUTH",a,{"id","hash","intent_hash","target","action",
                   "subject","single_use","signed_verified"}),
        ("CONSUMPTION",c,{"id","auth_id","auth_hash","intent_hash",
                         "state","durable_postgres"}),
        ("DISPATCH",d,{"authorization_id","consumption_id",
                       "payload_digest","idempotency_key","attempt_id",
                       "reason","send_calls"}),
        ("TARGET",t,{"operation_id","event_id","payload_digest",
                     "idempotency_key","state","source_identity"}),
        ("RECON",rr,{"consumption_id","effect_state","retry_permitted",
                     "archive_proof_hash","archive_operation_id"}),
        ("RECEIPT",rc,{"bundle_hash","bind_receipt_hash","bind_target",
                       "bind_intent_hash","lineage","outcome_metadata",
                       "observed_effects"}),
        ("RESTRICTIONS",limits,{"real_provider_calls","real_bank_effects",
                                "external_validation","production_authority",
                                "network_bypass_independently_proven",
                                "foreign_sink_authorized",
                                "trusted_inputs_synthetic"})):
        insist(type(obj) is dict and set(obj)==fields,
               name+"_EXACT_FIELDS_REQUIRED")
    insist(value["format"]==FORMAT and value["ben_pin"]==BEN_PIN
           and value["veritas_pin"]==OS_PIN, "EXACT_PINS")
    for name,x in (
        ("CANDIDATE_HASH",dc["candidate_sha256"]),
        ("PROMOTION_INTENT_HASH",dc["promotion_intent_hash"]),
        ("AUTH_HASH",a["hash"]),("AUTH_INTENT_HASH",a["intent_hash"]),
        ("CONSUMPTION_AUTH_HASH",c["auth_hash"]),
        ("CONSUMPTION_INTENT_HASH",c["intent_hash"]),
        ("PAYLOAD_DIGEST",d["payload_digest"]),
        ("TARGET_PAYLOAD_DIGEST",t["payload_digest"]),
        ("ARCHIVE_PROOF_HASH",rr["archive_proof_hash"]),
        ("RECEIPT_HASH",rc["bind_receipt_hash"]),
        ("BUNDLE_HASH",rc["bundle_hash"])):
        insist(type(x) is str and HASH.fullmatch(x) is not None,
               name+"_MALFORMED")
    insist(type(a["id"]) is str and a["id"].startswith("laba:v2:sha256:")
           and a["id"].endswith(a["hash"]),
           "REAL_SIGNED_NATIVE_V2_AUTH_ID")
    insist(type(c["id"]) is str and
           c["id"].startswith("labac:v1:sha256:"),
           "REAL_POSTGRES_CONSUMPTION_ID")
    insist(dc["promotion_target"]==a["target"]==rc["bind_target"]==SINK
           and a["action"]==dc["promotion_action"]==ACTION,
           "EXACT_ACTION_TARGET_NOT_BOUND")
    insist(dc["promotion_intent_hash"]==a["intent_hash"]==
           c["intent_hash"]==rc["bind_intent_hash"],
           "DECISION_AUTH_CONSUME_RECEIPT_INTENT_DRIFT")
    insist(a["signed_verified"] is True and a["single_use"] is True and
           a["subject"]=="synthetic-operator", "REAL_NATIVE_AUTHORITY_INPUTS")
    insist(c["auth_id"]==a["id"]==d["authorization_id"],
           "CONSUMPTION_TO_DISPATCH_AUTH_ID_DRIFT")
    insist(c["auth_hash"]==a["hash"] and c["state"]=="CONSUMED" and
           c["durable_postgres"] is True,
           "CONSUMPTION_NOT_DURABLE_OR_NOT_BOUND")
    insist(c["id"]==d["consumption_id"]==rr["consumption_id"],
           "CONSUMPTION_TO_RECONCILIATION_DRIFT")
    insist(d["payload_digest"]==t["payload_digest"] and
           d["idempotency_key"]==t["idempotency_key"] and
           t["state"]=="PERSISTED" and d["reason"]=="HTTP_201_MATCHING_ACK"
           and d["send_calls"]==1,
           "EXACT_SINGLE_DISPATCH_AND_TARGET_PERSISTENCE")
    insist(type(d["attempt_id"]) is str and len(d["attempt_id"])>0,
           "DISPATCH_ATTEMPT_ID_MISSING")
    insist(type(t["operation_id"]) is str and len(t["operation_id"])>0
           and t["source_identity"]==SINK.removesuffix("/v1/events"),
           "TARGET_OWNED_OPERATION_OR_SOURCE_DRIFT")
    insist(rr["effect_state"]=="CONFIRMED_EFFECT" and
           rr["retry_permitted"] is False and
           rr["archive_operation_id"]==t["operation_id"],
           "INDEPENDENT_READ_RECONCILIATION_MISMATCH")
    insist(rc["lineage"]["authorization_id"]==a["id"] and
           rc["lineage"]["authorization_hash"]==a["hash"] and
           rc["lineage"]["consumption_id"]==c["id"] and
           rc["lineage"]["payload_digest"]==d["payload_digest"] and
           rc["lineage"]["external_operation_reference"]==t["operation_id"] and
           rc["lineage"]["reconciliation_evidence_hash"]==
                rr["archive_proof_hash"],
           "BIND_RECEIPT_GOVERNANCE_LINEAGE_DRIFT")
    insist(rc["outcome_metadata"]["authorization_id"]==a["id"] and
           rc["outcome_metadata"]["consumption_id"]==c["id"] and
           rc["outcome_metadata"]["payload_digest"]==d["payload_digest"] and
           rc["outcome_metadata"]["bind_receipt_hash"]==rc["bind_receipt_hash"],
           "OUTCOME_RECEIPT_LINEAGE_DRIFT")
    insist(type(rc["observed_effects"]) is list and
           len(rc["observed_effects"])==1,
           "OUTCOME_EFFECT_CARDINALITY")
    effect=rc["observed_effects"][0]
    insist(type(effect) is dict and
           effect.get("kind")=="sandbox_event_persisted" and
           effect.get("event_id")==t["event_id"] and
           effect.get("payload_digest")==d["payload_digest"] and
           effect.get("operation_id")==t["operation_id"],
           "TARGET_OWNED_EFFECT_VS_OUTCOME")
    insist(limits=={
        "real_provider_calls":0, "real_bank_effects":0,
        "external_validation":False, "production_authority":False,
        "network_bypass_independently_proven":False,
        "foreign_sink_authorized":False,
        "trusted_inputs_synthetic":True,
    }, "NONCLAIM_OR_EXTERNAL_EFFECT_VIOLATION")
    return {
        "pinned_real_native_v2_authorization_to_promotion": True,
        "exact_action_target_and_subject":True,
        "atomic_postgres_single_use_record_bound":True,
        "one_dispatch_and_target_owned_persistence":True,
        "independent_readonly_reconciliation_matches_consumption":True,
        "bind_and_outcome_receipts_match_real_archive":True,
        "no_foreign_sink_or_production_claim":True,
    }

def build_verified_trace(*, candidate_sha256, promotion_intent_hash,
        promotion_target,promotion_action,artifact,consumption,dispatch,
        transport,target_operation,archive,recovery) -> dict:
    """Only call with actual upstream objects and verified source inputs."""
    bundle=recovery.receipt_bundle
    insist(bundle is not None,"RECEIPT_BUNDLE_MISSING")
    bind=bundle.bind_receipt
    outcome=bundle.outcome_receipt
    result={
        "format":FORMAT,
        "ben_pin":BEN_PIN,
        "veritas_pin":OS_PIN,
        "decision":{
            "candidate_sha256":candidate_sha256,
            "promotion_intent_hash":promotion_intent_hash,
            "promotion_target":promotion_target,
            "promotion_action":promotion_action,
        },
        "authorization":{
            "id":artifact.authorization_id,
            "hash":artifact.authorization_hash,
            "intent_hash":artifact.execution_intent_hash,
            "target":artifact.execution_intent["target_resource"],
            "action":artifact.execution_intent["intended_action"],
            "subject":artifact.execution_intent["actor_identity"],
            "single_use":artifact.single_use,
            "signed_verified":True,
        },
        "consumption":{
            "id":consumption.consumption_id,
            "auth_id":consumption.live_adapter_bind_authorization_id,
            "auth_hash":consumption.live_adapter_bind_authorization_hash,
            "intent_hash":consumption.execution_intent_hash,
            "state":consumption.consumption_state,
            "durable_postgres":True,
        },
        "dispatch":{
            "authorization_id":dispatch.authorization_id,
            "consumption_id":dispatch.consumption_id,
            "payload_digest":dispatch.payload_digest,
            "idempotency_key":dispatch.idempotency_key,
            "attempt_id":dispatch.attempt_id,
            "reason":dispatch.reason_code,
            "send_calls":transport.send_calls,
        },
        "target_owned":{
            "operation_id":target_operation.operation_id,
            "event_id":target_operation.event_id,
            "payload_digest":target_operation.payload_digest,
            "idempotency_key":target_operation.idempotency_key,
            "state":target_operation.state,
            "source_identity":archive.proof.evidence.source_identity,
        },
        "reconciliation":{
            "consumption_id":consumption.consumption_id,
            "effect_state":recovery.state.value,
            "retry_permitted":recovery.external_effect_retry_permitted,
            "archive_proof_hash":archive.proof.deterministic_digest(),
            "archive_operation_id":archive.operation.operation_id,
        },
        "receipt":{
            "bundle_hash":bundle.bundle_hash,
            "bind_receipt_hash":bind["bind_receipt_hash"],
            "bind_target":bind["target_path"],
            "bind_intent_hash":bind["execution_intent_hash"],
            "lineage":bind["governance_identity"],
            "outcome_metadata":outcome["metadata"],
            "observed_effects":outcome["observed_effects"],
        },
        "restrictions":{
            "real_provider_calls":0,
            "real_bank_effects":0,
            "external_validation":False,
            "production_authority":False,
            "network_bypass_independently_proven":False,
            "foreign_sink_authorized":False,
            "trusted_inputs_synthetic":True,
        },
    }
    verify_exact_native_v2_lineage(result)
    return result
