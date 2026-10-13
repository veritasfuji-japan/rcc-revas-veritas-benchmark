"""Task4 #374: fail-closed cross-boundary verifier regression negatives.

These are synthetic validator fixtures only. The authoritative positive proof
comes from Native-v2+Postgres+TLS+read-only reconciliation integration CI.
"""
from __future__ import annotations
from copy import deepcopy
import pytest

from integration.current_veritas_uninterrupted.task4_374_native_v2_lineage import (
    FORMAT, BEN_PIN, OS_PIN, ACTION, SINK, canonical_hash,
    verify_exact_native_v2_lineage,
)

def fixture():
    h=lambda n:format(n,"064x")
    a_id="laba:v2:sha256:"+h(1)
    c_id="labac:v1:sha256:"+h(2)
    op="8ae9c145-4e39-4a86-8adc-2d4273948b9e"
    return {
        "format":FORMAT,"ben_pin":BEN_PIN,"veritas_pin":OS_PIN,
        "decision":{"candidate_sha256":h(3),"promotion_intent_hash":h(4),
                    "promotion_target":SINK,"promotion_action":ACTION},
        "authorization":{"id":a_id,"hash":h(1),"intent_hash":h(4),
                         "target":SINK,"action":ACTION,"subject":"synthetic-operator",
                         "single_use":True,"signed_verified":True},
        "consumption":{"id":c_id,"auth_id":a_id,"auth_hash":h(1),
                       "intent_hash":h(4),"state":"CONSUMED",
                       "durable_postgres":True},
        "dispatch":{"authorization_id":a_id,"consumption_id":c_id,
                    "payload_digest":h(5),"idempotency_key":"idem-A",
                    "attempt_id":"attempt-A","reason":"HTTP_201_MATCHING_ACK",
                    "send_calls":1},
        "target_owned":{"operation_id":op,"event_id":"33333333-3333-4333-8333-333333333333",
                        "payload_digest":h(5),"idempotency_key":"idem-A",
                        "state":"PERSISTED",
                        "source_identity":SINK.removesuffix("/v1/events")},
        "reconciliation":{"consumption_id":c_id,"effect_state":"CONFIRMED_EFFECT",
                          "retry_permitted":False,
                          "archive_proof_hash":h(6),"archive_operation_id":op},
        "receipt":{
            "bundle_hash":h(9),"bind_receipt_hash":h(7),
            "bind_target":SINK,"bind_intent_hash":h(4),
            "lineage":{"authorization_id":a_id,"authorization_hash":h(1),
                       "consumption_id":c_id,"payload_digest":h(5),
                       "external_operation_reference":op,
                       "reconciliation_evidence_hash":h(6)},
            "outcome_metadata":{"authorization_id":a_id,
                                "consumption_id":c_id,"payload_digest":h(5),
                                "bind_receipt_hash":h(7)},
            "observed_effects":[{
                "kind":"sandbox_event_persisted",
                "event_id":"33333333-3333-4333-8333-333333333333",
                "payload_digest":h(5),"operation_id":op}]},
        "restrictions":{
            "real_provider_calls":0,"real_bank_effects":0,
            "external_validation":False,"production_authority":False,
            "network_bypass_independently_proven":False,
            "foreign_sink_authorized":False,
            "trusted_inputs_synthetic":True},
    }

def test_valid_closed_synthetic_fixture():
    e=fixture()
    assert len(verify_exact_native_v2_lineage(e))==7
    assert all(verify_exact_native_v2_lineage(e).values())
    assert len(canonical_hash(e))==64
    assert canonical_hash(e)==canonical_hash(deepcopy(e))

@pytest.mark.parametrize("path,value",[
    (("authorization","target"),"https://foreign.example.invalid/v1/events"),
    (("authorization","action"),"different.action"),
    (("authorization","subject"),"unknown-operator"),
    (("authorization","single_use"),False),
    (("authorization","signed_verified"),False),
    (("authorization","hash"),"0"*64),
    (("authorization","intent_hash"),"0"*64),
    (("consumption","auth_id"),"laba:v2:sha256:"+"0"*64),
    (("consumption","durable_postgres"),False),
    (("consumption","state"),"UNKNOWN"),
    (("dispatch","authorization_id"),"foreign"),
    (("dispatch","idempotency_key"),"another-key"),
    (("dispatch","payload_digest"),"0"*64),
    (("dispatch","send_calls"),2),
    (("target_owned","source_identity"),"https://foreign.example.invalid"),
    (("target_owned","state"),"MISSING"),
    (("target_owned","payload_digest"),"0"*64),
    (("reconciliation","retry_permitted"),True),
    (("reconciliation","effect_state"),"EFFECT_UNKNOWN"),
    (("reconciliation","archive_operation_id"),"wrong-operation"),
    (("receipt","bind_target"),"https://other.example.invalid/v1/events"),
    (("receipt","bind_intent_hash"),"0"*64),
    (("restrictions","production_authority"),True),
    (("restrictions","foreign_sink_authorized"),True),
    (("restrictions","network_bypass_independently_proven"),True),
    (("restrictions","real_provider_calls"),1),
])
def test_single_field_tampering_rejected(path,value):
    e=fixture()
    e[path[0]][path[1]]=value
    with pytest.raises(ValueError,match="TASK4_374_"):
        verify_exact_native_v2_lineage(e)

def test_target_owned_receipt_tampering_rejected():
    for section,key in [
        ("lineage","consumption_id"),("lineage","external_operation_reference"),
        ("lineage","reconciliation_evidence_hash"),
        ("outcome_metadata","bind_receipt_hash"),
        ("outcome_metadata","payload_digest"),
    ]:
        e=fixture()
        e["receipt"][section][key]="wrong"
        with pytest.raises(ValueError,match="TASK4_374_"):
            verify_exact_native_v2_lineage(e)
    e=fixture()
    e["receipt"]["observed_effects"][0]["event_id"]="wrong"
    with pytest.raises(ValueError,match="TASK4_374_"):
        verify_exact_native_v2_lineage(e)

def test_unknown_or_missing_claims_rejected():
    base=fixture()
    for key in ("authorization","target_owned","restrictions"):
        e=deepcopy(base)
        e.pop(key)
        with pytest.raises(ValueError,match="TASK4_374_"):
            verify_exact_native_v2_lineage(e)
    extra=deepcopy(base)
    extra["authorization"]["permitted_even_if_target_changed"]=True
    with pytest.raises(ValueError,match="TASK4_374_"):
        verify_exact_native_v2_lineage(extra)
