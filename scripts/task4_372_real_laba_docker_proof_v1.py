#!/usr/bin/env python3
"""Task4 #372: invoke exact upstream formal LABA issuance, verification and consume.

Isolation: pinned veritas_os checkout inside networkless, unprivileged Docker.
Upstream issuer/governance fixtures use GENERATED test-only Ed25519 and a
frozen trusted test clock; no production authority or Provider calls.
Do not promote fixture authorization to the different #371 Docker sink target.
"""
from __future__ import annotations
import asyncio
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path

from veritas_os.policy.live_adapter_bind_authorization import (
    verify_live_adapter_bind_authorization_artifact,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption import (
    consume_live_adapter_bind_authorization_and_invoke_bind,
    LiveAdapterBindAuthorizationConsumptionError,
)
from veritas_os.policy.live_adapter_bind_authorization_consumption_store import (
    InMemoryAtomicAuthorizationConsumptionStore,
)
from veritas_os.tests.test_live_adapter_bind_authorization import (
    VERIFICATION_NOW, _build,
)
from veritas_os.tests.test_live_adapter_bind_authorization_consumption import (
    _Resolver,_HeaderConstructor,_Factory,
)

EXPECTED_PIN="b1835c9f5044855a7b69f82de997056bba8847ab"
EXPECTED_SHA_ENV="TASK4_372_OS_CONSUMER_SOURCE_SHA256"
SOURCE=Path("/app/veritas_os/policy/live_adapter_bind_authorization_consumption.py")
SINK="http://mock-effect:8081/mock-effect"

def need(value,code):
    if not value: raise AssertionError(code)

def as_json(value):
    return value.model_dump(mode="json")

async def consume(art,gov,trust,now,store,resolver,header,factory):
    return await consume_live_adapter_bind_authorization_and_invoke_bind(
        art,governance_inputs=gov,trust_inputs=trust,now=now,
        consumption_store=store,credential_resolver=resolver,
        authorization_header_constructor=header,adapter_factory=factory,
        append_trustlog=False,
    )

async def denied(call,code):
    try: await call
    except LiveAdapterBindAuthorizationConsumptionError as e:
        need(code in str(e),"INCORRECT_FORMAL_GATE_DENIAL_"+code+":"+str(e))
        return str(e)
    raise AssertionError("FORMAL_GATE_FAIL_OPEN_"+code)

def evidence_for(arm,human_required):
    artifact,governance,trust=_build(human_required=human_required)
    verified=verify_live_adapter_bind_authorization_artifact(
        artifact,governance_inputs=governance,trust_inputs=trust)
    need(verified==artifact,"UPSTREAM_SIGNATURE_AND_GOVERNANCE_VERIFICATION")
    need(artifact.bind_authorization_state=="AUTHORIZED",
         "SIGNED_FORMAL_ARTIFACT_NOT_AUTHORIZED")
    need(artifact.authorization_consumption_state=="NOT_CONSUMED",
         "PRECONSUMED_ISSUANCE")
    need(artifact.bind_invocation_state=="NOT_INVOKED",
         "EARLY_BIND_INVOCATION")
    need(artifact.single_use and artifact.replay_protection_required,
         "ONEUSE_RULE_NOT_IN_ISSUED_AUTHORIZATION")
    need(artifact.human_approval_requirement_status==
         ("VERIFIED" if human_required else "NOT_REQUIRED"),
         "HUMAN_POLICY_FIXTURE_MISMATCH")
    # Full intended action and target binding remains distinct from the
    # synthetic sink: real upstream authorization cannot be repurposed.
    bound_target=artifact.execution_intent["target_resource"]
    need(isinstance(bound_target,str) and bound_target and
         bound_target!=SINK,"UNEXPECTED_FORMAL_AUTHORIZATION_TARGET")
    auth_id=artifact.live_adapter_bind_authorization_id

    store=InMemoryAtomicAuthorizationConsumptionStore()
    resolver,header,factory=_Resolver(),_HeaderConstructor(),_Factory()
    original=as_json(artifact)
    altered=json.loads(json.dumps(original))
    altered["execution_intent_hash"]="0"*64
    bad=asyncio.run(denied(
        consume(altered,governance,trust,VERIFICATION_NOW,
                store,resolver,header,factory),
        "LABAC_AUTHORIZATION_VERIFICATION_FAILED"))
    need(resolver.calls==0 and header.calls==0 and factory.calls==0,
         "TAMPERED_FORMAL_AUTH_MAY_NOT_ACCESS_SECRETS")
    need(asyncio.run(store.get(auth_id)) is None,
         "TAMPERED_AUTH_CONSUMED")

    expired=asyncio.run(denied(
        consume(artifact,governance,trust,VERIFICATION_NOW+timedelta(days=1),
                store,resolver,header,factory),
        "LABAC_AUTHORIZATION_VERIFICATION_FAILED"))
    need(asyncio.run(store.get(auth_id)) is None,
         "EXPIRED_AUTH_CONSUMED")
    need(resolver.calls==0,"EXPIRED_AUTH_ACCESSED_CREDENTIAL")

    result=asyncio.run(consume(artifact,governance,trust,VERIFICATION_NOW,
        store,resolver,header,factory))
    need(result.authorization_consumed and
         result.consumption_record.consumption_state=="CONSUMED" and
         result.bind_core_invoked,
         "ACTUAL_VERITAS_CONSUMPTION_AND_BIND_NOT_INVOKED")
    need(result.consumption_record.live_adapter_bind_authorization_id==auth_id,
         "AUTHORIZE_CONSUME_ID_MISMATCH")
    need(result.bind_receipt.execution_intent_id==artifact.execution_intent_id,
         "AUTHORIZE_BIND_INTENT_MISMATCH")
    need(resolver.calls==header.calls==factory.calls==1,
         "CREDENTIAL_ACCESS_ORDER_OR_FACTORY_COUNT")
    replay=asyncio.run(denied(
        consume(artifact,governance,trust,VERIFICATION_NOW,
                store,resolver,header,factory),
        "LABAC_AUTHORIZATION_ALREADY_CONSUMED"))
    need(resolver.calls==header.calls==factory.calls==1,
         "REPLAY_ACCESSED_CREDENTIAL_OR_BOUND_ADAPTER")
    need(asyncio.run(store.get(auth_id))==result.consumption_record,
         "FORMAL_CONSUMPTION_RECORD_NOT_RETAINED")
    return {
        "arm":arm,
        "human_approval_requirement_status":artifact.human_approval_requirement_status,
        "upstream_issuance_used":True,
        "upstream_signature_and_governance_verified":True,
        "upstream_real_consumption_gate_invoked":True,
        "upstream_bind_core_entered":result.bind_core_invoked,
        "upstream_apply_attempted":result.adapter_apply_attempted,
        "authorization_id":auth_id,
        "authorization_hash":artifact.live_adapter_bind_authorization_hash,
        "execution_intent_id":artifact.execution_intent_id,
        "execution_intent_hash":artifact.execution_intent_hash,
        "authorized_target":bound_target,
        "docker_mock_sink_target":SINK,
        "exact_source_target_binding_to_docker_sink":False,
        "docker_mock_sink_dispatch_permitted_by_this_artifact":False,
        "consumption_id":result.consumption_record.consumption_id,
        "consumption_hash":result.consumption_record.consumption_hash,
        "bind_final_outcome":str(result.bind_receipt.final_outcome),
        "tamper_rejection":bad,
        "expired_rejection":expired,
        "oneuse_replay_rejection":replay,
        "secret_resolution_calls":resolver.calls,
        "credential_header_calls":header.calls,
        "adapter_factory_calls":factory.calls,
        "frozen_upstream_test_clock":VERIFICATION_NOW.isoformat(),
        "live_provider_calls":0,"real_bank_effects":0,
    }

async def postconsume_failure():
    art,gov,trust=_build()
    store=InMemoryAtomicAuthorizationConsumptionStore()
    failing=_Resolver(fail=True)
    denied_reason=await denied(
        consume(art,gov,trust,VERIFICATION_NOW,store,
                failing,_HeaderConstructor(),_Factory()),
        "LABAC_CREDENTIAL_RESOLUTION_FAILED_AFTER_CONSUMPTION")
    kept=await store.get(art.live_adapter_bind_authorization_id)
    need(kept is not None and failing.calls==1,
         "AFTER_CONSUME_FAILURE_MUST_STAY_CONSUMED")
    second=_Resolver()
    replay=await denied(
        consume(art,gov,trust,VERIFICATION_NOW,store,
                second,_HeaderConstructor(),_Factory()),
        "LABAC_AUTHORIZATION_ALREADY_CONSUMED")
    need(second.calls==0,"AFTER_CONSUMPTION_FAILURE_REPLAY_SECRET_ACCESS")
    return {
        "authorization_id":art.live_adapter_bind_authorization_id,
        "consumption_hash":kept.consumption_hash,
        "failure":denied_reason,"replay":replay,
        "credential_resolution_failed_after_consumption":True,
        "record_kept":True,"replay_secret_resolution_calls":second.calls,
    }

def main():
    need(os.geteuid()==65534 and os.getegid()==65534,
         "NONROOT_DOCKER_ONLY")
    need(not Path("/var/run/docker.sock").exists(),
         "DOCKER_DAEMON_CONTROL_MOUNT_FORBIDDEN")
    for name in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
                 "OPENAI_BASE_URL","AWS_SECRET_ACCESS_KEY","GH_TOKEN",
                 "GITHUB_TOKEN","VERITAS_DATABASE_URL"):
        need(not os.environ.get(name),"REAL_CREDENTIAL_FORBIDDEN_"+name)
    digest=hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    need(digest==os.environ.get(EXPECTED_SHA_ENV),
         "UPSTREAM_REAL_CONSUMER_SOURCE_DRIFT")
    os.environ["VERITAS_POSTURE"]="secure"
    arms=[evidence_for("A",True),evidence_for("B",False)]
    need(arms[0]["authorization_id"]!=arms[1]["authorization_id"],
         "A_AND_B_FORMAL_AUTHORIZATION_IDENTITIES_NOT_INDEPENDENT")
    failed=asyncio.run(postconsume_failure())
    checks={
        "real_upstream_formal_artifact_issued_for_both_arms":len(arms)==2,
        "upstream_signature_and_governance_verified_for_both":
            all(x["upstream_signature_and_governance_verified"] for x in arms),
        "real_HUMAN_VERIFIED_fixture_in_arm_A":
            arms[0]["human_approval_requirement_status"]=="VERIFIED",
        "human_not_required_fixture_arm_B":
            arms[1]["human_approval_requirement_status"]=="NOT_REQUIRED",
        "different_signed_real_authorization_ids":
            arms[0]["authorization_id"]!=arms[1]["authorization_id"],
        "real_consume_before_credential_and_bind":
            all(x["secret_resolution_calls"]==1 and
                x["upstream_bind_core_entered"] for x in arms),
        "real_consumption_record_matches_authorization":
            all(x["consumption_id"].startswith("labac:v1:sha256:") for x in arms),
        "altered_formal_artifact_denied_without_consumption":
            all("LABAC_AUTHORIZATION_VERIFICATION_FAILED" in
                x["tamper_rejection"] for x in arms),
        "expired_formal_artifact_denied_before_secret_access":
            all("LABAC_AUTHORIZATION_VERIFICATION_FAILED" in
                x["expired_rejection"] for x in arms),
        "duplicate_real_formal_authorization_denied":
            all("LABAC_AUTHORIZATION_ALREADY_CONSUMED" in
                x["oneuse_replay_rejection"] for x in arms),
        "postconsumption_credential_failure_irreversibly_consumed":
            failed["record_kept"] is True,
        "postconsumption_failure_replay_does_not_resolve_secret":
            failed["replay_secret_resolution_calls"]==0,
        "formal_target_does_not_authorize_different_docker_sink":
            all(x["exact_source_target_binding_to_docker_sink"] is False and
                x["docker_mock_sink_dispatch_permitted_by_this_artifact"] is False
                for x in arms),
        "frozen_synthetic_issuer_clock_disclosed":
            all(x["frozen_upstream_test_clock"] for x in arms),
        "no_provider_or_bank_effects":all(
            x["live_provider_calls"]==x["real_bank_effects"]==0 for x in arms),
        "not_production_authority":True,
    }
    need(len(checks)==16 and all(checks.values()),
         "SIXTEEN_REAL_LABA_DOCKER_INVARIANTS_FAILED")
    print(json.dumps({
        "rule":"TASK4_372_REAL_LABA_ISSUE_VERIFY_CONSUME_DOCKER_V1",
        "exact_os_pin":EXPECTED_PIN,
        "consumer_source_sha256":digest,
        "offline_network_namespace":"none",
        "actual_formal_veritas_functions_executed":True,
        "inputs_are_upstream_synthetic_governance_test_fixtures":True,
        "clock_is_frozen_according_to_upstream_fixture":True,
        "full_prod_authority_end_to_end":False,
        "formal_target_mismatch_prevents_docker_sink_dispatch":True,
        "in_memory_atomic_consumption_store_production_safe":False,
        "arms":arms,"failure_after_consume":failed,"checks":checks,
        "real_provider_calls":0,"real_bank_effects":0,"real_spend_usd":0,
    },sort_keys=True))

if __name__=="__main__":
    main()
