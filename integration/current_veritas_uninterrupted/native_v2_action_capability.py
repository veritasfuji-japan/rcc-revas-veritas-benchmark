#!/usr/bin/env python3
"""Ben-canonical front-half -> existing VERITAS Native-v2 consumption boundary.

Bounded local engineering proof only. This stage deliberately stops before
external dispatch; consumption is audit lineage, not execution permission.
"""
from __future__ import annotations
import argparse, asyncio, base64, inspect, json, os, secrets, tempfile
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from rveval.canonical import sha_file, sha_json
from rveval.guardrails import require
from rveval.integrations.decide_pipeline import NativeDecisionIntentFactory
from rveval.models import CandidateAction

BEN_PIN="1d3782d3aae5ff9c88036709c1a5642320cc53c2"
VERITAS_PIN="9b7376ba0077365b9d89004b06c80e76c8bfadc8"

def main(output: Path, veritas_root: Path) -> int:
    del output, veritas_root
    import pytest
    from scripts import run_decision_to_external_bind_poc as poc
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    from veritas_os.policy import sandbox_action_binding as binding
    from veritas_os.policy.canonical_verified_decision_promotion import (
        build_canonical_verified_decision_promotion_packet,
        verify_canonical_verified_decision_promotion_packet,
    )
    from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore
    from veritas_os.policy.native_bind_authorization import verify_native_bind_authorization
    from veritas_os.policy.native_bind_authorization_consumption import consume_native_bind_authorization
    from veritas_os.tests.helpers.fixture_clock import wait_for_fixture_issuance
    from veritas_os.tests.helpers.native_approval_source import build_native_authority_source
    from veritas_os.tests.test_native_bind_authorization import _setup
    from veritas_os.tests.test_native_bind_authorization_consumption import _fresh
    from veritas_os.tests.test_sandbox_action_binding import contract, deployment
    from veritas_os.tests import test_canonical_promotion_live_adapter_dry_run_endpoint_allowlist as endpoints
    from veritas_os.tests import test_canonical_promotion_live_adapter_dry_run_credential_authorization as credentials

    require(os.environ["BEN_CANONICAL_PIN"]==BEN_PIN,"BEN_PIN_CHANGED")
    require(os.environ["VERITAS_PIN"]==VERITAS_PIN,"VERITAS_PIN_CHANGED")
    payload={"event_id":"42345678-1234-4234-8234-123456789abc","message":"ben canonical native-v2 action capability"}
    config=deployment()
    action_binding=binding.build_sandbox_action_binding(json.dumps(payload),deployment=config,expected_contract=contract())
    upstream=CandidateAction("tool_call",name=binding.ACTION,arguments={"payload":deepcopy(payload)})
    upstream_hash=sha_json(upstream.to_dict())
    events=[]

    def journal(event,value): events.append({"event":event,"payload":deepcopy(value)})
    def candidate_factory(action,pre_state,rcc_review):
        del pre_state,rcc_review
        from veritas_os.policy.decision_candidate import DecisionCandidate
        require(sha_json(action.to_dict())==upstream_hash,"UPSTREAM_ACTION_CHANGED")
        return DecisionCandidate(
            candidate_id="ben-native-v2-sandbox-action",source_model="controlled-ben-canonical-fixture",
            source_trace_ref="ben-canonical:"+BEN_PIN,candidate_type="execution_intent_candidate",
            action_type="sandbox-effect",actor_identity="synthetic-operator",
            target_system=config.target_system,target_resource=config.endpoint_url,
            intended_action=binding.ACTION,required_authority=[],required_human_approval=False,
            risk_level="low",evidence_refs=[action_binding.reference,"rveval-candidate-sha256:"+upstream_hash])
    def request_context(action,pre_state):
        del action,pre_state
        return {"query":"Register exactly one controlled synthetic sandbox event.",
                "context":{"user_id":"synthetic-operator","mode":"fast","stakes":0.6,
                           "sandbox_operation":binding.ACTION,"sandbox_only":True,
                           "domain":"benchmark","route":"/v1/decide","actor":"synthetic-operator"}}

    with tempfile.TemporaryDirectory(prefix="ben-native-v2-") as td:
        runtime=Path(td)/"runtime"; runtime.mkdir()
        poc._configure_environment(runtime,"test-"+secrets.token_urlsafe(24),
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
        key_id=poc._configure_secure_test_infrastructure(runtime,"test-"+secrets.token_urlsafe(32))
        bundle=poc._configure_verified_policy_bundle(runtime)
        def post(request):
            del request
            from veritas_os.core import pipeline
            desired=candidate_factory(upstream,{},{}).to_dict()
            candidate=replace(poc._candidate(),intended_action=desired["intended_action"],
                target_system=desired["target_system"],target_resource=desired["target_resource"],
                evidence_refs=desired["evidence_refs"],required_human_approval=False)
            with (patch.object(poc,"_candidate",return_value=candidate),
                  patch.object(pipeline,"REPLAY_SOURCE_DIR",runtime/"replay-sources")):
                response,pipeline_ok,calls=poc._decide(
                    aws_clients=poc._DeterministicAwsClients(poc._DeterministicKmsClient(key_id),
                                                            poc._DeterministicObjectLockClient()),
                    policy_bundle_dir=bundle)
            require(pipeline_ok is True,"REAL_DECIDE_PIPELINE_NOT_OBSERVED")
            require(calls["kms_sign_calls"]>0 and calls["object_lock_put_calls"]>0,"REAL_DECIDE_TRUST_INFRA_NOT_OBSERVED")
            return response
        pins={"cda":sha_file(Path(inspect.getsourcefile(verify_canonical_decision_artifact))),
              "promotion":sha_file(Path(inspect.getsourcefile(build_canonical_verified_decision_promotion_packet)))}
        factory=NativeDecisionIntentFactory(post=post,candidate_factory=candidate_factory,
            request_context=request_context,
            verify_receipt=lambda response:isinstance(response.get("canonical_decision_trust_receipt"),dict),
            clock=lambda:datetime.now(UTC),journal=journal,source_pins=pins)
        exact_intent=factory(upstream,{},{"evidence":{"decision_lock":{"decision_id":"controlled"}}})
        require(factory.last_promotion is not None,"BEN_CANONICAL_PROMOTION_MISSING")
        promotion=verify_canonical_verified_decision_promotion_packet(factory.last_promotion)
        require(exact_intent==promotion.exact_execution_intent,"BEN_EXACT_EXECUTION_INTENT_CHANGED")
        require("rveval-candidate-sha256:"+upstream_hash in promotion.exact_execution_intent["evidence_refs"],
                "BEN_UPSTREAM_LINEAGE_LOST")

        issued_at=datetime.now(UTC)
        original_endpoint=endpoints._candidate; original_reference=credentials._reference
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(endpoints,"_candidate",lambda **kw:original_endpoint(
                **kw,endpoint_host="sandbox.example.invalid",endpoint_path_prefix="/v1/events"))
            mp.setattr(credentials,"_reference",lambda **kw:original_reference(
                **kw,credential_scope=config.credential_scope,credential_environment=config.credential_environment))
            source=build_native_authority_source(promotion,issued_at)
        artifact,inputs,*_=_setup(source,contract(),issued_at)
        wait_for_fixture_issuance(inputs["governance_inputs"].verification_now)
        verified=verify_native_bind_authorization(artifact,**inputs)
        require(verified==artifact,"NATIVE_V2_AUTHORIZATION_VERIFY_FAILED")
        require(artifact.execution_intent==promotion.exact_execution_intent,"NATIVE_V2_EXECUTION_INTENT_CHANGED")

        async def consume():
            store=PostgresAtomicAuthorizationConsumptionStore()
            now=datetime.now(UTC); risk,current_source=_fresh(inputs,now)
            result=await consume_native_bind_authorization(
                artifact,issuance_source_inputs=inputs["source_inputs"],
                governance_inputs=inputs["governance_inputs"],trust_inputs=inputs["trust_inputs"],
                current_source_inputs=current_source,current_runtime_risk_packet=risk,now=now,
                consumption_store=store)
            require(result.authorization_consumed is True,"NATIVE_V2_NOT_CONSUMED")
            require(result.durable_store_used is True,"NATIVE_V2_DURABLE_STORE_NOT_USED")
            require(result.execution_authority_created is False,"CONSUMPTION_CREATED_EXECUTION_AUTHORITY")
            require(result.external_action_executed is False,"CONSUMPTION_EXECUTED_EXTERNAL_ACTION")
            return result
        consumed=asyncio.run(consume())
        require(consumed.authorization.execution_intent_hash==promotion.execution_intent_hash,
                "CONSUMED_EXECUTION_INTENT_CHANGED")
        raise RuntimeError("NATIVE_V2_SANDBOX_DISPATCH_COMPOSITION_PENDING")

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,required=True); p.add_argument("--veritas-root",type=Path,required=True)
    a=p.parse_args(); raise SystemExit(main(a.output,a.veritas_root))
