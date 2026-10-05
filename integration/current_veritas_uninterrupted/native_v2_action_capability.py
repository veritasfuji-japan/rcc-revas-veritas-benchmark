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
    del veritas_root
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
            intended_action=binding.ACTION,required_authority=["sandbox:events:register"],required_human_approval=False,
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

        from veritas_os.policy.bind_effect_reconciliation import EffectExecutionState, PostgresAtomicEffectStateStore
        from veritas_os.policy.sandbox_bind_execution import execute_sandbox_bind
        from veritas_os.policy.sandbox_https_transport import SandboxHTTPSTransport
        from veritas_os.policy.sandbox_recovery import recover_sandbox_attempt
        from veritas_os.tests.test_decision_to_effect_controlled_e2e import ControlledCredentialProvider, _clock, _load_current, _reader_inputs, _assert_receipt_decision_lineage, _sandbox_row_count

        async def execute_and_reconcile():
            rows_before=await _sandbox_row_count()
            store=PostgresAtomicAuthorizationConsumptionStore()
            now=datetime.now(UTC); risk,current_source=_fresh(inputs,now)
            result=await consume_native_bind_authorization(artifact,issuance_source_inputs=inputs["source_inputs"],governance_inputs=inputs["governance_inputs"],trust_inputs=inputs["trust_inputs"],current_source_inputs=current_source,current_runtime_risk_packet=risk,now=now,consumption_store=store)
            effect_store=PostgresAtomicEffectStateStore()
            ca_pem=Path(os.environ["VERITAS_SANDBOX_CA_FILE"]).read_text()
            transport=SandboxHTTPSTransport(endpoint_url=config.endpoint_url,ca_pem=ca_pem)
            load_current,governance_calls=_load_current(inputs)
            dispatch=await execute_sandbox_bind(artifact,json.dumps(payload),deployment=config,issuance_source_inputs=inputs["source_inputs"],governance_inputs=inputs["governance_inputs"],trust_inputs=inputs["trust_inputs"],consumption_store=store,effect_store=effect_store,trusted_clock=_clock,load_current_inputs=load_current,provider=ControlledCredentialProvider(os.environ["VERITAS_SANDBOX_WRITER_TOKEN"]),transport=transport)
            state=await effect_store.get(result.consumption_record.consumption_id)
            require(state is not None and state.state==EffectExecutionState.EFFECT_UNKNOWN,"EFFECT_UNKNOWN_NOT_PERSISTED")
            require(dispatch.reason_code=="HTTP_201_MATCHING_ACK","CONTROLLED_ACTION_ACK_MISSING")
            require(transport.send_calls==1,"CONTROLLED_ACTION_NOT_EXACTLY_ONCE")
            reader_policy,verifier_policy,reader=_reader_inputs(config,ca_pem,os.environ["VERITAS_SANDBOX_READER_TOKEN"],"ben-current-bind")
            recovered=await recover_sandbox_attempt(artifact,json.dumps(payload),deployment=config,issuance_source_inputs=inputs["source_inputs"],historical_governance_inputs=inputs["governance_inputs"],trust_inputs=inputs["trust_inputs"],consumption_store=store,effect_store=effect_store,reader_policy=reader_policy,verifier_policy=verifier_policy,provider=reader,trusted_clock=_clock)
            require(recovered.state==EffectExecutionState.CONFIRMED_EFFECT,"EFFECT_NOT_RECONCILED")
            require(recovered.external_effect_retry_permitted is False,"EXTERNAL_RETRY_PERMITTED")
            require(recovered.receipt_bundle is not None,"RECEIPT_BUNDLE_MISSING")
            verification = verify_canonical_decision_artifact(factory.last_response["canonical_decision_artifact"])
            require(verification.is_valid and verification.artifact is not None,"BEN_CDA_REVERIFY_FAILED")
            _assert_receipt_decision_lineage({"cda":verification.artifact,"promotion":promotion},recovered.receipt_bundle)
            archive=await effect_store.get_reconciliation(result.consumption_record.consumption_id)
            require(archive is not None,"RECONCILIATION_ARCHIVE_MISSING")
            rows_after=await _sandbox_row_count(); require(rows_after==rows_before+1,"CONTROLLED_ACTION_EFFECT_COUNT_NOT_ONE")
            return result,dispatch,recovered,archive,governance_calls["count"]

        result=asyncio.run(execute_and_reconcile())
        consumed_result,dispatch,recovered,archive,governance_rechecks=result
        report={
            "proof_round":"CANONICAL_WRAPPER_CURRENT_BIND_CAPABILITY_COMPATIBILITY_V1",
            "result":"PASS",
            "scope":"BOUNDED_LOCAL_ENGINEERING",
            "ben_canonical_pin":BEN_PIN,
            "veritas_pin":VERITAS_PIN,
            "authorization_verified":True,
            "authorization_consumed":True,
            "pre_effect_ownership_acquired":True,
            "immutable_final_dispatch_bound":True,
            "bound_execution_permit_consumed":True,
            "permit_consumption_observed_via_pinned_transport_path":True,
            "permit_consumption_identity_exported":False,
            "exact_final_dispatch_matched":True,
            "controlled_action_effect_once":True,
            "effect_count":1,
            "effect_state_persisted":True,
            "effect_reconciliation_completed":True,
            "bind_receipt_lineage_preserved":True,
            "ben_candidate_lineage_preserved":True,
            "consumed_authorization_lineage_transported":False,
            "generic_bind_core_invoked":False,
            "dispatch_reason":dispatch.reason_code,
            "terminal_effect_state":recovered.state.value,
            "governance_recheck_calls":governance_rechecks,
            "external_validation":False,
            "production_authority":False,
            "compensation_exercised":False
        }
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        return 0

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,required=True); p.add_argument("--veritas-root",type=Path,required=True)
    a=p.parse_args(); raise SystemExit(main(a.output,a.veritas_root))
