#!/usr/bin/env python3
"""Ben-canonical selected action -> native v2 -> controlled TLS sandbox effect.

Bounded local integration only; the signed native v2 authorization and a
separate ownership/permit boundary are both required for the exact action.
Task4 #374 exports verified cross-boundary identity for the one local effect.
Synthetic issuer, TLS sandbox and benchmark host are NOT production IAM.
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
from integration.current_veritas_uninterrupted.task4_374_native_v2_lineage import (
    build_verified_trace, canonical_hash, verify_exact_native_v2_lineage,
)

BEN_PIN="1d3782d3aae5ff9c88036709c1a5642320cc53c2"
VERITAS_PIN="9b7376ba0077365b9d89004b06c80e76c8bfadc8"

def main(output: Path, veritas_root: Path, agent_request_json: Path | None = None) -> int:
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
    from veritas_os.policy.native_bind_authorization_consumption import (
        consume_native_bind_authorization, NativeAuthorizationConsumptionError,
    )
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
    inbound_request_digest = None
    inbound_request_id = None
    if agent_request_json is not None:
        # The untrusted bytes arrive via the broker's actual HTTP ingress, not
        # from the native fixture constructor. Re-check at the effect boundary.
        from scripts.task4_376_native_v2_agent_ingress_v1 import (
            decode, validate_agent_request,
        )
        inbound=decode(agent_request_json.read_bytes())
        inbound_request_digest=validate_agent_request(inbound)
        inbound_request_id=inbound["request_id"]
        payload=deepcopy(inbound["candidate"]["arguments"]["payload"])
        require(inbound["candidate"]["name"]==binding.ACTION,
                "TASK4_376_AGENT_CANDIDATE_ACTION_CHANGED")

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
        durable_database_url=os.environ["VERITAS_DATABASE_URL"]
        poc._configure_environment(runtime,"test-"+secrets.token_urlsafe(24),
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
        # The controlled /v1/decide fixture intentionally installs an unreachable TrustLog DSN.
        # Restore the workflow-pinned durable database before Native-v2 authorization consumption.
        os.environ["VERITAS_DATABASE_URL"]=durable_database_url
        key_id=poc._configure_secure_test_infrastructure(runtime,"test-"+secrets.token_urlsafe(32))
        # Secure infrastructure setup intentionally replaces the DB URL with an unreachable
        # TrustLog fixture. Native-v2 durable consumption must use the workflow-pinned DB.
        os.environ["VERITAS_DATABASE_URL"]=durable_database_url
        bundle=poc._configure_verified_policy_bundle(runtime)
        def post(request):
            del request
            from veritas_os.core import pipeline
            desired=candidate_factory(upstream,{},{}).to_dict()
            candidate=replace(poc._candidate(),candidate_id=desired["candidate_id"],source_model=desired["source_model"],
                source_trace_ref=desired["source_trace_ref"],candidate_type=desired["candidate_type"],
                action_type=desired["action_type"],actor_identity=desired["actor_identity"],
                intended_action=desired["intended_action"],target_system=desired["target_system"],
                target_resource=desired["target_resource"],required_authority=desired["required_authority"],
                evidence_refs=desired["evidence_refs"],required_human_approval=desired["required_human_approval"],
                risk_level=desired["risk_level"],regulated_or_high_impact=desired["regulated_or_high_impact"],
                policy_context_refs=desired["policy_context_refs"],ambiguity_flags=desired["ambiguity_flags"],
                missing_required_fields=desired["missing_required_fields"],candidate_rationale_ref=desired["candidate_rationale_ref"],
                metadata=desired["metadata"])
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
        from veritas_os.policy.bind_core.normalizers import normalize_execution_intent
        require(exact_intent==normalize_execution_intent(promotion.exact_execution_intent),"BEN_EXACT_EXECUTION_INTENT_CHANGED")
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
        require(artifact.execution_intent["target_resource"]==config.endpoint_url
            and artifact.execution_intent["intended_action"]==binding.ACTION
            and config.endpoint_url=="https://sandbox.example.invalid/v1/events",
            "TASK4_374_SIGNED_NATIVE_V2_EXACT_SANDBOX_TARGET_REQUIRED")
        require(artifact.single_use is True, "TASK4_374_NATIVE_ONE_USE_REQUIRED")
        # After issuance, replacing the exact authorized target in the
        # unsigned body must NEVER yield usable authorization.
        unauthorized=artifact.model_dump(mode="json")
        unauthorized["execution_intent"]["target_resource"]="https://foreign.example.invalid/v1/events"
        with pytest.raises(ValueError):
            verify_native_bind_authorization(unauthorized,**inputs)
        # Verification above neither consumes nor sends any operation.
        cross_target_substitution_rejected=True

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
            # The target-owning service state comes back via independently
            # authenticated READ-ONLY reconciliation, never from the dispatch
            # HTTP acknowledgement alone.
            require(archive.operation.state=="PERSISTED",
                    "TASK4_374_TARGET_OWNED_EFFECT_NOT_PERSISTED")
            require(archive.operation.payload_digest==dispatch.payload_digest,
                    "TASK4_374_TARGET_OWNED_DIGEST_CHANGED")
            # Do not let a successfully consumed grant be used a second time
            # after the verified effect, even on the same exact target.
            with pytest.raises(NativeAuthorizationConsumptionError,
                               match="NABC_ALREADY_CONSUMED"):
                await consume_native_bind_authorization(
                    artifact,
                    issuance_source_inputs=inputs["source_inputs"],
                    governance_inputs=inputs["governance_inputs"],
                    trust_inputs=inputs["trust_inputs"],
                    current_source_inputs=current_source,
                    current_runtime_risk_packet=risk,
                    now=now, consumption_store=store,
                )
            require(transport.send_calls==1,
                    "TASK4_374_POST_RECON_REPLAY_COULD_DISPATCH")
            rows_after=await _sandbox_row_count(); require(rows_after==rows_before+1,"CONTROLLED_ACTION_EFFECT_COUNT_NOT_ONE")
            return result,dispatch,recovered,archive,transport,governance_calls["count"]

        result=asyncio.run(execute_and_reconcile())
        consumed_result,dispatch,recovered,archive,transport,governance_rechecks=result
        exact_trace=build_verified_trace(
            candidate_sha256=upstream_hash,
            promotion_intent_hash=promotion.execution_intent_hash,
            promotion_target=promotion.exact_execution_intent["target_resource"],
            promotion_action=promotion.exact_execution_intent["intended_action"],
            artifact=artifact,
            consumption=consumed_result.consumption_record,
            dispatch=dispatch,
            transport=transport,
            target_operation=archive.operation,
            archive=archive,
            recovery=recovered,
        )
        trace_checks=verify_exact_native_v2_lineage(exact_trace)
        trace_hash=canonical_hash(exact_trace)
        report={
            "schema":"veritas.current-bind-action-capability-compatibility-proof.v1",
            "proof_round":"CANONICAL_WRAPPER_CURRENT_BIND_CAPABILITY_COMPATIBILITY_V1",
            "result":"PASS",
            "scope":"BOUNDED_LOCAL_ENGINEERING",
            "ben_canonical_pin":BEN_PIN,
            "veritas_pin":VERITAS_PIN,
            "current_veritas_pin":VERITAS_PIN,
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
            "task4_374_native_v2_trace":exact_trace,
            "task4_374_native_v2_trace_sha256":trace_hash,
            "task4_374_native_v2_trace_checks":trace_checks,
            "task4_374_cross_target_signed_artifact_substitution_rejected":
                cross_target_substitution_rejected,
            "task4_374_replay_after_reconciliation_rejected":True,
            "task4_374_network_bypass_independently_proven":False,
            "external_validation":False,
            "production_authority":False,
            "compensation_exercised":False
        }
        if agent_request_json is not None:
            report.update({
                "task4_376_ingress_request_digest":inbound_request_digest,
                "task4_376_ingress_request_id":inbound_request_id,
                "task4_376_input_candidate_sha256":upstream_hash,
                "task4_376_untrusted_request_is_execution_authority":False,
            })
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        return 0

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,required=True); p.add_argument("--veritas-root",type=Path,required=True)
    p.add_argument("--agent-request-json",type=Path)
    a=p.parse_args(); raise SystemExit(main(a.output,a.veritas_root,a.agent_request_json))
