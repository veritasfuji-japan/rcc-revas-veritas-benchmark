#!/usr/bin/env python3
"""Ben-canonical front-half -> existing VERITAS Native-v2 controlled ACTION path.

This is a bounded local engineering proof. It does not create production
authority and does not claim external validation.
"""
from __future__ import annotations
import argparse, json, os, tempfile
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from rveval.canonical import sha_file, sha_json
from rveval.guardrails import require
from rveval.models import CandidateAction
from rveval.integrations.decide_pipeline import NativeDecisionIntentFactory


def main(output: Path, veritas_root: Path) -> int:
    import pytest
    from veritas_os.policy import sandbox_action_binding as binding
    from veritas_os.policy.canonical_verified_decision_promotion import verify_canonical_verified_decision_promotion_packet
    from veritas_os.policy.live_adapter_bind_authorization_consumption_store import PostgresAtomicAuthorizationConsumptionStore
    from veritas_os.policy.native_bind_authorization import verify_native_bind_authorization
    from veritas_os.policy.native_bind_authorization_consumption import consume_native_bind_authorization
    from veritas_os.policy.bind_effect_reconciliation import EffectExecutionState, PostgresAtomicEffectStateStore
    from veritas_os.policy.sandbox_bind_execution import execute_sandbox_bind
    from veritas_os.policy.sandbox_https_transport import SandboxHTTPSTransport
    from veritas_os.policy.sandbox_recovery import recover_sandbox_attempt
    from veritas_os.security.hash import sha256_of_canonical_json
    from veritas_os.tests.helpers.native_approval_source import build_native_authority_source
    from veritas_os.tests.helpers.fixture_clock import wait_for_fixture_issuance
    from veritas_os.tests.test_native_bind_authorization import _setup
    from veritas_os.tests.test_native_bind_authorization_consumption import _fresh
    from veritas_os.tests.test_sandbox_action_binding import contract, deployment
    from veritas_os.tests import test_canonical_promotion_live_adapter_dry_run_endpoint_allowlist as endpoints
    from veritas_os.tests import test_canonical_promotion_live_adapter_dry_run_credential_authorization as credentials
    from veritas_os.tests.test_decision_to_effect_controlled_e2e import (
        ControlledCredentialProvider, _clock, _load_current, _reader_inputs,
    )

    BEN_PIN=os.environ["BEN_CANONICAL_PIN"]; VERITAS_PIN=os.environ["VERITAS_PIN"]
    require(BEN_PIN=="1d3782d3aae5ff9c88036709c1a5642320cc53c2","BEN_PIN_CHANGED")
    require(VERITAS_PIN=="9b7376ba0077365b9d89004b06c80e76c8bfadc8","VERITAS_PIN_CHANGED")

    payload={"event_id":"42345678-1234-4234-8234-123456789abc","message":"ben canonical native-v2 action capability"}
    config=deployment(); action_contract=contract()
    action_binding=binding.build_sandbox_action_binding(json.dumps(payload),deployment=config,expected_contract=action_contract)
    upstream=CandidateAction("tool_call",name=binding.ACTION,arguments={"payload":deepcopy(payload)})
    events=[]
    def journal(event,payload): events.append({"event":event,"payload":deepcopy(payload)})

    with tempfile.TemporaryDirectory(prefix="ben-native-v2-") as td:
        capture=Path(td)/"capture.json"
        # Use the real controlled /v1/decide capture only as transport/origin.
        # Candidate identity is supplied and checked by NativeDecisionIntentFactory.
        from veritas_os.tests.helpers.live_decision_capture import capture as live_capture
        def candidate_factory(action,pre,review):
            from veritas_os.policy.decision_candidate import DecisionCandidate
            require(sha_json(action.to_dict())==sha_json(upstream.to_dict()),"UPSTREAM_ACTION_CHANGED")
            return DecisionCandidate(
                candidate_id="ben-native-v2-sandbox-action",
                source_model="controlled-ben-canonical-fixture",
                source_trace_ref="ben-canonical:"+BEN_PIN,
                candidate_type="execution_intent_candidate",
                action_type="sandbox-effect",
                actor_identity="synthetic-operator",
                target_system=config.target_system,
                target_resource=config.endpoint_url,
                intended_action=binding.ACTION,
                required_authority=[],
                required_human_approval=False,
                risk_level="low",
                evidence_refs=[action_binding.reference,"rveval-candidate-sha256:"+sha_json(action.to_dict())],
            )
        def request_context(action,pre):
            return {"query":"Register exactly one controlled synthetic sandbox event.",
                    "context":{"user_id":"synthetic-operator","mode":"fast","stakes":0.6,
                               "sandbox_operation":binding.ACTION,"sandbox_only":True,
                               "domain":"benchmark","route":"/v1/decide","actor":"synthetic-operator"}}
        def post(req):
            # Capture a genuine current VERITAS response with the exact candidate fields.
            c=candidate_factory(upstream,{},{}).to_dict()
            overrides={k:c[k] for k in ("intended_action","target_system","target_resource","evidence_refs")}
            live_capture(capture,candidate_overrides=overrides)
            raw=json.loads(capture.read_text())
            # live_capture intentionally stores only the proof-relevant subset; factory
            # needs the complete response, so fail closed rather than synthesize it.
            raise RuntimeError("FULL_DECIDE_RESPONSE_ADAPTER_PENDING")

        from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
        from veritas_os.policy.canonical_verified_decision_promotion import build_canonical_verified_decision_promotion_packet
        pins={"cda":sha_file(Path(__import__("inspect").getsourcefile(verify_canonical_decision_artifact))),
              "promotion":sha_file(Path(__import__("inspect").getsourcefile(build_canonical_verified_decision_promotion_packet)))}
        factory=NativeDecisionIntentFactory(post=post,candidate_factory=candidate_factory,request_context=request_context,
            verify_receipt=lambda response: False,clock=lambda:datetime.now(UTC),journal=journal,source_pins=pins)
        # This call is intentionally the first executable boundary. Until a genuine
        # full DecideResponse adapter is wired, it fails closed and no authorization
        # or effect can be created.
        factory(upstream,{}, {"evidence":{"decision_lock":{"decision_id":"controlled"}}})

    return 2


if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,required=True); p.add_argument("--veritas-root",type=Path,required=True)
    a=p.parse_args(); raise SystemExit(main(a.output,a.veritas_root))
