#!/usr/bin/env python3
"""Ben canonical front-half into VERITAS Native-v2 ACTION proof.

Bounded local engineering only. No production-authority or external-validation
claim is made by this program.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
import inspect
import json
import os
from pathlib import Path
import secrets
import tempfile
from unittest.mock import patch

from rveval.canonical import sha_file, sha_json
from rveval.guardrails import require
from rveval.integrations.decide_pipeline import NativeDecisionIntentFactory
from rveval.models import CandidateAction


BEN_PIN = "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
VERITAS_PIN = "9b7376ba0077365b9d89004b06c80e76c8bfadc8"


def main(output: Path, veritas_root: Path) -> int:
    del output, veritas_root
    from scripts import run_decision_to_external_bind_poc as poc
    from veritas_os.governance.canonical_decision_artifact import verify_canonical_decision_artifact
    from veritas_os.policy import sandbox_action_binding as binding
    from veritas_os.policy.canonical_verified_decision_promotion import (
        build_canonical_verified_decision_promotion_packet,
        verify_canonical_verified_decision_promotion_packet,
    )
    from veritas_os.tests.test_sandbox_action_binding import contract, deployment

    require(os.environ["BEN_CANONICAL_PIN"] == BEN_PIN, "BEN_PIN_CHANGED")
    require(os.environ["VERITAS_PIN"] == VERITAS_PIN, "VERITAS_PIN_CHANGED")

    payload = {
        "event_id": "42345678-1234-4234-8234-123456789abc",
        "message": "ben canonical native-v2 action capability",
    }
    config = deployment()
    action_binding = binding.build_sandbox_action_binding(
        json.dumps(payload), deployment=config, expected_contract=contract()
    )
    upstream = CandidateAction(
        "tool_call", name=binding.ACTION, arguments={"payload": deepcopy(payload)}
    )
    upstream_hash = sha_json(upstream.to_dict())
    events: list[dict] = []

    def journal(event, value):
        events.append({"event": event, "payload": deepcopy(value)})

    def candidate_factory(action, pre_state, rcc_review):
        del pre_state, rcc_review
        from veritas_os.policy.decision_candidate import DecisionCandidate

        require(sha_json(action.to_dict()) == upstream_hash, "UPSTREAM_ACTION_CHANGED")
        # Start sandbox-compatible. Nothing may rewrite action/target/evidence after
        # Ben's candidate identity has been fixed.
        return DecisionCandidate(
            candidate_id="ben-native-v2-sandbox-action",
            source_model="controlled-ben-canonical-fixture",
            source_trace_ref="ben-canonical:" + BEN_PIN,
            candidate_type="execution_intent_candidate",
            action_type="sandbox-effect",
            actor_identity="synthetic-operator",
            target_system=config.target_system,
            target_resource=config.endpoint_url,
            intended_action=binding.ACTION,
            required_authority=[],
            required_human_approval=False,
            risk_level="low",
            evidence_refs=[
                action_binding.reference,
                "rveval-candidate-sha256:" + upstream_hash,
            ],
        )

    def request_context(action, pre_state):
        del action, pre_state
        return {
            "query": "Register exactly one controlled synthetic sandbox event.",
            "context": {
                "user_id": "synthetic-operator",
                "mode": "fast",
                "stakes": 0.6,
                "sandbox_operation": binding.ACTION,
                "sandbox_only": True,
                "domain": "benchmark",
                "route": "/v1/decide",
                "actor": "synthetic-operator",
            },
        }

    with tempfile.TemporaryDirectory(prefix="ben-native-v2-") as td:
        runtime = Path(td) / "runtime"
        runtime.mkdir()
        poc._configure_environment(
            runtime,
            "test-" + secrets.token_urlsafe(24),
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        )
        key_id = poc._configure_secure_test_infrastructure(
            runtime, "test-" + secrets.token_urlsafe(32)
        )
        bundle = poc._configure_verified_policy_bundle(runtime)

        def post(request):
            del request
            from veritas_os.core import pipeline

            desired = candidate_factory(upstream, {}, {}).to_dict()
            candidate = replace(
                poc._candidate(),
                intended_action=desired["intended_action"],
                target_system=desired["target_system"],
                target_resource=desired["target_resource"],
                evidence_refs=desired["evidence_refs"],
                required_human_approval=False,
            )
            with (
                patch.object(poc, "_candidate", return_value=candidate),
                patch.object(
                    pipeline, "REPLAY_SOURCE_DIR", runtime / "replay-sources"
                ),
            ):
                response, pipeline_ok, calls = poc._decide(
                    aws_clients=poc._DeterministicAwsClients(
                        poc._DeterministicKmsClient(key_id),
                        poc._DeterministicObjectLockClient(),
                    ),
                    policy_bundle_dir=bundle,
                )
            require(pipeline_ok is True, "REAL_DECIDE_PIPELINE_NOT_OBSERVED")
            require(calls["kms_sign_calls"] > 0, "REAL_DECIDE_KMS_NOT_OBSERVED")
            require(
                calls["object_lock_put_calls"] > 0,
                "REAL_DECIDE_PERSISTENCE_NOT_OBSERVED",
            )
            return response

        pins = {
            "cda": sha_file(Path(inspect.getsourcefile(verify_canonical_decision_artifact))),
            "promotion": sha_file(
                Path(inspect.getsourcefile(build_canonical_verified_decision_promotion_packet))
            ),
        }
        factory = NativeDecisionIntentFactory(
            post=post,
            candidate_factory=candidate_factory,
            request_context=request_context,
            # NativeDecisionIntentFactory independently verifies all trust-receipt
            # bindings. This callback is only the deployment-origin/persistence hook;
            # the controlled route above observed both KMS signing and object-lock put.
            verify_receipt=lambda response: isinstance(
                response.get("canonical_decision_trust_receipt"), dict
            ),
            clock=lambda: datetime.now(UTC),
            journal=journal,
            source_pins=pins,
        )
        exact_intent = factory(
            upstream, {}, {"evidence": {"decision_lock": {"decision_id": "controlled"}}}
        )
        require(factory.last_promotion is not None, "BEN_CANONICAL_PROMOTION_MISSING")
        promotion = verify_canonical_verified_decision_promotion_packet(
            factory.last_promotion
        )
        require(
            exact_intent == promotion.exact_execution_intent,
            "BEN_EXACT_EXECUTION_INTENT_CHANGED",
        )
        require(
            "rveval-candidate-sha256:" + upstream_hash
            in promotion.exact_execution_intent["evidence_refs"],
            "BEN_UPSTREAM_LINEAGE_LOST",
        )

        # Deliberately stop before Native-v2 authorization/effect until the remaining
        # existing VERITAS composition is connected. Front-half success alone is not
        # implementation proof and must not emit the proof report.
        raise RuntimeError("NATIVE_V2_EXECUTION_COMPOSITION_PENDING")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--veritas-root", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(main(args.output, args.veritas_root))
