"""#323: one selected native arm and one detached real local scorer per
separately started scripted SDK session. Derived from pinned #322 model driver
79c3e4464f2223a57671b09b43709b9f38073670. No real Provider sender or real-effect authority.
"""
#!/usr/bin/env python3
"""#322: two independent *locally scripted* Arm A/B model-session starts.

Exercise pinned real OpenAI SDK serialization, a fresh SDK/MockTransport and
a fresh test date issuer for EACH candidate origin, through unchanged native
Task4 RCC/VERITAS Bind and post-native AgentDojo scorer.

The existing #209 native trajectory intentionally replays its own candidate
into both A and B for paired internal diagnostic evidence. THIS proof selects
A only from independently started source A, and B only from source B. The
other two arm diagnostics are NOT attributed as independent A/B trial scores.

This is NOT genuine independent LLM inference and grants no API permission.
"""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from scripts import task4_320_local_sdk_complete_native_v1 as base
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json

RULE="TASK4_323_TRUE_ONE_ARM_PER_MODEL_ORIGIN_NATIVE_OFFLINE_V1"
PARENT="0fb040772a3c6b0c2913c014667b7d995793b228"
CASE="banking:user_task_4:injection_task_0:dev-one-arm-323"
ARMS=("A","B")
ROOT=Path(__file__).resolve().parents[1]

class OneArmMock(base.OfflineSDKMockServer):
    """Separate fake model namespace per source; each request consumed once."""
    def __init__(self, arm):
        base.need(arm in ARMS,"NOT_A_B_SOURCE")
        super().__init__("preissued_owned_date")
        self.origin_arm=arm

    def __call__(self, request):
        import httpx
        response=super().__call__(request)
        payload=response.json()
        idx=self.attempts-1
        # Distinct SOURCE model identities, not a shared or replayed output.
        payload["id"]="offline-323-"+self.origin_arm+"-"+str(idx)
        calls=payload["choices"][0]["message"]["tool_calls"]
        if calls:
            calls[0]["id"]="offline-323-call-"+self.origin_arm+"-"+str(idx)
        self.responses[-1]=copy.deepcopy(payload)
        return httpx.Response(200,json=payload,request=request)

    def verify(self):
        base.need(not self.closed and self.attempts==4
             and len(self.requests)==len(self.responses)==4
             and [x["choices"][0]["finish_reason"] for x in self.responses]==
                 ["tool_calls","tool_calls","tool_calls","stop"]
             and [x["id"] for x in self.responses]==
                 ["offline-323-"+self.origin_arm+"-"+str(i) for i in range(4)],
             "INDEPENDENT_LOCAL_SOURCE_FIVE_CALLS_REQUIRED")
        return True

def run_source(arm):
    """Entire provenance chain from the first model-shaped SDK request."""
    base.reject_live_context()
    base.need(arm in ARMS,"ONLY_INDEPENDENT_A_B_ORIGINS")
    import httpx
    import openai
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import (
        load_rcc_gate,verify_authority_fixture)
    from task4_trusted_execution_date_profile_v1 import Task4DateProfileSession
    from task4_trusted_execution_date_runner_integration_v1 import Task4ControlledDateRunner
    from task4_frozen_provider_transport_date_context_binding_v1 import Task4FrozenTransportElement
    from task4_323_single_arm_trajectory_v1 import Task4OneArmProspectiveTrajectory
    from task4_323_single_arm_scorer_v1 import observe_completed_one_arm
    from scripts.task4_319_injected_scripted_wire_native_terminal_audit_v1 import injected_environment

    suite=get_suite("v1.2.2","banking")
    env,pre=injected_environment(suite)
    original_sha=sha_json(pre)
    base.need(original_sha==base.SOURCE_PRESTATE_SHA,
              "PINNED_NATIVE_INJECTION_PRESTATE_REQUIRED")
    server=OneArmMock(arm)
    clock=lambda:datetime(2031,7,8,12,tzinfo=timezone.utc)
    date_source="task4-323-offline-only-"+arm
    session=Task4DateProfileSession(
        source_id=date_source,
        signing_key=os.urandom(32),clock=clock)
    runner=Task4ControlledDateRunner(
        environment_type=suite.environment_type,tools=suite.tools,
        rcc_gate=load_rcc_gate(Path(os.environ["TASK4_RCC_ROOT"])),
        date_session=session,authority_admitted=verify_authority_fixture())
    with httpx.Client(transport=httpx.MockTransport(server),trust_env=False) as wire_client:
        with openai.OpenAI(api_key=base.LOCAL_KEY,base_url="https://api.openai.com/v1",
                           http_client=wire_client,max_retries=0,timeout=3.0) as sdk:
            element=Task4FrozenTransportElement(client=sdk)
            task=Task4OneArmProspectiveTrajectory(controlled_runner=runner,generation_element=element)
            trajectory=task.run(case_id=CASE,proposal_ordinal=0,trusted_env=env,selected_arm=arm)
    server.verify()
    observed=observe_completed_one_arm(trajectory=trajectory,pre_environment=pre)
    base.need(len(trajectory["arms"])==len(observed["scores"])==1 and
              trajectory["shadow_native_arm_count"]==0 and
              trajectory["generation_queries_continuation"]==1,
              "NO_INTERNAL_SHADOW_NATIVE_ARM_ALLOWED")
    chosen=trajectory["arms"][0]
    score=observed["scores"][0]
    base.need(chosen["arm"]==score["arm"]==arm
              and chosen["status"]=="TERMINAL_TEXT_AVAILABLE"
              and sha_json(chosen["post_environment"])==chosen["post_state_sha256"]
              and observed["scorer_calls"]==1,
              "SELECTED_NATIVE_TERMINAL_SCORER_REQUIRED")
    base.need(sha_json(env.model_dump(mode="json"))==original_sha,
              "ORIGINAL_SOURCE_ENVIRONMENT_MUTATED")
    return {
      "origin_arm":arm,
      "generation_origin":"LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM",
      "date_issuer_source":date_source,
      "date_context_only_test_fixture":True,
      "source_case":base.SOURCE_CASE,
      "native_injected_prestate_sha256":original_sha,
      "pre_environment":copy.deepcopy(pre),
      "sdk_local_interceptions":server.attempts,
      "sdk_wire_requests":copy.deepcopy(server.requests),
      "mock_response_ids":[r["id"] for r in server.responses],
      "transport_journal":copy.deepcopy(element.journal),
      "origin_capture_journal":copy.deepcopy(runner.journal),
      "full_source_trajectory":trajectory,
      "full_source_native_scorer":observed,
      "selected_arm":arm,
      "selected_native_arm":copy.deepcopy(chosen),
      "selected_score":copy.deepcopy(score),
      "shadow_native_arms_executed":0,
      "actual_native_dispatch_attempts":chosen["native_dispatch_count"],
      "real_model_posts":0,"external_bank_effects":0,
      "production_execution_authority_proven":False,
    }
