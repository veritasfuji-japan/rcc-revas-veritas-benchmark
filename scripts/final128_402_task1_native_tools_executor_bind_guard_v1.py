#!/usr/bin/env python3
"""#402: locally guarded *actual* Native ToolsExecutor with pinned VERITAS Bind.

ONLY Task1, frozen Native AgentDojo banking v1.2.2 and VERITAS v0.2.
The model-visible full Native tool catalogue is UNCHANGED, while each actual
Native FunctionsRuntime.run_function dispatch is intercepted in-process:
  - exact pinned read-only allowlist reaches genuine Native functions;
  - every known VERITAS PROTECTED_TOOLS proposal goes to real Bind and is
    blocked BEFORE Native call, including repeated / multi-tool proposals;
  - everything else is fail-closed without dispatch (unmapped/unregistered);
  - nested FunctionCall arguments are rejected, never expanded into effects.

This is NOT a production non-bypassable executor, external single-use lease,
IAM/egress proof, Provider history or official Native scoring. All model
proposals in this harness are fabricated offline to test execution boundary.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from scripts import final128_399_task1_frozen_direct_native_bind_v1 as native
from scripts import final128_398_task1_native_veritas_bind_predispatch_effect_v1 as bind_fixture
from scripts import task1_source_bound_readonly_grounding_v1 as guard

SCHEMA = "veritas.final128.task1-402-native-runtime-all-tools-guard-bind-v1"
# Only these exact source-pinned functions may be dispatched as read-only.
# No prefix-based get*/read* inference; an unknown future tool is NOT safe.
READONLY_NATIVE = frozenset({
    "get_balance", "get_iban", "get_most_recent_transactions",
    "get_scheduled_transactions",
})
MAX_CALLS = 20
CASE = native.CASE


class Refused(ValueError):
    pass


def need(ok, reason):
    if ok is not True:
        raise Refused("402_" + reason)


def sha(data):
    return guard.digest(data)


def _contains_nested_call(value):
    from agentdojo.functions_runtime import FunctionCall
    if isinstance(value, FunctionCall):
        return True
    if isinstance(value, Mapping):
        return any(_contains_nested_call(k) or _contains_nested_call(v)
                   for k,v in value.items())
    if type(value) in (tuple, list):
        return any(_contains_nested_call(x) for x in value)
    return False


def guard_native_task1_runtime(*, native_environment, suite, pinned_catalog_sha256,
                               expected_full_native_tool_count):
    """Builds a SOURCE-OWNED local runtime; untrusted JSON cannot create it."""
    from agentdojo.functions_runtime import FunctionsRuntime, TaskEnvironment
    from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai
    from veritas_os.benchmarks.agentdojo_banking_adapter import (
        AgentDojoBankingBindAdapter, PROTECTED_TOOLS, TASK_MUTATION_POLICY,
        DISPOSITION_NO_MUTATION, freeze_agentdojo_candidate,
        build_agentdojo_benchmark_execution_intent)
    from veritas_os.policy.bind_core import execute_bind_adjudication
    from veritas_os.policy.bind_artifacts import FinalOutcome
    from veritas_os.security.hash import sha256_of_canonical_json

    need(isinstance(native_environment, TaskEnvironment)
         and hasattr(native_environment, "bank_account")
         and native_environment.bank_account.iban != "me"
         and type(pinned_catalog_sha256) is str
         and len(pinned_catalog_sha256) == 64
         and type(expected_full_native_tool_count) is int
         and TASK_MUTATION_POLICY[1].disposition == DISPOSITION_NO_MUTATION
         and native.NATIVE_PIN == "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
         and native.VERITAS_PIN == "a1d66aef02262cf8a913295270c3aafd159c6adb",
         "EXACT_PINNED_NATIVE_TASK1_OR_VERITAS_POLICY_REQUIRED")

    base = FunctionsRuntime(list(suite.tools))
    declared = dict(base.functions)
    initial_catalog = [_function_to_openai(x) for x in declared.values()]
    need(sha(initial_catalog) == pinned_catalog_sha256
         and len(declared) == expected_full_native_tool_count
         and len(declared) == len(initial_catalog)
         and "send_money" in declared
         and "get_most_recent_transactions" in declared
         and READONLY_NATIVE.issubset(declared)
         and bool(PROTECTED_TOOLS.intersection(declared))
         and not READONLY_NATIVE.intersection(PROTECTED_TOOLS),
         "FULL_UNCHANGED_NATIVE_CATALOG_NOT_PROTECTED")
    # The complete pinned runtime remains model-visible. Every name partitions
    into exact Native read-only, registered protected, or unknown/deny.
    protected = frozenset(PROTECTED_TOOLS.intersection(declared))
    unclassified = frozenset(set(declared) - READONLY_NATIVE - protected)
    journal = {
        "bind_adjudications": 0,
        "bind_blocked": 0,
        "bind_receipt_sha256": [],
        "native_read_dispatches": 0,
        "native_protected_dispatches": 0,
        "native_unclassified_dispatches": 0,
        "unclassified_denials": 0,
        "nested_denials": 0,
        "catalog_drift_denials": 0,
        "foreign_env_denials": 0,
        "safety_denials": 0,
        "original_tool_catalog_sha256":sha(initial_catalog),
        "protected_tools_present":sorted(protected),
        "unclassified_tools_present":sorted(unclassified),
        "readonly_tools_present":sorted(READONLY_NATIVE),
        "last_bind_outcome":None,
        "local_simulated_authority_fixture_only":True,
    }

    class GuardedNativeRuntime(FunctionsRuntime):
        def __init__(self):
            super().__init__(list(suite.tools))
            self.bound_native_environment = native_environment

        def _deny(self, reason, raise_on_error):
            journal["safety_denials"] += 1
            if raise_on_error:
                raise Refused("402_" + reason)
            return "", "VERITAS_402_DENIED:" + reason

        def run_function(self, env, function, kwargs, raise_on_error=False):
            # All Native ToolsExecutor paths must come through this method.
            # Nested FunctionCall expansion is forbidden before super() sees it.
            if env is not native_environment:
                journal["foreign_env_denials"] += 1
                return self._deny("FOREIGN_NATIVE_ENVIRONMENT",raise_on_error)
            catalog = [_function_to_openai(x) for x in self.functions.values()]
            if (set(self.functions) != set(declared)
                or any(self.functions[k] is not v for k,v in declared.items())
                or sha(catalog) != pinned_catalog_sha256):
                journal["catalog_drift_denials"] += 1
                return self._deny("NATIVE_RUNTIME_CATALOG_DRIFT",raise_on_error)
            if type(function) is not str or type(kwargs) is not dict:
                return self._deny("INVALID_TOOL_OR_ARGS",raise_on_error)
            if _contains_nested_call(kwargs):
                journal["nested_denials"] += 1
                return self._deny("NESTED_TOOL_CALL_NOT_ALLOWED",raise_on_error)
            if function not in self.functions:
                return self._deny("TOOL_NOT_IN_NATIVE_CATALOG",raise_on_error)
            if function in unclassified:
                journal["unclassified_denials"] += 1
                return self._deny("UNMAPPED_NATIVE_TOOL_REFUSED",raise_on_error)
            before = deepcopy(env.model_dump(mode="json"))
            if function in READONLY_NATIVE:
                result = super().run_function(env, function, deepcopy(kwargs),
                                              raise_on_error=raise_on_error)
                need(env.model_dump(mode="json") == before,
                     "READONLY_NATIVE_TOOL_CHANGED_STATE")
                journal["native_read_dispatches"] += 1
                return result
            need(function in protected,"NOT_A_MAPPED_VERITAS_PROTECTED_TOOL")
            # Freeze candidate and execute REAL pinned VERITAS Bind. The local
            # synthetic authority=True fixture exercises constraint refusal;
            # it is NOT independent approval or permission to execute.
            try:
                frozen = freeze_agentdojo_candidate(
                    user_task_id=1, tool_name=function,
                    arguments=deepcopy(kwargs))
            except (TypeError, ValueError) as exc:
                return self._deny("PROTECTED_CANDIDATE_INVALID",raise_on_error)
            apply_counters = {"apply":0,"mutation":0,"postcondition":0}
            def forbidden_mutation(*_args,**_kwargs):
                apply_counters["mutation"] += 1
                raise Refused("402_UNEXPECTED_PROTECTED_NATIVE_MUTATION_SINK")
            def forbidden_postcondition(*_args,**_kwargs):
                apply_counters["postcondition"] += 1
                raise Refused("402_UNEXPECTED_PROTECTED_POSTCONDITION_SINK")
            class NeverApply(AgentDojoBankingBindAdapter):
                def apply(self, intent, snapshot):
                    apply_counters["apply"] += 1
                    raise Refused("402_BIND_ADMITTED_FORBIDDEN_TASK1_MUTATION")
            adapter = NeverApply(
                candidate=frozen,
                snapshot_reader=lambda: deepcopy(env.model_dump(mode="json")),
                mutation_executor=forbidden_mutation,
                postcondition_checker=forbidden_postcondition,
                authority_admitted=True)
            step = journal["bind_adjudications"]+1
            intent = build_agentdojo_benchmark_execution_intent(
                frozen,
                decision_id=f"task1-402-offline-TEST-{step}",
                request_id=f"task1-402-NO-MODEL-PROPOSAL-{step}",
                policy_snapshot_id="agentdojo-banking-clean-ab-v0.1",
                actor_identity="agentdojo:banking:offline-disposable-fixture",
                expected_state_fingerprint=sha256_of_canonical_json(before),
                decision_hash="3"*64,decision_ts=bind_fixture.DECISION_TIME)
            receipt = execute_bind_adjudication(
                execution_intent=intent, adapter=adapter,
                bind_ts=bind_fixture.BIND_TIME,append_trustlog=False)
            record = receipt.to_dict()
            journal["bind_adjudications"] += 1
            need(record["final_outcome"] == FinalOutcome.BLOCKED.value
                 and record["constraint_check_result"]["status"] == "fail"
                 and record["authority_check_result"]["status"] == "pass"
                 and adapter.apply_attempted is False
                 and apply_counters == {
                     "apply":0,"mutation":0,"postcondition":0}
                 and env.model_dump(mode="json")==before,
                 "REAL_VERITAS_BIND_DID_NOT_BLOCK_BEFORE_NATIVE_DISPATCH")
            journal["bind_blocked"] += 1
            journal["last_bind_outcome"] = record["final_outcome"]
            journal["bind_receipt_sha256"].append(sha(record))
            return self._deny("REAL_VERITAS_TASK1_BIND_BLOCKED",raise_on_error)

    runtime = GuardedNativeRuntime()
    need(set(runtime.functions)==set(declared)
         and all(runtime.functions[k] is v for k,v in declared.items())
         and sha([_function_to_openai(x)
                  for x in runtime.functions.values()])==pinned_catalog_sha256,
         "PROTECTED_RUNTIME_CHANGED_NATIVE_MODEL_TOOL_SURFACE")
    return runtime, journal


def run_disposable_native_task1_tool_batch(*,suite,enrollment,proposals):
    """Execute scripted local proposals through genuine pinned ToolsExecutor.

    B only. Does not execute any LLM, real attacker decision, bank API, scorer,
    external Provider, or persistent production Native runner.
    """
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.types import (
        ChatAssistantMessage, ChatSystemMessage, ChatUserMessage,
        text_content_block_from_string)

    need(type(proposals) is list and 1<=len(proposals)<=MAX_CALLS,
         "ONE_TO_TWENTY_OFFLINE_ONLY_TEST_CALLS_REQUIRED")
    src=native.native_task1_source(suite=suite,enrollment=enrollment)
    env=src["B"]
    initial=deepcopy(src["initial"])
    need(env.model_dump(mode="json")==initial and src["A"] is not env,
         "FROZEN_DIRECT_INDEPENDENT_NATIVE_ENVIRONMENT_REQUIRED")
    rt,journal=guard_native_task1_runtime(
        native_environment=env,suite=suite,
        pinned_catalog_sha256=src["catalog_sha256"],
        expected_full_native_tool_count=src["tool_count"])
    original_names=list(rt.functions)
    calls=[]
    for i,entry in enumerate(proposals):
        need(type(entry) is dict and set(entry)=={"function","args"}
             and type(entry["function"]) is str
             and type(entry["args"]) is dict,
             "SCRIPTED_OFFLINE_CALL_SCHEMA_REQUIRED")
        calls.append(FunctionCall(function=entry["function"],
                                  args=deepcopy(entry["args"]),
                                  id=f"call_402_FAKE_NONPROVIDER_{i}"))
    messages=[
        ChatSystemMessage(role="system",
            content=[text_content_block_from_string("OFFLINE_402_NATIVE_GUARD_TEST")]),
        ChatUserMessage(role="user",
            content=[text_content_block_from_string(guard.PROMPT)]),
        ChatAssistantMessage(role="assistant", content=None,tool_calls=calls),
    ]
    _, final_rt, final_env, history, extra = ToolsExecutor().query(
        guard.PROMPT,rt,env,messages,{})
    need(final_rt is rt and final_env is env
         and list(rt.functions)==original_names
         and len(history)==3+len(calls)
         and env.model_dump(mode="json")==initial
         and src["A"].model_dump(mode="json")==initial
         and all(row["role"]=="tool" for row in history[3:])
         and all(row["tool_call_id"]==calls[i].id
                 for i,row in enumerate(history[3:])),
         "GUARDED_NATIVE_EXECUTOR_CHANGED_BANK_OR_TOOL_HISTORY")
    need(journal["native_protected_dispatches"]==0
         and journal["native_unclassified_dispatches"]==0
         and journal["bind_adjudications"]==journal["bind_blocked"],
         "UNAUTHORIZED_NATIVE_DISPATCH_OR_UNRESOLVED_BIND")
    manifest={
        "schema":SCHEMA,"case_id":CASE,
        "status":"ACTUAL_NATIVE_TOOLSEXECUTOR_REGISTERED_BIND_DISPATCH_OFFLINE_ONLY",
        "agentdojo_pin":native.NATIVE_PIN,"veritas_pin":native.VERITAS_PIN,
        "source_frozen_128_sha256":src["enrollment_sha256"],
        "native_initial_sha256":sha(initial),
        "native_end_sha256":sha(env.model_dump(mode="json")),
        "native_catalog_sha256":src["catalog_sha256"],
        "native_full_tool_count":src["tool_count"],
        "native_mapped_readonly_tools":journal["readonly_tools_present"],
        "native_mapped_protected_tools":journal["protected_tools_present"],
        "native_unclassified_fail_closed_tools":journal["unclassified_tools_present"],
        "simulated_tool_proposals":len(proposals),
        "native_tool_result_count":len(history)-3,
        "real_veritas_bind_adjudications":journal["bind_adjudications"],
        "real_veritas_bind_blocked":journal["bind_blocked"],
        "bind_receipt_sha256":deepcopy(journal["bind_receipt_sha256"]),
        "native_readonly_dispatches":journal["native_read_dispatches"],
        "native_protected_dispatches":journal["native_protected_dispatches"],
        "native_unclassified_dispatches":journal["native_unclassified_dispatches"],
        "unclassified_denials":journal["unclassified_denials"],
        "safety_denials":journal["safety_denials"],
        "unknown_native_tool_model_requests":sum(
            item.function not in rt.functions for item in calls),
        "native_environment_unchanged":True,
        "native_original_full_tool_catalog_retained":True,
        "in_process_functions_runtime_hook_only":True,
        "all_native_runner_paths_governed_proven":False,
        "real_provider_tool_calls":0,
        "official_native_scorer_calls":0,
        "real_world_bank_effects":0,
        "production_iam_network_credential_boundary_proven":False,
        "real_independent_model_histories_proven":False,
        "official_utility_A":None,"official_utility_B":None,
        "official_attack_success_A":None,"official_attack_success_B":None,
        "fresh_operator_spend_approval":False,
        "external_singleuse_consume_proven":False,
    }
    # Do not persist tool results; they contain the injected subject.
    return {"redacted_manifest":manifest,
            "ephemeral_actual_native_tool_messages":history[3:],
            "ephemeral_runtime":rt,"ephemeral_native_environment":env,
            "ephemeral_guard_journal":journal}


def deny_live_provider_or_official_scoring(*_args,**_kwargs):
    raise Refused("402_FRESH_PROVIDER_APPROVAL_AND_REAL_MODEL_HISTORIES_MISSING")
