"""Two independent *synthetic* Task15 three-candidate native-history sessions.

One trusted local paired runner per logical arm is run separately. Each source
session uses only its OWN pinned B-subarm native returns for subsequent source
queries. The runner's internal A/B pairing remains the frozen comparison
invariant, not the logical benchmark-arm pairing. No provider, native scorer,
canonical enrollment, live effect, or shared V13 authorization.
"""
from __future__ import annotations
import copy
from threading import RLock

from task15_offline_continuous_native_history_v1 import (
    Task15OfflineContinuousNativeHistoryReplayV1,
    RULE as SOURCE_RULE,
)
from task15_composed_native_return_binding_v1 import (
    Task15ComposedNativeReturnBindingRunnerV1,
)
from task15_native_model_response_capture_boundary_v1 import (
    sha, ORDINALS, FUNCTIONS,
)

RULE = "TASK15_INDEPENDENT_AB_THREE_STEP_OFFLINE_NATIVE_HISTORY_V1"
ARMS = ("A", "B")
CASE = "banking:user_task_15:refund-design-v1"


class IndependentABThreeStepViolation(ValueError):
    pass


def require(predicate, reason):
    if not predicate:
        raise IndependentABThreeStepViolation(reason)


class Task15IndependentABThreeStepOfflineNativeHistoryV1:
    """Independent injected model sources with independent owned local runners."""

    def __init__(self, *, envelope, case_id, runners, clients,
                 transport_mode="OFFLINE_INJECTED_CLIENT"):
        require(transport_mode == "OFFLINE_INJECTED_CLIENT"
                and type(case_id) is str and case_id == CASE
                and type(envelope.instruction) is str
                and bool(envelope.instruction.strip())
                and type(envelope.digest) is str,
                "EXACT_NONCANONICAL_LOCAL_OFFLINE_CONTEXT_REQUIRED")
        require(type(runners) is dict and list(runners) == list(ARMS)
                and type(clients) is dict and list(clients) == list(ARMS)
                and runners["A"] is not runners["B"]
                and clients["A"] is not clients["B"],
                "DISTINCT_A_B_RUNNER_AND_CLIENT_OBJECTS_REQUIRED")
        original = None
        for arm in ARMS:
            runner, client = runners[arm], clients[arm]
            require(type(runner) is Task15ComposedNativeReturnBindingRunnerV1
                    and runner.observation()["phase"] == "READY"
                    and runner._envelope_digest == envelope.digest
                    and runner._case_id == case_id
                    and callable(getattr(getattr(getattr(
                        client, "chat", None), "completions", None), "create", None)),
                    "EXACT_UNUSED_OWNED_NATIVE_RUNNER_AND_CLIENT_REQUIRED")
            state = runner.observation()
            if original is None:
                original = state["initial_state_sha256"]
            require(state["initial_state_sha256"] == original,
                    "EQUAL_INITIAL_BANKING_STATE_REQUIRED")
        require(runners["A"]._state is not runners["B"]._state
                and runners["A"]._sessions is not runners["B"]._sessions
                and runners["A"]._boundaries is not runners["B"]._boundaries,
                "NO_MUTABLE_GOVERNANCE_SESSION_ALIAS_ALLOWED")
        self._envelope = envelope
        self._case_id = case_id
        self._runners = runners
        self._clients = clients
        self._initial_sha256 = original
        self._attempted = False
        self._phase = "READY"
        self._lock = RLock()
        self._journal = []
        self._provisional = {}

    def run(self):
        with self._lock:
            require(not self._attempted and self._phase == "READY",
                    "A_B_THREE_STEP_ONE_ATTEMPT_ONLY")
            self._attempted = True
            self._phase = "RUNNING"
        record = {}
        global_ids = set()
        response_sha_by_arm = {}
        try:
            for arm in ARMS:
                runner, client = self._runners[arm], self._clients[arm]
                entry = {"logical_arm": arm, "status": "ATTEMPTED"}
                self._journal.append(entry)
                require(runner.observation()["phase"] == "READY"
                        and runner.observation()["initial_state_sha256"]
                            == self._initial_sha256,
                        "LOGICAL_ARM_SESSION_ALREADY_CONSUMED_OR_DRIFTED")
                capture = Task15OfflineContinuousNativeHistoryReplayV1(
                    runner=runner, envelope=self._envelope, client=client)
                linked = capture.run()
                state = runner.observation()
                require(linked["rule_of_one"] == SOURCE_RULE
                        and linked["source_mode"] == "OFFLINE_INJECTED_CLIENT"
                        and linked["source_arm_for_continuation"] == "B"
                        and linked["source_model_queries_used_prior_tool_results"] is True
                        and linked["source_queries_are_sequential_native_history"] is True
                        and linked["bounded_offline_three_candidate_continuity_tested"] is True
                        and linked["model_continuous_conversation_proven"] is False
                        and linked["actual_provider_execution"] is False
                        and linked["scorer_calls"] == linked["new_provider_calls"] == 0
                        and len(linked["source_query_history_evidence"]) == 3
                        and len(linked["source_query_transport_journal"]) == 3
                        and len(linked["source_call_id_return_bindings"]) == 3
                        and state["phase"] == "COMPLETE_LOCAL_COMPOSED_RUN"
                        and len(state["completed_steps"]) == 3
                        and state["initial_state_sha256"] == self._initial_sha256
                        and state["native_return_history_fully_composed"] is True
                        and linked["composed_result_sha256"] == sha(state),
                        "EXACT_THREE_SOURCE_QUERIES_WITH_LOCAL_GOVERNED_RETURNS_REQUIRED")
                queries = linked["source_query_history_evidence"]
                journals = linked["source_query_transport_journal"]
                links = linked["source_call_id_return_bindings"]
                source_events = []
                for i, (query, journal, binding, step) in enumerate(zip(
                        queries, journals, links, state["completed_steps"])):
                    call_id = binding["source_tool_call_id"]
                    require(query["step"] == binding["step"] == step["step"] == i
                            and query["ordinal"] == binding["ordinal"]
                                == step["actual_generation_ordinal"] == ORDINALS[i]
                            and journal["status"] == "RESPONSE_DECODED"
                            and journal["phase"] == "PROTECTED_CANDIDATE"
                            and journal["ordinal"] == ORDINALS[i]
                            and len(journal["wire_messages"]) == 2 + 2*i
                            and query["wire_messages_sha256"]
                                == sha(journal["wire_messages"])
                            and query["native_previous_results_present_at_query"] == i
                            and len(query["previous_native_links"]) == i
                            and call_id not in global_ids
                            and journal["decoded_response"]["tool_calls"][0]["id"] == call_id
                            and step["candidate_sha256"] == binding["candidate_sha256"]
                            and step["arms"]["B"]["candidate_sha256"]
                                == binding["candidate_sha256"]
                            and step["arms"]["B"]["disposition"] == "COMMITTED"
                            and step["arms"]["B"]["native_dispatch_count"] == 1,
                            "ARM_OWNED_CANDIDATE_NATIVE_CALL_AND_SINK_REQUIRED")
                    global_ids.add(call_id)
                    for prior in query["previous_native_links"]:
                        k = prior["prior_step"]
                        own = state["completed_steps"][k]["arms"]["B"]
                        require(0 <= k < i
                                and prior["source_arm"] == "B"
                                and prior["source_call_id"] == links[k]["source_tool_call_id"]
                                and prior["candidate_sha256"] == links[k]["candidate_sha256"]
                                and prior["native_return_sha256"] == sha(own["native_return"])
                                and prior["post_state_sha256"] == own["post_state_sha256"]
                                and prior["model_tool_message_sha256"]
                                    == links[k]["arms"]["B"]["native_tool_message_sha256"],
                                "LATER_MODEL_QUERY_CONSUMED_FOREIGN_NATIVE_RETURN")
                    source_events.append({
                        "logical_arm": arm,
                        "step": i,
                        "ordinal": ORDINALS[i],
                        "function": FUNCTIONS[i],
                        "call_id": call_id,
                        "candidate_sha256": binding["candidate_sha256"],
                        "source_response_sha256": journal["response_sha256"],
                        "wire_request_sha256": journal["wire_request_sha256"],
                        "prior_native_returns_at_query": i,
                        "own_local_B_subarm_native_return_sha256":
                            binding["arms"]["B"]["native_return_sha256"],
                    })
                require(len(source_events) == 3
                        and len({x["call_id"] for x in source_events}) == 3,
                        "THREE_DISTINCT_NATIVE_PROPOSALS_PER_LOGICAL_ARM_REQUIRED")
                response_sha_by_arm[arm] = [x["source_response_sha256"]
                                            for x in source_events]
                record[arm] = {
                    "logical_arm": arm,
                    "underlying_local_controlled_runner_source_subarm": "B",
                    "initial_state_sha256": state["initial_state_sha256"],
                    "composed_native_state_sha256": sha(state),
                    "source_events": source_events,
                    "exact_source_history": copy.deepcopy(linked),
                    "exact_local_composed_execution": copy.deepcopy(state),
                    "local_governed_native_dispatches": 6,
                    "provider_authenticated": False,
                }
                entry.update(status="COMPLETED_OFFLINE_THREE_SOURCE_STEPS",
                             source_call_ids=[x["call_id"] for x in source_events],
                             composed_native_state_sha256=sha(state))
            require(list(record) == list(ARMS)
                    and len(global_ids) == 6
                    and response_sha_by_arm["A"] != response_sha_by_arm["B"]
                    and record["A"]["initial_state_sha256"]
                        == record["B"]["initial_state_sha256"],
                    "TWO_OWNED_DISTINCT_THREE_STEP_SOURCE_CHAINS_REQUIRED")
            self._phase = "COMPLETE_OFFLINE_TWO_THREE_STEP_SOURCE_CHAINS"
            return {
                "rule_of_one": RULE,
                "determination": "TWO_ISOLATED_OFFLINE_THREE_STEP_MODEL_SOURCE_CHAINS_OBSERVED",
                "original_local_case_id": self._case_id,
                "source_mode": "OFFLINE_INJECTED_CLIENT",
                "logical_source_arms": list(ARMS),
                "original_instruction_digest": self._envelope.digest,
                "shared_initial_state_sha256": self._initial_sha256,
                "sources": copy.deepcopy(record),
                "source_transport_journal": copy.deepcopy(self._journal),
                "offline_source_queries": 6,
                "owned_native_return_feedback_links": 4,
                "local_governed_native_dispatches": 12,
                "independent_logical_A_B_three_step_offline_sources_observed": True,
                "independent_real_provider_computation_proven": False,
                "canonical_case_enrollment_proven": False,
                "provider_calls": 0,
                "scorer_calls": 0,
                "real_external_effects": 0,
                "actual_provider_execution": False,
                "canonical_final128_utility_measured": False,
                "canonical_injection_success_measured": False,
                "production_readiness_proven": False,
            }
        except BaseException:
            self._phase = "TERMINAL_UNKNOWN_OR_FAILED"
            if self._journal and self._journal[-1]["status"] == "ATTEMPTED":
                self._journal[-1]["status"] = "FAILED_OR_CANCELLED"
            self._provisional = {
                "arm_states": {
                    arm: copy.deepcopy(self._runners[arm].observation())
                    for arm in ARMS
                },
                "terminal_transport": copy.deepcopy(self._journal),
                "completed_sources_not_promoted": True,
                "retry_allowed": False,
                "rollback_or_no_effect_claim": False,
            }
            raise

    def observation(self):
        with self._lock:
            return {
                "rule_of_one": RULE,
                "phase": self._phase,
                "attempted": self._attempted,
                "journal": copy.deepcopy(self._journal),
                "provisional_on_failure": copy.deepcopy(self._provisional),
                "retry_allowed": False,
                "provider_calls": 0,
                "scorer_calls": 0,
                "real_external_effects": 0,
            }
