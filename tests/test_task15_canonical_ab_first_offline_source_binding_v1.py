"""Sixteen first native candidate-source requests, each case-bound, no attack observation."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

if os.environ.get("TASK15_CANONICAL_FIRST_SOURCE_PROOF") != "1":
    pytest.skip("Exact synthetic canonical first-source audit only",
                allow_module_level=True)

from test_task15_native_model_response_capture_boundary_v1 import (
    StrictOfflineClient, no_external_services,
)
from test_task15_composed_native_return_binding_v1 import forbidden_effects
from task15_canonical_ab_first_offline_source_binding_v1 import (
    Task15CanonicalABFirstOfflineSourceBindingV1,
    CanonicalFirstSourceViolation, RULE,
)
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_native_model_response_capture_boundary_v1 import FUNCTIONS, sha


@pytest.fixture(autouse=True)
def deny_real_services_and_effects(forbidden_effects, no_external_services):
    yield


@pytest.fixture(scope="module")
def frozen_contexts():
    path = os.environ["TASK15_CANONICAL_FIRST_SOURCE_CONTEXT_EVIDENCE"]
    return json.loads(Path(path).read_text().splitlines()[0])["proof"]


class CaseArmClient(StrictOfflineClient):
    def __init__(self, case_index, arm, fault=None):
        super().__init__()
        self.case_index, self.arm, self.test_fault = case_index, arm, fault

    def create(self, **kw):
        if self.test_fault == "exception":
            self.calls.append(copy.deepcopy(kw))
            raise RuntimeError("OFFLINE_INJECTED_CLIENT_FAILURE")
        if self.test_fault == "cancel":
            self.calls.append(copy.deepcopy(kw))
            raise KeyboardInterrupt("OFFLINE_INJECTED_CLIENT_CANCEL")
        raw = super().create(**kw)
        call = raw.choices[0].message.tool_calls[0]
        call.id = f"offline-c{self.case_index}-{self.arm}-first"
        if self.test_fault == "wrong_tool":
            call.function.name = "send_money"
        if self.test_fault == "duplicate_id":
            call.id = "offline-c0-A-first"
        if self.test_fault == "no_call":
            raw.choices[0].message.tool_calls = None
        if self.test_fault == "refusal":
            raw.choices[0].message.refusal = "synthetic refusal"
        if self.test_fault == "mutation":
            kw["messages"][1]["content"][0]["text"] = "FORGED CANONICAL TASK PROMPT"
        if self.test_fault == "extra_choice":
            raw.choices.append(copy.deepcopy(raw.choices[0]))
        return raw


def clients_for(*, fail_case=None, fail_arm=None, fault=None):
    return {
        case_id: {
            arm: CaseArmClient(i, arm, fault
                               if case_id == fail_case and arm == fail_arm
                               else None)
            for arm in ("A", "B")
        }
        for i, case_id in enumerate(ENROLLED_TASK15)
    }


def save(which, data):
    p = os.environ.get("TASK15_CANONICAL_FIRST_SOURCE_" + which)
    if p:
        with Path(p).open("a") as f:
            f.write(json.dumps(data, sort_keys=True) + "\n")


def test_all_sixteen_separate_native_first_proposals_are_provenance_bound(frozen_contexts):
    clients = clients_for()
    source = Task15CanonicalABFirstOfflineSourceBindingV1(
        contexts=frozen_contexts, clients=clients)
    proof = source.run()
    assert proof["rule_of_one"] == RULE
    assert proof["determination"] == "EIGHT_NATIVE_CASES_SIXTEEN_OFFLINE_FIRST_PROPOSALS_BOUND"
    assert proof["native_task15_case_count"] == 8
    assert proof["independent_synthetic_client_invocations"] == 16
    assert proof["context_proof_sha256"] == sha(frozen_contexts)
    assert [r["case_id"] for r in proof["source_bindings"]] == list(ENROLLED_TASK15)
    assert proof["native_injection_visible_to_model"] is False
    assert proof["canonical_full_trajectories_proven"] is False
    assert proof["canonical_scoring_eligible"] is False
    assert proof["real_model_computation_proven"] is False
    assert proof["provider_calls"] == proof["scorer_calls"] == 0
    assert proof["canonical_native_tool_dispatches"] == proof["external_effects"] == 0
    assert proof["final128_utility_measured"] is False
    assert proof["injection_success_measured"] is False
    assert len(proof["source_transport_journal"]) == 16
    ids = set()
    for i, row in enumerate(proof["source_bindings"]):
        assert list(row["arms"]) == ["A", "B"]
        for arm in ("A", "B"):
            rec = row["arms"][arm]
            client = clients[row["case_id"]][arm]
            assert len(client.calls) == 1
            assert len(client.calls[0]["messages"]) == 2
            assert [m["role"] for m in client.calls[0]["messages"]] == ["developer", "user"]
            assert client.calls[0]["model"] == "gpt-4.1-mini-2025-04-14"
            assert client.calls[0]["tool_choice"] == "auto"
            assert client.calls[0]["temperature"] == 0.0
            assert rec["native_call_id"] == f"offline-c{i}-{arm}-first"
            assert rec["native_call_id"] not in ids
            ids.add(rec["native_call_id"])
            assert rec["first_wire_request_sha256"] == sha({
                "messages": client.calls[0]["messages"],
                "tools": client.calls[0]["tools"],
            })
            assert rec["first_candidate"]["name"] == FUNCTIONS[0]
            assert rec["case_id"] == row["case_id"]
            assert rec["logical_arm"] == arm
            assert rec["injected_initial_environment_sha256"] == frozen_contexts["contexts"][i]["arms"][arm]["environment_sha256"]
            assert rec["injection_observed_by_model"] is False
            assert rec["native_tool_dispatched"] is False
            assert rec["canonical_score_eligible"] is False
    assert len(ids) == 16
    with pytest.raises(CanonicalFirstSourceViolation, match="CANONICAL_FIRST_SOURCE_ONE_ATTEMPT_ONLY"):
        source.run()
    save("EVIDENCE", {"proof": proof, "client_calls": {
        cid: {a: copy.deepcopy(c.calls) for a,c in pair.items()}
        for cid,pair in clients.items()}})


@pytest.mark.parametrize("fault_case_index,arm,fault", [
    (0, "A", "wrong_tool"),
    (0, "B", "no_call"),
    (7, "B", "duplicate_id"),
    (7, "B", "refusal"),
    (7, "A", "mutation"),
    (1, "B", "extra_choice"),
    (3, "A", "exception"),
    (4, "B", "cancel"),
])
def test_failed_or_tampered_case_never_promotes_sixteen_case_proof(
        frozen_contexts, fault_case_index, arm, fault):
    case_id=ENROLLED_TASK15[fault_case_index]
    clients=clients_for(fail_case=case_id,fail_arm=arm,fault=fault)
    source=Task15CanonicalABFirstOfflineSourceBindingV1(
        contexts=frozen_contexts, clients=clients)
    with pytest.raises((CanonicalFirstSourceViolation, RuntimeError, KeyboardInterrupt, ValueError)):
        source.run()
    state=source.observation()
    assert state["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert state["retry_allowed"] is False
    assert state["provisional_on_failure"]["completed_partial_source_evidence_not_promoted"] is True
    assert state["provider_calls"]==state["scorer_calls"]==0
    assert state["canonical_native_tool_dispatches"]==state["external_effects"]==0
    with pytest.raises(CanonicalFirstSourceViolation, match="CANONICAL_FIRST_SOURCE_ONE_ATTEMPT_ONLY"):
        source.run()
    save("REFUSALS", {
        "fault":f"case{fault_case_index}-{arm}-{fault}",
        "result":"NO_CANONICAL_SOURCE_PROOF_PROMOTION",
        "observation":state})


@pytest.mark.parametrize("fault", [
    "missing_case","reordered_case","shared_client",
    "context_wrong_case","context_forged_env_sha","context_wrong_prompt",
])
def test_bad_initial_context_or_client_alias_cannot_start(
        frozen_contexts,fault):
    contexts=copy.deepcopy(frozen_contexts)
    clients=clients_for()
    if fault=="missing_case":
        contexts["contexts"].pop()
    elif fault=="reordered_case":
        contexts["contexts"].reverse()
    elif fault=="shared_client":
        clients[ENROLLED_TASK15[1]]["A"]=clients[ENROLLED_TASK15[0]]["B"]
    elif fault=="context_wrong_case":
        contexts["contexts"][0]["arms"]["A"]["case_id"]=ENROLLED_TASK15[1]
    elif fault=="context_forged_env_sha":
        contexts["contexts"][0]["arms"]["B"]["environment_sha256"]="0"*64
    elif fault=="context_wrong_prompt":
        contexts["contexts"][0]["arms"]["B"]["native_prospective_messages"][1]["content"][0]["text"]="FORGED"
    with pytest.raises(CanonicalFirstSourceViolation):
        Task15CanonicalABFirstOfflineSourceBindingV1(
            contexts=contexts, clients=clients
        ).run()
    assert all(len(c.calls)==0 for pair in clients.values() for c in pair.values())
    save("REFUSALS",{"fault":fault,"result":"NO_CANONICAL_SOURCE_PROOF_PROMOTION"})
