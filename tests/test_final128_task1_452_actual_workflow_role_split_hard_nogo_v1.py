"""Task1 #452 actual GitHub workflow role split; NO EFFECT or paid consent."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
HIST = ROOT / "docs/optimization/FINAL128_423_HISTORICAL_PRE_452_WORKFLOW.snapshot.txt"
DOC = ROOT / "docs/optimization/FINAL128_TASK1_452_ACTUAL_MANUAL_JOB_SPLIT_HARD_NOGO_V1.md"
HIST_BLOB = "c2182fef2574d1be3019cf6455947b64751ef474"
NEW_BLOB = "85c68dc7073ab9515373dfba44439e7122626fe3"
CONDITION = ("${{ false && github.actor == 'veritasfuji-japan' && "
             "github.ref == 'refs/heads/main' && github.run_attempt == 1 }}")
SENDER_OFF = "${{ false }}"
ISSUER_IF = ("github.actor == 'veritasfuji-japan' && "
             "github.ref == 'refs/heads/main' && github.run_attempt == 1")
TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"


class Refused(ValueError):
    pass


class StrictBaseLoader(yaml.BaseLoader):
    """Detect duplicated YAML keys including job if and permissions."""
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise Refused("DUPLICATE_YAML_MAPPING_KEY")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def check(ok, label):
    if ok is not True:
        raise Refused(label)


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def inspect(text):
    try:
        w = yaml.load(text, Loader=StrictBaseLoader)
    except (yaml.YAMLError, ValueError, TypeError) as exc:
        raise Refused("INVALID_OR_DUPLICATE_YAML") from exc
    check(type(w) is dict and type(w.get("on")) is dict
          and set(w["on"]) == {"workflow_dispatch"}
          and w.get("permissions") == {"contents": "read"},
          "EXACT_MANUAL_ONLY_READ_DEFAULT")
    check(w["concurrency"]["cancel-in-progress"] == "false"
          and set(w["jobs"]) == {"preflight", "issuer", "sender"},
          "EXACT_THREE_JOB_GRAPH")
    pre, issuer, sender = (w["jobs"][x] for x in ("preflight", "issuer", "sender"))
    check(pre["if"] == CONDITION and sender["if"] == SENDER_OFF,
          "HARD_DISABLE_PRESEND_AND_SEND")
    check(issuer["if"] == ISSUER_IF and issuer["needs"] == ["preflight"]
          and sender["needs"] == ["issuer"], "DEPENDENCY_CHAIN")
    check(pre["permissions"] == {"contents": "read"}
          and issuer["permissions"] == {"contents": "write"}
          and sender["permissions"] == {"contents": "read"},
          "LEAST_PRIVILEGE_ROLE_CAPABILITIES")
    check(pre.get("environment") == "task1-real-model-pilot"
          and "environment" not in issuer
          and sender.get("environment") == "task1-real-model-pilot",
          "ONLY_PROTECTED_SECRET_HOLDING_JOBS")
    p, i, s = (str(w["jobs"][x]) for x in ("preflight", "issuer", "sender"))
    check("GH_TOKEN" not in p and "/git/refs" not in p
          and "--mode send" not in p, "PREFLIGHT_NOT_ISSUER_OR_SENDER")
    check("GH_TOKEN" in i and "/git/refs" in i and 'method="POST"' in i
          and TAG in i, "ISSUER_PRODUCTION_REF_BOUNDARY")
    check("TASK1_OPENAI_API_KEY" not in i
          and "TASK1_CAPTURE_AES256_KEY" not in i
          and "--mode send" not in i
          and "api.openai.com" not in i,
          "ISSUER_MUST_NOT_HAVE_PROVIDER_CREDENTIALS")
    check("GH_TOKEN" not in s and "/git/refs" not in s
          and "--mode send --output-dir results" in s
          and "TASK1_OPENAI_API_KEY" in s and "TASK1_CAPTURE_AES256_KEY" in s
          and "needs.issuer.outputs.consumed_sha" in s,
          "SENDER_CANNOT_CREATE_TAG_AND_USES_ONLY_HANDOFF_SHAPE")
    steps_i, steps_s = issuer["steps"], sender["steps"]
    check(issuer["outputs"] == {
        "consumed_sha": "${{ steps.consume.outputs.consumed_sha }}"}
          and sum(step.get("id") == "consume" for step in steps_i) == 1
          and sum("--mode send --output-dir results" in step.get("run", "")
                  for step in steps_s) == 1,
          "ONE_TAG_WRITER_ONE_SENDER_STEP")
    check(sum("secrets-preflight" in step.get("run", "")
              for step in pre["steps"]) == 1
          and all("secrets-preflight" not in step.get("run", "")
                  for step in steps_i)
          and sum("--mode preflight" in step.get("run", "")
                  for step in steps_s) == 1,
          "BOUNDARY_INITIALIZATION")
    return {"installed_three_job_graph": True,
            "preflight_send_and_tag_hard_disabled": True,
            "issuer_provider_secrets_inaccessible_in_yaml": True,
            "sender_job_github_contents_read_only": True,
            "actual_global_remote_ledger_installed": False,
            "independent_sender_iam_attested": False,
            "provider_egress_bypass_denied": False,
            "live_send_enabled": False,
            "production_tag_issuance_enabled": False,
            "new_provider_calls": 0,
            "new_native_utility_recoveries": 0,
            "paid_task1_decision": "NO_GO_ISSUE_427"}


def test_exact_immutable_original_and_new_graph_bytes():
    assert git_blob(HIST.read_bytes()) == HIST_BLOB
    assert git_blob(LIVE.read_bytes()) == NEW_BLOB
    assert HIST.read_bytes() != LIVE.read_bytes()
    v = inspect(LIVE.read_text())
    assert v["installed_three_job_graph"] is True
    assert v["preflight_send_and_tag_hard_disabled"] is True
    assert v["sender_job_github_contents_read_only"] is True
    assert v["paid_task1_decision"] == "NO_GO_ISSUE_427"
    for k in ("actual_global_remote_ledger_installed",
              "independent_sender_iam_attested",
              "provider_egress_bypass_denied",
              "live_send_enabled",
              "production_tag_issuance_enabled"):
        assert v[k] is False


@pytest.mark.parametrize("mutate", [
    lambda w: w["jobs"]["preflight"].update(**{"if": "true"}),
    lambda w: w["jobs"]["preflight"].update(**{"if": "${{ true }}"}),
    lambda w: w["jobs"]["sender"].update(**{"if": "success()"}),
    lambda w: w["jobs"]["issuer"].update(**{"needs": []}),
    lambda w: w["jobs"]["sender"].update(**{"needs": ["preflight"]}),
    lambda w: w["jobs"]["issuer"].update(**{"environment": "task1-real-model-pilot"}),
    lambda w: w["jobs"]["issuer"].update(**{"permissions": {"contents": "read"}}),
    lambda w: w["jobs"]["sender"].update(**{"permissions": {"contents": "write"}}),
    lambda w: w["permissions"].update({"contents": "write"}),
    lambda w: w["on"].update({"push": {}}),
    lambda w: w["jobs"]["sender"].pop("environment"),
    lambda w: w["jobs"]["issuer"]["steps"].append({
        "name": "Steal",
        "env": {"TASK1_OPENAI_API_KEY": "${{ secrets.TASK1_OPENAI_API_KEY }}"},
        "run": "echo forbidden"}),
])
def test_role_security_changes_refused(mutate):
    modified = deepcopy(yaml.load(LIVE.read_text(), Loader=yaml.BaseLoader))
    mutate(modified)
    with pytest.raises(Refused):
        inspect(yaml.dump(modified, sort_keys=False))


def test_duplicate_if_and_duplicate_job_names_denied():
    src = LIVE.read_text()
    for bad in (
        src.replace("  preflight:\n", "  preflight:\n    if: true\n", 1),
        src.replace("  issuer:\n", "  issuer:\n  issuer:\n", 1),
        src.replace("    permissions:\n      contents: read\n",
                    "    if: true\n    permissions:\n      contents: read\n", 1),
    ):
        with pytest.raises(Refused):
            inspect(bad)


def test_archive_is_inert_and_scope_is_faithful():
    assert HIST.suffix == ".txt" and ".github/workflows" not in str(HIST)
    doc = DOC.read_text()
    for phrase in ("NO-GO", "Issue #427", "#423", "#445", "#450",
                   "#451", "preflight", "issuer", "sender",
                   "actual workflow", "not a real external Executor",
                   "no Provider"):
        assert phrase in doc
