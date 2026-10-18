"""Task1 #452 no-PyYAML, no-effect source-only three-job permission gate."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / ".github/workflows/final128-423-task1-protected-first-two-native-chat-live-v1.yml"
HIST = ROOT / "docs/optimization/FINAL128_423_HISTORICAL_PRE_452_WORKFLOW.snapshot.txt"
DOC = ROOT / "docs/optimization/FINAL128_TASK1_452_ACTUAL_MANUAL_JOB_SPLIT_HARD_NOGO_V1.md"
HIST_BLOB = "c2182fef2574d1be3019cf6455947b64751ef474"
NEW_BLOB = "85c68dc7073ab9515373dfba44439e7122626fe3"
PREFLIGHT_OFF = ("${{ false && github.actor == 'veritasfuji-japan' && "
                 "github.ref == 'refs/heads/main' && github.run_attempt == 1 }}")
SENDER_OFF = "${{ false }}"
ISSUER_IF = ("github.actor == 'veritasfuji-japan' && "
             "github.ref == 'refs/heads/main' && github.run_attempt == 1")
TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"


class Refused(ValueError):
    pass


def need(ok, code):
    if ok is not True:
        raise Refused(code)


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def role_segments(src):
    # Exact top-level Job keys by leading TWO spaces. No synthetic YAML object
    # can satisfy this by slipping a duplicate if/permissions past a loader.
    need(type(src) is str and "\t" not in src, "NO_TABS")
    parts = src.split("\njobs:\n")
    need(len(parts) == 2, "EXACT_JOB_ROOT")
    header, jobs_text = parts
    keys = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):[ ]*$", jobs_text))
    need([m.group(1) for m in keys] == ["preflight", "issuer", "sender"],
         "EXACT_JOB_NAMES_AND_ORDER")
    spans = {}
    for index, match in enumerate(keys):
        end = keys[index + 1].start() if index + 1 < len(keys) else len(jobs_text)
        spans[match.group(1)] = jobs_text[match.start():end]
    return header, spans


def top(job):
    need(job.count("    steps:\n") == 1, "EXACT_STEPS_ROOT")
    front = job.split("    steps:\n", 1)[0]
    for field in ("if", "needs", "permissions", "environment", "outputs"):
        need(len(re.findall(r"(?m)^    " + field + r":[ ]*", front)) <= 1,
             "DUPLICATE_JOB_FIELD_" + field)
    return front


def inspect(src):
    header, jobs = role_segments(src)
    need(header.startswith(
        "name: Task1 Native First Two Chat A/B HARD NO-GO ROLE SPLIT V1\n"
    ) and "\non:\n  workflow_dispatch:\n" in header
        and "\n  pull_request:" not in header and "\n  push:" not in header
        and "\npermissions:\n  contents: read\n" in header
        and header.count("\npermissions:\n") == 1
        and "cancel-in-progress: false" in header,
        "MANUAL_ONLY_DEFAULT_READ_AND_NO_CANCEL")
    pre, iss, snd = (jobs[k] for k in ("preflight", "issuer", "sender"))
    a,b,c=top(pre),top(iss),top(snd)
    need("    if: " + PREFLIGHT_OFF + "\n" in a
         and "    if: " + SENDER_OFF + "\n" in c
         and "    if: " + ISSUER_IF + "\n" in b,
         "EXACT_JOB_LEVEL_HARD_NO_GO")
    need("    needs:" not in a
         and "    needs: [preflight]\n" in b
         and "    needs: [issuer]\n" in c, "ISSUER_SENDER_NEEDS_CHAIN")
    need("    permissions:\n      contents: read\n" in a
         and "    permissions:\n      contents: write\n" in b
         and "    permissions:\n      contents: read\n" in c,
         "JOB_TOKEN_PRIVILEGE_SPLIT")
    need("    environment: task1-real-model-pilot\n" in a
         and "    environment:" not in b
         and "    environment: task1-real-model-pilot\n" in c,
         "ISSUER_NO_ENVIRONMENT")
    need("GH_TOKEN" not in pre and "/git/refs" not in pre
         and "--mode send" not in pre
         and pre.count("--mode secrets-preflight --output-dir results") == 1,
         "PREFLIGHT_CANNOT_WRITE_OR_SEND")
    need('GH_TOKEN: ${{ github.token }}' in iss
         and 'method="POST"' in iss
         and TAG in iss
         and "TASK1_OPENAI_API_KEY" not in iss
         and "TASK1_CAPTURE_AES256_KEY" not in iss
         and "api.openai.com" not in iss
         and "--mode send" not in iss,
         "ISSUER_TAG_ONLY_NO_PROVIDER_KEYS")
    need("GH_TOKEN" not in snd and "/git/refs" not in snd
         and "TASK1_OPENAI_API_KEY: ${{ secrets.TASK1_OPENAI_API_KEY }}" in snd
         and "TASK1_CAPTURE_AES256_KEY: ${{ secrets.TASK1_CAPTURE_AES256_KEY }}" in snd
         and "TASK1_423_TAG_READBACK_SHA: ${{ needs.issuer.outputs.consumed_sha }}" in snd
         and snd.count("--mode send --output-dir results") == 1
         and snd.count("--mode preflight --output-dir results") == 1,
         "SENDER_READ_ONLY_SOURCE_AND_HANDOFF")
    need("    outputs:\n      consumed_sha: ${{ steps.consume.outputs.consumed_sha }}" in b
         and iss.count("id: consume") == 1
         and iss.count("method=\"POST\"") == 1,
         "TAG_ISSUER_SINGLE_OPERATION")
    need(not re.search(r"(?m)^  (?!preflight:|issuer:|sender:)[A-Za-z0-9_-]+:", 
                       "\n".join(jobs.values())),
         "UNREGISTERED_TOP_LEVEL_JOB")
    return {"actual_three_job_split_installed": True,
            "preflight_and_sender_disabled": True,
            "issuer_provider_secret_isolated_in_source": True,
            "sender_github_token_read_only": True,
            "independent_iam_attested": False,
            "remote_atomic_ledger_installed": False,
            "provider_egress_nonbypassable": False,
            "production_tag_issuance_enabled": False,
            "provider_send_enabled": False,
            "new_utility_recovery": 0,
            "paid_task1_decision": "NO_GO_ISSUE_427"}


def test_archived_blob_and_current_role_split():
    assert git_blob(HIST.read_bytes()) == HIST_BLOB
    assert git_blob(LIVE.read_bytes()) == NEW_BLOB
    observed = inspect(LIVE.read_text())
    assert observed["actual_three_job_split_installed"] is True
    assert observed["preflight_and_sender_disabled"] is True
    for name in ("independent_iam_attested", "remote_atomic_ledger_installed",
                 "provider_egress_nonbypassable",
                 "production_tag_issuance_enabled", "provider_send_enabled"):
        assert observed[name] is False


def test_security_drift_is_refused():
    original = LIVE.read_text()
    cases = [
        ("    if: " + PREFLIGHT_OFF + "\n", "    if: true\n"),
        ("    if: " + SENDER_OFF + "\n", "    if: true\n"),
        ("    if: " + ISSUER_IF + "\n", "    if: success()\n"),
        ("    needs: [preflight]\n", "    needs: []\n"),
        ("    needs: [issuer]\n", "    needs: [preflight]\n"),
        ("  contents: read\n\nconcurrency:", "  contents: write\n\nconcurrency:"),
        ("  issuer:\n", "  issuer:\n    environment: task1-real-model-pilot\n"),
        ("  issuer:\n", "  issuer:\n    env:\n      TASK1_OPENAI_API_KEY: placeholder\n"),
        ("  sender:\n", "  sender:\n    permissions:\n      contents: write\n"),
        ("  preflight:\n", "  preflight:\n    if: true\n"),
        ("  issuer:\n", "  issuer:\n  issuer:\n"),
        ("\non:\n  workflow_dispatch:\n", "\non:\n  push:\n  workflow_dispatch:\n"),
        ("    environment: task1-real-model-pilot\n    env:\n",
         "    environment: task1-real-model-pilot\n    env:\n      GH_TOKEN: placeholder\n"),
    ]
    for before, after in cases:
        assert before in original
        with pytest.raises(Refused):
            inspect(original.replace(before, after, 1))


def test_no_executable_snapshot_or_false_model_result_claim():
    assert HIST.suffix == ".txt" and ".github/workflows" not in str(HIST)
    docs = DOC.read_text(encoding="utf-8")
    for phrase in ("NO-GO", "Issue #427", "#423", "#445", "#450",
                   "#451", "preflight", "issuer", "sender",
                   "actual workflow", "not a real external Executor",
                   "no Provider"):
        assert phrase in docs
