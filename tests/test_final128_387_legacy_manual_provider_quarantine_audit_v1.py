"""#387: active manual Provider-secret jobs must be disabled at job admission."""
from __future__ import annotations
from pathlib import Path
import os
import pytest
from scripts import final128_387_legacy_manual_provider_quarantine_audit_v1 as g

D="$"
def source(before_if=True,secret=True,second_job=False):
    expr=("    if: "+D+"{{ inputs.confirmation == 'RUN' }}\n" if before_if else "")
    extra=("  unsafe-other:\n    runs-on: ubuntu-latest\n"
           "    steps:\n      - run: echo danger\n" if second_job else "")
    return ("name: Offline-only historical\n"
      "on:\n  workflow_dispatch:\n    inputs:\n      confirmation: {required: true}\n"
      "permissions: {contents: read}\n"
      "jobs:\n  manual:\n"+expr+"    runs-on: ubuntu-latest\n"
      "    env:\n      OPENAI_API_KEY: "+(D+"{{ secrets.OPENAI_API_KEY }}" if secret else '""')+"\n"
      "    steps:\n      - run: python scripts/historical.py\n"+extra)

def test_exact_old_if_transformation_has_single_false_job_admission():
    src=source()
    options=g.expected_variants(src)
    assert len(options)==2
    for x in options:
        assert len(g.jobs(x))==1
        assert g.frozen(g.jobs(x)[0][1])
        assert g.STOP_IF in x
        assert g.manual_provider(x)
    assert "Original historical condition" in options[0]
    assert "Previous historical condition" in options[1]

def test_no_original_if_still_gets_hard_stop():
    src=source(before_if=False)
    opts=g.expected_variants(src)
    assert len(opts)==2
    assert all(g.frozen(g.jobs(x)[0][1]) for x in opts)

@pytest.mark.parametrize("change",[
    lambda s:s.replace("if: "+D+"{{ false }}","if: "+D+"{{ true }}"),
    lambda s:s.replace("if: "+D+"{{ false }}","if: "+D+"{{ inputs.confirmation }}"),
    lambda s:s.replace("if: "+D+"{{ false }}","if: true"),
    lambda s:s.replace("if: "+D+"{{ false }}","if: False",1),
    lambda s:s.replace("if: "+D+"{{ false }}","if: "+D+"{{ always() }}"),
    lambda s:s.replace("    if: "+D+"{{ false }}","      if: "+D+"{{ false }}"),
    lambda s:s.replace("    if: "+D+"{{ false }}","    # if: "+D+"{{ false }}"),
    lambda s:s.replace("  manual:\n","  manual:\n    if: "+D+"{{ true }}\n"),
])
def test_mutated_admission_no_longer_both_exact_and_safe(change):
    src=source()
    good=g.expected_variants(src)[0]
    poisoned=change(good)
    assert poisoned not in g.expected_variants(src)

def test_active_second_job_detected_even_if_provider_secret_is_in_first_job():
    s=g.expected_variants(source())[0]
    s=s+"\n  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo fake\n"
    found=g.jobs(s)
    assert len(found)==2
    assert any(not g.frozen(body) for _,body in found)

def test_all_real_15_files_have_one_statically_false_job():
    files=g.all_files(".")
    assert len(files)>=330
    assert len(g.LEGACY)==15
    for n in g.LEGACY:
        path=g.ROOT+"/"+n
        assert path in files
        src=files[path]
        assert g.manual_provider(src)
        assert len(g.jobs(src))==1
        assert g.frozen(g.jobs(src)[0][1])

def test_detect_any_new_manual_secret_workflow_that_has_not_been_stopped():
    known={g.ROOT+"/"+n:g.expected_variants(source())[0] for n in g.LEGACY}
    other=g.ROOT+"/rogue-provider-dispatch.yml"
    known[other]=source()
    # Without base, the synthetic old files are not checked for exact diff;
    # the global active-provider check should independently refuse the rogue.
    with pytest.raises(g.Refused,match="UNCOVERED_MANUAL_PROVIDER_JOBS"):
        g.inspect(files=known)

def test_provider_secret_with_no_manual_dispatch_is_out_of_this_narrow_gate():
    assert g.manual_provider(source().replace("workflow_dispatch:","push:")) is False

def test_baseline_requires_exact_sha_not_branch_name():
    for value in ("main","1"*39,None,True):
        with pytest.raises(g.Refused,match="BASE_SHA_MUST_BE_EXACT"):
            g.baseline_blob(value,g.ROOT+"/x.yml")

def test_exact_base_diff_validation_on_real_tree_when_configured():
    base=os.environ.get("FINAL128_387_BASE_SHA")
    if not base:return
    record=g.inspect(files=g.all_files("."),base_sha=base,root=".")
    assert record["legacy_paths_checked"]==15
    assert record["unblocked_manual_provider_secret_workflows"]==0
    assert all(p["only_job_gate_changed"] is True for p in record["legacy_evidence"])
    assert record["real_provider_requests"]==0
    assert record["production_scope_complete"] is False
    assert record["historical_git_ref_dispatch_resistance_verified"] is False

def test_guard_is_read_only_and_not_paid_runner():
    s=Path(g.__file__).read_text()
    for bad in ("from openai import","http.client.HTTPSConnection(","requests.post(",
                "workflow_dispatch:","gh api -X POST"):
        assert bad not in s
