"""#385 workflow action SHA inventory tests."""
from pathlib import Path
import pytest
from scripts import final128_385_actions_sha_pinning_inventory_v1 as a

PINS=a.EXPECTED_CORE_ACTIONS

@pytest.mark.parametrize("ref,kind",[
    ("actions/checkout@v4","MUTABLE_ACTION_TAG"),
    ("actions/setup-python@v5","MUTABLE_ACTION_TAG"),
    ("actions/checkout@"+PINS["actions/checkout"],"PINNED_ACTION_SHA"),
    ("actions/setup-python@"+PINS["actions/setup-python"],"PINNED_ACTION_SHA"),
    ("actions/upload-artifact@"+PINS["actions/upload-artifact"],"PINNED_ACTION_SHA"),
    ("./.github/workflows/reusable.yml","LOCAL_ACTION"),
    ("docker://alpine:3.20","MUTABLE_DOCKER_IMAGE"),
    ("docker://ghcr.io/acme/image@sha256:"+"a"*64,"PINNED_DOCKER_DIGEST"),
    ("nope","INVALID_EXTERNAL_ACTION"),
    ("owner/action@v1@v2","INVALID_EXTERNAL_ACTION"),
])
def test_reference_classification(ref,kind):
    assert a.classify_uses(ref)[0]==kind

def test_direct_write_permissions_and_comment_are_distinguished():
    f=a.audit_workflow(".github/workflows/x.yml",
        "permissions:\n  contents: read\n  actions: write\n"
        "steps:\n  - uses: actions/checkout@v4\n"
        "  # - uses: bad/action@master\n")
    assert len(f["uses"])==1
    assert f["explicit_write_scopes"][0]["permission"]=="actions"

def test_no_new_mutable_reference_and_old_removed():
    before=[
      a.audit_workflow(a.CORE_FILES[0],
          "steps:\n  - uses: actions/checkout@v4\n"),
      a.audit_workflow(a.CORE_FILES[1],
          "steps:\n  - uses: actions/setup-python@v5\n"),
    ]
    after=[
      a.audit_workflow(a.CORE_FILES[0],
          "steps:\n  - uses: actions/checkout@"+PINS["actions/checkout"]+"\n"),
      a.audit_workflow(a.CORE_FILES[1],
          "steps:\n  - uses: actions/setup-python@"+PINS["actions/setup-python"]+"\n"),
    ]
    good=a.summarize(after,before)
    a.ensure_stage1(after,good)
    assert len(good["baseline_comparison"]["retired_unsafe_reference_keys"])==2
    assert good["repository_wide_sha_enforcement_ready"] is False

def test_new_mutable_reference_regression_denied():
    before=[
      a.audit_workflow(a.CORE_FILES[0],
          "steps:\n  - uses: actions/checkout@"+PINS["actions/checkout"]+"\n"),
      a.audit_workflow(a.CORE_FILES[1],
          "steps:\n  - uses: actions/setup-python@"+PINS["actions/setup-python"]+"\n"),
    ]
    bad=a.audit_workflow(".github/workflows/new.yml",
                         "steps:\n  - uses: attacker/other@main\n")
    snapshot=a.summarize(before+[bad],before)
    with pytest.raises(a.Refused,match="NEW_MUTABLE_REF_REGRESSION"):
        a.ensure_stage1(before+[bad],snapshot)

def test_real_core_files_pinned_to_reviewed_sha():
    files=a.scan_directory(".")
    assert set(a.CORE_FILES).issubset({x["path"] for x in files})
    for f in files:
        if f["path"] not in a.CORE_FILES:continue
        assert f["uses"]
        for x in f["uses"]:
            assert x["kind"]=="PINNED_ACTION_SHA"
            pkg,ref=x["reference"].rsplit("@",1)
            assert PINS[pkg]==ref

def test_symlink_and_nonworkflow_files(tmp_path):
    root=tmp_path/".github"/"workflows"
    root.mkdir(parents=True)
    (root/"a.yml").write_text("steps:\n  - uses: actions/checkout@v4\n")
    (root/"note.md").write_text("ignored")
    assert len(a.scan_directory(tmp_path))==1
    (root/"alias.yml").symlink_to(root/"a.yml")
    with pytest.raises(a.Refused,match="WORKFLOW_SYMLINK"):
        a.scan_directory(tmp_path)

@pytest.mark.parametrize("sha",["main","123",None,False])
def test_base_requires_full_commit_sha(tmp_path,sha):
    with pytest.raises(a.Refused,match="BASE_SHA_NOT_FULL_HEX"):
        a.scan_git_commit(tmp_path,sha)


def test_no_live_authority_even_if_every_action_is_pinned():
    f=a.audit_workflow(".github/workflows/safe.yml",
        "permissions:\n  contents: read\nsteps:\n"
        "  - uses: actions/checkout@"+PINS["actions/checkout"]+"\n")
    report=a.summarize([f],[f])
    assert report["unsafe_references_total"]==0
    assert report["repository_wide_sha_enforcement_ready"] is False
    assert report["github_settings_modified"] is False
    assert report["real_provider_calls"]==0
    assert report["production_bypass_resistance_verified"] is False
