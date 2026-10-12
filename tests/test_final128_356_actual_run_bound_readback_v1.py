from pathlib import Path
WORKFLOW=Path(".github/workflows/final128-356-task1-actual-run-bound-ruleset-readback.yml")
def test_no_user_supplied_identity():
    text=WORKFLOW.read_text()
    assert "workflow_dispatch:" in text
    assert "inputs:" not in text
    assert 'github.ref == \'refs/heads/main\'' in text
    assert 'GITHUB_SHA' in text and 'GITHUB_RUN_ID' in text
    assert 'final128-task1-real-ab-once-v1-' in text
def test_readonly_and_no_provider():
    text=WORKFLOW.read_text()
    assert "contents: read" in text
    assert "OPENAI_API_KEY: \"\"" in text
    assert "final128_355_task1_live_ruleset_evidence_v1" in text
    assert "git/refs" not in text
    assert "responses.create" not in text
