import pytest
from scripts.final128_355_task1_live_ruleset_evidence_v1 import main
def test_reject_wrong_repository(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_REPOSITORY","other/repo")
    monkeypatch.setenv("GITHUB_REF","refs/heads/main")
    monkeypatch.setenv("GH_RULESET_READ_TOKEN","placeholder")
    monkeypatch.setattr("sys.argv",["cmd","--tag-name","anything","--output",str(tmp_path/"x")])
    with pytest.raises(SystemExit,match="355_REPOSITORY_MISMATCH"):main()
def test_reject_nonmain(monkeypatch,tmp_path):
    monkeypatch.setenv("GITHUB_REPOSITORY","veritasfuji-japan/rcc-revas-veritas-benchmark")
    monkeypatch.setenv("GITHUB_REF","refs/heads/feature")
    monkeypatch.setenv("GH_RULESET_READ_TOKEN","placeholder")
    monkeypatch.setattr("sys.argv",["cmd","--tag-name","anything","--output",str(tmp_path/"x")])
    with pytest.raises(SystemExit,match="355_NOT_MAIN"):main()
def test_reject_missing_token(monkeypatch,tmp_path):
    monkeypatch.setenv("GITHUB_REPOSITORY","veritasfuji-japan/rcc-revas-veritas-benchmark")
    monkeypatch.setenv("GITHUB_REF","refs/heads/main")
    monkeypatch.delenv("GH_RULESET_READ_TOKEN",raising=False)
    monkeypatch.setattr("sys.argv",["cmd","--tag-name","anything","--output",str(tmp_path/"x")])
    with pytest.raises(SystemExit,match="355_MISSING_READ_TOKEN"):main()
