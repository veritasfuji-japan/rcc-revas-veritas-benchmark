import dataclasses
import pytest
from scripts.final128_351_task1_durable_lease_preflight_v1 import (
    Context,validate,authorized_for_provider,PreflightDenied,TAG_PREFIX)

GOOD=Context(repository="veritasfuji-japan/rcc-revas-veritas-benchmark",
 ref="refs/heads/main",sha="a"*40,run_id="38227769501",
 environment="task1-real-model-pilot",model="gpt-4.1-mini-2025-04-14",
 budget_usd="1.00",approved_phrase="I APPROVE TASK1 A/B ONE RUN UP TO USD 1",
 confirmed_protected_immutable_tag_ruleset=True,confirmed_project_hard_limit=True)
def test_valid_preflight_yields_tag_but_never_authorizes_provider():
    assert validate(GOOD)==TAG_PREFIX+"a"*40+"-38227769501"
    assert authorized_for_provider(GOOD) is False
@pytest.mark.parametrize("field,value",[
 ("repository","other/repo"),("ref","refs/heads/feature"),
 ("sha","bad"),("run_id",""),("environment","default"),
 ("model","other"),("budget_usd","10.00"),
 ("approved_phrase","yes"),("confirmed_protected_immutable_tag_ruleset",False),
 ("confirmed_project_hard_limit",False),
])
def test_any_boundary_change_fails(field,value):
    with pytest.raises(PreflightDenied):
        validate(dataclasses.replace(GOOD,**{field:value}))
def test_bools_must_be_actual_true():
    with pytest.raises(PreflightDenied,match="TAG_RULESET"):
        validate(dataclasses.replace(GOOD,confirmed_protected_immutable_tag_ruleset=1))
def test_wrong_context_type():
    with pytest.raises(PreflightDenied,match="CONTEXT_TYPE"):
        validate({})
