import copy
import pytest
from scripts.final128_353_task1_tag_ruleset_readonly_v1 import verify_ruleset,RuleDenied
TAG="final128-task1-real-ab-once-v1-"+"a"*40+"-38229513704"
RULE={"id":123,"name":"task1 immutable tag","target":"tag","enforcement":"active",
 "conditions":{"ref_name":{"include":["refs/tags/final128-task1-real-ab-once-v1-*"],"exclude":[]}},
 "bypass_actors":[],"rules":[{"type":"deletion"},{"type":"update"}]}
def check(rule,**kw):
    return verify_ruleset(rulesets=[rule],tag_name=TAG,verified_rest_origin=True,**kw)
def test_active_exact_namespace_rules():
    result=check(RULE)
    assert result["ruleset_id"]==123
    assert result["proof_of_live_rejection"] is False
@pytest.mark.parametrize("change",[
 {"enforcement":"evaluate"},{"target":"branch"},
 {"bypass_actors":[{"actor_id":1,"actor_type":"OrganizationAdmin","bypass_mode":"always"}]},
 {"rules":[{"type":"deletion"}]},
 {"conditions":{"ref_name":{"include":["refs/tags/other-*"],"exclude":[]}}},
 {"conditions":{"ref_name":{"include":["refs/tags/final128-task1-real-ab-once-v1-*"],"exclude":["refs/tags/final128-task1-real-ab-once-v1-*"]}}},
])
def test_reject_unprotected_rulesets(change):
    r=copy.deepcopy(RULE);r.update(change)
    with pytest.raises(RuleDenied):check(r)
def test_no_origin_proof():
    with pytest.raises(RuleDenied,match="ORIGIN"):
        verify_ruleset(rulesets=[RULE],tag_name=TAG)
def test_invalid_tag():
    with pytest.raises(RuleDenied,match="INVALID_TAG"):
        verify_ruleset(rulesets=[RULE],tag_name="bad",verified_rest_origin=True)
def test_no_ruleset():
    with pytest.raises(RuleDenied,match="NO_RULESETS"):
        verify_ruleset(rulesets=[],tag_name=TAG,verified_rest_origin=True)
