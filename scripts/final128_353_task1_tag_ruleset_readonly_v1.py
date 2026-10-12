"""#353 read-only tag ruleset verifier, deliberately conservative.

No ruleset is created or changed. Caller supplies GitHub REST ruleset JSON from
an independently authenticated GET. This parser alone cannot attest identity.
"""
import fnmatch
import re

PREFIX="final128-task1-real-ab-once-v1-"
class RuleDenied(RuntimeError):pass

def verify_ruleset(*,rulesets,tag_name,verified_rest_origin=False):
    if verified_rest_origin is not True:raise RuleDenied("353_UNVERIFIED_REST_ORIGIN")
    if not isinstance(tag_name,str) or not re.fullmatch(
        r"final128-task1-real-ab-once-v1-[0-9a-f]{40}-[1-9][0-9]{5,19}",tag_name):
        raise RuleDenied("353_INVALID_TAG")
    if not isinstance(rulesets,list) or not rulesets:
        raise RuleDenied("353_NO_RULESETS")
    for rule in rulesets:
        if not isinstance(rule,dict):continue
        if rule.get("target")!="tag" or rule.get("enforcement")!="active":continue
        conditions=rule.get("conditions") or {}
        ref=conditions.get("ref_name") or {}
        includes=ref.get("include") or []
        excludes=ref.get("exclude") or []
        if not isinstance(includes,list) or not isinstance(excludes,list):continue
        def matches(pattern):
            return isinstance(pattern,str) and fnmatch.fnmatchcase("refs/tags/"+tag_name,
                pattern if pattern.startswith("refs/") else "refs/tags/"+pattern)
        if not any(matches(p) for p in includes) or any(matches(p) for p in excludes):
            continue
        bypass=rule.get("bypass_actors")
        if bypass is not None and bypass!=[]:continue
        kinds={r.get("type") for r in rule.get("rules",[]) if isinstance(r,dict)}
        if {"deletion","update"}.issubset(kinds):
            return {"ruleset_id":rule.get("id"),"ruleset_name":rule.get("name"),
                "matched_tag":tag_name,"enforcement":"active",
                "no_declared_bypass_actors":True,"deletion_update_rules_present":True,
                "proof_of_live_rejection":False}
    raise RuleDenied("353_NO_MATCHING_IMMUTABLE_ACTIVE_TAG_RULESET")
