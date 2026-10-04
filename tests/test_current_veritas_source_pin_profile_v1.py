import json
from pathlib import Path

def test_current_veritas_source_pin_profile_is_independent_and_fail_closed():
    c=json.loads(Path("contracts/CURRENT_VERITAS_SOURCE_PIN_PROFILE_V1.json").read_text())
    assert c["status"]=="PROFILE_FREEZE"
    assert c["ben_historical_veritas_commit"] != c["current_veritas_commit"]
    rules="\n".join(c["rules"])
    assert "remains immutable" in rules
    assert "fail closed" in rules
    assert "disabled" in rules
    assert c["external_validation"] is False
    assert c["paid_provider_calls"]==0
