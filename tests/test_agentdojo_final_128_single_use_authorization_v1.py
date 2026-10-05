import copy
import pytest

def consume(auth, run_id, job_id):
    a = copy.deepcopy(auth)
    if not a["issued"] or not a["human_approved"]:
        raise ValueError("AUTHORIZATION_NOT_ISSUED")
    if a["consumed"]:
        raise ValueError("AUTHORIZATION_ALREADY_CONSUMED")
    a["consumed"] = True
    a["consumed_by_run"] = run_id
    a["consumed_by_job"] = job_id
    return a

def test_unissued_fails_closed():
    with pytest.raises(ValueError, match="AUTHORIZATION_NOT_ISSUED"):
        consume({"issued": False, "human_approved": False, "consumed": False}, 1, 2)

def test_single_use_consumes_once():
    base={"issued": True, "human_approved": True, "consumed": False}
    used=consume(base, 11, 22)
    assert used["consumed"] is True
    assert used["consumed_by_run"] == 11
    with pytest.raises(ValueError, match="AUTHORIZATION_ALREADY_CONSUMED"):
        consume(used, 33, 44)
