"""Zero-network tests for the owner-local REAL Ruleset GET audit preflight."""
from __future__ import annotations

import copy
import unittest

from scripts import final128_task1_owner_privileged_ruleset_readonly_capture_v1 as unit

SHA = "774dd6a2b0b991e99d498b3f2e4091dcb0f37658"
OBSERVED = "2026-10-17T10:30:00Z"


def real_shape():
    """Safe deterministic fixture matching known STRUCTURE, not a live GitHub read."""
    return {
        "id": unit.RULESET_ID,
        "target": "tag",
        "enforcement": "active",
        "source": unit.REPO,
        "source_type": "Repository",
        "updated_at": "2026-10-13T15:45:08.215+09:00",
        "current_user_can_bypass": "never",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {
                "include": [unit.PATTERN, unit.TAG],
                "exclude": [],
            },
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "update"},
        ],
    }


def exercise(*, ref_status=404, main_sha=SHA, listed=None,
             detail=None, list_status=200, detail_status=200, now=OBSERVED):
    if listed is None:
        listed = [{"id": unit.RULESET_ID, "target": "tag", "enforcement": "active"}]
    if detail is None:
        detail = real_shape()
    called = []

    def read(path):
        called.append(path)
        if path == unit.REF_PATH:
            return ref_status, None
        if path == unit.MAIN_PATH:
            return 200, {"commit": {"sha": main_sha}}
        if path == unit.LIST_PATH:
            return list_status, listed
        if path == unit.DETAIL_PATH:
            return detail_status, detail
        raise AssertionError("unknown endpoint " + path)

    status, observation = unit.inspect_privileged_read(read, SHA, observed_at=now)
    return status, observation, called


class TestOwnerPrivilegedReadOnly(unittest.TestCase):
    def test_privileged_explicit_empty_observation_is_audit_only(self):
        status, observation, called = exercise()
        self.assertEqual(status, "OBSERVATION_VALID_READ_ONLY_NOT_ISSUANCE_AUTHORITY")
        self.assertEqual(
            called,
            [unit.REF_PATH, unit.MAIN_PATH, unit.LIST_PATH, unit.DETAIL_PATH],
        )
        self.assertEqual(observation["bypass_actors_state"], "EXPLICIT_EMPTY")
        self.assertEqual(observation["audience"], "AUDIT_ONLY_NOT_TAG_OR_PROVIDER_AUTHORITY")
        self.assertEqual(observation["expected_main_sha"], SHA)
        self.assertEqual(len(unit.digest_observation(observation)), 64)
        self.assertEqual(unit.digest_observation(observation),
                         unit.digest_observation(copy.deepcopy(observation)))
        self.assertNotIn("signature", observation)
        self.assertNotIn("token", observation)

    def test_redacted_bypass_field_is_denied(self):
        detail = real_shape()
        del detail["bypass_actors"]
        status, observation, _ = exercise(detail=detail)
        self.assertEqual(status, "DENY_BYPASS_FIELD_REDACTED")
        self.assertIsNone(observation)

    def test_null_or_nonempty_bypass_never_count_as_empty(self):
        for value in (None, [{"actor_type": "User", "actor_id": 123}], "[]"):
            with self.subTest(value_type=type(value).__name__):
                detail = real_shape()
                detail["bypass_actors"] = value
                status, observation, _ = exercise(detail=detail)
                self.assertEqual(status, "DENY_BYPASS_NOT_EXPLICITLY_EMPTY")
                self.assertIsNone(observation)

    def test_consumed_or_unknown_tag_fails_before_later_reads(self):
        for code in (0, 200, 401, 403, 429, 500):
            with self.subTest(code=code):
                status, observation, called = exercise(ref_status=code)
                self.assertEqual(status, "DENY_SINGLETON_NOT_CONFIRMED_ABSENT")
                self.assertIsNone(observation)
                self.assertEqual(called, [unit.REF_PATH])

    def test_changed_main_sha_fails_early(self):
        status, _, called = exercise(main_sha="f" * 40)
        self.assertEqual(status, "DENY_MAIN_SHA_CHANGED")
        self.assertEqual(called, [unit.REF_PATH, unit.MAIN_PATH])

    def test_ruleset_not_listed_active_or_duplicate_fails(self):
        for listed in (
            [],
            [{"id": unit.RULESET_ID, "target": "tag", "enforcement": "disabled"}],
            [{"id": unit.RULESET_ID, "target": "branch", "enforcement": "active"}],
            [{"id": unit.RULESET_ID, "target": "tag", "enforcement": "active"}] * 2,
        ):
            with self.subTest(n=len(listed)):
                status, obs, called = exercise(listed=listed)
                self.assertEqual(status, "DENY_EXPECTED_RULESET_NOT_UNIQUE_ACTIVE")
                self.assertIsNone(obs)
                self.assertEqual(called[-1], unit.LIST_PATH)

    def test_unreadable_list_or_detail_fails(self):
        self.assertEqual(exercise(list_status=403)[0], "DENY_RULESET_LIST_UNREADABLE")
        self.assertEqual(exercise(detail_status=403)[0],
                         "DENY_PRIVILEGED_RULESET_DETAIL_UNREADABLE")

    def test_tag_target_or_exclusion_change_fails(self):
        modifiers = [
            lambda detail: detail["conditions"]["ref_name"]["include"].remove(unit.TAG),
            lambda detail: detail["conditions"]["ref_name"]["exclude"].append(unit.TAG),
            lambda detail: detail["conditions"]["ref_name"]["include"].append("~ALL"),
            lambda detail: detail["conditions"]["ref_name"].update(include=[]),
        ]
        for mutate in modifiers:
            detail = real_shape()
            mutate(detail)
            self.assertEqual(exercise(detail=detail)[0], "DENY_RULESET_CONDITIONS")

    def test_missing_protection_or_creation_rule_fails(self):
        mutations = [
            lambda detail: detail["rules"].pop(0),
            lambda detail: detail["rules"].append({"type": "creation"}),
            lambda detail: detail["rules"][0].update(type="pull_request"),
        ]
        for mutate in mutations:
            detail = real_shape()
            mutate(detail)
            self.assertEqual(exercise(detail=detail)[0], "DENY_RULESET_RULES")

    def test_wrong_source_identity_revision_or_caller_bypass_fails(self):
        for key, value in (
            ("source", "not-our-repository"),
            ("source_type", "Organization"),
            ("target", "branch"),
            ("enforcement", "disabled"),
            ("updated_at", None),
            ("current_user_can_bypass", "always"),
            ("id", unit.RULESET_ID + 1),
        ):
            with self.subTest(key=key):
                detail = real_shape()
                detail[key] = value
                self.assertEqual(
                    exercise(detail=detail)[0], "DENY_RULESET_IDENTITY_OR_REVISION",
                )

    def test_invalid_runtime_sha_or_timestamp_denied(self):
        status, observation = unit.inspect_privileged_read(
            lambda path: (_ for _ in ()).throw(AssertionError("should not fetch")),
            "not-a-sha", observed_at=OBSERVED,
        )
        self.assertEqual((status, observation), ("DENY_INVALID_EXPECTED_SHA", None))
        status, observation = unit.inspect_privileged_read(
            lambda path: (_ for _ in ()).throw(AssertionError("should not fetch")),
            SHA, observed_at="not-a-timestamp",
        )
        self.assertEqual((status, observation), ("DENY_OBSERVATION_CLOCK", None))

    def test_network_paths_are_fixed_and_method_is_get_only(self):
        self.assertEqual(
            unit.ALLOWED_PATHS,
            frozenset((unit.REF_PATH, unit.MAIN_PATH,
                       unit.LIST_PATH, unit.DETAIL_PATH)),
        )
        self.assertEqual(unit.safe_get("git/refs", "no-secret"), (0, None))

    def test_owner_script_refuses_ci_context_without_reading_credentials(self):
        from pathlib import Path
        code = Path(unit.__file__).read_text()
        self.assertIn('if os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI")', code)
        self.assertIn("STOP_CI_CONTEXT_FORBIDDEN", code)
        self.assertIn("AUDIT_ONLY_NOT_TAG_OR_PROVIDER_AUTHORITY", code)
        self.assertNotIn("requests.post", code)
        self.assertNotIn("openai.OpenAI(", code)
        self.assertNotIn('method="POST"', code)
        self.assertNotIn('"https://api.openai.com/', code)


if __name__ == "__main__":
    unittest.main()
