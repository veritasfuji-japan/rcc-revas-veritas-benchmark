"""Task1 integrated no-effect dry-run: synthetic signer is NEVER execution authority."""
from __future__ import annotations

import contextlib
import io
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import final128_task1_integrated_signed_evidence_no_effect_dry_run_v1 as harness
from scripts import final128_task1_privileged_ruleset_attestation_offline_v1 as bridge

SHA = "33701c5d5a3936bfaee442bdb93e7bec0d9a4fa4"
RUN = "39021182542"
NOW = datetime(2026, 10, 17, 9, 50, 0, tzinfo=timezone.utc)
NONCE = "a1" * 32


def runtime():
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": bridge.REPOSITORY,
        "GITHUB_ACTOR": "veritasfuji-japan",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": SHA,
        "GITHUB_RUN_ID": RUN,
    }


class TestTask1IntegratedNoEffectDryRun(unittest.TestCase):
    def test_integrated_synthetic_cases_are_complete_and_no_go(self):
        cases = harness.exercise_offline_cases(SHA, RUN, NONCE, NOW)
        self.assertEqual(len(cases), 13)
        self.assertEqual(len({label for label, _, _ in cases}), len(cases))
        statuses = dict((label, result) for label, result, _ in cases)
        self.assertEqual(statuses["SYNTHETIC_SIGNED_BASELINE"], bridge.OFFLINE_ONLY)
        self.assertEqual(statuses["TAMPERED_AFTER_SIGNATURE"], "DENY_SIGNATURE")
        self.assertEqual(statuses["BYPASS_FIELD_REDACTED"], "DENY_RULESET_SNAPSHOT")
        self.assertEqual(statuses["BYPASS_ACTOR_PRESENT"], "DENY_RULESET_SNAPSHOT")
        self.assertEqual(statuses["PRIVILEGED_REVISION_CHANGED"], "DENY_PRIVILEGED_CURRENT_REVISION")
        for _, _, outcome in cases:
            self.assertIn(outcome, {harness.NO_GO, harness.DENY})

    def test_even_valid_synthetic_signed_evidence_never_issues(self):
        self.assertEqual(harness.simulated_final_boundary(bridge.OFFLINE_ONLY), harness.NO_GO)
        self.assertEqual(harness.simulated_final_boundary("DENY_TIME"), harness.DENY)
        self.assertNotIn("ALLOWED", (harness.NO_GO, harness.DENY))
        self.assertIn("ADMIN_CHANGE_RACE_NOT_CLOSED", harness.EXPLICITLY_MISSING_PRODUCTION_CONTROLS)

    def test_fake_ruleset_is_not_github_observation(self):
        e = harness.hypothetical_evidence(NOW, SHA, RUN, NONCE)
        self.assertEqual(e["ruleset_updated_at"], "2026-01-01T00:00:00Z")
        self.assertEqual(e["ruleset"]["bypass_actors"], [])
        self.assertEqual(e["challenge_hex"], NONCE)
        self.assertEqual(e["schema"], bridge.SCHEMA)

    def test_missing_or_wrong_runtime_context_fails_before_any_signing(self):
        for key, value in (
            ("GITHUB_ACTOR", "attacker"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_SHA", "not-sha"),
            ("GITHUB_RUN_ID", "not-id"),
        ):
            with self.subTest(key=key):
                env = runtime()
                env[key] = value
                buffer = io.StringIO()
                with contextlib.redirect_stdout(buffer):
                    status = harness.main(env)
                self.assertEqual(status, 1)
                self.assertEqual(buffer.getvalue().strip(),
                                 harness.PREFIX + "STOP_BAD_RUNTIME_CONTEXT")

    def test_modules_and_workflow_have_no_provider_or_mutation_surface(self):
        src = Path(harness.__file__).read_text()
        self.assertNotIn("urllib.request", src)
        self.assertNotIn("requests.", src)
        self.assertNotIn("httpx.", src)
        self.assertNotIn("openai.OpenAI", src)
        self.assertNotIn("git/refs", src)
        self.assertNotIn("secrets.TASK1_", src)
        self.assertNotIn("GITHUB_TOKEN", src)
        self.assertNotIn("GH_TOKEN", src)

    def test_public_fixture_key_cannot_be_called_production_trust(self):
        self.assertEqual(len(harness._SYNTHETIC_PUBLIC), 32)
        self.assertIn("PRODUCTION_SIGNING_KEY_NOT_ENROLLED",
                      harness.EXPLICITLY_MISSING_PRODUCTION_CONTROLS)


if __name__ == "__main__":
    unittest.main()
