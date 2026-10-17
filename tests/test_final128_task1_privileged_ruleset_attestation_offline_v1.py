"""Offline adverse-case tests for a NON-AUTHORIZING signed evidence candidate."""
from __future__ import annotations

import base64
import copy
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import final128_task1_privileged_ruleset_attestation_offline_v1 as bridge


# Deliberately public, deterministic synthetic fixture; NOT an enrolled signer.
FIXTURE_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
FIXTURE_PUBLIC = FIXTURE_SIGNER.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
SHA = "1bdf8bc9cc28d33671d5b96ebfd2c81cc75c9f6f"
RUN_ID = "39021182542"
NONCE = "ab" * 32
REVISION = "2026-10-17T09:29:00Z"
NOW = datetime(2026, 10, 17, 9, 30, 10, tzinfo=timezone.utc)


def valid_payload():
    return {
        "schema": bridge.SCHEMA,
        "audience": bridge.AUDIENCE,
        "repository": bridge.REPOSITORY,
        "main_sha": SHA,
        "run_id": RUN_ID,
        "challenge_hex": NONCE,
        "singleton_ref": bridge.TAG,
        "ruleset_id": bridge.RULESET_ID,
        "ruleset_updated_at": REVISION,
        "observed_at": "2026-10-17T09:30:00Z",
        "expires_at": "2026-10-17T09:31:00Z",
        "ruleset": {
            "source": bridge.REPOSITORY,
            "source_type": "Repository",
            "target": "tag",
            "enforcement": "active",
            "conditions": {"ref_name": {
                "include": [bridge.TAG,
                            "refs/tags/final128-task1-real-ab-once-v1-*"],
                "exclude": [],
            }},
            "rules": [{"type": "deletion"}, {"type": "update"},
                      {"type": "non_fast_forward"}],
            "bypass_actors": [],
        },
    }


def signed(payload=None, signer=FIXTURE_SIGNER):
    data = copy.deepcopy(payload if payload is not None else valid_payload())
    signature = signer.sign(bridge.canonical_evidence_bytes(data))
    return {"evidence": data,
            "signature_b64": base64.b64encode(signature).decode("ascii")}


def inspect(envelope=None, **changes):
    context = {
        "trusted_public_key_bytes": FIXTURE_PUBLIC,
        "expected_sha": SHA,
        "expected_run_id": RUN_ID,
        "expected_challenge_hex": NONCE,
        "privileged_current_ruleset_updated_at": REVISION,
        "observed_singleton_absent": True,
        "now": NOW,
    }
    context.update(changes)
    return bridge.review_candidate_offline(
        envelope if envelope is not None else signed(), **context
    )


class TestSignedEvidenceBridgeOffline(unittest.TestCase):
    def test_fixture_valid_but_never_admitted_to_live_execution(self):
        self.assertEqual(inspect(), bridge.OFFLINE_ONLY)
        self.assertIn("NOT_DISPATCH_AUTHORITY", bridge.OFFLINE_ONLY)

    def test_no_trust_anchor_must_deny(self):
        self.assertEqual(inspect(trusted_public_key_bytes=None),
                         "DENY_TRUST_ANCHOR_NOT_ENROLLED")

    def test_alternate_self_signed_key_is_not_enrolled(self):
        untrusted = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
        self.assertEqual(inspect(signed(signer=untrusted)), "DENY_SIGNATURE")

    def test_tamper_after_signature_denied(self):
        env = signed()
        env["evidence"]["ruleset"]["bypass_actors"] = [{"actor_id": 1234}]
        self.assertEqual(inspect(env), "DENY_SIGNATURE")

    def test_modified_signature_denied(self):
        env = signed()
        env["signature_b64"] = base64.b64encode(bytes(64)).decode()
        self.assertEqual(inspect(env), "DENY_SIGNATURE")

    def test_unauthorized_unsigned_envelope_denied(self):
        env = signed()
        del env["signature_b64"]
        self.assertEqual(inspect(env), "DENY_ENVELOPE")

    def test_wrong_run_or_sha_or_challenge_cannot_replay(self):
        for key, value in (
            ("expected_sha", "f" * 40),
            ("expected_run_id", "39021182543"),
            ("expected_challenge_hex", "cd" * 32),
        ):
            with self.subTest(key=key):
                self.assertEqual(inspect(**{key: value}), "DENY_RUNTIME_BINDING")

    def test_wrong_repository_or_ruleset_id_denied_even_signed(self):
        for key, value in (
            ("repository", "attacker/repo"),
            ("ruleset_id", 24921426),
            ("singleton_ref", "refs/tags/other"),
            ("audience", "task1-live-provider"),
        ):
            with self.subTest(key=key):
                payload = valid_payload()
                payload[key] = value
                self.assertEqual(inspect(signed(payload)), "DENY_IDENTITY")

    def test_bad_revision_and_missing_privileged_current_observation(self):
        self.assertEqual(
            inspect(privileged_current_ruleset_updated_at=None),
            "DENY_PRIVILEGED_CURRENT_REVISION",
        )
        self.assertEqual(
            inspect(privileged_current_ruleset_updated_at="2026-10-17T09:30:12Z"),
            "DENY_PRIVILEGED_CURRENT_REVISION",
        )

    def test_consumed_or_undetermined_singleton_denied(self):
        for value in (False, None, "404"):
            with self.subTest(value=value):
                self.assertEqual(inspect(observed_singleton_absent=value),
                                 "DENY_SINGLETON_NOT_PROVEN_ABSENT")

    def test_stale_expired_and_future_proof_denied(self):
        for key, value in (
            ("observed_at", "2026-10-17T09:28:00Z"),
            ("expires_at", "2026-10-17T09:30:00Z"),
            ("observed_at", "2026-10-17T09:30:30Z"),
            ("expires_at", "2026-10-17T09:35:00Z"),
            ("observed_at", "2026-10-17T09:30:00+00:00"),
        ):
            with self.subTest(key=key, value=value):
                payload = valid_payload()
                payload[key] = value
                self.assertEqual(inspect(signed(payload)), "DENY_TIME")

    def test_redacted_null_or_nonempty_bypass_denied_even_if_signed(self):
        for category, value in (
            ("missing", "omit"),
            ("null", None),
            ("nonempty", [{"actor_type": "Team", "actor_id": 99}]),
            ("type", "unknown"),
        ):
            with self.subTest(category=category):
                payload = valid_payload()
                if value == "omit":
                    del payload["ruleset"]["bypass_actors"]
                else:
                    payload["ruleset"]["bypass_actors"] = value
                self.assertEqual(inspect(signed(payload)), "DENY_RULESET_SNAPSHOT")

    def test_protection_removed_creation_prohibition_or_exclusion_denied(self):
        def delete_update(p):
            p["ruleset"]["rules"].pop(1)
        def add_creation(p):
            p["ruleset"]["rules"].append({"type": "creation"})
        def add_exclusion(p):
            p["ruleset"]["conditions"]["ref_name"]["exclude"].append(bridge.TAG)
        def change_ref(p):
            p["ruleset"]["conditions"]["ref_name"]["include"][0] = "refs/tags/other"
        for modifier in (delete_update, add_creation, add_exclusion, change_ref):
            with self.subTest(modifier=modifier.__name__):
                payload = valid_payload()
                modifier(payload)
                self.assertEqual(inspect(signed(payload)), "DENY_RULESET_SNAPSHOT")

    def test_unexpected_extra_field_denied(self):
        payload = valid_payload()
        payload["approved"] = True
        self.assertEqual(inspect(signed(payload)), "DENY_EVIDENCE_SHAPE")

    def test_bad_timestamp_or_naive_clock_denied(self):
        self.assertEqual(inspect(now=datetime(2026, 10, 17, 9, 30, 10)),
                         "DENY_TIME")
        payload = valid_payload()
        payload["ruleset_updated_at"] = "not a timestamp"
        self.assertEqual(inspect(signed(payload),
                                 privileged_current_ruleset_updated_at="not a timestamp"),
                         "DENY_PRIVILEGED_CURRENT_REVISION")

    def test_never_builds_provider_client_or_tag_writer(self):
        # Offline module must remain independent from requests, urllib and
        # anything that could issue GitHub refs or send a Provider POST.
        from pathlib import Path
        source = Path(bridge.__file__).read_text()
        for forbidden in (
            "urllib.request", "requests.post", "httpx.post",
            "openai.OpenAI(", "git/refs", "GITHUB_TOKEN", "TASK1_OPENAI_API_KEY",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
