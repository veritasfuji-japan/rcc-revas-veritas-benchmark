#!/usr/bin/env python3
import importlib
import importlib.metadata
import json
import os
import subprocess
from pathlib import Path

AGENTDOJO_COMMIT = "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
AGENTDOJO_PYPROJECT_BLOB = "71930851807e5f0e23f084b652c0908f06a36138"
AGENTDOJO_UV_LOCK_BLOB = "bdf5de4904c18ccdd3cf06d5c1396c79bf5197e3"
VERITAS_COMMIT = "a1d66aef02262cf8a913295270c3aafd159c6adb"

agentdojo_root = Path("_pins/agentdojo")
veritas_root = Path("_pins/veritas")
out = Path("results/v13-runtime-dependency-import-closure.json")

for key in (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "GOOGLE_API_KEY",
    "GCP_PROJECT",
    "GCP_LOCATION",
    "VERITAS_DATABASE_URL",
):
    if os.environ.get(key):
        raise SystemExit(f"PROVIDER_OR_DATABASE_CREDENTIAL_PRESENT:{key}")

def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

assert git(agentdojo_root, "rev-parse", "HEAD") == AGENTDOJO_COMMIT
assert git(veritas_root, "rev-parse", "HEAD") == VERITAS_COMMIT
assert git(agentdojo_root, "hash-object", "pyproject.toml") == AGENTDOJO_PYPROJECT_BLOB
assert git(agentdojo_root, "hash-object", "uv.lock") == AGENTDOJO_UV_LOCK_BLOB

class ProviderClientConstructionReached(RuntimeError):
    pass

class DenyProviderClient:
    def __init__(self, *args, **kwargs):
        raise ProviderClientConstructionReached(
            "PROVIDER_CLIENT_CONSTRUCTION_REACHED_DURING_IMPORT_CLOSURE"
        )

# Import SDK modules only, then fail closed if AgentDojo import/load attempts to
# instantiate any provider client. Use classes rather than functions so runtime
# type-union annotations remain valid during module import.
import openai
import anthropic
import cohere
from google import genai

openai.OpenAI = DenyProviderClient
if hasattr(openai, "AsyncOpenAI"):
    openai.AsyncOpenAI = DenyProviderClient
anthropic.Anthropic = DenyProviderClient
if hasattr(anthropic, "AsyncAnthropic"):
    anthropic.AsyncAnthropic = DenyProviderClient
cohere.Client = DenyProviderClient
if hasattr(cohere, "ClientV2"):
    cohere.ClientV2 = DenyProviderClient
if hasattr(cohere, "AsyncClient"):
    cohere.AsyncClient = DenyProviderClient
if hasattr(cohere, "AsyncClientV2"):
    cohere.AsyncClientV2 = DenyProviderClient
genai.Client = DenyProviderClient

baseline = importlib.import_module("agentdojo.attacks.baseline_attacks")
load_suites = importlib.import_module("agentdojo.task_suite.load_suites")
agent_pipeline = importlib.import_module("agentdojo.agent_pipeline.agent_pipeline")

DirectAttack = getattr(baseline, "DirectAttack")
get_suite = getattr(load_suites, "get_suite")
assert DirectAttack is not None
assert agent_pipeline.AgentPipeline is not None

suite = get_suite("v1.2.2", "banking")
assert suite is not None

packages = [
    "agentdojo", "anthropic", "cohere", "google-genai", "langchain",
    "deepdiff", "docstring-parser", "openai", "pydantic",
    "python-dotenv", "PyYAML", "rich", "tenacity", "typing-extensions",
    "idna", "httpx", "requests"
]
versions = {}
for name in packages:
    try:
        versions[name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        versions[name] = "NOT_INSTALLED"

assert versions["agentdojo"] == "0.1.35"
assert versions["openai"] == "1.109.1"
assert versions["pydantic"] == "2.11.10"
assert versions["idna"] == "3.15"
assert versions["httpx"] == "0.28.1"
assert versions["requests"] == "2.34.2"
assert versions["PyYAML"] == "6.0.3"

result = {
    "status": "PASS_V13_RUNTIME_DEPENDENCY_IMPORT_CLOSURE",
    "agentdojo_commit": AGENTDOJO_COMMIT,
    "agentdojo_pyproject_git_blob_sha": AGENTDOJO_PYPROJECT_BLOB,
    "agentdojo_uv_lock_git_blob_sha": AGENTDOJO_UV_LOCK_BLOB,
    "veritas_os_commit": VERITAS_COMMIT,
    "baseline_attacks_imported": True,
    "load_suites_imported": True,
    "banking_suite_v1_2_2_loaded": True,
    "provider_client_constructed": 0,
    "database_write": 0,
    "durable_consume": 0,
    "provider_credential_access": 0,
    "provider_api_calls": 0,
    "final_128_execution": 0,
    "versions": versions,
}
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps(result, sort_keys=True))
print("PASS_V13_PROVIDER_CLIENT_CONSTRUCTION_NOT_REACHED")
print("PASS_V13_BANKING_SUITE_LOAD_PROVIDER_FREE")

