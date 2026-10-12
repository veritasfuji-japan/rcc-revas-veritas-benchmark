"""#351: strict offline preflight for Task1 durable one-use GitHub tag lease.

This module DOES NOT create a lease, access secrets, or invoke any provider.
A subsequent protected dispatcher must atomically create a protected immutable
tag through GitHub API, verify its ruleset, and bind it to exact run/head.
"""
import re
from dataclasses import dataclass

ENVIRONMENT="task1-real-model-pilot"
BRANCH="refs/heads/main"
MAX_BUDGET_USD="1.00"
EXPECTED_MODEL="gpt-4.1-mini-2025-04-14"
TAG_PREFIX="refs/tags/final128-task1-real-ab-once-v1-"
SHA_RE=re.compile(r"^[0-9a-f]{40}$")
RUN_RE=re.compile(r"^[1-9][0-9]{5,19}$")

class PreflightDenied(RuntimeError):
    pass

@dataclass(frozen=True)
class Context:
    repository:str
    ref:str
    sha:str
    run_id:str
    environment:str
    model:str
    budget_usd:str
    approved_phrase:str
    confirmed_protected_immutable_tag_ruleset:bool
    confirmed_project_hard_limit:bool

def validate(c:Context)->str:
    if type(c) is not Context:
        raise PreflightDenied("351_CONTEXT_TYPE")
    checks={
      "351_WRONG_REPOSITORY":c.repository=="veritasfuji-japan/rcc-revas-veritas-benchmark",
      "351_NOT_MAIN":c.ref==BRANCH,
      "351_BAD_SHA":isinstance(c.sha,str) and SHA_RE.fullmatch(c.sha) is not None,
      "351_BAD_RUN_ID":isinstance(c.run_id,str) and RUN_RE.fullmatch(c.run_id) is not None,
      "351_WRONG_ENVIRONMENT":c.environment==ENVIRONMENT,
      "351_WRONG_MODEL":c.model==EXPECTED_MODEL,
      "351_WRONG_BUDGET":c.budget_usd==MAX_BUDGET_USD,
      "351_NO_EXPLICIT_APPROVAL":c.approved_phrase=="I APPROVE TASK1 A/B ONE RUN UP TO USD 1",
      "351_TAG_RULESET_UNVERIFIED":c.confirmed_protected_immutable_tag_ruleset is True,
      "351_PROJECT_LIMIT_UNVERIFIED":c.confirmed_project_hard_limit is True,
    }
    for reason,passed in checks.items():
        if not passed:raise PreflightDenied(reason)
    return TAG_PREFIX+c.sha+"-"+c.run_id

def authorized_for_provider(c:Context)->bool:
    """Always false: preflight cannot substitute atomic durable tag creation."""
    validate(c)
    return False
