"""Task1 #350: fail-closed one-shot Responses API transport and local budget guard.

This transport is intentionally not a full independent A/B native scorer runner.
It never reads an API key from disk, executes bank effects, scores a model answer,
or authenticates operator consent. The protected caller must provide the client,
an owned immutable model input, and an external durable once-only lease.
"""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
import hashlib,json

MODEL="gpt-4.1-mini-2025-04-14"
MAX_INPUT_TOKENS=12000
MAX_OUTPUT_TOKENS=256
MAX_CALLS_TOTAL=8
INPUT_USD_PER_M=Decimal("0.40")
OUTPUT_USD_PER_M=Decimal("1.60")
MAX_USD=Decimal("1.00")

class Refused(RuntimeError):pass

def need(condition,why):
    if not condition:raise Refused(why)

def reserved_max_usd():
    return (Decimal(MAX_CALLS_TOTAL)*(Decimal(MAX_INPUT_TOKENS)*INPUT_USD_PER_M+
            Decimal(MAX_OUTPUT_TOKENS)*OUTPUT_USD_PER_M)/Decimal(1000000))

def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,
        separators=(",",":"),allow_nan=False).encode()).hexdigest()

@dataclass
class Budget:
    """Volatile in-process guard only. Durable once-only lock belongs to runner."""
    used:int=0
    reserved:Decimal=Decimal("0")
    observed:Decimal=Decimal("0")

    def reserve(self):
        need(type(self.used) is int and 0<=self.used<MAX_CALLS_TOTAL,
             "350_CALL_COUNT_LIMIT")
        per=(Decimal(MAX_INPUT_TOKENS)*INPUT_USD_PER_M+
             Decimal(MAX_OUTPUT_TOKENS)*OUTPUT_USD_PER_M)/Decimal(1000000)
        need(self.reserved+per<=MAX_USD,"350_LOCAL_RESERVED_USD_LIMIT")
        self.reserved+=per
        self.used+=1

    def reconcile(self,usage):
        inp=getattr(usage,"input_tokens",None)
        out=getattr(usage,"output_tokens",None)
        need(type(inp) is int and type(out) is int and inp>=0 and out>=0,
             "350_PROVIDER_USAGE_MISSING")
        actual=(Decimal(inp)*INPUT_USD_PER_M+Decimal(out)*OUTPUT_USD_PER_M)/Decimal(1000000)
        self.observed+=actual
        need(inp<=MAX_INPUT_TOKENS and out<=MAX_OUTPUT_TOKENS,
             "350_TOKEN_CAP_VIOLATED")
        need(self.observed<=MAX_USD,"350_OBSERVED_COST_CAP_VIOLATED")
        return actual

def response_once(*,client:Any,owned_input:list,budget:Budget,
                  externally_authenticated_oneuse_lease:bool=False):
    need(externally_authenticated_oneuse_lease is True,
         "350_EXTERNAL_DURABLE_ONEUSE_LEASE_NOT_VERIFIED")
    need(type(owned_input) is list and len(owned_input)>0,
         "350_EMPTY_OR_UNOWNED_MODEL_INPUT")
    need(type(budget) is Budget,"350_BUDGET_NOT_EXACT_TYPE")
    # Reserve before call, even if request fails. Never retry.
    budget.reserve()
    digest=fingerprint(owned_input)
    response=client.responses.create(
       model=MODEL,input=owned_input,max_output_tokens=MAX_OUTPUT_TOKENS,
       truncation="disabled",store=False)
    need(getattr(response,"model",None) in (MODEL,MODEL.replace("-2025-04-14","")),
         "350_PROVIDER_MODEL_MISMATCH")
    cost=budget.reconcile(getattr(response,"usage",None))
    need(fingerprint(owned_input)==digest,"350_CALLER_OWNED_INPUT_MUTATED")
    return {"response":response,"input_sha256":digest,"model":MODEL,
            "call_number":budget.used,"observed_usd":str(cost),
            "aggregate_observed_usd":str(budget.observed),
            "aggregate_reserved_usd":str(budget.reserved),
            "official_native_scorer_invoked":False,
            "independent_ab_completed":False}
