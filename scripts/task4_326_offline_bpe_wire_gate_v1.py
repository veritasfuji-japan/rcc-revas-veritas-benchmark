#!/usr/bin/env python3
"""#326: actual SDK JSON with a pinned local BPE + UTF-8 full-body deny gate.

This gate is exercised ONLY inside a local httpx.MockTransport. Both checks
are over client-side bytes, not the Provider's private chat/tool accounting:
a passing local count NEVER authorizes a real model POST or paid usage.

Central invariant: oversized or unknown wire request MUST fail closed BEFORE
the synthetic assistant reply and native effect can be produced.
"""
from __future__ import annotations
import copy
from importlib.metadata import version
import json
import os
from pathlib import Path
import threading

from scripts import task4_325_exact_sdk_wire_offline_v1 as parent
from scripts import task4_320_local_sdk_complete_native_v1 as base
from unittest.mock import patch

RULE="TASK4_326_OFFLINE_LOCAL_BPE_UTF8_WIRE_DENY_V1"
PARENT_MAIN="5b32fee871bf8b445fa03b5ee91c453d5fc485b8"
EXPECTED_TIKTOKEN_VERSION="0.12.0"
ENCODING_NAME="o200k_base"
MODEL=parent.MODEL
CAP_OUTPUT=parent.OUTPUT_CAP
# All request bytes include model, messages, tool schema, headers excluded.
# This is a strict conservative local wire SIZE policy (<=10k UTF8 bytes).
# It is NOT an upper bound on server-billed input tokens.
MAX_JSON_UTF8_BYTES=10_000
MAX_LOCAL_BPE_TOKENS=10_000
MAX_LOCAL_BPE_SUM=100_000
MAX_PER_ARM=5
MAX_BOTH_ARMS=10
ROOT=Path(__file__).resolve().parents[1]

class Denied(ValueError):pass

def need(x,reason):
    if not x:raise Denied(reason)

def tiktoken_encoder():
    need(version("tiktoken")==EXPECTED_TIKTOKEN_VERSION,
         "PINNED_LOCAL_BPE_PACKAGE_REQUIRED")
    import tiktoken
    enc=tiktoken.get_encoding(ENCODING_NAME)
    need(enc.name==ENCODING_NAME,"PINNED_LOCAL_ENCODING_REQUIRED")
    need(tiktoken.encoding_for_model(MODEL).name==ENCODING_NAME,
         "PINNED_MODEL_ENCODING_MAPPING_REQUIRED")
    return enc

class OfflineWireBudget:
    """Independent per-arm gate; no approval and no durable cross-run ledger.

    Receipt is issued BEFORE the local mock response. Replaying a request,
    failure to tokenize, bad encoding, unknown JSON or budget overflow freezes
    the session. Calls cannot be recovered following ambiguous failure.
    """
    def __init__(self,arm,encoder=None, *, max_bytes=MAX_JSON_UTF8_BYTES,
                 max_local_bpe=MAX_LOCAL_BPE_TOKENS):
        need(arm in ("A","B"),"ARM_REQUIRED")
        need(type(max_bytes) is int and 1<=max_bytes<=MAX_JSON_UTF8_BYTES and
             type(max_local_bpe) is int and 1<=max_local_bpe<=MAX_LOCAL_BPE_TOKENS,
             "STRICT_POLICY_NOT_RELAXABLE")
        self.arm=arm
        self.encoder=encoder if encoder is not None else tiktoken_encoder()
        need(getattr(self.encoder,"name",None)==ENCODING_NAME,"INVALID_ENCODING")
        self.max_bytes=max_bytes
        self.max_local_bpe=max_local_bpe
        self.entries=[]
        self.closed=False
        self._lock=threading.Lock()
        self._previous="0"*64
        self._bpe_total=0
        self._seen_request_hashes=set()

    def inspect(self,request):
        with self._lock:
            need(not self.closed,"SESSION_ALREADY_CLOSED_AFTER_UNKNOWN_OR_DENIAL")
            # Deny-on-any-error; do not rely on later fake responder executing.
            try:
                need(len(self.entries)<MAX_PER_ARM,"ARM_REQUEST_COUNT_EXHAUSTED")
                need(request.method=="POST" and
                     request.url.scheme=="https" and
                     request.url.host=="api.openai.com" and
                     request.url.path=="/v1/chat/completions" and
                     not request.url.query,
                     "UNEXPECTED_PROVIDER_SHAPED_ENDPOINT")
                need(request.headers.get("authorization")==
                     "Bearer "+base.LOCAL_KEY and
                     request.headers.get("content-type","").startswith("application/json"),
                     "LOCAL_FAKE_AUTH_ONLY")
                raw=request.content
                need(type(raw) is bytes and 0<len(raw)<=self.max_bytes,
                     "RAW_HTTP_BODY_EXCEEDS_LOCAL_BYTE_GATE")
                data=json.loads(raw.decode("utf-8"),object_pairs_hook=parent.unique)
                need(type(data) is dict and set(data)==parent.ALLOWED_WIRE_FIELDS,
                     "UNKNOWN_OR_MISSING_WIRE_FIELDS")
                need(data["model"]==MODEL and
                     type(data["max_completion_tokens"]) is int and
                     data["max_completion_tokens"]==CAP_OUTPUT and
                     data["tool_choice"]=="auto" and data["temperature"]==0.0 and
                     type(data["messages"]) is list and
                     type(data["tools"]) is list,
                     "OUTPUT_CAP_OR_MODEL_OR_TASK_TOOLS_NOT_PINNED")
                raw_sha=parent.hash_bytes(raw)
                need(raw_sha not in self._seen_request_hashes,
                     "DUPLICATE_RAW_WIRE_REQUEST_REPLAY_DENIED")
                # This local BPE count includes actual wire JSON representation.
                # The Provider's own message/tool framing and usage can differ.
                text=raw.decode("utf-8",errors="strict")
                local_bpe=len(self.encoder.encode(text,disallowed_special=()))
                need(type(local_bpe) is int and
                     0<local_bpe<=self.max_local_bpe and
                     self._bpe_total+local_bpe<=MAX_LOCAL_BPE_SUM,
                     "LOCAL_BPE_TOKEN_POLICY_EXCEEDED")
                ordinal=len(self.entries)
                row={
                  "arm":self.arm,"ordinal":ordinal,
                  "raw_sdk_http_body_sha256":raw_sha,
                  "raw_sdk_json_utf8_bytes":len(raw),
                  "local_json_bpe_tokens_not_provider_usage":local_bpe,
                  "whole_arm_local_bpe_after":self._bpe_total+local_bpe,
                  "output_cap_on_sdk_request":CAP_OUTPUT,
                  "encoding":ENCODING_NAME,
                  "tiktoken_version":EXPECTED_TIKTOKEN_VERSION,
                  "raw_body_utf8":text,
                  "previous_receipt_sha256":self._previous,
                  "true_provider_input_tokens_bound_proven":False,
                  "real_provider_post_allowed":False,
                }
                row["receipt_sha256"]=parent.hash_bytes(parent.canonical(row))
                self.entries.append(row)
                self._seen_request_hashes.add(raw_sha)
                self._previous=row["receipt_sha256"]
                self._bpe_total+=local_bpe
                return data
            except Exception:
                self.closed=True
                raise

    def simulated_unknown(self):
        with self._lock:
            self.closed=True

    @property
    def live_send_allowed(self):
        return False

class OfflineCappedMock(parent.GuardedMock):
    """Two independent local script sources, with early byte/BPE refusal."""
    instances=[]
    def __init__(self,arm):
        super().__init__(arm)
        self.byte_bpe_gate=OfflineWireBudget(arm)
        OfflineCappedMock.instances.append(self)

    def __call__(self,request):
        self.byte_bpe_gate.inspect(request)  # before fake responder
        return super().__call__(request)

def run_two_sources():
    base.reject_live_context()
    need(not any(os.environ.get(k) for k in base.SENSITIVE),
         "NO_PROVIDER_SECRETS")
    encoder=tiktoken_encoder()
    OfflineCappedMock.instances=[]
    rows=[]
    # Reuse #325's real SDK + MockTransport + native/single scorer path.
    for arm in ("A","B"):
        with patch.object(parent,"GuardedMock",OfflineCappedMock):
            # Parent run_both_sources owns the full two-arm test; we run it ONCE.
            if arm=="A":
                all_native=parent.run_both_sources()
        # All two independent sources were created inside first invocation.
        if arm=="A":
            all_guards=OfflineCappedMock.instances[:]
        saved=next(x for x in all_native if x["arm"]==arm)
        server=next(x for x in all_guards if x.origin_arm==arm)
        need(len(server.byte_bpe_gate.entries)==len(saved["wire_proof"])==4
             and server.byte_bpe_gate.live_send_allowed is False,
             "ALL_FOUR_ACTUAL_SDK_POSTS_MUST_PASS_OFFLINE_BYTE_BPE")
        rows.append({
            "arm":arm,
            "original_325_native_wire_row":copy.deepcopy(saved),
            "early_local_budget_receipts":copy.deepcopy(server.byte_bpe_gate.entries),
            "no_network_provider_calls":0,
            "authoritative_provider_token_count":False,
            "real_send_allowed":False
        })
    need(len(OfflineCappedMock.instances)==2,"EXACT_TWO_SOURCE_INSTANCES")
    return rows
