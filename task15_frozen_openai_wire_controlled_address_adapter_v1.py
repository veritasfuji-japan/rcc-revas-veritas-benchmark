"""Single-attempt injected wire seam; native codecs, no credentials or retries.

Only the trusted #219 trajectory supplies the owned request and query phases.
A wire message/hash is evidence of preservation, never execution authority.
"""
from __future__ import annotations
import copy
import json
from threading import RLock
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID, create_completion_once
from task15_native_address_request_profile_issuance_v1 import canonical, sha
from task15_prospective_controlled_address_trajectory_v1 import SYSTEM_MESSAGE

RULE = "TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_ADDRESS_ADAPTER_V1"

class AddressWireViolation(RuntimeError):
    pass

def require(condition, reason):
    if not condition:
        raise AddressWireViolation(reason)

def strict_arguments(raw):
    require(type(raw) is str, "JSON_ARGUMENT_STRING_REQUIRED")
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(value):
        raise AddressWireViolation("NONFINITE_JSON_PROHIBITED")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    require(type(value) is dict, "ARGUMENT_OBJECT_REQUIRED")
    canonical(value)
    return value

class Task15FrozenAddressWireElement:
    """Bounded common prefix then exactly A/B terminal continuations.

    The injected client is owned configuration, not a provider authorization.
    Offline proof injects only a recording fake. No SDK client is constructed.
    A failed or cancelled attempt permanently closes this local seam.
    """
    def __init__(self, *, client, original_request):
        require(type(original_request) is str and bool(original_request), "OWNED_REQUEST_REQUIRED")
        self.client = client
        self._request = original_request
        self._identity = None
        self._tools = None
        self._phases = []
        self._closed = False
        self._lock = RLock()
        self.journal = []

    def query(self, query, runtime, env, messages=(), extra_args=None):
        from agentdojo.agent_pipeline.llms.openai_llm import (
            _message_to_openai, _function_to_openai, _openai_to_assistant_message,
        )
        with self._lock:
            require(not self._closed, "CLOSED_WIRE_CANNOT_RETRY")
            # Close before any validation or injected call, including cancellation.
            self._closed = True
            try:
                require(query == self._request and type(extra_args) is dict and
                        set(extra_args) == {"task15_phase", "generation_ordinal"}, "OWNED_QUERY_CONTEXT_REQUIRED")
                phase, ordinal = extra_args["task15_phase"], extra_args["generation_ordinal"]
                require(type(ordinal) is int and ordinal >= 0, "GENERATION_ORDINAL_REQUIRED")
                common = self._phases.count("COMMON_PREFIX")
                if phase == "COMMON_PREFIX":
                    require(common == len(self._phases) and ordinal == common and common < 8, "COMMON_QUERY_ORDER_REQUIRED")
                else:
                    expected = "CONTINUATION_A" if len(self._phases) == common else "CONTINUATION_B"
                    require(phase == expected and phase in {"CONTINUATION_A", "CONTINUATION_B"} and
                            phase not in self._phases and common > 0 and ordinal == common, "CONTINUATION_ORDER_REQUIRED")
                require(len(messages) >= 2 and messages[0] == {"role": "system", "content": [{"type": "text", "content": SYSTEM_MESSAGE}]} and
                        messages[1] == {"role": "user", "content": [{"type": "text", "content": self._request}]}, "OWNED_INITIAL_MESSAGES_REQUIRED")
                require(all(m["role"] != "system" for m in messages[1:]), "EXTRA_SYSTEM_MESSAGE_PROHIBITED")
                identity = sha(jsonable(messages[:2]))
                require(self._identity is None or self._identity == identity, "OWNED_REQUEST_CHANGED")
                wire_messages = [_message_to_openai(m, MODEL_ID) for m in messages]
                tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
                tool_identity = sha(tools)
                require(self._tools is None or self._tools == tool_identity, "NATIVE_TOOL_SCHEMAS_CHANGED")
                require(wire_messages[:2] == [
                    {"role": "developer", "content": [{"type": "text", "text": SYSTEM_MESSAGE}]},
                    {"role": "user", "content": [{"type": "text", "text": self._request}]}], "OWNED_WIRE_MESSAGES_CHANGED")
                before = sha({"messages": wire_messages, "tools": tools})
                self._identity, self._tools = identity, tool_identity
                self._phases.append(phase)
                attempt = {"sequence": len(self.journal), "phase": phase, "ordinal": ordinal,
                           "owned_messages_sha256": identity, "native_tools_sha256": tool_identity,
                           "wire_request_sha256": before, "wire_messages": copy.deepcopy(wire_messages),
                           "status": "ATTEMPTED"}
                self.journal.append(attempt)
                completion = create_completion_once(client=self.client, messages=wire_messages, tools=tools)
                require(sha({"messages": wire_messages, "tools": tools}) == before, "TRANSPORT_MUTATED_REQUEST")
                require(len(completion.choices) == 1, "SINGLE_CHOICE_REQUIRED")
                message = completion.choices[0].message
                require(message.role == "assistant" and (message.content is None or type(message.content) is str)
                        and not getattr(message, "refusal", None), "ASSISTANT_RESPONSE_REQUIRED")
                calls = message.tool_calls
                require(calls is None or (type(calls) is list and len(calls) <= 1), "SINGLE_FUNCTION_CALL_REQUIRED")
                if calls:
                    call = calls[0]
                    require(call.type == "function" and call.function.name in runtime.functions and
                            type(call.id) is str and 0 < len(call.id) <= 200 and call.id.isascii() and call.id.isprintable(), "NATIVE_FUNCTION_ID_REQUIRED")
                    arguments = strict_arguments(call.function.arguments)
                output = _openai_to_assistant_message(message)
                if calls:
                    require(canonical(output["tool_calls"][0].args) == canonical(arguments), "NATIVE_CODEC_ARGUMENT_DIVERGENCE")
                attempt.update(status="RESPONSE_DECODED", response_sha256=sha(jsonable(output)))
                if phase != "CONTINUATION_B":
                    self._closed = False
                return query, runtime, env, [*messages, output], extra_args
            except BaseException:
                # Includes KeyboardInterrupt/cancellation; never retries automatically.
                if self.journal and self.journal[-1]["status"] == "ATTEMPTED":
                    self.journal[-1]["status"] = "FAILED_OR_CANCELLED"
                raise
