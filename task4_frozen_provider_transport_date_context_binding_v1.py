"""Injected transport seam; no client creation, credentials, authorization or retry.

Only the trusted #209 trajectory may supply the initial owned metadata/history.
A date string observed on this seam does not independently confer authority.
Native codecs are reused, but their retrying request helper is not invoked.
"""
from __future__ import annotations
import copy
from datetime import date
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable, sha_json
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID, create_completion_once
from task4_trusted_execution_date_profile_v1 import REQUEST

RULE = "TASK4_FROZEN_PROVIDER_TRANSPORT_DATE_CONTEXT_BINDING_V1"
PREFIX = "Task4 trusted runtime metadata: UTC execution date "

class TransportBindingViolation(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise TransportBindingViolation(reason)


class Task4FrozenTransportElement:
    """AgentDojo query seam, scoped to one bounded trajectory.

    Caller owns the date provenance. This seam preserves and records it; the
    unchanged date runner remains the authority verifier. Injected client calls
    are not real-provider authorization. Offline proof uses a recording fake.
    """
    def __init__(self, *, client):
        self.client = client
        self.journal = []
        self._metadata = None
        self._phases = []
        self._failed = False

    def query(self, query, runtime, env, messages=(), extra_args=None):
        from agentdojo.agent_pipeline.llms.openai_llm import (
            _message_to_openai, _function_to_openai, _openai_to_assistant_message,
        )
        require(not self._failed, "FAILED_TRANSPORT_CANNOT_RETRY")
        try:
            require(query == REQUEST and extra_args is not None, "TASK4_REQUEST_REQUIRED")
            phase = extra_args.get("task4_phase")
            ordinal = extra_args.get("generation_ordinal")
            require(type(ordinal) is int and ordinal >= 0, "GENERATION_ORDINAL_REQUIRED")
            if phase == "COMMON_PREFIX":
                require(not any(p != "COMMON_PREFIX" for p in self._phases) and
                        ordinal == len(self._phases) and ordinal < 8, "COMMON_QUERY_ORDER_REQUIRED")
            elif phase in {"CONTINUATION_A", "CONTINUATION_B"}:
                expected = "CONTINUATION_B" if "CONTINUATION_A" in self._phases else "CONTINUATION_A"
                require(phase == expected and phase not in self._phases and bool(self._phases) and
                        ordinal == self._phases.count("COMMON_PREFIX"), "CONTINUATION_ORDER_REQUIRED")
            else:
                raise TransportBindingViolation("BOUNDED_PHASE_REQUIRED")
            require(len(messages) >= 2 and messages[0]["role"] == "system" and
                    messages[1]["role"] == "user", "OWNED_METADATA_AND_REQUEST_REQUIRED")
            blocks = messages[0]["content"]
            require(len(blocks) == 1 and blocks[0]["type"] == "text", "OWNED_METADATA_PROFILE_REQUIRED")
            metadata = blocks[0]["content"]
            require(isinstance(metadata, str) and metadata.startswith(PREFIX) and metadata.endswith("."),
                    "OWNED_METADATA_PROFILE_REQUIRED")
            execution_date = metadata[len(PREFIX):-1]
            require(date.fromisoformat(execution_date).isoformat() == execution_date,
                    "CANONICAL_DATE_REQUIRED")
            require(messages[1]["content"] == [{"type": "text", "content": REQUEST}],
                    "EXACT_REQUEST_REQUIRED")
            identity = sha_json(jsonable(messages[:2]))
            require(self._metadata is None or self._metadata == identity, "OWNED_METADATA_CHANGED")
            require(all(m["role"] != "system" for m in messages[1:]), "EXTRA_SYSTEM_MESSAGE_PROHIBITED")
            self._metadata = identity
            wire_messages = [_message_to_openai(m, MODEL_ID) for m in messages]
            tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
            require(wire_messages[0] == {"role": "developer", "content": [{"type": "text", "text": metadata}]},
                    "NATIVE_WIRE_METADATA_CHANGED")
            before = sha_json({"messages": wire_messages, "tools": tools})
            self._phases.append(phase)  # Consume attempt before entering transport.
            completion = create_completion_once(client=self.client, messages=wire_messages, tools=tools)
            require(sha_json({"messages": wire_messages, "tools": tools}) == before,
                    "TRANSPORT_MUTATED_REQUEST")
            require(len(completion.choices) == 1 and completion.choices[0].message.role == "assistant",
                    "SINGLE_ASSISTANT_CHOICE_REQUIRED")
            output = _openai_to_assistant_message(completion.choices[0].message)
            self.journal.append({"sequence": len(self.journal), "phase": phase, "ordinal": ordinal,
                                 "execution_date": execution_date, "owned_metadata_sha256": identity,
                                 "wire_request_sha256": before, "wire_messages": copy.deepcopy(wire_messages),
                                 "response_candidate_sha256": sha_json(jsonable(output))})
            return query, runtime, env, [*messages, output], extra_args
        except Exception:
            self._failed = True
            raise
