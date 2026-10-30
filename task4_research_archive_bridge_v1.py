"""Closed research deployment: variable Native histories and real AEAD custody.

The explicit receiver is trusted local test infrastructure. No Provider client,
credential loader, live admission, role installation or permission is supplied.
Reuse the existing raw envelope, framing and response-ID guards without changing
their frozen profiles. This is not the fixed four-step issuer's deployment.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sqlite3

from task4_research_experiment_profile_v1 import Task4ResearchProfile, canonical, digest
from task4_research_case_runner_v1 import LocalArmRecord, LocalModelTurn
from scripts import task4_provider_shaped_raw_ingress_v1 as raw
from scripts.task4_native_response_framing_guard_v1 import require_framing
from scripts.task4_native_response_id_guard_v1 import require_one_id

DOMAIN = b"TASK4_LOCAL_RESEARCH_ARCHIVE_JOIN_V1\0"


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def seed_request(profile, suite):
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai
    from task4_trusted_execution_date_profile_v1 import REQUEST
    return dict(model=profile.model_id, messages=[
        dict(role="developer", content=[dict(type="text", text=
             "Task4 trusted runtime metadata: UTC execution date " + profile.task_date + ".")]),
        dict(role="user", content=[dict(type="text", text=REQUEST)])],
        tools=[_function_to_openai(t) for t in FunctionsRuntime(list(suite.tools)).functions.values()],
        tool_choice="auto", temperature=0.0, max_completion_tokens=profile.output_token_cap)


def parse_archived_wire(wire, completion, model):
    """Parse only AFTER seal; retain duplicate headers until ID validation."""
    need(completion == "eof", "INCOMPLETE_ARCHIVED_HTTP")
    require_framing(wire)
    head, _, body = wire.partition(b"\r\n\r\n")
    headers = []
    for row in head.split(b"\r\n")[1:]:
        name, _, value = row.partition(b":")
        need(value.startswith(b" "), "CANONICAL_HEADER_VALUE_REQUIRED")
        headers.append((name.decode("ascii"), value[1:].decode("ascii")))
    request_id = require_one_id(headers)["request_id"]
    value = raw.strict(body)
    need(type(value) is dict and value.get("object") == "chat.completion"
         and value.get("model") == model and type(value.get("id")) is str
         and 0 < len(value["id"]) <= 256 and type(value.get("choices")) is list
         and len(value["choices"]) == 1, "RESEARCH_COMPLETION_SHAPE")
    choice = value["choices"][0]
    need(type(choice) is dict and type(choice.get("index")) is int and choice["index"] == 0
         and type(choice.get("finish_reason")) is str
         and type(choice.get("message")) is dict, "RESEARCH_CHOICE_SHAPE")
    message = choice["message"]
    need(message.get("role") == "assistant" and set(message) <= {
             "role", "content", "tool_calls", "refusal", "annotations", "audio", "function_call"}
         and all(message.get(k) is None for k in ("refusal", "audio", "function_call"))
         and message.get("annotations") in (None, [])
         and (message.get("content") is None or type(message["content"]) is str),
         "RESEARCH_ASSISTANT_SHAPE")
    calls = message.get("tool_calls")
    need(calls is None or type(calls) is list, "RESEARCH_CALLS_SHAPE")
    for call in calls or []:
        need(type(call) is dict and set(call) == {"id", "type", "function"}
             and call["type"] == "function" and type(call["id"]) is str and call["id"]
             and type(call["function"]) is dict and set(call["function"]) == {"name", "arguments"}
             and type(call["function"]["name"]) is str
             and type(call["function"]["arguments"]) is str
             and type(raw.strict(call["function"]["arguments"])) is dict, "RESEARCH_CALL_SHAPE")
    return body, value, request_id


def native_turn(value):
    from openai.types.chat import ChatCompletionMessage
    from agentdojo.agent_pipeline.llms.openai_llm import _openai_to_assistant_message
    choice = value["choices"][0]
    message = ChatCompletionMessage.model_validate(choice["message"])
    return LocalModelTurn(_openai_to_assistant_message(message), choice["finish_reason"])


class ResearchArchiveCustody:
    """Trusted local custody with retained per-arm attempts and original sealing.

    Caller provisions the fixed profile, Native seed, recipient and signing key.
    Receiver is injected explicitly; no network fallback or inference authority.
    SQLite protects this retained directory, not replacement/reset by its owner.
    """
    def __init__(self, *, base, profile, initial_request, signer, receive, create=False):
        need(type(profile) is Task4ResearchProfile, "EXACT_RESEARCH_PROFILE")
        self.base, self.profile = Path(base), profile
        self.seed, self.signer, self.receive = deepcopy(initial_request), signer, receive
        self.file = self.base / "custody/research-attempts.sqlite3"
        need(callable(receive), "EXPLICIT_LOCAL_RECEIVER")
        need(self.seed["model"] == profile.model_id and self.seed["max_completion_tokens"] == profile.output_token_cap,
             "SEED_PROFILE_JOIN")
        self.enrollment = dict(profile_sha256=profile.identity, seed_sha256=digest(self.seed),
            recipient_sha256=sha((self.base / "public/recipient.pub").read_bytes()),
            signer_public=signer.public_key().public_bytes_raw().hex())
        if create:
            fd = os.open(self.file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with self.db() as db:
                db.execute("CREATE TABLE enrollment (value TEXT)")
                db.execute("INSERT INTO enrollment VALUES (?)", (canonical(self.enrollment),))
                db.execute("CREATE TABLE arms (arm TEXT PRIMARY KEY, ordinal INTEGER, total INTEGER, state TEXT, history TEXT, parent TEXT)")
                db.execute("CREATE TABLE attempts (arm TEXT, ordinal INTEGER, request TEXT, state TEXT, receipt TEXT, observation TEXT, PRIMARY KEY(arm,ordinal))")
                for arm in ("A", "B"):
                    db.execute("INSERT INTO arms VALUES (?,0,0,'READY',?,NULL)", (arm, canonical(self.seed["messages"])))
            fd = os.open(self.file.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        with self.db() as db:
            need(db.execute("PRAGMA quick_check").fetchall() == [("ok",)]
                 and db.execute("SELECT value FROM enrollment").fetchall() == [(canonical(self.enrollment),)],
                 "RETAINED_RESEARCH_ENROLLMENT")

    def db(self):
        need(self.file.is_file() and not self.file.is_symlink()
             and self.file.stat().st_uid == os.geteuid()
             and self.file.stat().st_mode & 0o777 == 0o600, "RETAINED_RESEARCH_DB")
        db = sqlite3.connect(self.file.resolve().as_uri() + "?mode=rw", uri=True)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def exchange(self, arm, request, parent=None):
        need(arm in ("A", "B"), "RESEARCH_ARM")
        encoded = canonical(request)
        wire = encoded.encode("utf8")
        need(canonical({k: v for k, v in request.items() if k != "messages"})
             == canonical({k: v for k, v in self.seed.items() if k != "messages"}), "RESEARCH_FIXED_PARAMETERS")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            ordinal, total, state, history, expected_parent = db.execute("SELECT ordinal,total,state,history,parent FROM arms WHERE arm=?", (arm,)).fetchone()
            need(state == "READY" and request["messages"] == raw.strict(history), "RESEARCH_PENDING_OR_HISTORY_CHANGED")
            need(parent == expected_parent, "SIGNED_RESEARCH_PARENT_REQUIRED")
            need(ordinal < self.profile.max_requests_per_arm and len(wire) <= self.profile.max_request_bytes
                 and total + len(wire) <= self.profile.max_total_request_bytes_per_arm, "RESEARCH_BUDGET")
            db.execute("INSERT INTO attempts VALUES (?,?,?,'UNKNOWN',NULL,NULL)", (arm, ordinal, encoded))
            db.execute("UPDATE arms SET ordinal=?,total=?,state='PENDING' WHERE arm=?", (ordinal + 1, total + len(wire), arm))
        # Commit the attempt before entering the receiver. Failure never rolls it back.
        op = arm + str(ordinal)
        wire_response, completion = self.receive(wire, op)
        plan = dict(run_id=self.profile.identity, request_sha256=sha(wire),
                    recipient_sha256=self.enrollment["recipient_sha256"])
        archive = raw.seal(self.base, op, wire_response, completion, plan)
        body, value, response_id = parse_archived_wire(wire_response, completion, self.profile.model_id)
        statement = dict(profile_sha256=self.profile.identity, operation_id=op,
            request_sha256=sha(wire), response_sha256=sha(body), archive=archive,
            upstream_request_id=response_id, completion_id=value["id"],
            origin="CLOSED_LOCAL_RESEARCH_CUSTODY_NOT_PROVIDER", provider_permission=False)
        receipt = dict(statement=statement, signature=self.signer.sign(DOMAIN + canonical(statement).encode()).hex())
        with self.db() as db:
            db.execute("UPDATE attempts SET state='ARCHIVED',receipt=? WHERE arm=? AND ordinal=?",
                       (canonical(receipt), arm, ordinal))
        return dict(body=body, receipt=receipt)

    def observe(self, arm, ordinal, receipt, history, terminal=False):
        """Trusted runtime adapter supplies the actually observed history.

        This local fixture trusts its runtime; no arbitrary Python sandbox claim.
        """
        statement = dict(profile_sha256=self.profile.identity, arm=arm, ordinal=ordinal,
                         archive_receipt_sha256=digest(receipt), history_sha256=digest(history),
                         terminal=terminal, origin="TRUSTED_LOCAL_NATIVE_OBSERVER_NOT_ATTESTED_RUNTIME")
        observation = dict(statement=statement, signature=self.signer.sign(DOMAIN + canonical(statement).encode()).hex())
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,receipt FROM attempts WHERE arm=? AND ordinal=?", (arm, ordinal)).fetchone()
            state, count = db.execute("SELECT state,ordinal FROM arms WHERE arm=?", (arm,)).fetchone()
            need(row == ("ARCHIVED", canonical(receipt)) and state == "PENDING" and count == ordinal + 1,
                 "RESEARCH_OBSERVATION_ALREADY_USED_OR_UNKNOWN")
            db.execute("UPDATE attempts SET state='OBSERVED',observation=? WHERE arm=? AND ordinal=?",
                       (canonical(observation), arm, ordinal))
            db.execute("UPDATE arms SET state=?,history=?,parent=? WHERE arm=?",
                       ("TERMINAL" if terminal else "READY", canonical(history), digest(observation), arm))
        return observation


class ArchivedResearchRun:
    """Joins every released completion to Native tools and the detached scorer."""
    def __init__(self, *, runner, custody):
        need(runner.profile.identity == custody.profile.identity, "RUNNER_CUSTODY_PROFILE_JOIN")
        need(canonical(custody.seed) == canonical(seed_request(runner.profile, runner.suite)),
             "PINNED_NATIVE_SEED_PROFILE_JOIN")
        self.runner, self.custody = runner, custody

    def run_arm(self, arm):
        from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
        from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
        from task4_research_terminal_scoring_v1 import score_local_arm
        records = []

        def observe(history, terminal=False):
            previous = records[-1]
            expected = previous["request"]["messages"]
            assistant = _message_to_openai(native_turn(raw.strict(previous["body"])).message, self.runner.profile.model_id)
            addition = history[len(expected):]
            need(history[:len(expected)] == expected and addition and addition[0] == assistant,
                 "ARCHIVED_RESPONSE_NATIVE_HISTORY_JOIN")
            choice = raw.strict(previous["body"])["choices"][0]
            if choice["finish_reason"] == "stop":
                need(terminal and len(addition) == 1, "ARCHIVED_TERMINAL_JOIN")
            else:
                calls = assistant.get("tool_calls") or []
                need(choice["finish_reason"] == "tool_calls" and len(calls) == 1 and len(addition) == 2,
                     "ARCHIVED_ONE_NATIVE_TOOL_RESULT")
                tool = addition[1]
                need(tool.get("role") == "tool" and tool.get("tool_call_id") == calls[0]["id"]
                     and tool.get("name") == calls[0]["function"]["name"], "ARCHIVED_TOOL_ID_JOIN")
            previous["observation"] = self.custody.observe(arm, len(records)-1, previous["receipt"], history, terminal)
            verify_signed(self.custody.enrollment["signer_public"], previous["observation"])
            need(previous["observation"]["statement"] == dict(profile_sha256=self.runner.profile.identity,
                 arm=arm, ordinal=len(records)-1, archive_receipt_sha256=digest(previous["receipt"]),
                 history_sha256=digest(history), terminal=terminal,
                 origin="TRUSTED_LOCAL_NATIVE_OBSERVER_NOT_ATTESTED_RUNTIME"), "SIGNED_NATIVE_OBSERVATION_JOIN")
            previous["observed_history_sha256"] = digest(history)

        def generate(request):
            if records:
                observe(request["messages"])
            parent = digest(records[-1]["observation"]) if records else None
            reply = self.custody.exchange(arm, request, parent)
            verify_signed(self.custody.enrollment["signer_public"], reply["receipt"])
            statement = reply["receipt"]["statement"]
            need(statement["profile_sha256"] == self.runner.profile.identity
                 and statement["operation_id"] == arm + str(len(records))
                 and statement["request_sha256"] == digest(request)
                 and statement["response_sha256"] == sha(reply["body"])
                 and statement["origin"] == "CLOSED_LOCAL_RESEARCH_CUSTODY_NOT_PROVIDER"
                 and statement["provider_permission"] is False, "SIGNED_ARCHIVE_RELEASE_JOIN")
            records.append(dict(request=deepcopy(request), body=reply["body"], receipt=reply["receipt"]))
            return native_turn(raw.strict(reply["body"]))

        record = self.runner.run_arm(arm, generate)
        r = record.payload()
        joined = False
        if r["stop_reason"] == "TERMINAL":
            try:
                from agentdojo.functions_runtime import FunctionCall
                messages = deepcopy(r["messages"])
                for msg in messages:
                    if msg["role"] == "assistant" and msg.get("tool_calls"):
                        msg["tool_calls"] = [FunctionCall.model_validate(x) for x in msg["tool_calls"]]
                    elif msg["role"] == "tool":
                        msg["tool_call"] = FunctionCall.model_validate(msg["tool_call"])
                history = [_message_to_openai(msg, self.runner.profile.model_id) for msg in messages]
                observe(history, terminal=True)
                need(len(records) == r["model_attempts"], "ALL_NATIVE_ATTEMPTS_ARCHIVED")
                for local, archived in zip(r["steps"], records, strict=True):
                    need(local["request_sha256"] == digest(archived["request"])
                         and local["response_sha256"] == digest(jsonable(native_turn(raw.strict(archived["body"])).message)),
                         "ACTUAL_NATIVE_RECORD_ARCHIVE_JOIN")
                joined = True
            except Exception:
                # Preserve the actual Native record and attempted-arm denominator.
                # A missing/invalid final custody ACK is never a scored success.
                joined = False
        score = score_local_arm(record) if joined else dict(status="UNSCORED_INCOMPLETE", native_scorer_calls=0,
            local_utility=None, local_attack_goal_success=None, official_utility=None)
        return dict(record=record, score=score, archive_join_complete=joined,
                    records=[dict(request_sha256=digest(x["request"]), receipt=deepcopy(x["receipt"]),
                                  observation=deepcopy(x.get("observation")),
                                  observed_history_sha256=x.get("observed_history_sha256")) for x in records],
                    official_utility=None, new_measured_utility_recoveries=0,
                    provider_permission=False, production_bypass_resistance_proven=False)


def verify_signed(public_hex, receipt):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    need(type(receipt) is dict and set(receipt) == {"statement", "signature"}, "SIGNED_RESEARCH_OBJECT")
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
        bytes.fromhex(receipt["signature"]), DOMAIN + canonical(receipt["statement"]).encode())


class UnixTLSReceiver:
    """Concrete closed-local transport; AF_UNIX only, verified TLS, no fallback.

    No bearer/Provider credential. Backend belongs to a separately provisioned
    local test deployment. Peer UID and pinned leaf are checked before POST.
    Internal operation ID is kept separate from upstream response IDs.
    """
    def __init__(self, *, address, ca_file, hostname, leaf_sha256, peer_uid):
        import ssl
        self.address, self.hostname = str(address), hostname
        self.leaf_sha256, self.peer_uid = leaf_sha256, peer_uid
        self.context = ssl.create_default_context(cafile=str(ca_file))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def __call__(self, wire, op):
        import socket
        import struct
        from scripts.task4_native_total_deadline_v1 import bounded_capture
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(5)
            channel.connect(self.address)
            _, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(uid == self.peer_uid, "LOCAL_RESEARCH_BACKEND_UID")
            with self.context.wrap_socket(channel, server_hostname=self.hostname) as tls:
                need(sha(tls.getpeercert(binary_form=True)) == self.leaf_sha256, "LOCAL_RESEARCH_PINNED_TLS_LEAF")
                need(type(op) is str and op[0] in "AB" and op[1:].isdigit(), "LOCAL_RESEARCH_OPERATION_ID")
                head = ("POST /v1/chat/completions HTTP/1.1\r\nHost: " + self.hostname
                        + "\r\nContent-Type: application/json\r\nContent-Length: " + str(len(wire))
                        + "\r\nX-Client-Request-Id: " + op + "\r\nConnection: close\r\n\r\n").encode("ascii")
                tls.sendall(head + wire)
                tls.settimeout(0.7)
                response, completion, _ = bounded_capture(tls)
                return response, completion
