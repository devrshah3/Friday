"""PIN authorization: grants, brute-force lockout, and channels that must not approve."""
import asyncio
import json
import logging
import os
import time
import types
from pathlib import Path
from unittest.mock import MagicMock

os.environ["JARVIS_REGEN_PIN"] = "false"

import pytest

from jarvis import mcp_server
from jarvis.agent.executor import AgentExecutor
from jarvis.agent.tools_schema import TOOL_REGISTRY, TOOL_SCHEMAS
from jarvis.channels import imessage, telegram
from jarvis.config import settings
from jarvis.core import authz, pending_actions, permissions, tracing
from jarvis.core import secrets as secret_store
from jarvis.core.confirmation import confirmed_scope
from jarvis.core.permissions import TOOL_PERMISSIONS, RiskLevel, assess_tool_call
from jarvis.tools import filesystem
from jarvis.voice.confirm import run_voice_confirmation

PIN = "2468"


def _reset():
    authz.reset_state()
    authz._ui_notifiers.clear()
    authz._info_notifiers.clear()
    pending_actions._notifiers.clear()
    pending_actions._pending.clear()
    pending_actions._futures.clear()


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    store: dict[str, str] = {}
    monkeypatch.setattr(authz, "get_secret", lambda name: store.get(name, ""))
    monkeypatch.setattr(authz, "set_secret", lambda name, value: store.__setitem__(name, value))
    monkeypatch.setattr(authz, "_SCRYPT_N", 2**4)  # fast hashes; the stored string records its own cost
    clock = {"t": time.time()}
    monkeypatch.setattr(authz, "_now", lambda: clock["t"])
    docs = tmp_path / "docs"
    docs.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("FRIDAY_ALLOWED_ROOTS", str(docs))
    monkeypatch.setattr(permissions, "DB_PATH", tmp_path / "audit.db")
    traced: list[dict] = []  # trace events are captured, never written to the real log
    monkeypatch.setattr(tracing, "_write_event", lambda event, path=None: traced.append(event))

    async def no_real_process(*args, **kwargs):
        raise AssertionError(f"test tried to start a real process: {args[:1]}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", no_real_process)
    monkeypatch.delenv("JARVIS_TOOL_PERMISSION_MODE", raising=False)
    monkeypatch.delenv("JARVIS_TRUST_MODEL_CONFIRMATION", raising=False)
    _reset()
    yield types.SimpleNamespace(store=store, clock=clock, docs=docs, trace=traced)
    _reset()


def make_file(env, name="report.txt", text="hello"):
    path = env.docs / name
    path.write_text(text)
    return path


class FakeUI:
    """Stands in for the local web UI: records what it is asked to show."""

    def __init__(self):
        self.events: list[dict] = []

    async def __call__(self, payload):
        self.events.append(payload)

    @property
    def prompt(self) -> dict:
        return next(e["authorization"] for e in self.events if e["type"] == "authorization_required")


async def start_request(args, tool="trash_file", timeout_s=5.0):
    ui = FakeUI()
    authz.add_ui_notifier(ui)
    task = asyncio.create_task(authz.request_authorization(tool, args, timeout_s=timeout_s))
    for _ in range(200):
        if any(e["type"] == "authorization_required" for e in ui.events) or task.done():
            break
        await asyncio.sleep(0.01)
    return ui, task


async def finish(ui, task):
    if not task.done():
        authz.cancel_authorization(ui.prompt["id"], is_local=True)
    return await task


# ------------------------------------------------------------ the permission flag


def test_trash_file_requires_authorization():
    permission = TOOL_PERMISSIONS["trash_file"]
    assert permission.requires_authorization is True
    assert permission.risk == RiskLevel.CRITICAL


@pytest.mark.parametrize("mode", ["enforce", "audit"])
def test_authorization_cannot_be_bypassed_by_mode_confirmation_or_model_flags(monkeypatch, env, mode):
    monkeypatch.setenv("JARVIS_TOOL_PERMISSION_MODE", mode)
    monkeypatch.setenv("JARVIS_TRUST_MODEL_CONFIRMATION", "true")
    args = {"path": str(make_file(env)), "confirmed": True, "authorized": True, "authorization": "yes"}
    assert assess_tool_call("trash_file", args).allowed is False
    with confirmed_scope():  # a server-granted *confirmation* is not an authorization
        assert assess_tool_call("trash_file", args).allowed is False


def test_model_supplied_flags_do_not_change_what_is_authorized():
    assert authz.args_hash({"path": "/a"}) == authz.args_hash({"path": "/a", "authorized": True, "confirmed": True})
    assert authz.args_hash({"path": "/a"}) != authz.args_hash({"path": "/b"})


def test_new_tools_have_explicit_low_risk_entries_and_are_registered():
    for name in ("open_file", "reveal_file", "open_website"):
        permission = TOOL_PERMISSIONS[name]
        assert permission.risk == RiskLevel.LOW
        assert not permission.requires_confirmation and not permission.requires_authorization
    schema_names = {schema["name"] for schema in TOOL_SCHEMAS}
    for name in ("trash_file", "reveal_file", "open_website"):
        assert name in TOOL_REGISTRY and name in schema_names and name in TOOL_PERMISSIONS


def test_mcp_never_exposes_authorization_tools():
    assert "trash_file" not in mcp_server.exposed_tools(extra="trash_file")


# ------------------------------------------------------------------ PIN storage


def test_only_a_salted_scrypt_hash_is_stored(env):
    authz.set_pin(PIN)
    first = env.store[authz.PIN_SECRET_NAME]
    assert first.startswith("scrypt$") and first != PIN
    assert authz._verify_against(PIN, first) is True
    assert authz._verify_against("1357", first) is False
    authz.set_pin(PIN)
    assert env.store[authz.PIN_SECRET_NAME] != first  # fresh salt every time


@pytest.mark.parametrize("bad", ["12", "abcd", "123456789", "12 34", "", "١٢٣٤"])
def test_set_pin_rejects_malformed_pins(bad):
    with pytest.raises(authz.AuthzError):
        authz.set_pin(bad)


def test_pin_secret_is_private(monkeypatch):
    assert authz.PIN_SECRET_NAME in secret_store.PRIVATE_SECRETS
    assert authz.PIN_SECRET_NAME not in secret_store.SUPPORTED_SECRETS  # not settable from the settings API
    monkeypatch.setattr(secret_store, "_load_keyring", lambda: None)
    monkeypatch.setenv(authz.PIN_SECRET_NAME, "attacker-chosen-hash")
    assert secret_store.get_secret(authz.PIN_SECRET_NAME) == ""  # the environment cannot override it


def test_set_pin_cli_refuses_remote_shells(monkeypatch, capsys):
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.2 5000 10.0.0.1 22")
    assert authz.main(["set-pin"]) == 2
    assert "SSH" in capsys.readouterr().err


# --------------------------------------------------------------------- the grant


async def test_correct_pin_issues_a_grant_bound_to_the_exact_call(env):
    authz.set_pin(PIN)
    target = make_file(env)
    args = {"path": str(target)}
    ui, task = await start_request(args)
    summary = ui.prompt["summary"]
    assert str(target.resolve()) in summary and "5.0 B" in summary  # full resolved path and size
    assert authz.submit_pin(ui.prompt["id"], PIN, is_local=True).ok is True
    outcome = await task
    assert outcome.granted and outcome.grant.tool_name == "trash_file"
    with authz.authorized_scope(outcome.grant):
        assert assess_tool_call("trash_file", args).allowed is True
        assert authz.consume_grant("trash_file", args) == ""


async def test_wrong_pin_fails_and_logs_without_the_pin(env, caplog):
    caplog.set_level(logging.DEBUG, logger="jarvis.authz")
    authz.set_pin(PIN)
    ui, task = await start_request({"path": str(make_file(env))})
    action_id = ui.prompt["id"]
    result = authz.submit_pin(action_id, "wrongpin", is_local=True)
    assert result.ok is False and result.attempts_left == 2 and not task.done()
    assert pending_actions.get_authorization(action_id) is not None  # still waiting; nothing was released
    assert (await finish(ui, task)).granted is False
    logged = caplog.text.replace(action_id, "")
    assert "failures=1/3" in logged
    assert "wrongpin" not in logged and PIN not in logged
    attempts = [e for e in env.trace if e.get("event") == "authz.attempt" or e.get("name") == "authz.attempt"]
    assert attempts, "the attempt should be traced"
    assert "wrongpin" not in json.dumps(env.trace, default=str)  # traces carry outcomes, never the PIN


async def test_expired_grant_fails(env):
    authz.set_pin(PIN)
    args = {"path": str(make_file(env))}
    ui, task = await start_request(args)
    authz.submit_pin(ui.prompt["id"], PIN, is_local=True)
    outcome = await task
    env.clock["t"] += authz.GRANT_TTL_S + 1
    with authz.authorized_scope(outcome.grant):
        assert "expired" in authz.consume_grant("trash_file", args)
        assert assess_tool_call("trash_file", args).allowed is False


async def test_replayed_grant_fails(env):
    authz.set_pin(PIN)
    args = {"path": str(make_file(env))}
    ui, task = await start_request(args)
    authz.submit_pin(ui.prompt["id"], PIN, is_local=True)
    outcome = await task
    with authz.authorized_scope(outcome.grant):
        assert authz.consume_grant("trash_file", args) == ""
        assert "already used" in authz.consume_grant("trash_file", args)
        assert assess_tool_call("trash_file", args).allowed is False


async def test_grant_for_different_arguments_fails(env):
    authz.set_pin(PIN)
    approved = make_file(env, "approved.txt")
    other = make_file(env, "other.txt")
    ui, task = await start_request({"path": str(approved)})
    authz.submit_pin(ui.prompt["id"], PIN, is_local=True)
    outcome = await task
    with authz.authorized_scope(outcome.grant):
        assert assess_tool_call("trash_file", {"path": str(other)}).allowed is False
        assert "different action" in authz.consume_grant("trash_file", {"path": str(other)})


async def test_grant_for_a_different_tool_fails(env):
    authz.set_pin(PIN)
    args = {"path": str(make_file(env))}
    ui, task = await start_request(args)
    authz.submit_pin(ui.prompt["id"], PIN, is_local=True)
    outcome = await task
    with authz.authorized_scope(outcome.grant):
        assert authz.consume_grant("move_file", args) != ""


async def test_grant_is_void_if_the_target_changes_after_the_prompt(env):
    authz.set_pin(PIN)
    target = make_file(env, text="hello")
    args = {"path": str(target)}
    ui, task = await start_request(args)
    authz.submit_pin(ui.prompt["id"], PIN, is_local=True)
    outcome = await task
    target.write_text("something quite different")  # swapped after the user saw the prompt
    with authz.authorized_scope(outcome.grant):
        assert "changed" in authz.consume_grant("trash_file", args)


def test_tool_guard_rejects_direct_calls():
    assert "needs PIN authorization" in authz.tool_guard("trash_file")


# ------------------------------------------------------------- blocked, never allowed


async def test_no_pin_set_blocks(env):
    outcome = await authz.request_authorization("trash_file", {"path": str(make_file(env))}, timeout_s=0.05)
    assert outcome.granted is False and "set-pin" in outcome.reason


async def test_no_ui_blocks(env):
    authz.set_pin(PIN)
    outcome = await authz.request_authorization("trash_file", {"path": str(make_file(env))}, timeout_s=0.05)
    assert outcome.granted is False and "No local" in outcome.reason
    assert pending_actions.list_authorizations() == []


async def test_ui_that_cannot_deliver_blocks(env):
    authz.set_pin(PIN)

    async def nobody_home(_payload):
        raise RuntimeError("no local client connected")

    authz.add_ui_notifier(nobody_home)
    outcome = await authz.request_authorization("trash_file", {"path": str(make_file(env))}, timeout_s=0.05)
    assert outcome.granted is False


async def test_timeout_blocks(env):
    authz.set_pin(PIN)
    ui, task = await start_request({"path": str(make_file(env))}, timeout_s=0.05)
    outcome = await task
    assert outcome.granted is False
    assert pending_actions.list_authorizations() == []
    assert any(e["type"] == "authorization_resolved" and e["approved"] is False for e in ui.events)


async def test_request_for_an_invalid_target_never_prompts(env):
    authz.set_pin(PIN)
    ui = FakeUI()
    authz.add_ui_notifier(ui)
    outcome = await authz.request_authorization("trash_file", {"path": str(env.docs)}, timeout_s=0.05)  # a folder
    assert outcome.granted is False and ui.events == []


async def test_pin_from_a_non_local_request_is_refused(env):
    authz.set_pin(PIN)
    ui, task = await start_request({"path": str(make_file(env))})
    assert authz.submit_pin(ui.prompt["id"], PIN, is_local=False).ok is False
    assert not task.done()
    assert authz.submit_pin(ui.prompt["id"], PIN, is_local=True).ok is True
    assert (await task).granted is True


# ------------------------------------------------------------------------ lockout


async def test_three_wrong_pins_lock_authorization_for_five_minutes(env):
    authz.set_pin(PIN)
    args = {"path": str(make_file(env))}
    ui, task = await start_request(args)
    action_id = ui.prompt["id"]
    for attempts_left in (2, 1):
        result = authz.submit_pin(action_id, "0000", is_local=True)
        assert result.attempts_left == attempts_left and not result.locked
    locked = authz.submit_pin(action_id, "0000", is_local=True)
    assert locked.locked is True
    assert (await task).granted is False  # the open prompt is denied

    # While locked even the right PIN is refused, and new requests are blocked outright.
    assert authz.submit_pin(action_id, PIN, is_local=True).locked is True
    blocked = await authz.request_authorization("trash_file", args, timeout_s=0.05)
    assert blocked.granted is False and "locked" in blocked.reason

    env.clock["t"] += authz.LOCKOUT_S + 1
    ui2, task2 = await start_request(args)
    assert authz.submit_pin(ui2.prompt["id"], PIN, is_local=True).ok is True
    assert (await task2).granted is True


async def test_a_correct_pin_resets_the_failure_count(env):
    authz.set_pin(PIN)
    args = {"path": str(make_file(env))}
    ui, task = await start_request(args)
    authz.submit_pin(ui.prompt["id"], "0000", is_local=True)
    authz.submit_pin(ui.prompt["id"], "0000", is_local=True)
    assert authz.submit_pin(ui.prompt["id"], PIN, is_local=True).ok is True
    await task
    ui2, task2 = await start_request(args)
    assert authz.submit_pin(ui2.prompt["id"], "0000", is_local=True).attempts_left == 2
    await finish(ui2, task2)


# ------------------------------------------------- channels that must not approve


async def test_pending_actions_resolve_refuses_authorizations(env):
    authz.set_pin(PIN)
    ui, task = await start_request({"path": str(make_file(env))})
    action_id = ui.prompt["id"]
    assert pending_actions.resolve(action_id, True) is False
    assert pending_actions.list_pending() == []  # invisible to channels that answer "the oldest pending"
    assert not task.done()
    await finish(ui, task)


async def test_telegram_cannot_approve(env, monkeypatch):
    monkeypatch.setattr(settings, "TELEGRAM_ALLOWED_USER_IDS", "111,222")
    calls = []

    async def runner(text):
        return "ok"

    bridge = telegram.TelegramBridge("token", runner=runner)

    async def fake_call(method, **params):
        calls.append((method, params))
        return True

    monkeypatch.setattr(bridge, "_call", fake_call)
    authz.add_info_notifier(bridge.authorization_notifier)
    authz.set_pin(PIN)
    ui, task = await start_request({"path": str(make_file(env))})
    action_id = ui.prompt["id"]

    assert [(m, p["text"]) for m, p in calls if m == "sendMessage"] == [("sendMessage", authz.NEEDS_PIN_MESSAGE)]
    assert all("reply_markup" not in p for _, p in calls)  # no approve button

    # Even the owner tapping a forged button cannot approve.
    await bridge.handle_update(
        {"update_id": 1, "callback_query": {"id": "cb", "from": {"id": 111}, "data": f"approve:{action_id}"}}
    )
    assert any(m == "answerCallbackQuery" and p["text"] == "Already handled" for m, p in calls)
    assert pending_actions.get_authorization(action_id) is not None and not task.done()
    # And the confirmation notifier ignores authorization prompts altogether.
    before = len(calls)
    await bridge.confirmation_notifier({"type": "authorization_required", "authorization": ui.prompt})
    assert len(calls) == before
    assert (await finish(ui, task)).granted is False


async def test_imessage_cannot_approve(env, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "IMESSAGE_ALLOWED_HANDLES", "+15551234567")
    sent, asked = [], []

    async def runner(text):
        asked.append(text)
        return "On it."

    async def sender(handle, text):
        sent.append((handle, text))

    bridge = imessage.IMessageBridge(runner=runner, db_path=tmp_path / "chat.db", sender=sender)
    await bridge.handle_message("+15551234567", "hi")  # makes the owner reachable
    authz.add_info_notifier(bridge.authorization_notifier)
    authz.set_pin(PIN)
    ui, task = await start_request({"path": str(make_file(env))})

    assert sent[-1][1] == imessage.REPLY_MARKER + authz.NEEDS_PIN_MESSAGE
    await bridge.handle_message("+15551234567", "yes")
    assert asked == ["hi", "yes"]  # an ordinary message, not an approval
    assert pending_actions.get_authorization(ui.prompt["id"]) is not None and not task.done()
    await finish(ui, task)


async def test_voice_cannot_approve(env):
    class Speaker:
        async def speak(self, text, **kwargs):
            return None

    class Listener:
        async def capture_reply(self, timeout=0):
            return "yes, go ahead"

    authz.set_pin(PIN)
    ui, task = await start_request({"path": str(make_file(env))})
    await run_voice_confirmation(Speaker(), Listener(), ui.prompt["id"], ui.prompt["summary"])
    assert pending_actions.get_authorization(ui.prompt["id"]) is not None and not task.done()
    await finish(ui, task)


# --------------------------------------------------------------- HTTP routes


@pytest.fixture
def client(monkeypatch, tmp_path):
    """Test client for the real app; its remote-access PIN files go to tmp_path, not the data dir."""
    from fastapi.testclient import TestClient

    from jarvis.core import auth

    monkeypatch.setattr(auth, "PIN_HASH_FILE", tmp_path / "remote-pin.hash")
    monkeypatch.setattr(auth, "PIN_SALT_FILE", tmp_path / "remote-pin.salt")
    from jarvis.core import server

    return TestClient(server.app, client=("127.0.0.1", 50000))


def test_authorize_routes_are_loopback_only(env, client):
    relayed = {"x-forwarded-for": "203.0.113.7", "x-jarvis-client": "test"}  # a tunnelled browser
    for path, body in (
        ("/tools/authorize", {"action_id": "x", "pin": PIN}),
        ("/tools/authorize/cancel", {"action_id": "x"}),
    ):
        assert client.post(path, json=body, headers=relayed).status_code in (401, 403)

    local = client.post("/tools/authorize", json={"action_id": "nope", "pin": "000000"})
    assert local.status_code == 401 and local.json()["ok"] is False
    assert "000000" not in local.text  # the PIN is never echoed back


# --------------------------------------------------------------- the executor


async def test_executor_blocks_trash_without_authorization_whatever_the_model_claims(env):
    authz.set_pin(PIN)
    target = make_file(env)
    executor = AgentExecutor(llm=MagicMock())
    result = await executor._execute_tool("trash_file", {"path": str(target), "authorized": True, "confirmed": True})
    assert "was not run" in result and target.exists()


async def test_executor_trashes_after_the_pin_and_the_grant_is_single_use(env, monkeypatch):
    authz.set_pin(PIN)
    target = make_file(env)
    monkeypatch.setattr(filesystem, "sys", types.SimpleNamespace(platform="darwin"))
    launched = []

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kwargs):
        launched.append(argv)
        Path(argv[-1]).unlink()  # what Finder would do
        return FakeProcess()

    monkeypatch.setattr(filesystem.asyncio, "create_subprocess_exec", fake_exec)

    async def typist(payload):
        if payload["type"] == "authorization_required":
            assert authz.submit_pin(payload["authorization"]["id"], PIN, is_local=True).ok

    authz.add_ui_notifier(typist)
    executor = AgentExecutor(llm=MagicMock())
    result = await executor._execute_tool("trash_file", {"path": str(target)})
    assert "Trash" in result and not target.exists()
    assert len(launched) == 1 and launched[0][-1] == str(target.resolve())

    # The same call again needs a fresh PIN; with nobody to type it, it is blocked.
    authz.remove_ui_notifier(typist)
    again = make_file(env, "report.txt")
    blocked = await executor._execute_tool("trash_file", {"path": str(again)})
    assert "was not run" in blocked and again.exists() and len(launched) == 1


# ------------------------------------------------- every path that can run a tool


async def test_registry_entry_refuses_a_direct_call(env, monkeypatch):
    """A dispatcher that looks the tool up and calls it, bypassing the executor, is refused."""
    monkeypatch.setattr(filesystem, "sys", types.SimpleNamespace(platform="darwin"))
    target = make_file(env)
    result = await TOOL_REGISTRY["trash_file"](path=str(target))
    assert "needs PIN authorization" in result and target.exists()


def test_every_authorization_tool_is_guarded_in_the_registry():
    gated = [name for name, perm in TOOL_PERMISSIONS.items() if perm.requires_authorization]
    assert "trash_file" in gated
    for name in gated:
        assert getattr(TOOL_REGISTRY[name], "__authz_guarded__", False), name


def test_only_reviewed_modules_dispatch_from_the_registry():
    """Tripwire: a new module that runs tools by name must be reviewed for authorization.

    Today only the executor runs registry tools (MCP server, jobs, workflows, the
    scheduler, routines, channels and the coordinator all go through it). The other
    entries only register or inspect tools.
    """
    root = Path(__file__).resolve().parents[1] / "jarvis"
    reviewed = {
        "agent/executor.py",       # the one place tools run: PIN flow + grant consumption
        "agent/tools_schema.py",   # defines the registry and guards authorization tools
        "agent/platform_tools.py", # reads the function's module only
        "core/mcp_client.py",      # registers third-party mcp__ tools
        "mcp_server.py",           # exposes tools but calls executor._execute_tool
    }
    users = {
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if "TOOL_REGISTRY" in path.read_text(encoding="utf-8")
    }
    assert users <= reviewed, f"unreviewed TOOL_REGISTRY users: {sorted(users - reviewed)}"


def test_validation_errors_never_echo_the_submitted_pin(env, client):
    for body in ({"action_id": "x", "pin": 135790}, {"action_id": "x", "pin": "135790" * 10}, {"pin": "135790"}):
        response = client.post("/tools/authorize", json=body)
        assert response.status_code == 422
        assert "135790" not in response.text


def test_the_pin_hash_is_unreachable_from_the_settings_api():
    from jarvis.core import settings_api

    assert authz.PIN_SECRET_NAME not in settings_api.SECRET_KEYS
    assert authz.PIN_SECRET_NAME not in settings_api.SAFE_CONFIG_KEYS
