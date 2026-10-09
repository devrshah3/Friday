"""PIN authorization for the highest-risk tools (requires_authorization).

Confirmation (jarvis.core.confirmation) answers "does the user want this?" and
can come from the web UI, Telegram, iMessage or a spoken "yes". Authorization is
stronger: the user must type a PIN, and only in the local web UI.

Flow: the executor calls request_authorization(), which registers a pending
action of kind "authorize" (see pending_actions: no other channel can resolve
it) and asks the local UI for the PIN. submit_pin() checks it against a salted
scrypt hash held in the keyring and, on success, issues a Grant: server-side,
single-use, valid for 60 seconds, bound to the tool name, a hash of the exact
arguments and the pending action id. The executor runs the tool inside
authorized_scope(grant); assess_tool_call() and the tool itself both check it.
A model-supplied "authorized"/"confirmed" flag is never consulted.

The PIN is typed, never spoken, never sent to the model and never logged. It
can only be set from a terminal on this Mac: ``python -m jarvis.core.authz
set-pin``. No tool, route or model output can read or change it.

Lockout state is in memory: three wrong PINs lock authorization for five
minutes, and a restart clears the lock (an attacker who can restart the server
already has the machine).
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import logging
import os
import secrets as stdlib_secrets
import sys
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from jarvis.core import pending_actions
from jarvis.core.secrets import SecretStoreError, get_secret, set_secret

logger = logging.getLogger("jarvis.authz")

PIN_SECRET_NAME = "AUTHZ_PIN_HASH"
NEEDS_PIN_MESSAGE = "This needs your PIN on your Mac."

GRANT_TTL_S = 60.0
PIN_PROMPT_TIMEOUT_S = 60.0
MAX_FAILED_PINS = 3
LOCKOUT_S = 300.0
PIN_MIN_LENGTH = 4
PIN_MAX_LENGTH = 8

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024

# Flags a model may add to a tool call. They carry no authority and are removed
# before the arguments are hashed or the tool runs.
_IGNORED_FLAGS = frozenset({"confirmed", "authorized", "authorization", "pin"})

Notifier = Callable[[dict[str, Any]], Awaitable[Any]]

# The local web UI prompts for the PIN. Other channels (Telegram, iMessage,
# voice) only get an informational notice and can never answer.
_ui_notifiers: list[Notifier] = []
_info_notifiers: list[Notifier] = []


class AuthzError(RuntimeError):
    """Raised when the PIN cannot be set."""


# ---------------------------------------------------------------- PIN storage


def _valid_pin_format(pin: object) -> bool:
    return isinstance(pin, str) and pin.isascii() and pin.isdigit() and PIN_MIN_LENGTH <= len(pin) <= PIN_MAX_LENGTH


def _scrypt(pin: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        pin.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM
    )


def _hash_for_storage(pin: str) -> str:
    salt = stdlib_secrets.token_bytes(16)
    digest = _scrypt(pin, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def _verify_against(pin: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        candidate = _scrypt(pin, bytes.fromhex(salt_hex), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


def pin_is_set() -> bool:
    return bool(get_secret(PIN_SECRET_NAME))


def set_pin(new_pin: str) -> None:
    """Store a new PIN hash. Called only from the local CLI below, never from a route or tool."""
    if not _valid_pin_format(new_pin):
        raise AuthzError(f"The PIN must be {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits.")
    try:
        set_secret(PIN_SECRET_NAME, _hash_for_storage(new_pin))
    except SecretStoreError as exc:
        raise AuthzError(str(exc)) from exc


# ------------------------------------------------------------------- lockout

_failed_pins = 0
_locked_until = 0.0


def _now() -> float:
    return time.time()


def lockout_remaining() -> float:
    """Seconds until authorization unlocks (0 when it is not locked)."""
    global _failed_pins, _locked_until
    if _locked_until and _now() >= _locked_until:
        _failed_pins = 0
        _locked_until = 0.0
    return max(0.0, _locked_until - _now())


def reset_state() -> None:
    """Clear lockout, grants and open requests (tests)."""
    global _failed_pins, _locked_until
    _failed_pins = 0
    _locked_until = 0.0
    _grants.clear()
    _requests.clear()


def _locked_message(remaining: float) -> str:
    minutes = max(1, int(remaining // 60) + (1 if remaining % 60 else 0))
    return f"Authorization is locked after too many wrong PINs. Try again in about {minutes} minute(s)."


# -------------------------------------------------------------------- grants


@dataclass
class Grant:
    """A server-side, single-use permission to run exactly one authorized tool call."""

    action_id: str
    tool_name: str
    args_hash: str
    binding: str
    expires_at: float
    state: str = "valid"  # "valid" -> "used"


@dataclass(frozen=True)
class _Request:
    tool_name: str
    args_hash: str
    binding: str


_grants: dict[str, Grant] = {}
_requests: dict[str, _Request] = {}
_scope: ContextVar[Grant | None] = ContextVar("jarvis_authz_grant", default=None)


def strip_authorization_flags(tool_input: dict[str, Any]) -> dict[str, Any]:
    """Drop model-supplied authority flags from a tool call's arguments."""
    return {k: v for k, v in tool_input.items() if k not in _IGNORED_FLAGS}


def args_hash(tool_input: dict[str, Any]) -> str:
    """Hash of the exact arguments of a call (authority flags excluded)."""
    canonical = json.dumps(strip_authorization_flags(tool_input), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _prepare_trash(tool_input: dict[str, Any]) -> tuple[str, str, str]:
    from jarvis.tools.filesystem import TrashRefused, format_size, prepare_trash

    try:
        target = prepare_trash(str(tool_input.get("path", "")))
    except TrashRefused as exc:
        return str(exc), "", ""
    summary = f"Move to Trash: {target.path} ({format_size(target.size)})"
    binding = f"{target.path}|{target.size}|{target.mtime_ns}|{target.inode}"
    return "", summary, binding


# tool name -> (tool_input) -> (error, summary shown at the PIN prompt, binding).
# The binding pins what the call acts on (e.g. the resolved path and its stat),
# so a file swapped or a symlink retargeted during the prompt voids the grant.
_PREPARERS: dict[str, Callable[[dict[str, Any]], tuple[str, str, str]]] = {
    "trash_file": _prepare_trash,
}


def prepare(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, str, str]:
    preparer = _PREPARERS.get(tool_name)
    if preparer is not None:
        return preparer(tool_input)
    from jarvis.core.permissions import describe_tool_call

    return "", describe_tool_call(tool_name, tool_input), ""


def _mismatch(grant: Grant, tool_name: str, tool_input: dict[str, Any]) -> str:
    if grant.state != "valid" or _grants.get(grant.action_id) is not grant:
        return "The authorization was already used."
    if _now() > grant.expires_at:
        _grants.pop(grant.action_id, None)
        return "The authorization expired."
    if grant.tool_name != tool_name or grant.args_hash != args_hash(tool_input):
        return "The authorization was for a different action."
    return ""


@contextmanager
def authorized_scope(grant: Grant) -> Iterator[None]:
    """Run a tool call under a grant. Only the executor does this, after a PIN check."""
    token = _scope.set(grant)
    try:
        yield
    finally:
        _scope.reset(token)


def grant_problem(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Why the current scope does not authorize this call ('' if it does). Does not consume."""
    grant = _scope.get()
    if grant is None:
        return "Needs PIN authorization."
    return _mismatch(grant, tool_name, tool_input)


def consume_grant(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Use up the scoped grant for this exact call. Returns '' on success, else the reason."""
    grant = _scope.get()
    if grant is None:
        return "Needs PIN authorization."
    problem = _mismatch(grant, tool_name, tool_input)
    if not problem and grant.binding:
        _, _, current = prepare(tool_name, tool_input)
        if current != grant.binding:
            problem = "The target changed after you were asked; ask again."
    if problem:
        _grants.pop(grant.action_id, None)
        return problem
    grant.state = "used"
    _grants.pop(grant.action_id, None)
    return ""


def tool_guard(tool_name: str) -> str:
    """Tool-side check: '' only when running under a grant the executor already consumed.

    Keeps an authorization-level tool from running when called directly,
    bypassing the executor.
    """
    grant = _scope.get()
    if grant is None or grant.state != "used" or grant.tool_name != tool_name:
        return f"{tool_name} needs PIN authorization and cannot be run directly."
    return ""


# ---------------------------------------------------------------- UI channels


def add_ui_notifier(notifier: Notifier) -> None:
    """Register the channel that prompts for the PIN. Local web UI only."""
    if notifier not in _ui_notifiers:
        _ui_notifiers.append(notifier)


def remove_ui_notifier(notifier: Notifier) -> None:
    _ui_notifiers[:] = [n for n in _ui_notifiers if n != notifier]


def add_info_notifier(notifier: Notifier) -> None:
    """Register a channel (Telegram, iMessage, voice) told that a PIN is needed. It cannot answer."""
    if notifier not in _info_notifiers:
        _info_notifiers.append(notifier)


def remove_info_notifier(notifier: Notifier) -> None:
    _info_notifiers[:] = [n for n in _info_notifiers if n != notifier]


async def _send(notifiers: list[Notifier], payload: dict[str, Any]) -> bool:
    delivered = False
    for notifier in list(notifiers):
        try:
            await notifier(payload)
            delivered = True
        except Exception as exc:  # one bad channel must not hang or approve anything
            logger.warning("Authorization notifier failed: %s", exc)
    return delivered


# --------------------------------------------------------------- the PIN flow


@dataclass(frozen=True)
class AuthzResult:
    granted: bool
    reason: str = ""
    grant: Grant | None = None


async def request_authorization(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    risk: str = "critical",
    timeout_s: float = PIN_PROMPT_TIMEOUT_S,
) -> AuthzResult:
    """Ask for the PIN in the local UI. Blocked (never allowed) if it cannot be asked or answered."""
    for stale in [a for a, g in _grants.items() if _now() > g.expires_at]:
        _grants.pop(stale, None)
    if not pin_is_set():
        return AuthzResult(False, "No authorization PIN is set. Run `python -m jarvis.core.authz set-pin` in a terminal on your Mac.")
    remaining = lockout_remaining()
    if remaining > 0:
        return AuthzResult(False, _locked_message(remaining))

    tool_input = strip_authorization_flags(tool_input)
    error, summary, binding = prepare(tool_name, tool_input)
    if error:
        return AuthzResult(False, error)

    action = pending_actions.open_authorization(tool_name, summary=summary, risk=risk)
    _requests[action.id] = _Request(tool_name, args_hash(tool_input), binding)
    try:
        prompt = {"type": "authorization_required", "authorization": action.public()}
        if not await _send(_ui_notifiers, prompt):
            pending_actions.settle_authorization(action.id, False)
            await pending_actions.wait_authorization(action.id, 1.0)
            return AuthzResult(False, "No local FRIDAY window is open to enter the PIN, so this was blocked.")
        await _send(_info_notifiers, {"type": "authorization_info", "message": NEEDS_PIN_MESSAGE})

        approved = await pending_actions.wait_authorization(action.id, timeout_s)
        await _send(_ui_notifiers, {"type": "authorization_resolved", "id": action.id, "approved": approved})
        grant = _grants.get(action.id)
        if not approved or grant is None:
            return AuthzResult(False, "Authorization was not granted (cancelled, timed out or locked).")
        return AuthzResult(True, grant=grant)
    finally:
        _requests.pop(action.id, None)


@dataclass(frozen=True)
class PinResult:
    ok: bool
    error: str = ""
    locked: bool = False
    attempts_left: int | None = None


def _log_attempt(action_id: str, ok: bool, failures: int) -> None:
    # Never the PIN itself, only the outcome.
    logger.warning("Authorization PIN attempt: action=%s ok=%s failures=%d/%d", action_id, ok, failures, MAX_FAILED_PINS)
    try:
        from jarvis.core.tracing import record_event

        record_event("authz.attempt", action_id=action_id, ok=ok, failures=failures)
    except Exception as exc:  # tracing must never break authorization
        logger.debug("authz trace event failed: %s", exc)


def submit_pin(action_id: str, pin: str, *, is_local: bool) -> PinResult:
    """Check a typed PIN for a pending authorization. ``is_local`` must come from the transport.

    On success a single-use Grant is stored server-side and the waiting tool
    call is released; the PIN is never stored or returned.
    """
    global _failed_pins, _locked_until
    if not is_local:
        logger.warning("Authorization PIN attempt refused: not a local request (action=%s).", action_id)
        return PinResult(False, "Authorization is only available on this Mac.")
    remaining = lockout_remaining()
    if remaining > 0:
        return PinResult(False, _locked_message(remaining), locked=True, attempts_left=0)

    request = _requests.get(action_id)
    action = pending_actions.get_authorization(action_id)
    if request is None or action is None or _now() - action.created_at > PIN_PROMPT_TIMEOUT_S:
        return PinResult(False, "That authorization request is no longer pending.")
    stored = get_secret(PIN_SECRET_NAME)
    if not stored:
        pending_actions.settle_authorization(action_id, False)
        return PinResult(False, "No authorization PIN is set.")

    if _valid_pin_format(pin) and _verify_against(pin, stored):
        _failed_pins = 0
        _grants[action_id] = Grant(
            action_id=action_id,
            tool_name=request.tool_name,
            args_hash=request.args_hash,
            binding=request.binding,
            expires_at=_now() + GRANT_TTL_S,
        )
        _log_attempt(action_id, True, 0)
        pending_actions.settle_authorization(action_id, True)
        return PinResult(True)

    _failed_pins += 1
    _log_attempt(action_id, False, _failed_pins)
    if _failed_pins >= MAX_FAILED_PINS:
        _locked_until = _now() + LOCKOUT_S
        logger.warning("Authorization locked for %.0fs after %d wrong PINs.", LOCKOUT_S, _failed_pins)
        for pending in pending_actions.list_authorizations():
            pending_actions.settle_authorization(pending["id"], False)
        return PinResult(False, _locked_message(LOCKOUT_S), locked=True, attempts_left=0)
    return PinResult(False, "Wrong PIN.", attempts_left=MAX_FAILED_PINS - _failed_pins)


def cancel_authorization(action_id: str, *, is_local: bool) -> bool:
    """Deny a pending authorization (the user dismissed the prompt)."""
    if not is_local:
        return False
    return pending_actions.settle_authorization(action_id, False)


# ------------------------------------------------------------------------ CLI


def _refuse_if_remote_shell() -> str:
    if any(os.environ.get(name) for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")):
        return "Refusing to set the PIN over SSH. Run this in a terminal on the Mac itself."
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return "Refusing to set the PIN without an interactive terminal."
    return ""


def _cli_set_pin() -> int:
    refusal = _refuse_if_remote_shell()
    if refusal:
        print(refusal, file=sys.stderr)
        return 2
    stored = get_secret(PIN_SECRET_NAME)
    if stored:
        current = getpass.getpass("Current PIN: ")
        if not (_valid_pin_format(current) and _verify_against(current, stored)):
            time.sleep(1.0)
            print("Current PIN is wrong.", file=sys.stderr)
            return 1
    new_pin = getpass.getpass(f"New PIN ({PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits): ")
    if getpass.getpass("Repeat new PIN: ") != new_pin:
        print("The PINs did not match.", file=sys.stderr)
        return 1
    try:
        set_pin(new_pin)
    except AuthzError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("Authorization PIN saved.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["set-pin"]:
        return _cli_set_pin()
    print("usage: python -m jarvis.core.authz set-pin", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
