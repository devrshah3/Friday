"""JARVIS File System Tools: safe file operations for managing files and folders."""
import asyncio
import fnmatch
import logging
import os
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("jarvis.tools.filesystem")

PROTECTED_DIRS = [
    "/System", "/usr", "/bin", "/sbin", "/private", "/Library/Apple",
]

# Temp roots stay usable even though they live under a protected prefix
# (on macOS /tmp -> /private/tmp, and gettempdir() is /private/var/folders/...).
# "/tmp" here is a read-allowlist entry for the path guard, not a temp-file
# write target, so B108 (hardcoded tmp dir) does not apply.
_TEMP_ROOTS = tuple(sorted({
    str(Path(p).resolve()) for p in ("/tmp", tempfile.gettempdir())  # nosec B108
}))

# Directory names that hold credentials/keys. Blocked anywhere in the path so
# both reads and writes are refused (e.g. ~/.ssh, ~/.aws, project .git/config).
SENSITIVE_DIR_NAMES = {
    ".ssh", ".aws", ".gnupg", ".gpg", ".kube", ".docker",
    ".config/gcloud", ".azure", ".password-store",
}

# Filename globs for secret material, matched case-insensitively on any file.
SENSITIVE_FILE_GLOBS = [
    ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*",
    "id_ecdsa*", "id_dsa*", ".netrc", "credentials", "credentials.*",
    "*.keychain", "*.keychain-db", ".htpasswd", "*.pfx", "*.p12",
]


def _is_path_safe(path: str) -> tuple[bool, str]:
    """Verify a path is neither a protected system dir nor a credential file.

    Applied to every read and write entry point so the LLM (or a prompt-injected
    instruction) cannot use these tools to exfiltrate secrets such as
    ``~/.ssh/id_rsa`` or a project ``.env``.
    """
    resolved = Path(path).expanduser().resolve()
    resolved_str = str(resolved)

    # Credential checks run first so secrets are refused even inside a temp root.
    lowered_parts = {part.lower() for part in resolved.parts}
    for sensitive in SENSITIVE_DIR_NAMES:
        # Handle both single-segment (".ssh") and nested (".config/gcloud") names.
        if all(seg in lowered_parts for seg in sensitive.split("/")):
            return False, f"Sensitive credential path: {sensitive}"

    name = resolved.name.lower()
    for glob in SENSITIVE_FILE_GLOBS:
        if fnmatch.fnmatch(name, glob):
            return False, f"Sensitive credential file: {resolved.name}"

    if resolved_str.startswith(_TEMP_ROOTS):
        return True, "OK"

    for protected in PROTECTED_DIRS:
        if resolved_str.startswith(protected):
            return False, f"Protected system path: {protected}"

    return True, "OK"


async def list_directory(path: str = ".", detailed: bool = True) -> str:
    """List contents of a directory."""
    safe, reason = _is_path_safe(path)
    if not safe:
        return f"Cannot list: {reason}"
    try:
        target = Path(path).expanduser().resolve()
        if not target.exists():
            return f"Directory not found: {path}"
        if not target.is_dir():
            return f"Not a directory: {path}"

        items = sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        lines = [f"Contents of {target}:\n"]

        for item in items:
            if item.name.startswith("."):
                continue

            if detailed:
                stat = item.stat()
                size = stat.st_size
                modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                if item.is_dir():
                    lines.append(f"  [DIR]  {item.name}/  ({modified})")
                else:
                    size_str = _format_size(size)
                    lines.append(f"  [FILE] {item.name}  ({size_str}, {modified})")
            else:
                prefix = "[DIR] " if item.is_dir() else "      "
                lines.append(f"  {prefix}{item.name}")

        if len(lines) == 1:
            lines.append("  (empty directory)")

        return "\n".join(lines)
    except PermissionError:
        return f"Permission denied: {path}"
    except Exception as e:
        return f"Error listing directory: {e}"


async def read_file(path: str, max_lines: int = 100) -> str:
    """Read the contents of a text file."""
    safe, reason = _is_path_safe(path)
    if not safe:
        return f"Cannot read: {reason}"
    try:
        target = Path(path).expanduser().resolve()
        if not target.exists():
            return f"File not found: {path}"
        if not target.is_file():
            return f"Not a file: {path}"

        size = target.stat().st_size
        if size > 1_000_000:
            return f"File too large to read ({_format_size(size)}). Use a specific tool or command."

        with open(target, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if len(lines) > max_lines:
            content = "".join(lines[:max_lines])
            return f"{content}\n... (showing {max_lines} of {len(lines)} lines)"

        return "".join(lines)
    except Exception as e:
        return f"Error reading file: {e}"


async def write_file(path: str, content: str, overwrite: bool = False) -> str:
    """Write content to a file (creates or overwrites)."""
    safe, reason = _is_path_safe(path)
    if not safe:
        return f"Cannot write: {reason}"

    try:
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            return (
                f"File already exists: {target}. "
                "Pass overwrite=true only after reading the file or receiving explicit user confirmation."
            )

        with open(target, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("Wrote %d chars to %s", len(content), target)
        return f"Written {len(content)} characters to {target}."
    except Exception as e:
        return f"Error writing file: {e}"


async def create_directory(path: str) -> str:
    """Create a directory and parent directories if needed."""
    safe, reason = _is_path_safe(path)
    if not safe:
        return f"Cannot create: {reason}"

    try:
        target = Path(path).expanduser().resolve()
        target.mkdir(parents=True, exist_ok=True)
        return f"Created directory: {target}"
    except Exception as e:
        return f"Error creating directory: {e}"


async def move_file(source: str, destination: str) -> str:
    """Move or rename a file/directory."""
    safe_s, reason_s = _is_path_safe(source)
    safe_d, reason_d = _is_path_safe(destination)
    if not safe_s:
        return f"Cannot move source: {reason_s}"
    if not safe_d:
        return f"Cannot move to destination: {reason_d}"

    try:
        src = Path(source).expanduser().resolve()
        dst = Path(destination).expanduser().resolve()

        if not src.exists():
            return f"Source not found: {source}"
        if dst.exists():
            return f"Destination already exists: {dst}. Choose a different destination; move_file will not overwrite."

        shutil.move(str(src), str(dst))
        return f"Moved {src.name} to {dst}."
    except Exception as e:
        return f"Error moving: {e}"


async def copy_file(source: str, destination: str) -> str:
    """Copy a file or directory."""
    safe_s, reason_s = _is_path_safe(source)
    safe_d, reason_d = _is_path_safe(destination)
    if not safe_s:
        return f"Cannot copy source: {reason_s}"
    if not safe_d:
        return f"Cannot copy to destination: {reason_d}"

    try:
        src = Path(source).expanduser().resolve()
        dst = Path(destination).expanduser().resolve()

        if not src.exists():
            return f"Source not found: {source}"

        if src.is_dir():
            shutil.copytree(str(src), str(dst))
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))

        return f"Copied {src.name} to {dst}."
    except Exception as e:
        return f"Error copying: {e}"


async def search_files(
    directory: str = ".",
    pattern: str = "*",
    max_results: int = 20,
) -> str:
    """Search for files matching a glob pattern."""
    safe, reason = _is_path_safe(directory)
    if not safe:
        return f"Cannot search: {reason}"
    try:
        target = Path(directory).expanduser().resolve()
        if not target.exists():
            return f"Directory not found: {directory}"

        matches = [
            m for m in target.rglob(pattern)
            if _is_path_safe(str(m))[0]
        ][:max_results]

        if not matches:
            return f"No files matching '{pattern}' in {target}"

        lines = [f"Found {len(matches)} files matching '{pattern}':"]
        for m in matches:
            rel = m.relative_to(target) if m.is_relative_to(target) else m
            size = _format_size(m.stat().st_size) if m.is_file() else "DIR"
            lines.append(f"  {rel}  ({size})")

        return "\n".join(lines)
    except Exception as e:
        return f"Error searching: {e}"


async def get_file_info(path: str) -> str:
    """Get detailed information about a file or directory."""
    safe, reason = _is_path_safe(path)
    if not safe:
        return f"Cannot inspect: {reason}"
    try:
        target = Path(path).expanduser().resolve()
        if not target.exists():
            return f"Not found: {path}"

        stat = target.stat()
        info = [
            f"Path: {target}",
            f"Type: {'Directory' if target.is_dir() else 'File'}",
            f"Size: {_format_size(stat.st_size)}",
            f"Modified: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Created: {datetime.fromtimestamp(stat.st_birthtime).strftime('%Y-%m-%d %H:%M:%S')}",
        ]

        if target.is_dir():
            children = list(target.iterdir())
            info.append(f"Contains: {len(children)} items")

        return "\n".join(info)
    except Exception as e:
        return f"Error getting info: {e}"


# Folders the open/reveal/trash tools may touch, under the user's home. More can
# be added with FRIDAY_ALLOWED_ROOTS (absolute paths separated by os.pathsep).
DEFAULT_ALLOWED_ROOT_NAMES = ("Documents", "Downloads", "Desktop")


def allowed_roots() -> list[Path]:
    """Resolved folders that open_file, reveal_file and trash_file may act inside."""
    home = Path.home()
    candidates = [home / name for name in DEFAULT_ALLOWED_ROOT_NAMES]
    for raw in os.environ.get("FRIDAY_ALLOWED_ROOTS", "").split(os.pathsep):
        raw = raw.strip()
        if not raw:
            continue
        extra = Path(raw).expanduser()
        if not extra.is_absolute():
            logger.warning("Ignoring non-absolute FRIDAY_ALLOWED_ROOTS entry: %s", raw)
            continue
        candidates.append(extra)

    roots: list[Path] = []
    for candidate in candidates:
        try:
            root = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if root == Path(root.anchor) or root == home.resolve():
            logger.warning("Ignoring overly broad allowed root: %s", root)
            continue
        roots.append(root)
    return roots


def containing_root(resolved: Path) -> Path | None:
    """Return the allowed root that contains an already-resolved path, if any."""
    for root in allowed_roots():
        if resolved.is_relative_to(root):
            return root
    return None


def resolve_in_allowed_roots(path: str) -> tuple[Path | None, str]:
    """Resolve symlinks, then require the target to exist inside an allowed root.

    Returns (resolved, "") or (None, reason). The check runs on the resolved
    path, so a symlink in Documents pointing outside the roots is refused.
    """
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        return None, "Provide a single file path."
    safe, reason = _is_path_safe(path)
    if not safe:
        return None, reason
    raw = Path(path).expanduser()
    if not raw.is_absolute():
        return None, "Use a full path (starting with / or ~)."
    try:
        resolved = raw.resolve(strict=True)
    except FileNotFoundError:
        return None, f"Not found: {path}"
    except (OSError, RuntimeError) as exc:
        return None, f"Cannot resolve path: {exc}"
    safe, reason = _is_path_safe(str(resolved))
    if not safe:
        return None, reason
    if containing_root(resolved) is None:
        folders = ", ".join(str(r) for r in allowed_roots())
        return None, f"{resolved} is outside the allowed folders ({folders})."
    return resolved, ""


class TrashRefused(Exception):
    """A trash request that must not proceed; the message says why."""


class TrashTarget(NamedTuple):
    path: Path
    size: int
    mtime_ns: int
    inode: int


def prepare_trash(path: str) -> TrashTarget:
    """Validate one path for trash_file and describe it, or raise TrashRefused.

    Refuses directories (including .app bundles), hidden files, special files and
    anything that, once symlinks are resolved, is outside the allowed roots.
    """
    resolved, reason = resolve_in_allowed_roots(path)
    if resolved is None:
        raise TrashRefused(reason)
    raw_name = Path(path).expanduser().name
    root = containing_root(resolved)
    relative_parts = resolved.relative_to(root).parts if root else resolved.parts
    if raw_name.startswith(".") or any(part.startswith(".") for part in relative_parts):
        raise TrashRefused(f"{resolved} is a hidden file (or inside a hidden folder); it will not be trashed.")
    if any(part.lower().endswith(".app") for part in relative_parts):
        raise TrashRefused(f"{resolved} is part of an app bundle; it will not be trashed.")
    if resolved.is_dir():
        raise TrashRefused(f"{resolved} is a folder; trash_file only moves single files.")
    if not resolved.is_file():
        raise TrashRefused(f"{resolved} is not a regular file.")
    stat = resolved.stat()
    return TrashTarget(resolved, stat.st_size, stat.st_mtime_ns, stat.st_ino)


async def trash_file(path: str) -> str:
    """Move one file to the macOS Trash (recoverable). Needs PIN authorization.

    Never deletes permanently: there is no rm, no recursive delete and no
    empty-trash tool. The path reaches AppleScript as an argument, never as
    part of the script text.
    """
    if sys.platform != "darwin":
        return "trash_file only works on macOS."
    try:
        target = prepare_trash(path)
    except TrashRefused as exc:
        return f"Cannot trash: {exc}"

    from jarvis.core import authz

    problem = authz.tool_guard("trash_file")
    if problem:
        return problem

    try:
        process = await asyncio.create_subprocess_exec(
            "osascript",
            "-e", "on run argv",
            "-e", 'tell application "Finder" to delete (POSIX file (item 1 of argv) as alias)',
            "-e", "end run",
            str(target.path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
        except TimeoutError:
            process.kill()
            return "Trash request timed out; the file may not have been moved."
    except Exception as exc:
        return f"Error moving to Trash: {exc}"

    if process.returncode != 0:
        return f"Could not move to Trash: {stderr.decode().strip() or 'Finder reported an error'}"
    if target.path.exists():
        return f"Finder did not move {target.path} to the Trash."
    logger.info("Moved %s to the Trash.", target.path)
    return f"Moved {target.path.name} ({_format_size(target.size)}) to the Trash. Restore it from the Trash with Put Back."


def _format_size(size: int) -> str:
    """Convert bytes to human-readable format (B, KB, MB, GB, TB)."""
    size_float = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if size_float < 1024:
            return f"{size_float:.1f} {unit}"
        size_float /= 1024
    return f"{size_float:.1f} TB"


format_size = _format_size
