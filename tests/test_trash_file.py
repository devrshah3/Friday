"""trash_file: path validation, allowed roots, and how the path reaches Finder."""
import asyncio
import os
import types
from pathlib import Path

import pytest

from jarvis.core import authz
from jarvis.tools import filesystem
from jarvis.tools.filesystem import TrashRefused, prepare_trash


@pytest.fixture(autouse=True)
def _no_real_processes(monkeypatch):
    """Safety net: nothing in this file may start a real process (osascript, open, ...)."""

    async def refuse(*args, **kwargs):
        raise AssertionError(f"test tried to start a real process: {args[:1]}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", refuse)


@pytest.fixture
def roots(monkeypatch, tmp_path):
    home = tmp_path / "home"
    docs = tmp_path / "docs"
    outside = tmp_path / "elsewhere"
    for folder in (home, docs, outside):
        folder.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("FRIDAY_ALLOWED_ROOTS", str(docs))
    return types.SimpleNamespace(home=home, docs=docs, outside=outside)


def refused(path, match):
    with pytest.raises(TrashRefused, match=match):
        prepare_trash(str(path))


def test_accepts_a_plain_file_inside_an_allowed_root(roots):
    target = roots.docs / "report.txt"
    target.write_text("hello")
    result = prepare_trash(str(target))
    assert result.path == target.resolve() and result.size == 5


def test_default_roots_are_documents_downloads_and_desktop(roots, monkeypatch):
    monkeypatch.delenv("FRIDAY_ALLOWED_ROOTS")
    for name in ("Documents", "Downloads", "Desktop"):
        folder = roots.home / name
        folder.mkdir()
        (folder / "a.txt").write_text("x")
        assert prepare_trash(str(folder / "a.txt")).path == (folder / "a.txt").resolve()
    refused(roots.outside / "a.txt", "outside the allowed folders|Not found")


def test_extra_roots_come_from_the_environment(roots, monkeypatch):
    monkeypatch.setenv("FRIDAY_ALLOWED_ROOTS", os.pathsep.join([str(roots.docs), str(roots.outside)]))
    (roots.outside / "ok.txt").write_text("x")
    assert prepare_trash(str(roots.outside / "ok.txt")).path.name == "ok.txt"


def test_overly_broad_roots_are_ignored(roots, monkeypatch):
    monkeypatch.setenv("FRIDAY_ALLOWED_ROOTS", os.pathsep.join(["/", str(roots.home), "relative/dir"]))
    resolved = filesystem.allowed_roots()
    assert Path("/") not in resolved and roots.home.resolve() not in resolved
    assert all(root.is_absolute() for root in resolved)


def test_refuses_paths_outside_the_roots(roots):
    stray = roots.outside / "stray.txt"
    stray.write_text("x")
    refused(stray, "outside the allowed folders")


def test_refuses_a_symlink_that_escapes_the_roots(roots):
    secret = roots.outside / "secret.txt"
    secret.write_text("x")
    link = roots.docs / "innocent.txt"
    link.symlink_to(secret)
    refused(link, "outside the allowed folders")
    assert secret.exists()


def test_a_symlink_inside_the_roots_resolves_to_its_target(roots):
    real = roots.docs / "real.txt"
    real.write_text("x")
    link = roots.docs / "alias.txt"
    link.symlink_to(real)
    assert prepare_trash(str(link)).path == real.resolve()


def test_refuses_directories(roots):
    folder = roots.docs / "photos"
    folder.mkdir()
    (folder / "a.jpg").write_text("x")
    refused(folder, "folder")


def test_refuses_app_bundles_and_their_contents(roots):
    bundle = roots.docs / "Thing.app"
    (bundle / "Contents").mkdir(parents=True)
    (bundle / "Contents" / "Info.plist").write_text("x")
    refused(bundle, "app bundle")
    refused(bundle / "Contents" / "Info.plist", "app bundle")


def test_refuses_hidden_files_and_files_in_hidden_folders(roots):
    hidden = roots.docs / ".notes"
    hidden.write_text("x")
    refused(hidden, "hidden")
    (roots.docs / ".cache").mkdir()
    (roots.docs / ".cache" / "visible.txt").write_text("x")
    refused(roots.docs / ".cache" / "visible.txt", "hidden")


def test_refuses_a_visible_symlink_to_a_hidden_file(roots):
    hidden = roots.docs / ".secret"
    hidden.write_text("x")
    link = roots.docs / "harmless.txt"
    link.symlink_to(hidden)
    refused(link, "hidden")


def test_refuses_credential_files(roots):
    key = roots.docs / "id_rsa"
    key.write_text("x")
    refused(key, "credential")


@pytest.mark.parametrize("bad", ["", "   ", "relative/file.txt", "~/definitely-missing-file.txt"])
def test_refuses_empty_relative_and_missing_paths(roots, bad):
    with pytest.raises(TrashRefused):
        prepare_trash(bad)


def test_refuses_nul_bytes(roots):
    with pytest.raises(TrashRefused):
        prepare_trash(str(roots.docs / "a.txt") + "\x00.png")


# ------------------------------------------------------------ the tool itself


@pytest.fixture
def finder(monkeypatch):
    """Pretend to be macOS and capture what would be run instead of running it."""
    monkeypatch.setattr(filesystem, "sys", types.SimpleNamespace(platform="darwin"))
    launched = []

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def fake_exec(*argv, **kwargs):
        launched.append(argv)
        Path(argv[-1]).unlink()
        return FakeProcess()

    monkeypatch.setattr(filesystem.asyncio, "create_subprocess_exec", fake_exec)
    return launched


def used_grant():
    return authz.Grant(action_id="a1", tool_name="trash_file", args_hash="h", binding="", expires_at=0.0, state="used")


async def test_trash_file_refuses_to_run_without_an_authorization(roots, finder):
    target = roots.docs / "report.txt"
    target.write_text("hello")
    result = await filesystem.trash_file(str(target))
    assert "needs PIN authorization" in result
    assert target.exists() and finder == []


async def test_trash_file_is_macos_only(roots, monkeypatch):
    monkeypatch.setattr(filesystem, "sys", types.SimpleNamespace(platform="linux"))
    assert "only works on macOS" in await filesystem.trash_file(str(roots.docs / "a.txt"))


async def test_trash_file_reports_refusals_without_touching_anything(roots, finder):
    folder = roots.docs / "photos"
    folder.mkdir()
    with authz.authorized_scope(used_grant()):
        result = await filesystem.trash_file(str(folder))
    assert result.startswith("Cannot trash") and folder.exists() and finder == []


async def test_the_path_reaches_finder_as_an_argument_never_inside_the_script(roots, finder):
    target = roots.docs / "we\"ird '; quit.txt"
    target.write_text("hello")
    with authz.authorized_scope(used_grant()):
        result = await filesystem.trash_file(str(target))
    assert "Trash" in result and not target.exists()
    (argv,) = finder
    assert argv[0] == "osascript" and argv[-1] == str(target.resolve())
    assert str(target.resolve()) not in " ".join(argv[:-1])  # not interpolated into the script
    assert "item 1 of argv" in " ".join(argv)


async def test_trash_file_uses_the_trash_never_a_permanent_delete(roots, finder):
    target = roots.docs / "report.txt"
    target.write_text("hello")
    with authz.authorized_scope(used_grant()):
        await filesystem.trash_file(str(target))
    assert finder[0][0] == "osascript"
    script = " ".join(finder[0][:-1])  # everything but the path argument
    assert 'tell application "Finder" to delete' in script
    assert "empty" not in script.lower() and "rm " not in script
