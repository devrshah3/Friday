"""open_file / reveal_file / open_website / open_url: what they will and won't open."""
import types

import pytest

from jarvis.tools import mac_control


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


@pytest.fixture
def opened(monkeypatch):
    """Record `open` invocations instead of running them."""
    calls = []

    async def fake_run_open(*args):
        calls.append(args)
        return ""

    monkeypatch.setattr(mac_control, "_run_open", fake_run_open)
    return calls


# ------------------------------------------------------------------ open_file


async def test_open_file_opens_an_ordinary_file(roots, opened):
    target = roots.docs / "notes.txt"
    target.write_text("x")
    result = await mac_control.open_file(str(target))
    assert opened == [(str(target.resolve()),)] and result.startswith("Opened")


@pytest.mark.parametrize(
    "extension",
    [".app", ".command", ".sh", ".pkg", ".dmg", ".jar", ".scpt", ".workflow", ".terminal", ".py", ".SH", ".Py"],
)
async def test_open_file_reveals_instead_of_opening_executable_types(roots, opened, extension):
    target = roots.docs / f"thing{extension}"
    target.write_text("x")
    result = await mac_control.open_file(str(target))
    assert opened == [("-R", str(target.resolve()))]
    assert "Finder" in result and "did not open" in result


async def test_open_file_reveals_app_bundles(roots, opened):
    bundle = roots.docs / "Thing.app"
    (bundle / "Contents").mkdir(parents=True)
    await mac_control.open_file(str(bundle))
    assert opened == [("-R", str(bundle.resolve()))]


async def test_open_file_reveals_files_inside_app_bundles(roots, opened):
    inner = roots.docs / "Thing.app" / "Contents" / "MacOS" / "run"
    inner.parent.mkdir(parents=True)
    inner.write_text("x")
    await mac_control.open_file(str(inner))
    assert opened == [("-R", str(inner.resolve()))]


async def test_open_file_reveals_executables_with_no_extension(roots, opened):
    program = roots.docs / "tool"
    program.write_text("#!/bin/sh\n")
    program.chmod(0o755)
    await mac_control.open_file(str(program))
    assert opened == [("-R", str(program.resolve()))]


async def test_open_file_checks_the_symlink_target_too(roots, opened):
    script = roots.docs / "payload.sh"
    script.write_text("x")
    link = roots.docs / "holiday.jpg"
    link.symlink_to(script)
    await mac_control.open_file(str(link))
    assert opened == [("-R", str(script.resolve()))]


async def test_open_file_refuses_paths_outside_the_roots(roots, opened):
    stray = roots.outside / "stray.txt"
    stray.write_text("x")
    assert (await mac_control.open_file(str(stray))).startswith("Cannot open")
    assert opened == []


async def test_open_file_refuses_a_symlink_that_escapes_the_roots(roots, opened):
    secret = roots.outside / "secret.txt"
    secret.write_text("x")
    link = roots.docs / "innocent.txt"
    link.symlink_to(secret)
    assert (await mac_control.open_file(str(link))).startswith("Cannot open")
    assert opened == []


@pytest.mark.parametrize("bad", ["", "relative.txt", "~/definitely-missing.txt"])
async def test_open_file_refuses_empty_relative_and_missing_paths(roots, opened, bad):
    assert (await mac_control.open_file(bad)).startswith("Cannot open")
    assert opened == []


# ---------------------------------------------------------------- reveal_file


async def test_reveal_file_shows_the_file_in_finder(roots, opened):
    target = roots.docs / "notes.txt"
    target.write_text("x")
    await mac_control.reveal_file(str(target))
    assert opened == [("-R", str(target.resolve()))]


async def test_reveal_file_refuses_paths_outside_the_roots(roots, opened):
    stray = roots.outside / "stray.txt"
    stray.write_text("x")
    assert (await mac_control.reveal_file(str(stray))).startswith("Cannot reveal")
    assert opened == []


# --------------------------------------------------------------- open_website


@pytest.mark.parametrize(
    "site",
    [
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,<script>alert(1)</script>",
        "ftp://example.com/file",
        "vscode://file/etc/passwd",
        "x-apple.systempreferences:com.apple.preference.security",
        "http://user:secret@evil.example.com",
        "https://",
        "http://exa mple.com",
        "https://example.com/\nnext",
        "",
        "   ",
    ],
)
async def test_open_website_refuses_non_http_schemes_and_malformed_urls(opened, site):
    assert (await mac_control.open_website(site)).startswith("Cannot open")
    assert opened == []


async def test_open_website_opens_an_https_url_in_chrome(opened):
    await mac_control.open_website("https://example.com/a?b=1")
    assert opened == [("-a", "Google Chrome", "https://example.com/a?b=1")]


async def test_open_website_accepts_plain_http(opened):
    await mac_control.open_website("http://example.com")
    assert opened == [("-a", "Google Chrome", "http://example.com")]


@pytest.mark.parametrize(
    ("site", "url"),
    [
        ("github.com", "https://github.com"),
        ("GitHub.com/anthropics", "https://GitHub.com/anthropics"),
        ("example.com:8080/path", "https://example.com:8080/path"),
        ("HTTPS://Example.com", "HTTPS://Example.com"),
    ],
)
def test_clear_domains_become_https_urls(site, url):
    assert mac_control.website_to_url(site) == (url, "")


@pytest.mark.parametrize(
    ("site", "query"),
    [
        ("weather", "weather"),
        ("best pizza near me", "best+pizza+near+me"),
        ("localhost", "localhost"),
        ("openai", "openai"),
        ("what is 2+2?", "what+is+2%2B2%3F"),
    ],
)
def test_names_that_are_not_clear_domains_become_google_searches(site, query):
    assert mac_control.website_to_url(site) == (f"https://www.google.com/search?q={query}", "")


async def test_a_search_url_is_opened_as_an_argument(opened):
    await mac_control.open_website("best pizza near me")
    assert opened == [("-a", "Google Chrome", "https://www.google.com/search?q=best+pizza+near+me")]


# ------------------------------------------------- open_url (hardened the same way)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)", "data:text/plain,hi", "github.com"])
async def test_open_url_refuses_anything_but_http_urls(opened, url):
    assert (await mac_control.open_url(url)).startswith("Cannot open")
    assert opened == []


async def test_open_url_opens_http_urls_in_the_default_browser(opened):
    await mac_control.open_url("https://example.com")
    assert opened == [("https://example.com",)]


async def test_open_url_in_browser_only_uses_known_browsers(opened):
    assert "supported browser" in await mac_control.open_url_in_browser("https://example.com", "Terminal")
    assert opened == []
    await mac_control.open_url_in_browser("https://example.com", "Safari")
    assert opened == [("-a", "Safari", "https://example.com")]


async def test_open_url_in_browser_refuses_non_http_urls(opened):
    assert (await mac_control.open_url_in_browser("file:///etc/passwd")).startswith("Cannot open")
    assert opened == []

