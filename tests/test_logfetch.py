"""logfetch: local reads, byte cap, scheme + auth handling."""

from __future__ import annotations

import urllib.error

import pytest

from hermes_plugins.hermes_ci_triage import logfetch


def test_is_remote():
    assert logfetch.is_remote("https://example.com/log") is True
    assert logfetch.is_remote("http://example.com/log") is True
    assert logfetch.is_remote("/var/log/build.log") is False
    assert logfetch.is_remote("build.log") is False


def test_read_local_ok(tmp_path):
    p = tmp_path / "build.log"
    p.write_text("hello\nFAILED tests/test_x.py\n", encoding="utf-8")
    text = logfetch.read_local(str(p))
    assert "FAILED tests/test_x.py" in text


def test_read_local_missing(tmp_path):
    with pytest.raises(logfetch.LogFetchError) as ei:
        logfetch.read_local(str(tmp_path / "nope.log"))
    assert ei.value.remediation


def test_read_local_rejects_directory(tmp_path):
    with pytest.raises(logfetch.LogFetchError):
        logfetch.read_local(str(tmp_path))


def test_oversize_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(logfetch, "MAX_LOG_BYTES", 16)
    p = tmp_path / "big.log"
    p.write_text("x" * 4096, encoding="utf-8")
    with pytest.raises(logfetch.LogFetchError) as ei:
        logfetch.read_local(str(p))
    assert "too large" in str(ei.value).lower()


def test_non_https_url_rejected():
    with pytest.raises(logfetch.LogFetchError) as ei:
        logfetch.fetch_remote("http://example.com/log")
    msg = (str(ei.value) + ei.value.remediation).lower()
    assert "https" in msg


def test_missing_token_path_structured_error(monkeypatch):
    """An auth failure (no/insufficient token) surfaces a LogFetchError with a
    GITHUB_TOKEN remediation — no raw traceback leaks."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    def fake_urlopen(request, timeout=None, context=None):
        raise urllib.error.HTTPError(
            "https://api.github.com/x", 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr(logfetch.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(logfetch.LogFetchError) as ei:
        logfetch.fetch_remote("https://api.github.com/repos/o/r/actions/jobs/1/logs")
    assert "GITHUB_TOKEN" in ei.value.remediation


def test_fetch_dispatches_local(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("ERROR boom\n", encoding="utf-8")
    assert "ERROR boom" in logfetch.fetch(str(p))


def test_fetch_empty_rejected():
    with pytest.raises(logfetch.LogFetchError):
        logfetch.fetch("   ")
