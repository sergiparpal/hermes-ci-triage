"""logfetch: local reads, byte cap, scheme + auth handling.

Transport hardening (SSRF address vetting, the guarded redirect/connect path)
now lives in ``safehttp``; those tests reference it there. ``LogFetchError`` is
re-exported by ``logfetch`` so it is still asserted via ``logfetch.LogFetchError``.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from hermes_plugins.hermes_ci_triage import logfetch, safehttp


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


class _FakeResp:
    """Minimal context-manager HTTP response yielding *data* once."""

    def __init__(self, data=b""):
        self._data = data
        self._sent = False

    def read(self, _n):
        if self._sent:
            return b""
        self._sent = True
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _CaptureOpener:
    """Records the Request it was asked to open and returns a canned response."""

    def __init__(self, data=b"log line\nERROR boom\n", raises=None):
        self.request = None
        self._data = data
        self._raises = raises

    def open(self, request, timeout=None):
        self.request = request
        if self._raises is not None:
            raise self._raises
        return _FakeResp(self._data)


def test_missing_token_path_structured_error(monkeypatch):
    """An auth failure (no/insufficient token) surfaces a LogFetchError with a
    GITHUB_TOKEN remediation — no raw traceback leaks."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(safehttp, "is_blocked_address", lambda host: False)
    err = urllib.error.HTTPError(
        "https://api.github.com/x", 401, "Unauthorized", {}, None
    )
    monkeypatch.setattr(safehttp, "build_opener", lambda ctx: _CaptureOpener(raises=err))
    with pytest.raises(logfetch.LogFetchError) as ei:
        logfetch.fetch_remote("https://api.github.com/repos/o/r/actions/jobs/1/logs")
    assert "GITHUB_TOKEN" in ei.value.remediation


def test_token_not_sent_to_foreign_host(monkeypatch):
    """The token must NOT be attached to a non-GitHub host (credential leak)."""
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    monkeypatch.setattr(safehttp, "is_blocked_address", lambda host: False)
    cap = _CaptureOpener()
    monkeypatch.setattr(safehttp, "build_opener", lambda ctx: cap)
    out = logfetch.fetch_remote("https://evil.example/log")
    assert "ERROR boom" in out
    assert not any(k.lower() == "authorization" for k in cap.request.headers)


def test_token_sent_to_github_api(monkeypatch):
    """The token IS attached for the allow-listed GitHub API host."""
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    monkeypatch.setattr(safehttp, "is_blocked_address", lambda host: False)
    cap = _CaptureOpener()
    monkeypatch.setattr(safehttp, "build_opener", lambda ctx: cap)
    logfetch.fetch_remote("https://api.github.com/repos/o/r/actions/jobs/1/logs")
    auth = next(v for k, v in cap.request.headers.items() if k.lower() == "authorization")
    assert auth == "Bearer secret-token"


def test_ssrf_internal_address_rejected(monkeypatch):
    """A link-local address (e.g. cloud metadata) is refused before any fetch."""
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    with pytest.raises(logfetch.LogFetchError) as ei:
        logfetch.fetch_remote("https://169.254.169.254/latest/meta-data/")
    assert "ssrf" in (str(ei.value) + ei.value.remediation).lower()


def test_redirect_strips_auth_cross_host(monkeypatch):
    monkeypatch.setattr(safehttp, "is_blocked_address", lambda host: False)
    handler = safehttp.SafeRedirectHandler()
    req = urllib.request.Request(
        "https://api.github.com/x", headers={"Authorization": "Bearer t"}
    )
    new = handler.redirect_request(req, None, 302, "Found", {}, "https://blob.example/y")
    assert new is not None
    assert not any(k.lower() == "authorization" for k in new.headers)


def test_redirect_keeps_auth_same_host(monkeypatch):
    monkeypatch.setattr(safehttp, "is_blocked_address", lambda host: False)
    handler = safehttp.SafeRedirectHandler()
    req = urllib.request.Request(
        "https://api.github.com/x", headers={"Authorization": "Bearer t"}
    )
    new = handler.redirect_request(req, None, 302, "Found", {}, "https://api.github.com/y")
    assert any(k.lower() == "authorization" for k in new.headers)


def test_redirect_to_internal_address_refused(monkeypatch):
    """H1: the SSRF blocklist must apply to redirect targets, not just the
    initial URL — a public URL must not be able to 302 to cloud metadata."""
    monkeypatch.setattr(safehttp, "is_blocked_address", lambda host: True)
    handler = safehttp.SafeRedirectHandler()
    req = urllib.request.Request("https://logs.example/x")
    with pytest.raises(logfetch.LogFetchError) as ei:
        handler.redirect_request(
            req, None, 302, "Found", {}, "https://169.254.169.254/latest/meta-data/"
        )
    assert "ssrf" in (str(ei.value) + ei.value.remediation).lower()


def test_redirect_to_non_https_refused(monkeypatch):
    """H1: a redirect that downgrades to http:// must be refused (no scheme
    downgrade to e.g. http://169.254.169.254/)."""
    monkeypatch.setattr(safehttp, "is_blocked_address", lambda host: False)
    handler = safehttp.SafeRedirectHandler()
    req = urllib.request.Request("https://logs.example/x")
    with pytest.raises(logfetch.LogFetchError):
        handler.redirect_request(req, None, 302, "Found", {}, "http://logs.example/y")


def test_private_address_blocked_by_default(monkeypatch):
    """M1: RFC1918 destinations are blocked unless explicitly opted in; metadata
    and loopback stay blocked even when private ranges are permitted."""
    import ipaddress

    monkeypatch.delenv("HERMES_CI_TRIAGE_ALLOW_PRIVATE", raising=False)
    assert safehttp.ip_blocked(ipaddress.ip_address("10.0.0.5")) is True
    assert safehttp.ip_blocked(ipaddress.ip_address("192.168.1.1")) is True

    monkeypatch.setenv("HERMES_CI_TRIAGE_ALLOW_PRIVATE", "1")
    assert safehttp.ip_blocked(ipaddress.ip_address("10.0.0.5")) is False
    assert safehttp.ip_blocked(ipaddress.ip_address("127.0.0.1")) is True
    assert safehttp.ip_blocked(ipaddress.ip_address("169.254.169.254")) is True


def test_guarded_connection_refuses_resolved_internal_ip(monkeypatch):
    """M2: connect-time IP vetting refuses a name that resolves to an internal
    address (closes the DNS-rebinding TOCTOU window)."""
    conn = safehttp.GuardedHTTPSConnection("rebind.example", 443)
    monkeypatch.setattr(
        safehttp.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    with pytest.raises(logfetch.LogFetchError):
        conn.connect()


def test_log_roots_allowlist(tmp_path, monkeypatch):
    """M3: when HERMES_CI_TRIAGE_LOG_ROOTS is set, reads outside it are refused."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    inside = allowed / "build.log"
    inside.write_text("ERROR boom\n", encoding="utf-8")
    outside = tmp_path / "secret.log"
    outside.write_text("ERROR boom\n", encoding="utf-8")

    monkeypatch.setenv("HERMES_CI_TRIAGE_LOG_ROOTS", str(allowed))
    assert "ERROR boom" in logfetch.read_local(str(inside))
    with pytest.raises(logfetch.LogFetchError) as ei:
        logfetch.read_local(str(outside))
    assert ei.value.remediation


def test_fetch_dispatches_local(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("ERROR boom\n", encoding="utf-8")
    assert "ERROR boom" in logfetch.fetch(str(p))


def test_fetch_empty_rejected():
    with pytest.raises(logfetch.LogFetchError):
        logfetch.fetch("   ")
