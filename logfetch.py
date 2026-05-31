"""Log retrieval for hermes-ci-triage.

Turns a ``log_url_or_path`` into raw text, safely, for two input shapes:

* **Local path** — ``realpath``'d, confirmed to be a regular file, read with a
  hard byte cap. No credentials required; this path always works.
* **Remote URL** — HTTPS only, explicit timeout, streamed read with the same
  byte cap. The auth header targets the configured CI provider
  (**GitHub Actions**): a ``Bearer`` token read from ``GITHUB_TOKEN`` in the
  environment **at call time** (never at import). A missing/insufficient token
  surfaces as a :class:`LogFetchError` carrying a remediation hint rather than
  a raw traceback.

Pure standard library (``os``, ``ssl``, ``socket``, ``urllib``) — no Hermes
dependency, so it unit-tests in isolation.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Provider configuration — chosen at design time (decision point 1:
# "GitHub Actions"). Local-path retrieval is provider-agnostic and needs none
# of this.
# --------------------------------------------------------------------------

PROVIDER = "github_actions"
TOKEN_ENV_VAR = "GITHUB_TOKEN"

MAX_LOG_BYTES = 25 * 1024 * 1024   # 25 MB hard cap on any retrieved log
DEFAULT_TIMEOUT = 20.0             # seconds, explicit on every network call
_READ_CHUNK = 65_536
_USER_AGENT = "hermes-ci-triage/0.1"

# Remediation hints reused across several LogFetchErrors.
_PERMS_HINT = "Check the path and file permissions."
_TIMEOUT_HINT = "Retry, or point at a smaller/specific job log."


class LogFetchError(Exception):
    """A recoverable log-retrieval failure.

    ``remediation`` is an operator-facing hint the handler surfaces in the
    structured error envelope (e.g. "set GITHUB_TOKEN").
    """

    def __init__(self, message: str, remediation: str = "") -> None:
        super().__init__(message)
        self.remediation = remediation


def is_remote(target: str) -> bool:
    """True when *target* looks like an ``http(s)://`` URL (vs a local path).

    Note: plain ``http://`` is recognised as *remote* here only so it can be
    routed to :func:`fetch_remote`, which then rejects it (HTTPS-only).
    """
    lowered = (target or "").strip().lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def has_remote_credentials() -> bool:
    """True when a remote-fetch token is present.

    Diagnostics only — used to annotate tool output. It is **not** wired to
    the tool's ``check_fn``: a missing token must never hide the tool, because
    local-path triage works without any credentials.
    """
    return bool(os.environ.get(TOKEN_ENV_VAR, "").strip())


# --------------------------------------------------------------------------
# Outbound-request safety (token scoping + SSRF)
# --------------------------------------------------------------------------

# The auth token is sent ONLY to these hosts. GitHub Actions job-log URLs live on
# the API host and 302-redirect to a pre-signed blob URL that needs no token, so
# we never have to send it anywhere else. Override/extend for GitHub Enterprise
# via HERMES_CI_TRIAGE_TOKEN_HOSTS (comma-separated hostnames).
_DEFAULT_TOKEN_HOSTS = ("api.github.com", "raw.githubusercontent.com")


def _token_hosts() -> set:
    hosts = set(_DEFAULT_TOKEN_HOSTS)
    for h in os.environ.get("HERMES_CI_TRIAGE_TOKEN_HOSTS", "").split(","):
        h = h.strip().lower()
        if h:
            hosts.add(h)
    return hosts


def _host_allows_token(host: str) -> bool:
    """True only for GitHub hosts the token is meant for."""
    host = (host or "").lower()
    return host in _token_hosts() or host.endswith(".githubusercontent.com")


def _ip_blocked(ip) -> bool:
    # Block the SSRF-sensitive ranges (cloud metadata at 169.254.169.254 is
    # link-local; localhost services are loopback). RFC1918 private ranges are
    # deliberately left allowed so self-hosted/internal GitHub Enterprise log
    # hosts keep working.
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    )


def _is_blocked_address(host: str) -> bool:
    """True if *host* is, or resolves to, a non-routable/internal address."""
    if not host:
        return False
    try:
        return _ip_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass  # not a literal IP — resolve it
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # let the real connection attempt surface a network error
    for info in infos:
        try:
            if _ip_blocked(ipaddress.ip_address(info[4][0])):
                return True
        except ValueError:
            continue
    return False


class _AuthStrippingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but drop the Authorization header across hosts.

    GitHub serves job logs as a 302 to a pre-signed blob URL on a *different*
    host; forwarding the bearer token there would leak it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_host = (urlsplit(req.full_url).hostname or "").lower()
            new_host = (urlsplit(newurl).hostname or "").lower()
            if old_host != new_host:
                for key in list(new.headers):
                    if key.lower() == "authorization":
                        del new.headers[key]
        return new


def _build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _AuthStrippingRedirectHandler(),
    )


def _timeout_error(url: str, timeout: float) -> LogFetchError:
    """The single source of truth for the fetch-timeout error envelope."""
    return LogFetchError(f"Timed out after {timeout}s fetching {url}.", _TIMEOUT_HINT)


def _read_capped(resp) -> bytes:
    """Read a response body up to :data:`MAX_LOG_BYTES`, then stop."""
    chunks: list[bytes] = []
    total = 0
    while total < MAX_LOG_BYTES:
        chunk = resp.read(_READ_CHUNK)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)[:MAX_LOG_BYTES]


def read_local(path: str) -> str:
    """Read a local log file with a realpath check and byte cap."""
    real = os.path.realpath(os.path.expanduser(path))
    p = Path(real)
    if not p.exists():
        raise LogFetchError(
            f"Log file not found: {path}",
            "Provide a path to an existing CI log file, or an https:// URL "
            "to the raw log.",
        )
    if not p.is_file():
        raise LogFetchError(
            f"Not a regular file: {path}",
            "Point log_url_or_path at a log file, not a directory, device, "
            "or pipe.",
        )
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise LogFetchError(f"Could not stat log file: {path} ({exc})", _PERMS_HINT)
    if size > MAX_LOG_BYTES:
        raise LogFetchError(
            f"Log file too large: {size} bytes (cap {MAX_LOG_BYTES}).",
            "Pre-trim the log, or point at the specific failing job's log.",
        )
    try:
        with p.open("rb") as fh:
            data = fh.read(MAX_LOG_BYTES)
    except OSError as exc:
        raise LogFetchError(f"Could not read log file: {path} ({exc})", _PERMS_HINT)
    return data.decode("utf-8", errors="replace")


def fetch_remote(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Fetch a remote log over HTTPS with auth, timeout and byte cap.

    Safety: HTTPS only; the token is attached only to GitHub hosts
    (:func:`_host_allows_token`) and stripped on cross-host redirects; requests
    to loopback/link-local/reserved addresses are refused to blunt SSRF.
    """
    if not (url or "").strip().lower().startswith("https://"):
        raise LogFetchError(
            f"Refusing non-HTTPS URL: {url}",
            "Use an https:// URL — plain http and other schemes are not "
            "allowed.",
        )

    host = urlsplit(url).hostname or ""
    if _is_blocked_address(host):
        raise LogFetchError(
            f"Refusing to fetch from a non-routable/internal address: {host}",
            "Point at a public CI log URL; loopback, link-local and reserved "
            "addresses are blocked to prevent SSRF.",
        )

    headers = {"User-Agent": _USER_AGENT, "Accept": "text/plain, */*"}
    token = os.environ.get(TOKEN_ENV_VAR, "").strip()
    if token and _host_allows_token(host):
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    context = ssl.create_default_context()
    opener = _build_opener(context)
    try:
        with opener.open(request, timeout=timeout) as resp:
            data = _read_capped(resp)
        return data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise LogFetchError(
                f"Authentication failed (HTTP {exc.code}) fetching {url}.",
                f"Set the {TOKEN_ENV_VAR} environment variable to a token with "
                f"read access to the CI logs, then retry.",
            )
        if exc.code == 404:
            raise LogFetchError(
                f"Log not found (HTTP 404): {url}",
                "Check the URL — the run/job log may have expired or rotated.",
            )
        raise LogFetchError(
            f"HTTP error {exc.code} fetching {url}.",
            "Verify the URL and your network access.",
        )
    except socket.timeout:
        raise _timeout_error(url, timeout)
    except (urllib.error.URLError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise _timeout_error(url, timeout)
        raise LogFetchError(
            f"Network error fetching {url}: {reason}",
            "Check connectivity and that the host is reachable.",
        )


def fetch(target: str, *, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Resolve *target* (local path or https URL) to raw log text."""
    if not target or not str(target).strip():
        raise LogFetchError(
            "Empty log_url_or_path.",
            "Pass a local log file path or an https:// URL to the raw log.",
        )
    target = str(target).strip()
    if is_remote(target):
        return fetch_remote(target, timeout=timeout)
    return read_local(target)
