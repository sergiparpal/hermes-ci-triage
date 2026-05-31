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

This module owns *retrieval policy* (provider/token scoping, local-file roots,
byte caps, error mapping). The security-critical transport hardening — HTTPS-
only redirect/connect guards and SSRF address vetting — lives in the lower-level
:mod:`safehttp`, from which :class:`LogFetchError` is re-exported here so callers
keep using ``logfetch.LogFetchError``.

Pure standard library (``os``, ``ssl``, ``socket``, ``urllib``) — no Hermes
dependency, so it unit-tests in isolation.
"""

from __future__ import annotations

import os
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import safehttp
from .safehttp import LogFetchError  # re-export: public API + local raises

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

# Optional allowlist of directories local logs may be read from (os.pathsep-
# separated). Unset = no restriction (default); set it to confine reads so the
# tool cannot be steered into reading arbitrary files (~/.ssh/id_rsa, .env, …).
_LOG_ROOTS_ENV = "HERMES_CI_TRIAGE_LOG_ROOTS"


def _safe_path(path: str) -> str:
    """Basename only — don't echo the full local path back to the caller."""
    try:
        base = os.path.basename(str(path).rstrip("/").rstrip("\\"))
        return base or "the requested file"
    except Exception:
        return "the requested file"


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
# Token scoping (which hosts may receive the auth header)
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


def _timeout_error(url: str, timeout: float) -> LogFetchError:
    """The single source of truth for the fetch-timeout error envelope."""
    return LogFetchError(
        f"Timed out after {timeout}s fetching {safehttp.safe_url(url)}.",
        _TIMEOUT_HINT,
    )


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


# --------------------------------------------------------------------------
# Local-file retrieval
# --------------------------------------------------------------------------

def _log_roots() -> list:
    """Resolved directories that local logs may be read from (opt-in allowlist)."""
    roots = []
    for part in os.environ.get(_LOG_ROOTS_ENV, "").split(os.pathsep):
        part = part.strip()
        if part:
            roots.append(os.path.realpath(os.path.expanduser(part)))
    return roots


def _within_roots(real: str, roots: list) -> bool:
    for root in roots:
        try:
            if os.path.commonpath([real, root]) == root:
                return True
        except ValueError:
            continue  # e.g. different drive on Windows
    return False


def read_local(path: str) -> str:
    """Read a local log file with a realpath check and byte cap.

    When HERMES_CI_TRIAGE_LOG_ROOTS is set, the resolved path (after symlink
    resolution) must live inside one of those roots, so the tool cannot be
    steered into reading arbitrary files such as ~/.ssh/id_rsa or .env.
    """
    real = os.path.realpath(os.path.expanduser(path))
    roots = _log_roots()
    if roots and not _within_roots(real, roots):
        raise LogFetchError(
            f"Refusing to read a log outside the allowed roots: {_safe_path(path)}",
            f"The resolved path is outside {_LOG_ROOTS_ENV}; add its directory "
            "to that allowlist or point at an allowed path.",
        )
    p = Path(real)
    if not p.exists():
        raise LogFetchError(
            f"Log file not found: {_safe_path(path)}",
            "Provide a path to an existing CI log file, or an https:// URL "
            "to the raw log.",
        )
    if not p.is_file():
        raise LogFetchError(
            f"Not a regular file: {_safe_path(path)}",
            "Point log_url_or_path at a log file, not a directory, device, "
            "or pipe.",
        )
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise LogFetchError(
            f"Could not stat log file: {_safe_path(path)} ({type(exc).__name__})",
            _PERMS_HINT,
        )
    if size > MAX_LOG_BYTES:
        raise LogFetchError(
            f"Log file too large: {size} bytes (cap {MAX_LOG_BYTES}).",
            "Pre-trim the log, or point at the specific failing job's log.",
        )
    try:
        with p.open("rb") as fh:
            data = fh.read(MAX_LOG_BYTES)
    except OSError as exc:
        raise LogFetchError(
            f"Could not read log file: {_safe_path(path)} ({type(exc).__name__})",
            _PERMS_HINT,
        )
    return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------
# Remote retrieval
# --------------------------------------------------------------------------

def fetch_remote(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Fetch a remote log over HTTPS with auth, timeout and byte cap.

    Safety: HTTPS only; the token is attached only to GitHub hosts
    (:func:`_host_allows_token`) and stripped on cross-host redirects; requests
    to loopback/link-local/reserved addresses are refused to blunt SSRF (the
    redirect/connect-time guards live in :mod:`safehttp`).
    """
    if not (url or "").strip().lower().startswith("https://"):
        raise LogFetchError(
            f"Refusing non-HTTPS URL: {url}",
            "Use an https:// URL — plain http and other schemes are not "
            "allowed.",
        )

    host = urlsplit(url).hostname or ""
    if safehttp.is_blocked_address(host):
        raise LogFetchError(
            f"Refusing to fetch from a non-routable/internal address: {host}",
            safehttp.SSRF_HINT,
        )

    headers = {"User-Agent": _USER_AGENT, "Accept": "text/plain, */*"}
    token = os.environ.get(TOKEN_ENV_VAR, "").strip()
    if token and _host_allows_token(host):
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    context = ssl.create_default_context()
    opener = safehttp.build_opener(context)
    try:
        with opener.open(request, timeout=timeout) as resp:
            data = _read_capped(resp)
        return data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise LogFetchError(
                f"Authentication failed (HTTP {exc.code}) fetching {safehttp.safe_url(url)}.",
                f"Set the {TOKEN_ENV_VAR} environment variable to a token with "
                f"read access to the CI logs, then retry.",
            )
        if exc.code == 404:
            raise LogFetchError(
                f"Log not found (HTTP 404): {safehttp.safe_url(url)}",
                "Check the URL — the run/job log may have expired or rotated.",
            )
        raise LogFetchError(
            f"HTTP error {exc.code} fetching {safehttp.safe_url(url)}.",
            "Verify the URL and your network access.",
        )
    except socket.timeout:
        raise _timeout_error(url, timeout)
    except (urllib.error.URLError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise _timeout_error(url, timeout)
        raise LogFetchError(
            f"Network error fetching {safehttp.safe_url(url)}: {reason}",
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
