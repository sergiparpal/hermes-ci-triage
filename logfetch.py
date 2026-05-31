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

import os
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path

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


class LogFetchError(Exception):
    """A recoverable log-retrieval failure.

    ``remediation`` is an operator-facing hint the handler surfaces in the
    structured error envelope (e.g. "set GITHUB_TOKEN").
    """

    def __init__(self, message: str, remediation: str = "") -> None:
        super().__init__(message)
        self.remediation = remediation


def is_remote(target: str) -> bool:
    """True when *target* looks like an ``http(s)://`` URL (vs a local path)."""
    t = (target or "").strip().lower()
    return t.startswith("http://") or t.startswith("https://")


def has_remote_credentials() -> bool:
    """True when a remote-fetch token is present.

    Diagnostics only — used to annotate tool output. It is **not** wired to
    the tool's ``check_fn``: a missing token must never hide the tool, because
    local-path triage works without any credentials.
    """
    return bool(os.environ.get(TOKEN_ENV_VAR, "").strip())


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
        raise LogFetchError(
            f"Could not stat log file: {path} ({exc})",
            "Check the path and file permissions.",
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
            f"Could not read log file: {path} ({exc})",
            "Check the path and file permissions.",
        )
    return data.decode("utf-8", errors="replace")


def fetch_remote(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Fetch a remote log over HTTPS with auth, timeout and byte cap."""
    if not (url or "").strip().lower().startswith("https://"):
        raise LogFetchError(
            f"Refusing non-HTTPS URL: {url}",
            "Use an https:// URL — plain http and other schemes are not "
            "allowed.",
        )

    headers = {"User-Agent": _USER_AGENT, "Accept": "text/plain, */*"}
    token = os.environ.get(TOKEN_ENV_VAR, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            chunks = []
            total = 0
            while True:
                chunk = resp.read(_READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total >= MAX_LOG_BYTES:
                    chunks.append(chunk[: _READ_CHUNK - (total - MAX_LOG_BYTES)])
                    break
                chunks.append(chunk)
        return b"".join(chunks)[:MAX_LOG_BYTES].decode("utf-8", errors="replace")
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
    except (urllib.error.URLError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise LogFetchError(
            f"Network error fetching {url}: {reason}",
            "Check connectivity and that the host is reachable.",
        )
    except socket.timeout:
        raise LogFetchError(
            f"Timed out after {timeout}s fetching {url}.",
            "Retry, or point at a smaller/specific job log.",
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
