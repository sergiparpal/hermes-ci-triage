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

import http.client
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
_SSRF_HINT = (
    "Point at a public CI log URL; loopback, link-local, reserved and (by "
    "default) private/internal addresses are blocked to prevent SSRF. To allow "
    "RFC1918 ranges for self-hosted / GitHub Enterprise runners set "
    "HERMES_CI_TRIAGE_ALLOW_PRIVATE=1."
)

# Opt-in to permit RFC1918/private fetch destinations (self-hosted / GHE).
_ALLOW_PRIVATE_ENV = "HERMES_CI_TRIAGE_ALLOW_PRIVATE"
# Optional allowlist of directories local logs may be read from (os.pathsep-
# separated). Unset = no restriction (default); set it to confine reads so the
# tool cannot be steered into reading arbitrary files (~/.ssh/id_rsa, .env, …).
_LOG_ROOTS_ENV = "HERMES_CI_TRIAGE_LOG_ROOTS"


def _safe_url(url: str) -> str:
    """Scheme+host only — never echo a URL's path/query (may carry tokens/IDs)."""
    try:
        parts = urlsplit(url)
        if parts.scheme and parts.hostname:
            suffix = f":{parts.port}" if parts.port else ""
            return f"{parts.scheme}://{parts.hostname}{suffix}"
    except ValueError:
        pass
    return "the requested URL"


def _safe_path(path: str) -> str:
    """Basename only — don't echo the full local path back to the caller."""
    try:
        base = os.path.basename(str(path).rstrip("/").rstrip("\\"))
        return base or "the requested file"
    except Exception:
        return "the requested file"


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


def _allow_private() -> bool:
    """Whether RFC1918/private fetch destinations are permitted (opt-in)."""
    return os.environ.get(_ALLOW_PRIVATE_ENV, "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _ip_blocked(ip) -> bool:
    # Always block the SSRF-sensitive ranges: cloud metadata (169.254.169.254 is
    # link-local), loopback/localhost services, and unspecified/multicast/
    # reserved space. These stay blocked even when private ranges are permitted.
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    ):
        return True
    # Private/internal (RFC1918, CGNAT, …) is blocked by default; self-hosted or
    # GitHub Enterprise users opt back in via HERMES_CI_TRIAGE_ALLOW_PRIVATE.
    if ip.is_private and not _allow_private():
        return True
    return False


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


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but re-apply every safety check on each hop.

    The initial-URL guards (HTTPS-only, SSRF address blocking) are worthless if
    a redirect can escape them, so each redirect *target* is re-validated here:

    * non-HTTPS targets are refused — no http/ftp downgrade (e.g. a 302 to
      ``http://169.254.169.254/...`` to reach cloud metadata);
    * targets that are, or resolve to, loopback/link-local/reserved/(private)
      addresses are refused (SSRF);
    * the Authorization header is dropped on cross-host hops — GitHub serves
      job logs as a 302 to a pre-signed blob URL on a different host, and
      forwarding the bearer token there would leak it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        parts = urlsplit(newurl)
        if (parts.scheme or "").lower() != "https":
            raise LogFetchError(
                f"Refusing redirect to a non-HTTPS target ({_safe_url(newurl)}).",
                "The log host redirected to a non-HTTPS URL; only https:// "
                "targets are followed.",
            )
        if _is_blocked_address(parts.hostname or ""):
            raise LogFetchError(
                "Refusing redirect to a non-routable/internal address "
                f"({_safe_url(newurl)}).",
                _SSRF_HINT,
            )
        old_host = (urlsplit(req.full_url).hostname or "").lower()
        new_host = (parts.hostname or "").lower()
        if old_host != new_host:
            for key in list(new.headers):
                if key.lower() == "authorization":
                    del new.headers[key]
        return new


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that vets the resolved IP at the moment it connects.

    Closes the DNS-rebinding TOCTOU window for direct connections: the address
    we vet is exactly the one we then connect to. (The stdlib path resolves a
    second, independent time between an external pre-flight check and the socket
    connect, so a name that flips from a public to an internal address in
    between would slip past.)

    When a proxy CONNECT tunnel is in use the proxy performs resolution and we
    cannot pin the target IP, so we defer to the stdlib path; the pre-flight
    host check in :func:`fetch_remote` still applies in that case.
    """

    def connect(self):
        if getattr(self, "_tunnel_host", None):
            return super().connect()
        last_exc = None
        for _family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(
            self.host, self.port, 0, socket.SOCK_STREAM
        ):
            try:
                blocked = _ip_blocked(ipaddress.ip_address(sockaddr[0]))
            except ValueError:
                continue
            if blocked:
                raise LogFetchError(
                    "Refusing to connect to a non-routable/internal address "
                    f"({sockaddr[0]}).",
                    _SSRF_HINT,
                )
            try:
                sock = socket.create_connection(
                    (sockaddr[0], sockaddr[1]),
                    timeout=self.timeout,
                    source_address=self.source_address,
                )
            except OSError as exc:
                last_exc = exc
                continue
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            return
        if last_exc is not None:
            raise last_exc
        raise OSError(f"no permitted address for host {self.host!r}")


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler that connects via :class:`_GuardedHTTPSConnection`."""

    def https_open(self, req):
        return self.do_open(_GuardedHTTPSConnection, req, context=self._context)


def _build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    # _GuardedHTTPSHandler replaces the default HTTPSHandler and
    # _SafeRedirectHandler replaces the default redirect handler. The default
    # plain-HTTP/FTP/File/Data handlers remain installed but are unreachable:
    # the initial URL is HTTPS-only (fetch_remote) and every redirect target is
    # re-validated as HTTPS-only by _SafeRedirectHandler *before* any handler is
    # invoked for it — so no request can reach a non-HTTPS scheme handler.
    return urllib.request.build_opener(
        _GuardedHTTPSHandler(context=context),
        _SafeRedirectHandler(),
    )


def _timeout_error(url: str, timeout: float) -> LogFetchError:
    """The single source of truth for the fetch-timeout error envelope."""
    return LogFetchError(
        f"Timed out after {timeout}s fetching {_safe_url(url)}.", _TIMEOUT_HINT
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
            _SSRF_HINT,
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
                f"Authentication failed (HTTP {exc.code}) fetching {_safe_url(url)}.",
                f"Set the {TOKEN_ENV_VAR} environment variable to a token with "
                f"read access to the CI logs, then retry.",
            )
        if exc.code == 404:
            raise LogFetchError(
                f"Log not found (HTTP 404): {_safe_url(url)}",
                "Check the URL — the run/job log may have expired or rotated.",
            )
        raise LogFetchError(
            f"HTTP error {exc.code} fetching {_safe_url(url)}.",
            "Verify the URL and your network access.",
        )
    except socket.timeout:
        raise _timeout_error(url, timeout)
    except (urllib.error.URLError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise _timeout_error(url, timeout)
        raise LogFetchError(
            f"Network error fetching {_safe_url(url)}: {reason}",
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
