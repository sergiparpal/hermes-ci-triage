"""Hardened HTTPS transport + SSRF address vetting.

This is the security-critical lower layer beneath :mod:`logfetch`: it knows
nothing about CI providers, tokens, or local files — only how to open an HTTPS
URL *safely* and how to decide whether an address is one we refuse to touch.
Isolating it here means the highest-risk code in the plugin (the redirect and
connect-time guards) can be read, reasoned about, and unit-tested on its own,
and :mod:`logfetch` shrinks to retrieval policy.

The SSRF defences are re-applied **per hop**, not just on the initial URL:

* HTTPS-only is re-validated on every redirect (no http/ftp/data downgrade);
* the redirect *target* is re-checked against the address blocklist;
* the resolved IP is vetted at the moment of connect, closing the DNS-rebinding
  TOCTOU window for direct connections;
* loopback / link-local / cloud-metadata / reserved ranges are blocked
  regardless of the private-range opt-in.

:class:`LogFetchError` is defined here (the lowest layer that raises it) and
re-exported by :mod:`logfetch` so callers keep using ``logfetch.LogFetchError``.

Pure standard library (``http.client``, ``ipaddress``, ``os``, ``socket``,
``ssl``, ``urllib``) — no Hermes dependency, so it unit-tests in isolation.
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
import urllib.request
from urllib.parse import urlsplit

# Opt-in to permit RFC1918/private fetch destinations (self-hosted / GHE).
_ALLOW_PRIVATE_ENV = "HERMES_CI_TRIAGE_ALLOW_PRIVATE"

SSRF_HINT = (
    "Point at a public CI log URL; loopback, link-local, reserved and (by "
    "default) private/internal addresses are blocked to prevent SSRF. To allow "
    "RFC1918 ranges for self-hosted / GitHub Enterprise runners set "
    "HERMES_CI_TRIAGE_ALLOW_PRIVATE=1."
)


class LogFetchError(Exception):
    """A recoverable log-retrieval failure.

    ``remediation`` is an operator-facing hint the handler surfaces in the
    structured error envelope (e.g. "set GITHUB_TOKEN").
    """

    def __init__(self, message: str, remediation: str = "") -> None:
        super().__init__(message)
        self.remediation = remediation


def safe_url(url: str) -> str:
    """Scheme+host only — never echo a URL's path/query (may carry tokens/IDs)."""
    try:
        parts = urlsplit(url)
        if parts.scheme and parts.hostname:
            suffix = f":{parts.port}" if parts.port else ""
            return f"{parts.scheme}://{parts.hostname}{suffix}"
    except ValueError:
        pass
    return "the requested URL"


# --------------------------------------------------------------------------
# Address vetting
# --------------------------------------------------------------------------

def _allow_private() -> bool:
    """Whether RFC1918/private fetch destinations are permitted (opt-in)."""
    return os.environ.get(_ALLOW_PRIVATE_ENV, "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def ip_blocked(ip) -> bool:
    """True for an address we refuse to connect to (SSRF defence)."""
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


def is_blocked_address(host: str) -> bool:
    """True if *host* is, or resolves to, a non-routable/internal address."""
    if not host:
        return False
    try:
        return ip_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass  # not a literal IP — resolve it
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # let the real connection attempt surface a network error
    for info in infos:
        try:
            if ip_blocked(ipaddress.ip_address(info[4][0])):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------
# Guarded opener (redirect + connect-time vetting)
# --------------------------------------------------------------------------

class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
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

    Note the contract departure from the stdlib base: this *raises*
    :class:`LogFetchError` to abort a fetch where the base would proceed. That
    is intentional and only safe because this handler is installed solely by
    :func:`build_opener`, never used as a general-purpose substitute.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        parts = urlsplit(newurl)
        if (parts.scheme or "").lower() != "https":
            raise LogFetchError(
                f"Refusing redirect to a non-HTTPS target ({safe_url(newurl)}).",
                "The log host redirected to a non-HTTPS URL; only https:// "
                "targets are followed.",
            )
        if is_blocked_address(parts.hostname or ""):
            raise LogFetchError(
                "Refusing redirect to a non-routable/internal address "
                f"({safe_url(newurl)}).",
                SSRF_HINT,
            )
        old_host = (urlsplit(req.full_url).hostname or "").lower()
        new_host = (parts.hostname or "").lower()
        if old_host != new_host:
            for key in list(new.headers):
                if key.lower() == "authorization":
                    del new.headers[key]
        return new


class GuardedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that vets the resolved IP at the moment it connects.

    Closes the DNS-rebinding TOCTOU window for direct connections: the address
    we vet is exactly the one we then connect to. (The stdlib path resolves a
    second, independent time between an external pre-flight check and the socket
    connect, so a name that flips from a public to an internal address in
    between would slip past.)

    When a proxy CONNECT tunnel is in use the proxy performs resolution and we
    cannot pin the target IP, so we defer to the stdlib path; the pre-flight
    host check in :func:`logfetch.fetch_remote` still applies in that case.
    """

    def connect(self):
        if getattr(self, "_tunnel_host", None):
            return super().connect()
        last_exc = None
        for _family, _socktype, _proto, _canon, sockaddr in socket.getaddrinfo(
            self.host, self.port, 0, socket.SOCK_STREAM
        ):
            try:
                blocked = ip_blocked(ipaddress.ip_address(sockaddr[0]))
            except ValueError:
                continue
            if blocked:
                raise LogFetchError(
                    "Refusing to connect to a non-routable/internal address "
                    f"({sockaddr[0]}).",
                    SSRF_HINT,
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


class GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler that connects via :class:`GuardedHTTPSConnection`."""

    def https_open(self, req):
        return self.do_open(GuardedHTTPSConnection, req, context=self._context)


def build_opener(context: ssl.SSLContext) -> urllib.request.OpenerDirector:
    """An opener whose only reachable scheme is guarded HTTPS.

    :class:`GuardedHTTPSHandler` replaces the default HTTPSHandler and
    :class:`SafeRedirectHandler` replaces the default redirect handler. The
    default plain-HTTP/FTP/File/Data handlers remain installed but are
    unreachable: the initial URL is HTTPS-only (``logfetch.fetch_remote``) and
    every redirect target is re-validated as HTTPS-only by
    :class:`SafeRedirectHandler` *before* any handler is invoked for it — so no
    request can reach a non-HTTPS scheme handler.
    """
    return urllib.request.build_opener(
        GuardedHTTPSHandler(context=context),
        SafeRedirectHandler(),
    )
