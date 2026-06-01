"""Secret redaction for log excerpts before they leave the host.

CI logs routinely contain credentials (tokens, keys, connection strings). This
module scrubs the common formats from any text that is about to be (a) sent to
the LLM provider for classification, (b) forwarded to another tool, or (c)
echoed back in the tool's result — so a secret that leaked into a build log is
not propagated or reflected further.

Pure standard library; no Hermes dependency. Conservative by design: it targets
well-known secret *shapes* and explicit ``key = value`` secret assignments, so
it does not mangle ordinary failure text (a failure signal is never a token).
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER = "<REDACTED>"

# Standalone secret formats — the whole match is replaced.
_TOKEN_PATTERNS = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),            # GitHub PAT/OAuth/app/refresh
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),          # GitHub fine-grained PAT
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{12,}\b"),  # AWS key id
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),          # Slack
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35,}\b"),               # Google API key
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                   # OpenAI-style secret key
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),  # JWT
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        re.DOTALL,
    ),
]

# ``key = value`` / ``key: value`` assignments where the key names a secret.
# Only the value is replaced; the key (and surrounding quotes, if any) are kept
# so the line stays readable for triage. An explicit ':' or '=' separator is
# required, so prose such as "token not found" (no separator) is left intact.
# The value may be wrapped in matching single/double quotes — common in env
# dumps and `set -x` output (``PASSWORD="secret"``) — which the value class
# itself excludes, so they are matched explicitly via an optional quote whose
# close is a backreference.
_KV_PATTERN = re.compile(
    r"(?P<key>\b[\w.-]*?"
    r"(?:authorization|bearer|client[_-]?secret|private[_-]?key|access[_-]?key"
    r"|api[_-]?key|apikey|secret|password|passwd|pwd|token)\b)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>[\"']?)"
    r"(?P<val>(?:bearer\s+)?[^\s\"',;]{4,})"
    r"(?P=quote)",
    re.IGNORECASE,
)


def _kv_sub(m: "re.Match") -> str:
    quote = m.group("quote")
    return f"{m.group('key')}{m.group('sep')}{quote}{PLACEHOLDER}{quote}"


def redact(text: str) -> str:
    """Return *text* with recognised secrets replaced by :data:`PLACEHOLDER`."""
    if not text:
        return text
    out = text
    for pat in _TOKEN_PATTERNS:
        out = pat.sub(PLACEHOLDER, out)
    out = _KV_PATTERN.sub(_kv_sub, out)
    return out


def redact_obj(obj: Any) -> Any:
    """Recursively redact every string inside a JSON-ish structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj
