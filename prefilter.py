"""Local pre-filtering of CI/CD logs — the cost/latency control.

Real CI logs routinely exceed 10 MB. Sending one whole into an LLM breaks
prompt cache and inflates cost for no benefit, because the failure signal is
almost always a few dozen lines clustered near the end. This module shrinks a
raw log down to a bounded, signal-dense excerpt **before** any model call.

The public entry point is :func:`prefilter`, which returns
``(excerpt, stats)``. It is pure standard library and has no dependency on
Hermes, so it can be unit-tested in isolation.

Design notes:

* ANSI escape sequences are stripped first (CI runners colourise output).
* Lines matching a failure-signal regex anchor a context window
  (``before`` lines above / ``after`` below); overlapping windows merge.
* Runs of identical consecutive lines collapse to one line plus a count
  marker (stack frames and progress bars love to repeat).
* The excerpt is capped by characters *and* lines, whichever binds first.
  When the material overflows, the **tail** is kept (errors cluster at the
  end) and a one-line truncation note is prepended.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# Bounds (defaults — overridable per call)
# --------------------------------------------------------------------------

DEFAULT_BEFORE = 8          # context lines kept above each signal hit
DEFAULT_AFTER = 12          # context lines kept below each signal hit
DEFAULT_CHAR_CAP = 12_000   # hard cap on excerpt characters
DEFAULT_LINE_CAP = 200      # hard cap on excerpt lines
_COLLAPSE_THRESHOLD = 3     # collapse a run only once it reaches this length

TRUNCATION_NOTE = (
    "[hermes-ci-triage: pre-filter truncated — showing the most recent "
    "failure context; earlier matching regions were omitted]"
)

# --------------------------------------------------------------------------
# Failure-signal patterns
#
# Two compiled regexes per line keeps each pattern readable and lets us mix
# case-sensitive (CamelCase exception names) with case-insensitive keywords.
# Over-inclusion is harmless here — everything is bounded by the caps below.
# --------------------------------------------------------------------------

_KEYWORD_RE = re.compile(
    r"""
    \b(?:
        fail(?:ed|ure|ing)?            # fail / failed / failure / failing
      | error(?:s|ed)?                 # error / errors / errored
      | exception                      # bare 'exception'
      | traceback\ \(most\ recent      # python traceback header
      | panic(?::|\b)                  # go / rust panic
      | fatal                          # fatal:
      | segfault|segmentation\ fault   # native crashes
      | timed\ out|timeout             # timeouts
      | deadline\ exceeded
      | killed|oomkilled               # OOM / signal kills
      | assertion\ failed
      | no\ space\ left\ on\ device
      | connection\ (?:refused|reset)
      | could\ not\ resolve\ host
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# CamelCase exception / error class names: ValueError, RuntimeException,
# ModuleNotFoundError, TimeoutError, DeprecationWarning, ... Case-sensitive so
# it does not collide with the lowercase keyword 'error' above.
_CAMEL_RE = re.compile(r"\b[A-Z][A-Za-z0-9_]*(?:Error|Exception|Warning)\b")

# Non-zero exit / return codes from shells, make, subprocess, etc.
# Intentionally over-inclusive: the 'returned N' branch also matches benign
# phrasing like "returned 5 items". Harmless — everything is bounded by the
# caps above — so do not "tighten" this without re-checking the cost rationale.
_EXIT_RE = re.compile(
    r"(?:exit(?:ed)?(?:\ with)?(?:\ code| status)?|returned(?:\ non-zero\ exit\ status)?)"
    r"[:=\s]+([1-9]\d*)\b",
    re.IGNORECASE,
)

# Test-framework summary / report markers.
_FRAMEWORK_RE = re.compile(
    r"(?:"
    r"\b\d+\ (?:failed|errors?)\b"      # pytest: '3 failed, 5 passed'
    r"|<(?:failure|error)[\s>]"          # junit xml
    r"|FAILED\ "                          # pytest node id line
    r"|✕|✗|×"                              # mocha/jest fail glyphs
    r"|npm\ ERR!"
    r")",
    re.IGNORECASE,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    """Remove ANSI/VT100 escape sequences from *text*."""
    return _ANSI_RE.sub("", text)


def is_failure_line(line: str) -> bool:
    """Return True when *line* carries a recognised failure signal.

    Called once per log line; the per-line regex cost is bounded by the 25 MB
    fetch cap upstream. Blank lines short-circuit before any regex runs.
    """
    if not line:
        return False
    return bool(
        _KEYWORD_RE.search(line)
        or _CAMEL_RE.search(line)
        or _EXIT_RE.search(line)
        or _FRAMEWORK_RE.search(line)
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _merge_windows(
    hits: list[int], n_lines: int, before: int, after: int
) -> list[tuple[int, int]]:
    """Turn signal-hit line indices into merged ``[start, end)`` ranges."""
    ranges: list[tuple[int, int]] = []
    for i in hits:
        start = max(0, i - before)
        end = min(n_lines, i + after + 1)
        if ranges and start <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((start, end))
    return ranges


def _collapse_runs(block: list[str]) -> list[str]:
    """Collapse runs of identical consecutive lines into one + a marker."""
    out: list[str] = []
    i, n = 0, len(block)
    while i < n:
        j = i
        while j < n and block[j] == block[i]:
            j += 1
        run = j - i
        if run >= _COLLAPSE_THRESHOLD:
            repeats = run - 1
            out.append(block[i])
            out.append(
                f"        ⟪ previous line repeated {repeats} more "
                f"time{'s' if repeats != 1 else ''} ⟫"
            )
        else:
            out.extend(block[i:j])
        i = j
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def prefilter(
    raw_text: str,
    *,
    before: int = DEFAULT_BEFORE,
    after: int = DEFAULT_AFTER,
    char_cap: int = DEFAULT_CHAR_CAP,
    line_cap: int = DEFAULT_LINE_CAP,
) -> tuple[str, dict[str, object]]:
    """Reduce a raw CI log to a bounded, signal-dense excerpt.

    Returns ``(excerpt, stats)``. ``stats`` always contains
    ``original_bytes``, ``original_lines``, ``hit_count``, ``truncated``,
    ``excerpt_lines`` and ``excerpt_chars``. When the log carries no failure
    signal the excerpt is empty and ``hit_count`` is ``0``.
    """
    raw_text = raw_text or ""
    original_bytes = len(raw_text.encode("utf-8", "replace"))
    text = strip_ansi(raw_text)
    lines = text.split("\n")
    original_lines = len(lines)

    hits = [i for i, ln in enumerate(lines) if is_failure_line(ln)]
    stats: dict[str, object] = {
        "original_bytes": original_bytes,
        "original_lines": original_lines,
        "hit_count": len(hits),
        "truncated": False,
        "excerpt_lines": 0,
        "excerpt_chars": 0,
    }
    if not hits:
        return "", stats

    ranges = _merge_windows(hits, len(lines), before, after)

    parts: list[str] = []
    prev_end = None
    for (start, end) in ranges:
        if prev_end is not None and start > prev_end:
            parts.append(f"        ... ({start - prev_end} lines omitted) ...")
        parts.extend(_collapse_runs(lines[start:end]))
        prev_end = end

    truncated = False

    # Line cap — keep the tail (failures cluster at the end).
    if len(parts) > line_cap:
        parts = parts[-line_cap:]
        truncated = True

    excerpt = "\n".join(parts)

    # Char cap — keep the tail, then snap to a clean line boundary.
    if len(excerpt) > char_cap:
        excerpt = excerpt[-char_cap:]
        first_nl = excerpt.find("\n")
        if 0 <= first_nl < len(excerpt) - 1:
            excerpt = excerpt[first_nl + 1:]
        truncated = True

    if truncated:
        excerpt = TRUNCATION_NOTE + "\n" + excerpt

    stats["truncated"] = truncated
    stats["excerpt_lines"] = excerpt.count("\n") + 1 if excerpt else 0
    stats["excerpt_chars"] = len(excerpt)
    return excerpt, stats
