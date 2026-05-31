"""Optional triage enrichment via a partner *test-history* tool (guarded).

This is the **adapter** to another plugin's tools — it owns their names, their
argument keys, and the heuristic for telling "that tool isn't registered" apart
from "that tool ran and reported a problem". Keeping it out of ``handlers`` lets
the orchestrator decide only *whether* to enrich, not *how*; the partner-tool
contract can change here without touching the pipeline.

Soft dependency by design: any absence or error returns ``None`` (non-fatal),
and the partner tools are deliberately **not** named in the user-facing tool
schema, so the model never hallucinates calls to a toolset that may be disabled.

Security note: this module does **not** redact. The orchestrator scrubs both the
excerpt it passes in (so the query we derive is already clean) and the object we
return (before it is fed to the LLM or echoed back). Redaction stays a single
chokepoint in ``handlers`` — see the redaction invariant in CLAUDE.md.

Pure standard library; depends only on the sibling ``prefilter`` for failure-
line detection and on the ``ports`` Protocols for typing.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from . import prefilter
from .ports import ToolDispatcher

logger = logging.getLogger(__name__)

# Cap on the single signal line used to seed enrichment lookups.
_SIGNAL_LINE_CHARS = 200

# Partner tools tried in order, with the argument key each expects. The first
# one that actually runs and returns usable data wins.
_CANDIDATE_TOOLS = (
    ("test_failure_lookup", "query"),
    ("module_failure_history", "query"),
)


def _top_signal_line(excerpt: str) -> str:
    """Pick the most representative line of *excerpt* to seed the lookup query."""
    for line in (excerpt or "").split("\n"):
        if prefilter.is_failure_line(line):
            return line.strip()[:_SIGNAL_LINE_CHARS]
    return (excerpt or "").strip().split("\n")[0][:_SIGNAL_LINE_CHARS]


def _is_unknown_tool(data: Any) -> bool:
    """True for a registry-miss envelope: a lone ``{"error": "..."}``.

    A tool that actually ran returns more than just an error key, so the
    single-key shape is what distinguishes 'tool not registered' from a tool
    that ran and reported a problem worth surfacing.
    """
    return isinstance(data, dict) and bool(data.get("error")) and len(data) == 1


def enrich(
    dispatch_tool: Optional[ToolDispatcher], excerpt: str
) -> Optional[dict[str, Any]]:
    """Try the partner test-history tools; return ``{source, result}`` or None.

    Non-fatal: a missing dispatcher, an unregistered tool, an exception, or an
    empty/garbled response all yield ``None``. The returned object is *not*
    redacted — the caller must scrub it before use (see module docstring).
    """
    if dispatch_tool is None:
        return None
    query = _top_signal_line(excerpt)
    for tool_name, arg_key in _CANDIDATE_TOOLS:
        try:
            raw = dispatch_tool(tool_name, {arg_key: query})
        except Exception:
            logger.debug("enrichment via %s failed", tool_name, exc_info=True)
            continue
        if not raw:
            continue
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, ValueError):
            data = raw
        if _is_unknown_tool(data):
            continue
        return {"source": tool_name, "result": data}
    return None
