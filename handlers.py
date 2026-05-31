"""Handler glue for ``triage_pipeline_failure``.

Orchestrates the pipeline:

    validate input
      → logfetch (local path or https URL)
      → prefilter (bounded, signal-dense excerpt)
      → compute signature
      → patterns.lookup (prior becomes a classifier hint)
      → optional ctx.dispatch_tool enrichment (guarded, non-fatal)
      → classifier.classify (LLM + heuristic fallback)
      → patterns.record
      → JSON envelope

Kept thin: this module decides nothing about *how* each step works, only the
order and the error contract. It is pure standard library — Hermes objects
(``llm``, ``dispatch_tool``, ``hermes_home``) are injected by ``register()``
in ``__init__.py`` — so it unit-tests with fakes.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional

from . import classifier, logfetch, patterns, prefilter

logger = logging.getLogger(__name__)

# How many tail lines to classify when the log carries no clear failure signal.
_NO_SIGNAL_TAIL_LINES = 60
# Cap on the single signal line used to seed enrichment lookups.
_SIGNAL_LINE_CHARS = 200
_DB_RELATIVE = ("cache", "ci_triage_patterns.db")


# --------------------------------------------------------------------------
# Envelopes
# --------------------------------------------------------------------------

def _error(message: str, remediation: str = "") -> str:
    return json.dumps(
        {"success": False, "error": message, "remediation": remediation},
        ensure_ascii=False,
    )


def _ok(payload: dict[str, Any]) -> str:
    return json.dumps({"success": True, **payload}, ensure_ascii=False)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _resolve_hermes_home(hermes_home: Optional[str]) -> Path:
    if hermes_home:
        return Path(hermes_home)
    try:
        from hermes_constants import get_hermes_home  # type: ignore
        return get_hermes_home()
    except Exception:
        logger.debug(
            "hermes_constants unavailable; resolving HERMES_HOME from env",
            exc_info=True,
        )
        val = (os.environ.get("HERMES_HOME") or "").strip()
        return Path(val).resolve() if val else (Path.home() / ".hermes").resolve()


def _db_path(hermes_home: Optional[str]) -> Path:
    return _resolve_hermes_home(hermes_home).joinpath(*_DB_RELATIVE)


def _infer_project(args: dict[str, Any]) -> str:
    explicit = args.get("project")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()
    cwd = (os.environ.get("TERMINAL_CWD") or os.getcwd() or "").strip()
    name = os.path.basename(cwd.rstrip("/")) if cwd else ""
    return name or "default"


def _tail_excerpt(raw: str, n_lines: int = _NO_SIGNAL_TAIL_LINES) -> str:
    lines = prefilter.strip_ansi(raw).split("\n")
    return "\n".join(lines[-n_lines:])


def _is_unknown_tool(data: Any) -> bool:
    """True for a registry-miss envelope: a lone ``{"error": "..."}``.

    A tool that actually ran returns more than just an error key, so the
    single-key shape is what distinguishes 'tool not registered' from a tool
    that ran and reported a problem worth surfacing.
    """
    return isinstance(data, dict) and bool(data.get("error")) and len(data) == 1


def _try_enrich(
    dispatch_tool: Optional[Callable[..., str]], excerpt: str
) -> Optional[Any]:
    """Guarded optional enrichment via a test-history tool.

    Non-fatal: any absence/error returns ``None``. We deliberately do not
    name the tool in the user-facing schema; the dependency is soft.
    """
    if dispatch_tool is None:
        return None
    query = _top_signal_line(excerpt)
    for tool_name, arg_key in (
        ("test_failure_lookup", "query"),
        ("module_failure_history", "query"),
    ):
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


def _top_signal_line(excerpt: str) -> str:
    for line in (excerpt or "").split("\n"):
        if prefilter.is_failure_line(line):
            return line.strip()[:_SIGNAL_LINE_CHARS]
    return (excerpt or "").strip().split("\n")[0][:_SIGNAL_LINE_CHARS]


def _open_and_lookup(
    db_path: Path, project: str, signature: str, excerpt: str
) -> tuple[Optional[patterns.PatternStore], Optional[dict[str, Any]]]:
    """Open the pattern store and fetch any prior for *signature*.

    Returns ``(store, prior)`` on success — the caller owns the open store and
    must close it. On any failure returns ``(None, None)`` with the connection
    already closed, so the caller's happy path needs only a single
    ``finally``-close around the later record step.
    """
    store: Optional[patterns.PatternStore] = None
    try:
        store = patterns.PatternStore(db_path)
        return store, store.lookup(project, signature, excerpt)
    except Exception:
        logger.warning("pattern store unavailable", exc_info=True)
        if store is not None:
            try:
                store.close()  # don't leak the connection on a lookup error
            except Exception:
                pass
        return None, None


# --------------------------------------------------------------------------
# Tool entry point
# --------------------------------------------------------------------------

def triage_pipeline_failure(
    args: dict[str, Any],
    *,
    llm: Any = None,
    dispatch_tool: Optional[Callable[..., str]] = None,
    hermes_home: Optional[str] = None,
    enable_enrichment: bool = True,
) -> str:
    """Triage one CI/CD pipeline failure log. Always returns a JSON string."""
    # --- validate (before any side effect) -------------------------------
    if not isinstance(args, dict):
        return _error(
            "Invalid arguments: expected an object.",
            "Call with {\"log_url_or_path\": \"...\"}.",
        )
    target = args.get("log_url_or_path")
    if not isinstance(target, str) or not target.strip():
        return _error(
            "Missing required argument 'log_url_or_path'.",
            "Pass a local CI log file path or an https:// URL to the raw log.",
        )
    project = _infer_project(args)

    # --- retrieve --------------------------------------------------------
    try:
        raw = logfetch.fetch(target)
    except logfetch.LogFetchError as exc:
        return _error(str(exc), getattr(exc, "remediation", ""))
    except Exception as exc:  # defensive — never leak a traceback
        logger.exception("log retrieval failed")
        return _error(
            f"Failed to retrieve log ({type(exc).__name__}).",
            "Check the path/URL and try again.",
        )

    # --- pre-filter ------------------------------------------------------
    excerpt, stats = prefilter.prefilter(raw)
    low_signal = stats.get("hit_count", 0) == 0
    if low_signal:
        excerpt = _tail_excerpt(raw)

    # --- signature + prior ----------------------------------------------
    signature = patterns.compute_signature(excerpt)
    # An excerpt that normalises to nothing yields the empty-string signature,
    # which would collide across all such logs — skip the store entirely.
    has_signature = bool(patterns.normalize_signature_text(excerpt))
    store: Optional[patterns.PatternStore] = None
    prior: Optional[dict[str, Any]] = None
    if has_signature:
        store, prior = _open_and_lookup(
            _db_path(hermes_home), project, signature, excerpt
        )

    # --- optional enrichment (guarded) ----------------------------------
    enrichment = None
    if enable_enrichment:
        enrichment = _try_enrich(dispatch_tool, excerpt)

    # --- classify --------------------------------------------------------
    result = classifier.classify(llm, excerpt, prior=prior, enrichment=enrichment)

    # --- record ----------------------------------------------------------
    prior_occurrences = int(prior.get("occurrences", 0)) if prior else 0
    # Don't teach the store low-signal heuristic defaults — they'd resurface as
    # noisy fuzzy priors. A confident LLM call on a low-signal log still learns.
    learn = not (low_signal and result.get("method") == "heuristic")
    if store is not None:
        try:
            if learn:
                store.record(project, signature, result["category"], excerpt)
        except Exception:
            logger.warning("pattern record failed", exc_info=True)
        finally:
            store.close()

    # --- respond ---------------------------------------------------------
    payload: dict[str, Any] = {
        "category": result["category"],
        "confidence": round(float(result.get("confidence", 0.0)), 3),
        "summary": result.get("summary", ""),
        "evidence": result.get("evidence", []),
        "suggested_action": result.get("suggested_action", ""),
        "classification_method": result.get("method", "llm"),
        "prior_seen": prior is not None,
        "prior_occurrences": prior_occurrences,
        "project": project,
        "signature": signature,
        "log_stats": {
            "original_bytes": stats.get("original_bytes", 0),
            "hit_count": stats.get("hit_count", 0),
            "truncated": stats.get("truncated", False),
            "low_signal": low_signal,
        },
    }
    if prior is not None and prior.get("fuzzy"):
        payload["prior_match"] = "fuzzy"
    if enrichment is not None:
        payload["enrichment"] = enrichment
    return _ok(payload)
