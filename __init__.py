"""hermes-ci-triage — classify CI/CD pipeline failures and learn per-project patterns.

A ``general`` (standalone) Hermes Agent plugin. It registers one tool,
``triage_pipeline_failure``, in the ``ci_triage`` toolset. The tool fetches a
CI log (local path or https URL), pre-filters it to a bounded excerpt, asks the
host LLM to classify the failure into a fixed taxonomy (with a deterministic
rule-based fallback), and learns the failure pattern per project in local
SQLite.

This module is the only file that touches Hermes; the heavy lifting lives in
pure-stdlib siblings (``logfetch``, ``prefilter``, ``classifier``,
``patterns``, ``handlers``) which import nothing from Hermes and unit-test in
isolation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from . import handlers

logger = logging.getLogger(__name__)

TOOL_NAME = "triage_pipeline_failure"
TOOLSET = "ci_triage"

# Runtime version guard (warn-only — never crash a load). Baseline per the
# implementation plan; the manifest cannot pin this, so we check here.
_MIN_HERMES_VERSION = (0, 14, 0)

# Decision point 2: optional hermes-test-history enrichment, guarded.
ENABLE_ENRICHMENT = True

TRIAGE_SCHEMA = {
    "name": TOOL_NAME,
    "description": (
        "Triage a failed CI/CD pipeline run. Use this when you have a build, "
        "test, or deploy log (a local file path or an https:// URL to the raw "
        "log) and need to know WHY it failed. It pre-filters the log to the "
        "failure-relevant lines, classifies the root cause into one fixed "
        "category — broken_test, environment, data, timeout, flaky, or infra "
        "— and learns the pattern per project so repeat failures are "
        "recognised. Returns a JSON object with: category, confidence (0-1), a "
        "one-line summary, supporting evidence lines, a suggested next action, "
        "whether this signature was seen before (prior_seen / "
        "prior_occurrences), and log_stats. On failure it returns "
        "{success:false, error, remediation}. Local-file triage needs no "
        "credentials; fetching protected remote logs reads a token from the "
        "environment."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "log_url_or_path": {
                "type": "string",
                "description": (
                    "Local filesystem path to a CI log file, OR an https:// "
                    "URL to the raw log. Plain http and non-file schemes are "
                    "rejected."
                ),
            },
            "project": {
                "type": "string",
                "description": (
                    "Optional project key to scope pattern learning. Defaults "
                    "to the current working directory's name."
                ),
            },
        },
        "required": ["log_url_or_path"],
    },
}


def _check_version() -> None:
    """Warn (never raise) if the running Hermes predates the baseline."""
    try:
        from hermes_cli import __version__ as raw
        parts = tuple(int(x) for x in str(raw).split(".")[:3])
        if parts < _MIN_HERMES_VERSION:
            logger.warning(
                "hermes-ci-triage targets Hermes >= %s but found %s; "
                "proceeding, but some behaviour may differ.",
                ".".join(map(str, _MIN_HERMES_VERSION)),
                raw,
            )
    except Exception:
        logger.debug("could not determine Hermes version for guard", exc_info=True)


def register(ctx: Any) -> None:
    """Plugin entry point — register the triage tool."""
    _check_version()

    def handler(args, **kwargs):
        try:
            return handlers.triage_pipeline_failure(
                args if isinstance(args, dict) else {},
                llm=getattr(ctx, "llm", None),
                dispatch_tool=getattr(ctx, "dispatch_tool", None),
                enable_enrichment=ENABLE_ENRICHMENT,
            )
        except Exception as exc:  # last-resort guard — handler is the boundary
            logger.exception("triage_pipeline_failure crashed")
            return json.dumps({
                "success": False,
                "error": f"internal error ({type(exc).__name__})",
                "remediation": "See the agent log for details.",
            })

    # No check_fn: the tool must always be available because local-path triage
    # works without any credentials. Remote-auth state is reported in the
    # tool's own output, not used to hide it.
    ctx.register_tool(TOOL_NAME, TOOLSET, TRIAGE_SCHEMA, handler)
    logger.info("hermes-ci-triage registered tool %s in toolset %s", TOOL_NAME, TOOLSET)
