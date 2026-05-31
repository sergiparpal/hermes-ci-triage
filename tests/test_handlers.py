"""handlers: end-to-end pipeline with mocked llm / dispatch_tool."""

from __future__ import annotations

import json

import pytest

from hermes_plugins.hermes_ci_triage import classifier, handlers


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------

class _FakeStructured:
    def __init__(self, parsed, content_type="json", text=""):
        self.parsed = parsed
        self.content_type = content_type
        self.text = text


class FakeLlm:
    """Stand-in for ctx.llm. Records calls; returns a canned structured result."""

    def __init__(self, parsed=None, content_type="json", raise_exc=None):
        self._parsed = parsed
        self._ct = content_type
        self._raise = raise_exc
        self.calls = []

    def complete_structured(self, **kwargs):
        self.calls.append(kwargs)
        if self._raise is not None:
            raise self._raise
        return _FakeStructured(self._parsed, self._ct)


# Each fixture is crafted so the rule-based heuristic resolves it to its label.
CATEGORY_FIXTURES = {
    "broken_test": "AssertionError: expected 5 but got 4\nFAILED tests/test_math.py::test_add\n",
    "environment": "ModuleNotFoundError: No module named 'requests'\npip install failed\n",
    "data": "json.decoder.JSONDecodeError: Expecting value: line 1 column 1\nfixture load failed\n",
    "timeout": "step timed out after 600s\nTimeoutError: deadline exceeded\n",
    "flaky": "test failed but passed on retry (flaky)\nintermittent failure detected\n",
    "infra": "No space left on device\nrunner disconnected mid-job\n",
}


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# --------------------------------------------------------------------------
# Heuristic path (llm unavailable) — one fixture per taxonomy category
# --------------------------------------------------------------------------

@pytest.mark.parametrize("expected,log_text", list(CATEGORY_FIXTURES.items()))
def test_heuristic_classifies_each_category(tmp_path, tmp_hermes_home, expected, log_text):
    path = _write(tmp_path, f"{expected}.log", log_text)
    out = handlers.triage_pipeline_failure({"log_url_or_path": path, "project": "p"}, llm=None)
    data = json.loads(out)
    assert data["success"] is True
    assert data["category"] == expected
    assert data["classification_method"] == "heuristic"
    assert isinstance(out, str)


# --------------------------------------------------------------------------
# LLM path takes precedence and passes the schema through
# --------------------------------------------------------------------------

def test_llm_path_used_when_valid(tmp_path, tmp_hermes_home):
    # A broken_test-looking log, but the (mocked) llm says 'infra' — llm wins.
    path = _write(tmp_path, "x.log", "AssertionError: boom\nFAILED test_x\n")
    llm = FakeLlm(parsed={"category": "infra", "confidence": 0.92,
                          "summary": "runner died", "evidence": ["x"],
                          "suggested_action": "retry"})
    out = handlers.triage_pipeline_failure({"log_url_or_path": path}, llm=llm)
    data = json.loads(out)
    assert data["category"] == "infra"
    assert data["classification_method"] == "llm"
    assert data["confidence"] == 0.92
    # The fixed taxonomy schema was passed to the structured call.
    assert llm.calls and llm.calls[0]["json_schema"] is classifier.CLASSIFICATION_SCHEMA


def test_invalid_llm_output_falls_back_to_heuristic(tmp_path, tmp_hermes_home):
    path = _write(tmp_path, "x.log", "ModuleNotFoundError: No module named 'x'\n")
    # content_type 'text' (e.g. the model refused / returned prose) → fallback.
    llm = FakeLlm(parsed=None, content_type="text")
    out = handlers.triage_pipeline_failure({"log_url_or_path": path}, llm=llm)
    data = json.loads(out)
    assert data["success"] is True
    assert data["category"] == "environment"
    assert data["classification_method"] == "heuristic"


def test_llm_raising_falls_back(tmp_path, tmp_hermes_home):
    path = _write(tmp_path, "x.log", "No space left on device\n")
    llm = FakeLlm(raise_exc=ValueError("schema mismatch"))
    out = handlers.triage_pipeline_failure({"log_url_or_path": path}, llm=llm)
    data = json.loads(out)
    assert data["success"] is True
    assert data["category"] == "infra"


# --------------------------------------------------------------------------
# Error contract
# --------------------------------------------------------------------------

def test_missing_local_file_structured_error(tmp_path, tmp_hermes_home):
    out = handlers.triage_pipeline_failure(
        {"log_url_or_path": str(tmp_path / "absent.log")}, llm=None)
    data = json.loads(out)
    assert data["success"] is False
    assert "error" in data and "remediation" in data


def test_missing_argument_structured_error(tmp_hermes_home):
    data = json.loads(handlers.triage_pipeline_failure({}, llm=None))
    assert data["success"] is False
    assert "log_url_or_path" in data["error"]


# --------------------------------------------------------------------------
# Pattern learning + guarded enrichment
# --------------------------------------------------------------------------

def test_prior_seen_after_second_run(tmp_path, tmp_hermes_home):
    path = _write(tmp_path, "x.log", "AssertionError: boom\nFAILED test_x\n")
    args = {"log_url_or_path": path, "project": "proj"}
    first = json.loads(handlers.triage_pipeline_failure(args, llm=None))
    assert first["prior_seen"] is False
    assert first["prior_occurrences"] == 0
    second = json.loads(handlers.triage_pipeline_failure(args, llm=None))
    assert second["prior_seen"] is True
    assert second["prior_occurrences"] == 1


def test_enrichment_failure_is_non_fatal(tmp_path, tmp_hermes_home):
    path = _write(tmp_path, "x.log", "AssertionError: boom\n")

    def exploding_dispatch(name, args, **kwargs):
        raise RuntimeError("plugin not installed")

    out = handlers.triage_pipeline_failure(
        {"log_url_or_path": path}, llm=None,
        dispatch_tool=exploding_dispatch, enable_enrichment=True)
    data = json.loads(out)
    assert data["success"] is True  # enrichment failure did not break triage
    assert "enrichment" not in data


def test_enrichment_used_when_present(tmp_path, tmp_hermes_home):
    path = _write(tmp_path, "x.log", "AssertionError: boom\n")
    calls = []

    def dispatch(name, args, **kwargs):
        calls.append((name, args))
        return json.dumps({"matches": [{"test": "test_x", "history": "flaky"}]})

    out = handlers.triage_pipeline_failure(
        {"log_url_or_path": path}, llm=None,
        dispatch_tool=dispatch, enable_enrichment=True)
    data = json.loads(out)
    assert data["success"] is True
    assert data.get("enrichment", {}).get("source") == "test_failure_lookup"
    assert calls and calls[0][0] == "test_failure_lookup"


def test_low_signal_log_still_succeeds(tmp_path, tmp_hermes_home):
    path = _write(tmp_path, "clean.log", "\n".join(f"step {i} ok" for i in range(50)))
    data = json.loads(handlers.triage_pipeline_failure(
        {"log_url_or_path": path}, llm=None))
    assert data["success"] is True
    assert data["log_stats"]["low_signal"] is True
    assert data["category"] in classifier.TAXONOMY


def test_low_signal_heuristic_is_not_learned(tmp_path, tmp_hermes_home):
    """L7: low-signal heuristic defaults must not pollute the pattern store."""
    path = _write(tmp_path, "clean.log", "\n".join(f"step {i} ok" for i in range(40)))
    args = {"log_url_or_path": path, "project": "lp"}
    first = json.loads(handlers.triage_pipeline_failure(args, llm=None))
    assert first["log_stats"]["low_signal"] is True
    assert first["prior_seen"] is False
    second = json.loads(handlers.triage_pipeline_failure(args, llm=None))
    assert second["prior_seen"] is False  # nothing was recorded the first time


def test_blank_log_does_not_collide_in_store(tmp_path, tmp_hermes_home):
    """L1: an excerpt that normalises to empty is never recorded."""
    path = _write(tmp_path, "blank.log", "   \n\n   \n")
    args = {"log_url_or_path": path, "project": "bp"}
    first = json.loads(handlers.triage_pipeline_failure(args, llm=None))
    assert first["success"] is True
    assert first["prior_seen"] is False
    second = json.loads(handlers.triage_pipeline_failure(args, llm=None))
    assert second["prior_seen"] is False


def test_secrets_redacted_in_output(tmp_path, tmp_hermes_home):
    """M3: secrets in a CI log are not echoed back in the tool result."""
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    log = f"AssertionError: boom\nleaked token={secret}\nFAILED tests/test_x.py\n"
    path = _write(tmp_path, "x.log", log)
    out = handlers.triage_pipeline_failure({"log_url_or_path": path}, llm=None)
    assert secret not in out
    assert "ghp_" not in out
    data = json.loads(out)
    assert data["success"] is True
    assert data["category"] == "broken_test"  # classification still works


def test_secret_excerpt_not_sent_to_llm(tmp_path, tmp_hermes_home):
    """M3: the excerpt handed to the LLM is already redacted."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    path = _write(tmp_path, "x.log", f"AssertionError: boom\naws_key {secret}\n")
    llm = FakeLlm(parsed={"category": "broken_test", "confidence": 0.9,
                          "summary": "ok", "evidence": [], "suggested_action": "x"})
    handlers.triage_pipeline_failure({"log_url_or_path": path}, llm=llm)
    assert secret not in json.dumps(llm.calls[0]["input"])


def test_llm_error_is_logged(tmp_path, tmp_hermes_home, caplog):
    """H1: an LLM failure is logged (not silently swallowed) before fallback."""
    import logging

    path = _write(tmp_path, "x.log", "No space left on device\n")
    llm = FakeLlm(raise_exc=ValueError("boom"))
    with caplog.at_level(logging.WARNING):
        handlers.triage_pipeline_failure({"log_url_or_path": path}, llm=llm)
    assert any("heuristic fallback" in r.getMessage() for r in caplog.records)
