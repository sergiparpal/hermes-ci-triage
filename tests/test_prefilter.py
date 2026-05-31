"""prefilter: signal detection, bounding, ANSI strip, run collapse."""

from __future__ import annotations

from hermes_plugins.hermes_ci_triage import prefilter


def test_clean_log_yields_no_hits():
    text = "\n".join(f"step {i}: ok" for i in range(2000))
    excerpt, stats = prefilter.prefilter(text)
    assert stats["hit_count"] == 0
    assert excerpt == ""
    assert stats["truncated"] is False


def test_large_log_traceback_near_end_preserved():
    # ~5 MB of benign filler with a traceback only at the very end.
    filler = "INFO: doing work step\n" * 250_000
    traceback = (
        "Traceback (most recent call last):\n"
        '  File "app/core.py", line 42, in run\n'
        "    raise ValueError('boom-token-XYZ')\n"
        "ValueError: boom-token-XYZ\n"
    )
    text = filler + traceback
    assert len(text) > 5_000_000

    excerpt, stats = prefilter.prefilter(text)
    assert "ValueError: boom-token-XYZ" in excerpt
    assert stats["hit_count"] >= 1
    cap = prefilter.DEFAULT_CHAR_CAP + len(prefilter.TRUNCATION_NOTE) + 2
    assert len(excerpt) <= cap


def test_truncation_keeps_the_tail():
    lines = []
    for i in range(1000):
        lines.append(f"context line {i}")
        lines.append(f"ERROR: failure number {i}")
    excerpt, stats = prefilter.prefilter("\n".join(lines))
    assert stats["truncated"] is True
    assert "failure number 999" in excerpt
    assert "ERROR: failure number 0" not in excerpt  # earliest region dropped
    cap = prefilter.DEFAULT_CHAR_CAP + len(prefilter.TRUNCATION_NOTE) + 2
    assert len(excerpt) <= cap
    assert excerpt.startswith(prefilter.TRUNCATION_NOTE)


def test_ansi_escapes_stripped():
    text = "ok line\n\x1b[31mERROR: red failure here\x1b[0m\nok line 2\n"
    excerpt, _ = prefilter.prefilter(text)
    assert "\x1b[" not in excerpt
    assert "ERROR: red failure here" in excerpt


def test_identical_runs_collapsed():
    block = ["FAIL at start"] + ["same noisy stack line"] * 30 + ["tail line"]
    excerpt, _ = prefilter.prefilter("\n".join(block), before=0, after=40)
    assert "repeated" in excerpt
    assert excerpt.count("same noisy stack line") < 30


def test_exit_code_is_a_signal():
    assert prefilter.is_failure_line("process exited with code 137")
    assert prefilter.is_failure_line("Command returned non-zero exit status 1")
    assert not prefilter.is_failure_line("exit code 0 (success)")
