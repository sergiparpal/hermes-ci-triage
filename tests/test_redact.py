"""redact: secret scrubbing for excerpts before they leave the host."""

from __future__ import annotations

import pytest

from hermes_plugins.hermes_ci_triage import redact

SECRETS = [
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "github_pat_11ABCDEFG0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "AKIAIOSFODNN7EXAMPLE",
    "xoxb-123456789012-abcdefABCDEF",
    "AIzaSyA1234567890abcdefghijklmnopqrstuv0",
    "sk-ABCDEFGHIJKLMNOPQRSTUV",
    "eyJhbGciOi.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4f",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_standalone_secret_formats_redacted(secret):
    out = redact.redact(f"build failed, leaked {secret} in env dump")
    assert secret not in out
    assert redact.PLACEHOLDER in out


def test_private_key_block_redacted():
    text = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAA\nMOREBASE64==\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    out = redact.redact("ctx\n" + text + "tail")
    assert "PRIVATE KEY" not in out
    assert "MOREBASE64" not in out


def test_key_value_secret_value_redacted_key_kept():
    out = redact.redact("password=hunter2longvalue\nAPI_KEY: abcd1234efgh")
    assert "hunter2longvalue" not in out
    assert "abcd1234efgh" not in out
    assert "password" in out          # key context preserved for triage
    assert "API_KEY" in out


@pytest.mark.parametrize(
    "line",
    [
        'password="s3cr3tvalue"',
        "password='s3cr3tvalue'",
        'export DB_PASSWORD="s3cr3tvalue"',
        'client_secret: "s3cr3tvalue"',
        'authorization: "Bearer s3cr3tvalue"',
    ],
)
def test_quoted_key_value_secret_redacted(line):
    # Quoted values (env dumps, `set -x`) are common; the value class excludes
    # quotes, so they must be matched via the explicit optional-quote handling.
    out = redact.redact(line)
    assert "s3cr3tvalue" not in out
    assert redact.PLACEHOLDER in out


def test_failure_signals_not_mangled():
    # A redaction pass must never eat the failure signal itself.
    text = (
        "AssertionError: expected 5 but got 4\n"
        "ModuleNotFoundError: No module named 'requests'\n"
        "process exited with code 137\n"
        "test failed but passed on retry (flaky)\n"
    )
    assert redact.redact(text) == text


def test_redact_obj_walks_structures():
    obj = {"source": "t", "result": {"items": ["token=ghp_AAAAAAAAAAAAAAAAAAAAAAAA"]}}
    out = redact.redact_obj(obj)
    assert out["source"] == "t"
    assert "ghp_AAAAAAAAAAAAAAAAAAAAAAAA" not in str(out)


def test_redact_empty_and_none_safe():
    assert redact.redact("") == ""
    assert redact.redact(None) is None
