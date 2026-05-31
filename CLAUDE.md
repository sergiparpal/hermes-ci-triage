# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A standalone (`general`) [Hermes Agent](https://github.com/NousResearch/hermes-agent)
plugin that registers exactly one tool, `triage_pipeline_failure` (toolset
`ci_triage`). Given a CI/CD log (local path or `https://` URL) it fetches →
pre-filters → classifies the root cause into a fixed 6-category taxonomy via the
host LLM (heuristic fallback) → learns the failure pattern per project in local
SQLite. Standard-library only; developed/verified against Hermes **v0.15.1**
(baseline **v0.14.0**). See `README.md` for the user-facing contract and the
full security rationale, and `hermes-ci-triage-implementation-plan.md` for the
original design.

## Commands

```bash
./run_tests.sh                              # whole suite, parity env (TZ=UTC, creds cleared)
./run_tests.sh tests/test_patterns.py       # one file
./run_tests.sh tests/test_handlers.py::test_name -- -v   # one test; args after `--` go to pytest
python -m pytest tests/                      # direct (uses tests/pytest.ini, importlib mode)
```

`run_tests.sh` mirrors the hermes-agent CI: it blanks credential env vars
(`GITHUB_TOKEN`, cloud keys, …), pins `TZ`/`LANG`/`PYTHONHASHSEED`, and prefers a
hermes-agent venv if one exists. The suite is pure-stdlib and needs no live LLM
provider — `ctx.llm` and `ctx.dispatch_tool` are faked.

There is no build step, no lint config, and no third-party dependencies.

## Architecture

**One Hermes-facing module; everything else is pure stdlib.** `__init__.py` is
the *only* file that touches Hermes — it owns `register(ctx)`, the tool schema,
and the version guard. Every sibling (`logfetch`, `prefilter`, `redact`,
`classifier`, `patterns`, `handlers`) imports nothing from Hermes; Hermes objects
(`llm`, `dispatch_tool`, `hermes_home`) are *injected* as keyword args into
`handlers.triage_pipeline_failure`. This split is what lets the whole pipeline
unit-test with fakes — preserve it. If a sibling needs a Hermes capability, pass
it down from `register()` rather than importing it.

**The pipeline** (`handlers.triage_pipeline_failure`, the orchestrator — it
decides *order and error contract only*, never *how* a step works):

```
validate args → logfetch.fetch → prefilter.prefilter → redact.redact
  → patterns.compute_signature → patterns.PatternStore.lookup (prior = weak hint)
  → optional dispatch_tool enrichment (guarded) → classifier.classify
  → patterns.PatternStore.record → JSON envelope
```

## Invariants that span files — do not break these

- **The tool never raises.** Every public entry returns a JSON envelope:
  `{"success": true, …}` or `{"success": false, "error", "remediation"}`.
  Defense is layered: `classifier.classify` degrades to `heuristic_classify`
  instead of throwing; `handlers` wraps each side-effecting step; `register`'s
  `handler` has a last-resort `try/except`. Keep new failure modes inside an
  envelope, not as exceptions.

- **The tool is always registered.** No `check_fn`, no `requires_env` in
  `plugin.yaml`. A missing `GITHUB_TOKEN` must never hide the tool, because
  local-path triage needs no credentials. Remote-auth state is reported *in the
  output* (`has_remote_credentials`), never used to gate registration.

- **Redaction placement is load-bearing.** `redact.redact` runs in `handlers`
  *before* the excerpt is hashed into a signature, stored in SQLite, sent to the
  LLM, used to seed enrichment, or echoed back; enrichment output is passed
  through `redact.redact_obj` too. Any new path that lets log-derived text leave
  the host or hit the DB must redact first.

- **Log content is untrusted data, never instructions.** The classifier's
  `INSTRUCTIONS` explicitly fence the excerpt as data and tell the model to
  ignore embedded instructions; `_build_input` wraps it in BEGIN/END markers.
  Keep that framing if you touch the prompt.

- **The taxonomy is a fixed contract in three places.** `classifier.TAXONOMY`,
  `classifier.CLASSIFICATION_SCHEMA`, the `_CATEGORY_DEFINITIONS` prose, the tool
  description in `__init__.py`, and the table in `README.md` must stay in sync.
  Categories: `broken_test`, `environment`, `data`, `timeout`, `flaky`, `infra`.

- **Ordered regex tables encode priority — order is correctness, not style.**
  `patterns._NORMALISERS` (specific tokens before the bare-integer catch-all) and
  `classifier._HEURISTIC_RULES` (first match wins, most-specific first).
  Reordering can let a greedy rule mask a precise one.

- **SSRF defenses in `logfetch` are re-applied per hop.** HTTPS-only and address
  blocking are re-validated on *every* redirect (`_SafeRedirectHandler`); the
  resolved IP is vetted at connect time to close the DNS-rebinding window
  (`_GuardedHTTPSConnection`); the bearer token is scoped to GitHub hosts and
  dropped on cross-host redirects. Loopback/link-local/metadata are blocked
  regardless of `HERMES_CI_TRIAGE_ALLOW_PRIVATE`.

## Pattern store notes

`patterns.PatternStore` is per-operation: open one, use it, `close()` it (it's
WAL-mode SQLite). A **signature** is a SHA-1 over the excerpt after volatile
tokens are normalised away, so reruns of the same failure collapse to one row.
Fuzzy lookup uses FTS5 when the bundled sqlite3 supports it and falls back to
`LIKE` — detected at open time, never assumed; tests force the fallback with
`fts=False`. Retention (180 days / 500 rows per project) self-prunes on every
write. An excerpt that normalises to empty yields the empty signature, which
would collide across all such logs — `handlers` skips the store entirely in that
case (`has_signature`).

## Test harness gotcha

The plugin uses relative imports (`from . import handlers`) because Hermes loads
it as the package `hermes_plugins.hermes_ci_triage`. You **cannot** run a module
file directly. `tests/conftest.py` reconstructs that package at collection time;
`tests/pytest.ini` (kept in `tests/`, not the repo root, on purpose — the root's
`__init__.py` would otherwise be imported as a top-level package and break the
relative imports) sets `--import-mode=importlib`. Add new tests under `tests/`
and import via `from hermes_plugins.hermes_ci_triage import <module>`.
