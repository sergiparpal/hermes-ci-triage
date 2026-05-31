# hermes-ci-triage

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) **standalone
(`general`) plugin** that triages CI/CD pipeline failures. Given a build/test/
deploy log — a local file path or an `https://` URL to the raw log — it:

1. **Fetches** the log safely (byte-capped; HTTPS-only for remote).
2. **Pre-filters** it locally to a bounded, signal-dense excerpt *before* any
   LLM call (real CI logs routinely exceed 10 MB; sending one whole breaks
   prompt cache and inflates cost).
3. **Classifies** the root cause into a fixed taxonomy via the host LLM
   (`ctx.llm.complete_structured`), with a deterministic rule-based fallback.
4. **Learns** the failure pattern per project in local SQLite, so repeat
   failures are recognised (`prior_seen` / `prior_occurrences`).

Standard-library only. Local-first. No third-party dependencies.

- **Pinned Hermes version:** developed and verified against **v0.15.1**
  (baseline target: **v0.14.0 "Foundation"**). The plugin checks the running
  version at load and warns (never crashes) if it is older than the baseline.

## The tool

### `triage_pipeline_failure` (toolset `ci_triage`)

| Parameter | Type | Required | Description |
|---|---|---|---|
| `log_url_or_path` | string | ✅ | Local path to a CI log file, **or** an `https://` URL to the raw log. Plain `http` and non-file schemes are rejected. |
| `project` | string | — | Optional project key to scope pattern learning. Defaults to the working-directory name. |

**Returns** (success):

```json
{
  "success": true,
  "category": "broken_test",
  "confidence": 0.83,
  "summary": "Assertion failed in payments.refund.",
  "evidence": ["AssertionError: insufficient balance"],
  "suggested_action": "Fix the balance check in refund.py.",
  "classification_method": "llm",
  "prior_seen": true,
  "prior_occurrences": 3,
  "project": "my-service",
  "signature": "62d8c6d1…",
  "log_stats": {"original_bytes": 489, "hit_count": 5, "truncated": false, "low_signal": false}
}
```

**Returns** (failure): `{"success": false, "error": "…", "remediation": "…"}`.

## Taxonomy (fixed)

| Category | Meaning |
|---|---|
| `broken_test` | A genuine code/test defect — assertion failures, unexpected exceptions, wrong expectations. |
| `environment` | Misconfigured build/runtime env — missing/incompatible deps, import errors, wrong tool versions, permissions. |
| `data` | Bad/missing input, fixtures, seeds, schema/migration mismatch, (de)serialization of data. |
| `timeout` | A step/test/job exceeded its time budget — `timed out`, `TimeoutError`, deadline exceeded, hangs. |
| `flaky` | Non-deterministic — passes on retry, race conditions, order dependence, intermittent flakes. |
| `infra` | CI infrastructure unrelated to the code — runner died, OOM/disk, registry/network 5xx, rate limits, image-pull failures. |

When the LLM provider is unavailable, classification degrades to a rule-based
heuristic over the excerpt (`classification_method: "heuristic"`, low
confidence) — the tool always returns a valid category and never raises.

## Configuration & environment

| Setting | Default | Notes |
|---|---|---|
| **CI provider (remote fetch)** | **GitHub Actions** | Decision point 1. Sets the token env var and auth header. |
| `GITHUB_TOKEN` | _(unset)_ | Optional. A `Bearer` token used **only** for fetching protected remote logs. Read at call time. Missing/insufficient → a structured error with remediation, never a crash. |
| `HERMES_CI_TRIAGE_ALLOW_PRIVATE` | _(unset)_ | Opt-in. Permit fetching logs from RFC1918/private addresses (self-hosted / GitHub Enterprise runners). Off by default; loopback, link-local and cloud-metadata addresses are blocked **regardless** of this setting. |
| `HERMES_CI_TRIAGE_LOG_ROOTS` | _(unset)_ | Optional `os.pathsep`-separated allowlist of directories local logs may be read from (after symlink resolution). Unset = no restriction; set it to stop the tool being steered into reading arbitrary files. |
| **`hermes-test-history` enrichment** | **Enabled (guarded)** | Decision point 2. Triage tries `ctx.dispatch_tool("test_failure_lookup", …)` inside `try/except`; if that plugin/tool is absent, enrichment is silently skipped. |
| Pattern DB | `$HERMES_HOME/cache/ci_triage_patterns.db` | WAL mode; FTS5 used when available, `LIKE` fallback otherwise. Self-pruned: rows older than 180 days and beyond 500 rows/project are evicted on write. |

**Local-path triage requires no credentials and always works**, regardless of
the CI-provider choice or whether `GITHUB_TOKEN` is set. The token's absence
never disables the plugin or hides the tool.

### Install / enable

```bash
# Make discoverable (symlink or copy into the user plugin dir)
ln -s "$(pwd)" ~/.hermes/plugins/hermes-ci-triage

# Standalone plugins are opt-in:
hermes plugins enable hermes-ci-triage
hermes plugins list          # → hermes-ci-triage  enabled  0.1.0
hermes plugins disable hermes-ci-triage   # to turn off later
```

### Use

```bash
hermes -z "triage this CI log: /path/to/build.log"
# or paste an https:// URL to a raw job log
```

## Privilege surface

This plugin runs **with the full privileges of the Hermes agent process — there
is no sandbox.** Specifically:

- It **reads** arbitrary local files you point it at (via `log_url_or_path`),
  after `os.path.realpath()` and a regular-file check, capped at 25 MB. It
  refuses directories, devices, and pipes; it does not follow into special
  files.
- It **writes** only to `$HERMES_HOME/cache/ci_triage_patterns.db` (the pattern
  store). It writes nowhere else.
- It makes **outbound HTTPS** requests **only** when given an `https://` URL,
  with an explicit 20 s timeout, attaching `GITHUB_TOKEN` as a `Bearer` header
  when present. Every hop is guarded against SSRF: the scheme (HTTPS-only) and
  destination address are re-validated on **each redirect** (no http/ftp
  downgrade, no redirect to internal addresses), the resolved IP is vetted at
  connect time (DNS-rebinding defence), and loopback/link-local/metadata/(by
  default) private ranges are refused.
- Log content is treated as **untrusted data** and never as instructions (see
  prompt-injection note below). Recognised secrets (tokens, API keys, private
  keys, `secret=`/`password=` assignments) are **redacted from the excerpt
  before** it is hashed, sent to the LLM, forwarded to another tool, or echoed
  back in the result.

## Security checklist (Hermes best-practices)

- [x] Tool name is `snake_case`, unique, and does not collide with built-ins.
- [x] Schema `description` states **when to use it and what it returns**, and
      **never references tools from other toolsets by name** (avoids
      hallucinated calls when those toolsets are disabled).
- [x] Strict JSON-Schema typing; `required` limited to `log_url_or_path`.
- [x] Input is validated **inside the handler before any side effect**.
- [x] **Log content is treated as untrusted** — the classifier instructions
      explicitly tell the model to ignore any instructions embedded in the log
      and to treat the excerpt as data only.
- [x] **Secrets are redacted** from the excerpt before it leaves the host (LLM
      call, enrichment, or result echo), so credentials that leak into a CI log
      are not propagated further.
- [x] Structured error envelope on failure: `{success:false, error, remediation}`.
- [x] Network calls are **HTTPS-only with an explicit timeout**; non-HTTPS URLs
      are rejected.
- [x] `os.path.realpath()` before local-path access; reads are byte-capped and
      restricted to regular files; writes stay under `$HERMES_HOME`.
- [x] **Bounded output** — logs are pre-filtered and capped (~12 000 chars /
      200 lines) before any model call; oversize logs are never sent whole.
- [x] No `exec`/`eval` of strings. The plugin never reads `~/.hermes/.env` or
      `auth.json`; the optional token is read from the process environment only.
- [x] `has_remote_credentials()` is exposed for diagnostics — but is **not**
      wired to a `check_fn`, so a missing token never hides the tool.
- [x] No Hermes core files are modified; the plugin is fully self-contained.

## Layout

```
hermes-ci-triage/
├── plugin.yaml      # manifest (always loads; no requires_env gate)
├── __init__.py      # register(ctx) — the only file that touches Hermes
├── logfetch.py      # local/remote retrieval (HTTPS + byte cap)
├── prefilter.py     # regex pre-filtering → bounded excerpt
├── classifier.py    # taxonomy + complete_structured + heuristic fallback
├── patterns.py      # SQLite pattern store (signature, FTS5/LIKE, retention)
├── handlers.py      # pipeline glue
├── tests/           # pytest suite (importlib mode; see tests/pytest.ini)
└── README.md
```

`logfetch`, `prefilter`, `classifier`, `patterns`, and `handlers` import
nothing from Hermes — they are pure standard library and unit-test in
isolation. `__init__.py` is the only Hermes-facing module.

## Tests

```bash
./run_tests.sh                 # parity env (TZ=UTC, LANG=C.UTF-8, creds cleared)
# or directly:
python -m pytest tests/        # uses tests/pytest.ini (importlib import mode)
```

The suite mocks `ctx.llm` and `ctx.dispatch_tool` — no live provider is
required. It covers registration, log fetching, pre-filtering, signature
normalisation, the SQLite store (incl. FTS-off fallback and retention), and the
full handler pipeline across all six taxonomy categories.
