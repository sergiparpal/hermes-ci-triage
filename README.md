# hermes-ci-triage
Hermes Agent plugin that triages CI/CD pipeline failures: it pre-filters large logs, classifies them into a stable taxonomy via the active LLM (with a rule-based fallback), and learns per-project failure patterns in local SQLite. Standard-library only, local-first.
