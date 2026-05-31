"""Per-project failure-pattern store (local SQLite).

``general`` plugins have no Curator to manage retention for them, so this
module owns its own lifecycle: it learns failure *signatures* per project,
serves prior classifications back as a hint, and prunes itself (age + per-
project row cap) on every write.

A **signature** is a SHA-1 of the excerpt after volatile tokens (timestamps,
hex addresses, UUIDs, line/byte offsets, temp paths, bare numbers) are
normalised away, so two runs of the same failure that differ only in those
tokens collapse to one signature.

FTS5 is used for fuzzy lookup when available and falls back to ``LIKE``
otherwise — detected at open time, never assumed.

Pure standard library (``sqlite3``, ``hashlib``, ``re``, ``datetime``); the
caller supplies the DB path so the module stays decoupled from Hermes and
unit-testable.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

DEFAULT_RETENTION_DAYS = 180
DEFAULT_MAX_ROWS_PER_PROJECT = 500
_SAMPLE_CHARS = 4000   # bounded excerpt stored per pattern for fuzzy lookup

# --------------------------------------------------------------------------
# Signature normalisation
# --------------------------------------------------------------------------

# ORDER MATTERS: rules run top-to-bottom, so specific patterns must precede
# general ones (timestamps before clock times; long hex blobs before the
# bare-integer catch-all). Reordering can let a greedy rule mask a precise one.
_NORMALISERS = [
    # ISO-8601-ish timestamps: 2026-05-31T17:04:01.123Z / 2026-05-31 17:04:01
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    # clock times: 17:04:01 / 17:04:01.123
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TS>"),
    # UUIDs
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    # hex addresses: 0xdeadbeef
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<ADDR>"),
    # long hex blobs (git sha, content hashes) — 7+ hex chars
    (re.compile(r"\b[0-9a-fA-F]{7,}\b"), "<HEX>"),
    # temp paths
    (re.compile(r"(?:/tmp|/var/folders|/var/tmp|/private/var/folders)/[^\s:'\"]+"), "<TMP>"),
    # explicit line/offset markers: 'line 1234', 'offset 42', ':123:45'
    (re.compile(r"\b(?:line|offset|byte)\s+\d+\b", re.IGNORECASE), r"<POS>"),
    (re.compile(r":\d+:\d+\b"), ":<POS>"),
    (re.compile(r":\d+\b"), ":<POS>"),
    # any remaining bare integer run
    (re.compile(r"\b\d+\b"), "<N>"),
]


def normalize_signature_text(text: str) -> str:
    """Normalise volatile tokens so equivalent failures share a signature."""
    out = text or ""
    for pattern, repl in _NORMALISERS:
        out = pattern.sub(repl, out)
    # collapse whitespace so reflowed/indented variants converge
    out = re.sub(r"[ \t]+", " ", out)
    out = re.sub(r"\n{2,}", "\n", out)
    return out.strip()


def compute_signature(excerpt: str) -> str:
    """Return a stable SHA-1 hex signature for a (pre-filtered) excerpt."""
    normalised = normalize_signature_text(excerpt)
    # Non-cryptographic content fingerprint (dedup key), hence usedforsecurity=False.
    return hashlib.sha1(
        normalised.encode("utf-8", "replace"), usedforsecurity=False
    ).hexdigest()


def _iso_now(now: Optional[datetime] = None) -> str:
    return (now or datetime.now(timezone.utc)).isoformat()


def fts5_available() -> bool:
    """Probe whether the bundled sqlite3 supports FTS5 (no side effects)."""
    try:
        conn = sqlite3.connect(":memory:")
    except sqlite3.Error:
        return False
    try:
        conn.execute("CREATE VIRTUAL TABLE _fts5_probe USING fts5(c)")
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


_FTS_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,}")


def _fuzzy_tokens(excerpt: str, limit: int = 12) -> list[str]:
    """Pick salient alphanumeric tokens from an excerpt for an FTS query."""
    seen: dict[str, None] = {}
    for tok in _FTS_TOKEN_RE.findall(normalize_signature_text(excerpt)):
        low = tok.lower()
        if low not in seen:
            seen[low] = None
        if len(seen) >= limit:
            break
    return list(seen)


class PatternStore:
    """SQLite-backed per-project pattern store with self-retention.

    Open one per operation and :meth:`close` it; SQLite is opened in WAL mode
    for concurrent readers. Set ``fts=False`` to force the ``LIKE`` path
    (used by tests to exercise the fallback even where FTS5 is present).
    """

    def __init__(
        self,
        db_path,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_rows_per_project: int = DEFAULT_MAX_ROWS_PER_PROJECT,
        fts: Optional[bool] = None,
    ) -> None:
        self.db_path = str(db_path)
        self.retention_days = retention_days
        self.max_rows_per_project = max_rows_per_project
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.fts = fts5_available() if fts is None else bool(fts)
        self._init_schema()

    # -- schema ------------------------------------------------------------

    def _init_schema(self) -> None:
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS patterns (
                project     TEXT NOT NULL,
                signature   TEXT NOT NULL,
                category    TEXT NOT NULL,
                occurrences INTEGER NOT NULL DEFAULT 1,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                sample      TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (project, signature)
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_patterns_last_seen "
            "ON patterns(project, last_seen)"
        )
        if self.fts:
            try:
                self.conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS patterns_fts USING fts5("
                    "sample, project UNINDEXED, signature UNINDEXED)"
                )
                # Backfill rows missing from the index — e.g. a DB previously
                # written with FTS disabled, or created before this table existed.
                # Without this, those priors stay invisible to fuzzy lookup.
                self.conn.execute(
                    "INSERT INTO patterns_fts (sample, project, signature) "
                    "SELECT sample, project, signature FROM patterns p "
                    "WHERE NOT EXISTS (SELECT 1 FROM patterns_fts f "
                    "WHERE f.project = p.project AND f.signature = p.signature)"
                )
            except sqlite3.Error:
                # FTS5 vanished between probe and create — degrade gracefully.
                self.fts = False
        self.conn.commit()

    # -- reads -------------------------------------------------------------

    def _fetch_row(self, project: str, signature: str) -> Optional[sqlite3.Row]:
        """The canonical single-pattern read, shared by lookup and record."""
        return self.conn.execute(
            "SELECT * FROM patterns WHERE project=? AND signature=?",
            (project, signature),
        ).fetchone()

    def lookup(
        self, project: str, signature: str, excerpt: Optional[str] = None
    ) -> Optional[dict[str, object]]:
        """Return the prior record for a signature, or a fuzzy match, else None.

        Exact ``(project, signature)`` match wins. On a miss, if an *excerpt*
        is supplied a fuzzy lookup is attempted (FTS5 when available, ``LIKE``
        otherwise) and the most-seen similar prior is returned with
        ``fuzzy=True``.
        """
        row = self._fetch_row(project, signature)
        if row is not None:
            return self._row_to_dict(row, fuzzy=False)
        if excerpt:
            fuzzy = self._fuzzy_lookup(project, excerpt)
            if fuzzy is not None:
                return fuzzy
        return None

    def _fuzzy_lookup(
        self, project: str, excerpt: str
    ) -> Optional[dict[str, object]]:
        tokens = _fuzzy_tokens(excerpt)
        if not tokens:
            return None
        try:
            if self.fts:
                match = " OR ".join(f'"{t}"' for t in tokens)
                row = self.conn.execute(
                    "SELECT p.* FROM patterns_fts f "
                    "JOIN patterns p ON p.project=f.project AND p.signature=f.signature "
                    "WHERE f.project=? AND patterns_fts MATCH ? "
                    "ORDER BY p.occurrences DESC LIMIT 1",
                    (project, match),
                ).fetchone()
            else:
                clauses = " OR ".join("sample LIKE ?" for _ in tokens)
                params = [project] + [f"%{t}%" for t in tokens]
                row = self.conn.execute(
                    f"SELECT * FROM patterns WHERE project=? AND ({clauses}) "
                    "ORDER BY occurrences DESC LIMIT 1",
                    params,
                ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        return self._row_to_dict(row, fuzzy=True)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row, *, fuzzy: bool) -> dict[str, object]:
        return {
            "project": row["project"],
            "signature": row["signature"],
            "category": row["category"],
            "occurrences": row["occurrences"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "sample": row["sample"],
            "fuzzy": fuzzy,
        }

    # -- writes ------------------------------------------------------------

    def record(
        self,
        project: str,
        signature: str,
        category: str,
        excerpt: str,
        *,
        now: Optional[datetime] = None,
    ) -> dict[str, object]:
        """Upsert a pattern: bump ``occurrences`` and ``last_seen``.

        Stores a bounded sample of the excerpt for fuzzy lookup. Runs
        retention (age prune + per-project cap) after the write.
        """
        ts = _iso_now(now)
        sample = (excerpt or "")[:_SAMPLE_CHARS]
        existing = self.conn.execute(
            "SELECT occurrences FROM patterns WHERE project=? AND signature=?",
            (project, signature),
        ).fetchone()
        if existing is None:
            self.conn.execute(
                "INSERT INTO patterns "
                "(project, signature, category, occurrences, first_seen, last_seen, sample) "
                "VALUES (?, ?, ?, 1, ?, ?, ?)",
                (project, signature, category, ts, ts, sample),
            )
        else:
            self.conn.execute(
                "UPDATE patterns SET occurrences=occurrences+1, last_seen=?, "
                "category=?, sample=? WHERE project=? AND signature=?",
                (ts, category, sample, project, signature),
            )
        self._fts_delete(project, signature)
        self._fts_insert(project, signature, sample)
        self.conn.commit()
        self.prune(project, now=now)
        row = self._fetch_row(project, signature)
        return self._row_to_dict(row, fuzzy=False) if row else {}

    # -- retention ---------------------------------------------------------

    def prune(self, project: Optional[str] = None, *, now: Optional[datetime] = None) -> int:
        """Delete rows older than ``retention_days`` and enforce the per-
        project row cap (evicting least-recently-seen). Returns rows removed.
        """
        now_dt = now or datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(days=self.retention_days)).isoformat()
        removed = 0

        stale = self.conn.execute(
            "SELECT project, signature FROM patterns WHERE last_seen < ?"
            + (" AND project=?" if project else ""),
            (cutoff, project) if project else (cutoff,),
        ).fetchall()
        for r in stale:
            self._delete(r["project"], r["signature"])
            removed += 1

        projects = (
            [project]
            if project
            else [r["project"] for r in self.conn.execute(
                "SELECT DISTINCT project FROM patterns").fetchall()]
        )
        for proj in projects:
            count = self.conn.execute(
                "SELECT COUNT(*) AS c FROM patterns WHERE project=?", (proj,)
            ).fetchone()["c"]
            overflow = count - self.max_rows_per_project
            if overflow > 0:
                victims = self.conn.execute(
                    "SELECT signature FROM patterns WHERE project=? "
                    "ORDER BY last_seen ASC LIMIT ?",
                    (proj, overflow),
                ).fetchall()
                for v in victims:
                    self._delete(proj, v["signature"])
                    removed += 1

        if removed:
            self.conn.commit()
        return removed

    def _delete(self, project: str, signature: str) -> None:
        self.conn.execute(
            "DELETE FROM patterns WHERE project=? AND signature=?",
            (project, signature),
        )
        self._fts_delete(project, signature)

    # -- FTS index maintenance (best-effort; no-ops when FTS is off) --------

    def _fts_delete(self, project: str, signature: str) -> None:
        if not self.fts:
            return
        try:
            self.conn.execute(
                "DELETE FROM patterns_fts WHERE project=? AND signature=?",
                (project, signature),
            )
        except sqlite3.Error:
            pass

    def _fts_insert(self, project: str, signature: str, sample: str) -> None:
        if not self.fts:
            return
        try:
            self.conn.execute(
                "INSERT INTO patterns_fts (sample, project, signature) "
                "VALUES (?, ?, ?)",
                (sample, project, signature),
            )
        except sqlite3.Error:
            pass

    def count(self, project: Optional[str] = None) -> int:
        if project:
            row = self.conn.execute(
                "SELECT COUNT(*) AS c FROM patterns WHERE project=?", (project,)
            ).fetchone()
        else:
            row = self.conn.execute("SELECT COUNT(*) AS c FROM patterns").fetchone()
        return int(row["c"])

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "PatternStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
