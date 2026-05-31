"""Single source of truth for the CI-failure taxonomy.

The taxonomy is a contract that previously lived, hand-synced, in five places:
the LLM JSON-schema enum, the prose category definitions in the classifier
prompt, the ordered heuristic fallback rules, the tool-schema ``description``,
and the README table. This module collapses the *code-level* copies into one:
:data:`CATEGORIES` defines each category once — its key, a one-line summary, the
prose definition handed to the model, and its rule-based fallback signal — and
every other code representation is derived here.

Add, remove, or re-word a category in exactly one place: :data:`CATEGORIES`.
``tests/test_taxonomy.py`` guards the two representations that cannot be derived
(the tool ``description`` and the README table) by asserting they mention every
key, so drift fails the suite instead of shipping silently.

Pure standard library; no Hermes dependency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern


@dataclass(frozen=True)
class Category:
    """One taxonomy category and all of its derived representations.

    ``priority`` orders the heuristic fallback (lower fires first); it encodes
    correctness, not style — a greedy rule placed before a precise one would
    mask it. ``heuristic`` is the rule-based signal; ``None`` means the category
    is only ever reached as :data:`DEFAULT_CATEGORY`, never by a rule.
    """

    key: str
    summary: str                  # one-line meaning (quick reference / README parity)
    definition: str               # full prose handed to the LLM classifier
    heuristic: Optional[Pattern]  # rule-based fallback signal
    priority: int                 # heuristic match order; lower fires first


# The canonical taxonomy. Order here is the public taxonomy order (it drives the
# schema enum and the prose block); heuristic match order is separate and set by
# `priority`. ORDER WITHIN A REGEX still matters — see patterns/classifier notes.
CATEGORIES: list[Category] = [
    Category(
        key="broken_test",
        summary=(
            "A genuine code/test defect — assertion failures, unexpected "
            "exceptions, wrong expectations."
        ),
        definition=(
            "A genuine code/test defect. Assertion failures, unexpected "
            "exceptions in product or test code, wrong expected values. The test "
            "correctly caught something, or the test itself is wrong."
        ),
        heuristic=re.compile(
            r"assertionerror|assert\b|\d+ failed\b|FAILED \S|expected .* (?:but|to)"
            r"|test failure|<failure", re.I),
        priority=60,
    ),
    Category(
        key="environment",
        summary=(
            "Misconfigured build/runtime env — missing/incompatible deps, import "
            "errors, wrong tool versions, permissions."
        ),
        definition=(
            "The build/runtime environment is misconfigured. Missing or "
            "incompatible dependencies, import/module-not-found, wrong language/"
            "tool version, missing binaries, permission errors, bad PATH or env "
            "vars."
        ),
        heuristic=re.compile(
            r"modulenotfounderror|no module named|importerror|cannot find module"
            r"|command not found|no such file or directory.*(?:bin|exe)?"
            r"|version `?\S+'? not found|incompatible version|unsupported version"
            r"|permission denied|could not find a version that satisfies"
            r"|enoent|\bglibc\b|\.so(?:\.\d+)*: cannot open", re.I),
        priority=40,
    ),
    Category(
        key="data",
        summary=(
            "Bad/missing input, fixtures, seeds, schema/migration mismatch, "
            "(de)serialization of data."
        ),
        definition=(
            "Bad or missing input/fixture/seed data, schema/migration mismatches, "
            "serialization/deserialization of data, malformed test data — the code "
            "is fine but the data it was given is not."
        ),
        heuristic=re.compile(
            r"jsondecodeerror|fixture|seed data|schema (?:mismatch|validation|error)"
            r"|migration|malformed|could not (?:parse|deserialize|decode)"
            r"|unexpected (?:eof|token)|invalid (?:json|yaml|csv|payload)", re.I),
        priority=50,
    ),
    Category(
        key="timeout",
        summary=(
            "A step/test/job exceeded its time budget — timed out, TimeoutError, "
            "deadline exceeded, hangs."
        ),
        definition=(
            'A step, test, or job exceeded its time budget. "timed out", '
            "TimeoutError, deadline exceeded, watchdog/hang kills."
        ),
        heuristic=re.compile(
            r"timed out|timeouterror|deadline exceeded|\btimeout\b"
            r"|exceeded the (?:time|timeout)", re.I),
        priority=20,
    ),
    Category(
        key="flaky",
        summary=(
            "Non-deterministic — passes on retry, race conditions, order "
            "dependence, intermittent flakes."
        ),
        definition=(
            "Non-deterministic failure: passes on retry, race conditions, order "
            "dependence, intermittent network/timing flakes explicitly noted as "
            "flaky."
        ),
        heuristic=re.compile(
            r"\bflak|\bintermittent\b|passed on retry|retr(?:y|ied)\b|race condition",
            re.I),
        priority=10,
    ),
    Category(
        key="infra",
        summary=(
            "CI infrastructure unrelated to the code — runner died, OOM/disk, "
            "registry/network 5xx, rate limits, image-pull failures."
        ),
        definition=(
            "CI infrastructure problem unrelated to the code: runner died, out of "
            "disk/memory (OOM), registry/network 5xx, rate limits, connection "
            "refused, image pull failures, agent disconnects."
        ),
        heuristic=re.compile(
            r"no space left on device|oomkilled|out of memory|cannot allocate memory"
            r"|connection (?:refused|reset)|could not resolve host|network is unreachable"
            r"|\b5\d\d\b.*(?:gateway|server|service)|rate limit|too many requests"
            r"|runner (?:lost|disconnect|terminated)|error pulling image|manifest unknown"
            r"|docker(?:d)?: ", re.I),
        priority=30,
    ),
]

# Default category when no heuristic rule fires (the least-specific signal).
DEFAULT_CATEGORY = "broken_test"

# --------------------------------------------------------------------------
# Derived representations — do not hand-edit; change CATEGORIES instead.
# --------------------------------------------------------------------------

#: The taxonomy as the public ordered list of keys (drives the schema enum).
TAXONOMY: list[str] = [c.key for c in CATEGORIES]

#: Ordered ``(category, regex)`` heuristic rules; first match wins. Sorted by
#: `priority` so the more specific / less ambiguous signals are tried first.
HEURISTIC_RULES: list[tuple[str, Pattern]] = [
    (c.key, c.heuristic)
    for c in sorted(CATEGORIES, key=lambda c: c.priority)
    if c.heuristic is not None
]


def definitions_block() -> str:
    """Render the ``- key: prose`` definition block for the classifier prompt."""
    return "".join(f"- {c.key}: {c.definition}\n" for c in CATEGORIES)
