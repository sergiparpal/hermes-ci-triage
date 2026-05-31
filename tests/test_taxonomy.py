"""taxonomy: single-source-of-truth integrity + drift guards.

``taxonomy.CATEGORIES`` is the one place a category is defined. Most other
representations are *derived* (the schema enum, the prose block, the heuristic
rules) so they cannot drift. Two representations cannot be derived — the tool
schema ``description`` and the README table are human-facing prose — so this
module guards them: if a category is added/renamed in ``taxonomy.py`` without
updating those, the suite fails instead of shipping an inconsistent contract.
"""

from __future__ import annotations

from pathlib import Path

from hermes_plugins.hermes_ci_triage import classifier, taxonomy

PLUGIN_DIR = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# Internal consistency of the single source of truth
# --------------------------------------------------------------------------

def test_categories_are_unique():
    keys = [c.key for c in taxonomy.CATEGORIES]
    assert len(keys) == len(set(keys)), "duplicate category key"
    priorities = [c.priority for c in taxonomy.CATEGORIES]
    assert len(priorities) == len(set(priorities)), "duplicate heuristic priority"


def test_default_category_is_in_taxonomy():
    assert taxonomy.DEFAULT_CATEGORY in taxonomy.TAXONOMY


def test_classifier_reexports_match_source():
    assert classifier.TAXONOMY == taxonomy.TAXONOMY
    enum = classifier.CLASSIFICATION_SCHEMA["properties"]["category"]["enum"]
    assert set(enum) == set(taxonomy.TAXONOMY)
    assert len(enum) == len(taxonomy.TAXONOMY)


def test_heuristic_rules_derive_from_taxonomy():
    assert classifier._HEURISTIC_RULES is taxonomy.HEURISTIC_RULES
    rule_keys = [key for key, _ in taxonomy.HEURISTIC_RULES]
    # Every rule names a real category, and rules are in ascending priority.
    assert set(rule_keys) <= set(taxonomy.TAXONOMY)
    priorities = [
        c.priority for key in rule_keys for c in taxonomy.CATEGORIES if c.key == key
    ]
    assert priorities == sorted(priorities), "heuristic rules not in priority order"


def test_definitions_block_mentions_every_category():
    block = taxonomy.definitions_block()
    for c in taxonomy.CATEGORIES:
        assert f"- {c.key}:" in block


# --------------------------------------------------------------------------
# Drift guards for the two non-derivable, human-facing representations
# --------------------------------------------------------------------------

def test_tool_description_mentions_every_category():
    """The tool-schema description hand-lists the taxonomy; keep it complete."""
    import hermes_plugins.hermes_ci_triage as plugin

    description = plugin.TRIAGE_SCHEMA["description"]
    for c in taxonomy.CATEGORIES:
        assert c.key in description, (
            f"category '{c.key}' missing from the tool description in __init__.py"
        )


def test_readme_table_mentions_every_category():
    """The README taxonomy table must list every category."""
    readme = (PLUGIN_DIR / "README.md").read_text(encoding="utf-8")
    for c in taxonomy.CATEGORIES:
        assert f"`{c.key}`" in readme, (
            f"category '{c.key}' missing from README.md"
        )
