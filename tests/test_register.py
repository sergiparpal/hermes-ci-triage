"""Plugin registration against the real Hermes registry."""

from __future__ import annotations

import json
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1]


def test_registers_triage_tool(tmp_hermes_home):
    from hermes_cli.plugins import PluginManager, PluginManifest, PluginContext
    from tools.registry import registry
    import hermes_plugins.hermes_ci_triage as plugin

    pm = PluginManager()
    manifest = PluginManifest(
        name="hermes-ci-triage",
        version="0.1.0",
        source="user",
        path=str(PLUGIN_DIR),
        key="hermes-ci-triage",
        provides_tools=["triage_pipeline_failure"],
    )
    ctx = PluginContext(manifest, pm)
    plugin.register(ctx)

    entry = registry.get_entry("triage_pipeline_failure")
    assert entry is not None, "tool not registered"
    assert registry.get_toolset_for_tool("triage_pipeline_failure") == "ci_triage"
    assert "triage_pipeline_failure" in pm._plugin_tool_names


def test_schema_shape_and_no_cross_toolset_names():
    import hermes_plugins.hermes_ci_triage as plugin

    schema = plugin.TRIAGE_SCHEMA
    assert schema["name"] == "triage_pipeline_failure"
    assert isinstance(schema.get("description"), str) and len(schema["description"]) > 50
    params = schema["parameters"]
    assert params["type"] == "object"
    assert params["required"] == ["log_url_or_path"]
    assert "log_url_or_path" in params["properties"]

    # The schema description must not name tools from other toolsets — doing so
    # makes the model hallucinate calls to tools that may be disabled.
    desc = schema["description"].lower()
    for forbidden in (
        "web_search", "read_file", "terminal", "delegate_task",
        "test_failure_lookup", "module_failure_history",
    ):
        assert forbidden not in desc, f"description references foreign tool: {forbidden}"


def test_registered_handler_returns_json_string(tmp_hermes_home):
    """The registered handler must return a JSON string even on bad input."""
    from hermes_cli.plugins import PluginManager, PluginManifest, PluginContext
    from tools.registry import registry
    import hermes_plugins.hermes_ci_triage as plugin

    pm = PluginManager()
    manifest = PluginManifest(name="hermes-ci-triage", source="user",
                              path=str(PLUGIN_DIR), key="hermes-ci-triage")
    plugin.register(PluginContext(manifest, pm))

    out = registry.get_entry("triage_pipeline_failure").handler({})
    assert isinstance(out, str)
    data = json.loads(out)
    assert data["success"] is False
    assert "remediation" in data
