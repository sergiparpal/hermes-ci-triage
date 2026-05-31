"""Shared test fixtures + plugin package installation.

The plugin's modules use relative imports (``from . import prefilter``) because
that is how Hermes loads a multi-file plugin — as the package
``hermes_plugins.<slug>`` with the plugin directory on its ``__path__``. We
reproduce exactly that here so tests import the real package and exercise the
real import graph, rather than loading files in isolation.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
_NS_PARENT = "hermes_plugins"
_SLUG = "hermes_ci_triage"
_FQ = f"{_NS_PARENT}.{_SLUG}"


def _install_plugin_package() -> types.ModuleType:
    """Load the plugin as ``hermes_plugins.hermes_ci_triage`` (idempotent)."""
    if _FQ in sys.modules:
        return sys.modules[_FQ]

    if _NS_PARENT not in sys.modules:
        ns = types.ModuleType(_NS_PARENT)
        ns.__path__ = []  # namespace package
        ns.__package__ = _NS_PARENT
        sys.modules[_NS_PARENT] = ns

    init_file = PLUGIN_DIR / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        _FQ, init_file, submodule_search_locations=[str(PLUGIN_DIR)]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = _FQ
    module.__path__ = [str(PLUGIN_DIR)]
    sys.modules[_FQ] = module
    spec.loader.exec_module(module)
    return module


# Install at collection time so every test file can import submodules.
PLUGIN_PACKAGE = _install_plugin_package()


@pytest.fixture
def tmp_hermes_home(tmp_path, monkeypatch):
    """Point HERMES_HOME (and Path.home) at a temp dir so SQLite lands there."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # Pin the resolver directly so isolation never depends on whether the real
    # hermes_constants.get_hermes_home() honours HERMES_HOME at call time —
    # otherwise handler tests could read/write the operator's real pattern DB.
    from hermes_plugins.hermes_ci_triage import handlers
    monkeypatch.setattr(handlers, "_resolve_hermes_home", lambda hermes_home=None: home)
    return home
