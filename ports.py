"""Typed ports for the Hermes capabilities this plugin depends on.

The plugin follows a ports-and-adapters shape: ``__init__.register`` is the only
adapter that touches Hermes, and it *injects* the host's ``llm`` and
``dispatch_tool`` into the otherwise pure-stdlib pipeline. Those capabilities
used to cross the boundary as bare ``Any`` / ``Callable``; this module names the
narrow surface each one must satisfy (Interface Segregation — depend only on the
methods actually called) so the contract is explicit, type-checkable, and easy
to fake in tests.

These are :class:`typing.Protocol` definitions: structural, import-only, and
stdlib. They impose no runtime requirement on the real Hermes objects — the host
``ctx.llm`` already satisfies :class:`LlmPort` by shape, no registration needed.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable


@runtime_checkable
class StructuredResult(Protocol):
    """The result object returned by :meth:`LlmPort.complete_structured`.

    Mirrors ``agent.plugin_llm.PluginLlmStructuredResult``: ``parsed`` is the
    decoded object when ``content_type == "json"``, else ``text`` carries the
    raw model output.
    """

    parsed: Any
    content_type: str
    text: str


@runtime_checkable
class LlmPort(Protocol):
    """The single host-LLM method the classifier uses.

    The real implementation (``ctx.llm``) exposes more, but the classifier only
    needs a structured completion validated against a JSON schema. Keyword-only
    to match ``agent.plugin_llm.PluginLlm.complete_structured``.
    """

    def complete_structured(
        self,
        *,
        instructions: str,
        input: Sequence[Any],
        json_schema: Optional[Any] = ...,
        schema_name: Optional[str] = ...,
        temperature: Optional[float] = ...,
        max_tokens: Optional[int] = ...,
        timeout: Optional[float] = ...,
        purpose: Optional[str] = ...,
    ) -> StructuredResult: ...


@runtime_checkable
class ToolDispatcher(Protocol):
    """Invoke another registered tool by name with a JSON-ish argument map.

    Matches ``ctx.dispatch_tool`` and returns whatever that tool returns —
    typically a JSON string, occasionally a decoded object. The optional
    enrichment path is the only caller.
    """

    def __call__(
        self, name: str, arguments: Mapping[str, Any], **kwargs: Any
    ) -> Any: ...
