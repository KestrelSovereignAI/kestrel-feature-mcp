"""Bounded private result associations for the originating MCP registration.

This is an in-process component, not an HTTP authorization service. The host
must resolve the original publisher and authenticate each reader through the
two supplied callbacks. A chat part contains only a locator; neither that
locator nor its chat metadata grants access to a native result or resource.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AsyncExitStack
from copy import deepcopy
from dataclasses import dataclass, field
import json
import math
import secrets
import time
from weakref import WeakSet

from mcp import types
from kestrel_sdk.resources import ResourceConflict, ResourceError
from kestrel_sdk.tools import DeferredToolResultHost, ToolPublicationContext

from .apps_execution import (
    AppExecutor, AppView, MCPAppResultWithheld, RegisteredAppTool,
    call_synchronous_callback, require_synchronous_callback,
)
from .dynamic_tools import MCPToolWrapper


@dataclass(eq=False)
class _Batch:
    tools: tuple[RegisteredAppTool, ...]
    is_current: Callable[[], bool]
    active: bool = True

    def is_live(self) -> bool:
        return (self.active and call_synchronous_callback(self.is_current, label="registration authority") is True
                and all(tool.binding.is_current for tool in self.tools)
                and self.tools[0].tool.bound_caller.is_current)

    def require_current(self) -> None:
        if not self.is_live():
            raise ResourceConflict("MCP App registration is unavailable; reopen without replaying prior calls")


@dataclass(eq=False)
class _Publication:
    batch: _Batch
    source: RegisteredAppTool
    context: ToolPublicationContext
    owner: object = field(repr=False)
    native: types.CallToolResult = field(repr=False)
    arguments: dict = field(repr=False)
    expires_at: float
    views: set[AppView] = field(default_factory=set, repr=False)


class AppPublications:
    """Per-feature original ownership, bounded retention and physical Views.

    ``publication_owner`` returns a host-resolved immutable principal snapshot,
    or None when there is no authorized interactive publisher. ``require_reader``
    must independently authenticate the current reader and check that original
    principal AND chat on every call; it returns None or raises. These functions
    are trusted host integrations, never supplied by a tool, part or request DTO.
    """

    def __init__(
        self, *, host: DeferredToolResultHost, max_pending_calls: int, agent_id: str,
        publication_owner: Callable[[ToolPublicationContext], object | None],
        require_reader: Callable[[object, ToolPublicationContext], None],
        max_publications: int, max_views: int, max_payload_bytes: int,
        max_publications_per_owner: int, max_views_per_owner: int,
        retention_seconds: float, clock: Callable[[], float] = time.monotonic,
    ):
        for value in (max_publications, max_views, max_payload_bytes,
                      max_publications_per_owner, max_views_per_owner):
            if type(value) is not int or value <= 0:
                raise ValueError("MCP Apps publication limits must be positive integers")
        if max_publications_per_owner > max_publications or max_views_per_owner > max_views:
            raise ValueError("MCP Apps owner limits cannot exceed their feature limits")
        if (isinstance(retention_seconds, bool) or not math.isfinite(retention_seconds)
                or retention_seconds <= 0):
            raise ValueError("MCP Apps retention must be positive and finite")
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("MCP Apps require the owning agent identity")
        require_synchronous_callback(publication_owner, label="publication owner")
        require_synchronous_callback(require_reader, label="reader authorization")
        require_synchronous_callback(clock, label="monotonic clock", allow_builtin=True)
        self._agent_id = agent_id
        self._publication_owner, self._require_reader = publication_owner, require_reader
        self._max_publications, self._max_views = max_publications, max_views
        self._max_publications_per_owner, self._max_views_per_owner = max_publications_per_owner, max_views_per_owner
        self._max_payload_bytes, self._retention_seconds = max_payload_bytes, retention_seconds
        self._clock = clock
        self._batches: dict[str, _Batch] = {}
        # A deferred factory retains its original wrapper across the SQL await.
        # Never let a later registration reuse that object to retarget the
        # staged native result. Weak keys do not retain retired tool catalogs.
        self._known_tools: WeakSet[MCPToolWrapper] = WeakSet()
        self._publications: dict[str, _Publication] = {}
        # Retain revoked Views until their owned approvals/effects/audit finish.
        self._views: dict[AppView, object] = {}
        self._closed = False
        self._now()
        # One constructor owns both sides of initial publication; a callback
        # cannot accidentally retain another registry's executor or source map.
        self.executor = AppExecutor(host=host, max_pending_calls=max_pending_calls,
            initial_publisher=self.publish)

    def _now(self) -> float:
        now = call_synchronous_callback(self._clock, label="monotonic clock")
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ValueError("MCP Apps monotonic clock must return a finite number")
        return now

    def register(self, owner: str, tools: list[RegisteredAppTool], *, is_current: Callable[[], bool]) -> None:
        """Retain exactly the handles confirmed by Core's registration callback."""
        if self._closed:
            raise ResourceConflict("MCP Apps publisher is closed")
        if (not isinstance(owner, str) or not owner or not callable(is_current)
                or not isinstance(tools, list)):
            raise ValueError("MCP Apps require an original registration owner and confirmed tool list")
        require_synchronous_callback(is_current, label="registration owner predicate")
        # The executor owns batch validation, including exact executor,
        # caller and source identities. A batch without a UI cannot publish one.
        source = next((item for item in tools if item.tool.resource_uri), None)
        if source is not None:
            self.executor.registration_tools(source, tools)
        else:
            self.retire(owner)
            return
        batch = _Batch(tuple(tools), is_current)
        batch.require_current()
        if any(item.tool in self._known_tools for item in tools):
            raise ValueError("MCP App tool wrapper already belonged to an original registration; build fresh wrappers")
        # Complete validation precedes withdrawing a currently usable batch.
        self.retire(owner)
        self._known_tools.update(item.tool for item in tools)
        self._batches[owner] = batch

    def retire(self, owner: str) -> None:
        batch = self._batches.pop(owner, None)
        if batch is None:
            return
        batch.active = False
        for reference, publication in tuple(self._publications.items()):
            if publication.batch is batch:
                self._discard(reference, publication)

    def _discard(self, reference: str, publication: _Publication) -> None:
        self._publications.pop(reference, None)
        for view in publication.views:
            view.revoke()

    def _prune(self) -> None:
        now = self._now()
        for reference, publication in tuple(self._publications.items()):
            if now >= publication.expires_at or not publication.batch.is_live():
                self._discard(reference, publication)

    def publish(self, tool: MCPToolWrapper, context: ToolPublicationContext,
                native: types.CallToolResult, arguments: dict) -> list[dict]:
        """Called synchronously by the post-policy, post-audit deferred factory."""
        if self._closed or context.agent_id != self._agent_id:
            raise MCPAppResultWithheld("MCP App publisher changed after execution; do not replay")
        candidates = [(batch, item) for batch in self._batches.values()
                      for item in batch.tools if item.tool is tool]
        if len(candidates) != 1:
            raise MCPAppResultWithheld("MCP App lost its unique original registration; do not replay")
        batch, source = candidates[0]
        batch.require_current()
        owner = call_synchronous_callback(self._publication_owner, context, label="publication owner")
        if owner is None:
            return []
        self._prune()
        owner_count = sum(value.owner == owner for value in self._publications.values())
        if (len(self._publications) >= self._max_publications
                or owner_count >= self._max_publications_per_owner):
            raise MCPAppResultWithheld("MCP App private result capacity reached; do not replay the completed tool")
        size = len(native.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))
        size += len(json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        if size > self._max_payload_bytes:
            raise MCPAppResultWithheld("MCP App private result exceeds its configured byte limit; do not replay")
        reference = secrets.token_urlsafe(32)
        if reference in self._publications:
            raise MCPAppResultWithheld("MCP App result locator collision; do not replay")
        self._publications[reference] = _Publication(batch, source, context, owner,
            native.model_copy(deep=True), deepcopy(arguments), self._now() + self._retention_seconds)
        return [{"type": "mcp_app", "data": {"reference": reference, "session_id": context.session_id}}]

    def _require_publication(self, reference: str) -> _Publication:
        self._prune()
        publication = self._publications.get(reference)
        if self._closed or publication is None:
            raise ResourceConflict("MCP App result is unavailable; do not replay the completed tool")
        try:
            publication.batch.require_current()
            if call_synchronous_callback(self._require_reader, publication.owner, publication.context,
                    label="reader authorization") is not None:
                raise TypeError("MCP App reader authorization must return None or raise")
        except (ResourceError, PermissionError) as error:
            # Keep the original diagnostic in-process. A locator cannot disclose
            # whether another principal's record exists or its source expired.
            raise ResourceConflict("MCP App result is unavailable; do not replay the completed tool") from error
        return publication

    def open_view(self, reference: str) -> AppView:
        """Create one physical View after independently authenticating its reader."""
        publication = self._require_publication(reference)
        owner_count = sum(owner == publication.owner for owner in self._views.values())
        if len(self._views) >= self._max_views or owner_count >= self._max_views_per_owner:
            raise ResourceConflict("MCP Apps physical View limit reached; close a View before opening another")

        def current():
            if self._require_publication(reference) is not publication:
                raise ResourceConflict("MCP App result was replaced")
            return True

        view = self.executor.open_view(publication.source, list(publication.batch.tools),
            session_id=publication.context.session_id, owner_is_current=current)
        publication.views.add(view)
        self._views[view] = publication.owner
        return view

    def initial_result(self, reference: str, view: AppView) -> tuple[dict, types.CallToolResult]:
        """Return copies to this authenticated physical View without tool replay."""
        publication = self._require_publication(reference)
        if view not in publication.views:
            raise ResourceConflict("MCP App View does not own this original result")
        view.require_current()
        return deepcopy(publication.arguments), publication.native.model_copy(deep=True)

    async def close_view(self, view: AppView) -> None:
        if view not in self._views:
            raise ResourceConflict("MCP App View belongs to another publisher")
        await self._close_owned_view(view)

    async def _close_owned_view(self, view: AppView) -> None:
        # Both an admitted physical close and a teardown snapshot can own this
        # same join. revoke() cancels once; close() retains its original calls
        # through audit settlement. Either owner may release the settled entry.
        await view.close()
        self._views.pop(view, None)
        for publication in self._publications.values():
            publication.views.discard(view)

    async def drain_retired(self) -> None:
        """Join revoked Views before retiring their connection or feature owner."""
        self._prune()
        async with AsyncExitStack() as cleanup:
            for view in tuple(self._views):
                if view._closed:
                    cleanup.push_async_callback(self._close_owned_view, view)

    async def close(self) -> None:
        self._closed = True
        for owner in tuple(self._batches):
            self.retire(owner)
        await self.drain_retired()
