"""Optional Apps composition owned by one feature and its native connections."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from pathlib import Path

from mcp.client.extension import advertise
from mcp.server.apps import EXTENSION_ID
from pydantic import BaseModel, ConfigDict, Field, model_validator
from kestrel_sdk.features.ui import UIContributions
from kestrel_sdk.resources import ResourceConflict

from .apps_publication import AppPublications
from .connection import MCPConnection
from ._lifecycle import MCPFeatureClosingError, run_cleanup_steps


class AppsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)
    enabled: bool = False
    host: dict = Field(default_factory=dict)
    max_publications: int = Field(default=64, gt=0, le=4096)
    max_publications_per_owner: int = Field(default=16, gt=0, le=1024)
    max_views: int = Field(default=32, gt=0, le=1024)
    max_views_per_owner: int = Field(default=8, gt=0, le=256)
    max_payload_bytes: int = Field(default=2_097_152, gt=0, le=33_554_432)
    max_pending_calls: int = Field(default=4, gt=0, le=32)
    retention_seconds: float = Field(default=900.0, gt=0, le=86400)
    maintenance_seconds: float = Field(default=1.0, gt=0, le=60)

    @model_validator(mode="after")
    def owner_budgets(self):
        if (self.max_publications_per_owner > self.max_publications
                or self.max_views_per_owner > self.max_views):
            raise ValueError("MCP Apps owner limits cannot exceed feature limits")
        return self


class MCPAppsFeatureMixin:
    """Core owns policy and HTTP; this feature owns native MCP resources."""

    def _init_apps(self):
        self._apps_settings = AppsSettings()
        self._apps_host = self._apps_publications = self._apps_maintenance = None
        self._apps_router = None

    @property
    def config_schema(self):
        return {"type": "object", "additionalProperties": False,
                "properties": {"apps": AppsSettings.model_json_schema()}}

    async def get_config(self):
        return {"apps": self._apps_settings.model_dump(mode="json")}

    async def set_config(self, config):
        async with self._lifecycle_transition, self._docker_operations, self._docker_initialization:
            self._require_open()
            await self._set_apps_config(config)

    async def _set_apps_config(self, config):
        if not isinstance(config, dict) or set(config) - {"apps"}:
            raise ValueError("MCP configuration accepts only Apps host settings")
        settings = AppsSettings.model_validate(deepcopy(config.get("apps", {})))
        if settings.enabled:
            validate = getattr(self.agent, "validate_mcp_apps_host_configuration", None)
            if getattr(self.agent, "supports_mcp_apps_host", None) is not True or not callable(validate):
                raise TypeError("MCP Apps require Core's authenticated physical View host")
            settings = settings.model_copy(update={"host": validate(settings.host)})
        if settings == self._apps_settings:
            if settings.enabled and self._apps_host is None:
                await self._start_apps()
            return
        if (self._remote_connections or self.gateway_manager is not None
                or self.manager is not None and self.manager.owned_containers):
            raise ResourceConflict("Unload MCP connections before changing Apps host configuration")
        self._lifecycle_generation += 1
        await self._close_apps()
        self._require_open()
        self._apps_settings = settings
        if settings.enabled:
            await self._start_apps()

    async def _start_apps(self):
        if getattr(self.agent, "supports_mcp_apps_host", None) is not True:
            raise TypeError("MCP Apps require Core's authenticated physical View host")
        assets = Path(__file__).with_name("apps_sandbox")
        if not (assets / "parent-entry.js").is_file():
            raise RuntimeError("MCP Apps parent renderer is missing from the installed package")
        generation = self._lifecycle_generation

        def current():
            return (not self._closing and self._lifecycle_generation == generation
                    and self._apps_host is host
                    and (self._apps_maintenance is None or not self._apps_maintenance.done()))

        host = self.agent.create_mcp_apps_host(self, configuration=self._apps_settings.host,
                                               is_current=current)
        settings = self._apps_settings
        try:
            publications = AppPublications(host=self.agent, agent_id=self._connection_owner_did(),
                publication_owner=host.publication_owner, require_reader=host.require_reader,
                **{name: getattr(settings, name) for name in (
                    "max_publications", "max_publications_per_owner", "max_views", "max_views_per_owner",
                    "max_payload_bytes", "max_pending_calls", "retention_seconds")})
            host.attach(publications)
        except BaseException as error:
            await run_cleanup_steps([(True, host.close)], failure=error)
            raise

        async def maintain():
            try:
                while True:
                    await asyncio.sleep(settings.maintenance_seconds)
                    await host.maintain()
            finally:
                host.withdraw_private_data()
        maintenance = asyncio.create_task(maintain(), name="mcp-apps-private-retention")
        self._apps_host, self._apps_publications, self._apps_maintenance = host, publications, maintenance

    def _new_mcp_connection(self, *args, **kwargs):
        self._require_open()
        if self._apps_settings.enabled and self._apps_host is None:
            raise MCPFeatureClosingError("MCP Apps host is not initialized")
        if self._apps_host is not None:
            if self._apps_maintenance is None or self._apps_maintenance.done():
                raise MCPFeatureClosingError("MCP Apps retention owner is unavailable")
            kwargs["extensions"] = [advertise(EXTENSION_ID)]
            kwargs["before_close"] = self._apps_publications.retire_connection
        return MCPConnection(*args, **kwargs)

    def _manager_connection_settings(self):
        return {"connection_factory": self._new_mcp_connection}

    async def _drain_apps(self):
        if self._apps_host is not None:
            await self._apps_host.maintain()

    async def _close_apps(self):
        host, maintenance = self._apps_host, self._apps_maintenance
        if host is None:
            return
        host.withdraw_private_data()
        if maintenance is not None and not maintenance.done():
            maintenance.cancel()

        async def join_maintenance():
            if maintenance is not None:
                cancellation = None
                while not maintenance.done():
                    try:
                        await asyncio.wait({maintenance})
                    except asyncio.CancelledError as error:
                        cancellation = error
                failure = None if maintenance.cancelled() else maintenance.exception()
                if failure is not None and cancellation is not None:
                    raise BaseExceptionGroup("MCP Apps retention cleanup failed", [cancellation, failure])
                if failure is not None:
                    raise failure
                if cancellation is not None:
                    raise cancellation
        try:
            await run_cleanup_steps([(True, host.close), (True, join_maintenance)])
        finally:
            # A settled owner may report its failure once without poisoning
            # every later shutdown. A partial close keeps its original custody.
            if host.retired and (maintenance is None or maintenance.done()):
                self._apps_host = self._apps_publications = self._apps_maintenance = None

    def get_router(self):
        if getattr(self.agent, "supports_mcp_apps_host", None) is not True:
            return None
        if self._apps_router is None:
            self._apps_router = self.agent.create_mcp_apps_router(self, resolve_host=lambda: self._apps_host)
        return self._apps_router

    def get_ui_contributions(self):
        if getattr(self.agent, "supports_mcp_apps_host", None) is not True:
            return None
        return UIContributions(static_dir=str(Path(__file__).with_name("apps_sandbox")),
                               modules=["parent-entry.js"])
