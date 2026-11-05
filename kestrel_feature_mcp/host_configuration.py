"""One configuration generation for the feature's Apps and OAuth hosts."""

from __future__ import annotations

import asyncio
import contextvars
from copy import deepcopy
from pathlib import Path

from kestrel_sdk.features.ui import UIContributions
from kestrel_sdk.resources import ResourceConflict

from ._lifecycle import MCPFeatureClosingError, join_maintenance, run_cleanup_steps
from .apps_host import AppsSettings, MCPAppsFeatureMixin
from .oauth_grants import initialize_grant_schema
from .oauth_runtime import OAuthRuntime, OAuthSettings


class MCPHostFeatureMixin(MCPAppsFeatureMixin):
    def _init_hosts(self):
        self._init_apps()
        self._oauth_settings = OAuthSettings()
        self._oauth_host = self._oauth_runtime = self._oauth_maintenance = None
        self._host_router = None

    @property
    def config_schema(self):
        return {'type': 'object', 'additionalProperties': False, 'properties': {
            'apps': AppsSettings.model_json_schema(), 'oauth': OAuthSettings.model_json_schema()}}

    async def get_config(self):
        return {'apps': self._apps_settings.model_dump(mode='json'),
            'oauth': self._oauth_settings.model_dump(mode='json')}

    async def set_config(self, config):
        async with self._lifecycle_transition, self._docker_operations, self._docker_initialization:
            self._require_open()
            if not isinstance(config, dict) or set(config) - {'apps', 'oauth'}:
                raise ValueError('MCP configuration accepts Apps and OAuth host settings')
            apps = AppsSettings.model_validate(deepcopy(config.get('apps', self._apps_settings.model_dump())))
            oauth = OAuthSettings.model_validate(deepcopy(config.get('oauth', self._oauth_settings.model_dump())))
            if apps.enabled or oauth.enabled:
                self._require_governed_host()
            # Validate both domains before retiring either original host.
            if apps.enabled:
                validate = getattr(self.agent, 'validate_mcp_apps_host_configuration', None)
                if getattr(self.agent, 'supports_mcp_apps_host', None) is not True or not callable(validate):
                    raise TypeError("MCP Apps require Core's authenticated physical View host")
                apps = apps.model_copy(update={'host': validate(apps.host)})
            if oauth.enabled and (getattr(self.agent, 'supports_mcp_oauth_host', None) is not True
                    or not callable(getattr(self.agent, 'create_mcp_oauth_host', None))):
                raise TypeError("MCP OAuth requires Core's authenticated native OAuth host")
            if apps == self._apps_settings and oauth == self._oauth_settings:
                await self._start_configured_hosts()
                return
            if (self._remote_connections or self.gateway_manager is not None
                    or self.manager is not None and self.manager.owned_containers
                    or self._oauth_runtime is not None and self._oauth_runtime.has_owners):
                raise ResourceConflict('Unload MCP connections and authorization operations before changing host configuration')
            self._lifecycle_generation += 1
            await run_cleanup_steps([(True, self._close_oauth), (True, self._close_apps)])
            self._require_open()
            self._apps_settings, self._oauth_settings = apps, oauth
            await self._start_configured_hosts()

    async def _start_configured_hosts(self):
        if self._apps_settings.enabled or self._oauth_settings.enabled:
            self._require_governed_host()
        # Readiness refusal does not consume an existing owner's cleanup
        # failure. Explicit shutdown/re-enable joins that original owner.
        if self._apps_settings.enabled and self._apps_host is not None:
            self._require_apps_ready()
        if self._oauth_settings.enabled and self._oauth_host is not None:
            self._require_oauth_ready()
        try:
            if self._apps_settings.enabled and self._apps_host is None:
                await self._start_apps()
            if self._oauth_settings.enabled and self._oauth_host is None:
                await self._start_oauth()
        except BaseException as error:
            await run_cleanup_steps([(True, self._close_oauth), (True, self._close_apps)], failure=error)
            raise

    def _require_oauth_ready(self):
        if (self._oauth_host is None or self._oauth_host.retired
                or self._oauth_maintenance is None or self._oauth_maintenance.done()):
            raise MCPFeatureClosingError('MCP OAuth maintenance owner is unavailable')

    async def _start_oauth(self):
        generation = self._lifecycle_generation
        def current():
            return (not self._closing and self._lifecycle_generation == generation
                and self._oauth_host is host
                and (self._oauth_maintenance is None or not self._oauth_maintenance.done()))
        host = self.agent.create_mcp_oauth_host(self, is_current=current)
        settings = self._oauth_settings
        try:
            await initialize_grant_schema(host.database)
            self._require_open(generation)
            runtime = OAuthRuntime(self, host, settings)
            host.attach(runtime)
        except BaseException as error:
            await run_cleanup_steps([(True, host.close)], failure=error)
            raise
        async def maintain():
            try:
                while True:
                    await asyncio.sleep(settings.maintenance_seconds)
                    await runtime.maintain()
            finally:
                host.withdraw()
        maintenance = asyncio.create_task(maintain(), context=contextvars.Context(), name='mcp-oauth-retention')
        self._oauth_host, self._oauth_runtime, self._oauth_maintenance = host, runtime, maintenance

    async def _close_oauth(self):
        host, maintenance = self._oauth_host, self._oauth_maintenance
        if host is None:
            return
        host.withdraw()
        if maintenance is not None and not maintenance.done():
            maintenance.cancel()
        try:
            await run_cleanup_steps([(True, lambda: join_maintenance(maintenance, 'MCP OAuth')),
                (True, host.close)])
        finally:
            if host.retired and (maintenance is None or maintenance.done()):
                self._oauth_host = self._oauth_runtime = self._oauth_maintenance = None

    def get_router(self):
        apps = getattr(self.agent, 'supports_mcp_apps_host', None) is True
        oauth = getattr(self.agent, 'supports_mcp_oauth_host', None) is True
        if not apps and not oauth:
            return None
        from fastapi import APIRouter

        if self._host_router is None:
            router = APIRouter()
            if apps:
                router.include_router(self.agent.create_mcp_apps_router(self, resolve_host=lambda: self._apps_host))
            if oauth:
                router.include_router(self.agent.create_mcp_oauth_router(self, resolve_host=lambda: self._oauth_host))
            self._host_router = router
        return self._host_router

    def get_ui_contributions(self):
        modules = []
        if getattr(self.agent, 'supports_mcp_apps_host', None) is True:
            modules.append('parent-entry.js')
        if getattr(self.agent, 'supports_mcp_oauth_host', None) is True:
            modules.append('oauth-panel.js')
        if not modules:
            return None
        return UIContributions(static_dir=str(Path(__file__).with_name('apps_sandbox')), modules=modules,
            css=['oauth-panel.css'] if 'oauth-panel.js' in modules else [])
