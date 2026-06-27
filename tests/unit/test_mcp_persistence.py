"""MCP server enablement persistence (#1979 PR4): enable/disable persist
mcp_server deltas via the host foundation, and post_all_features_loaded
auto-restores them on restart. No Docker required — the host API + gateway are
mocked; what's verified is the persist/forget/restore wiring."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

import kestrel_feature_mcp.feature as feat_mod
from kestrel_feature_mcp.feature import MCPAgent


def _host(*, with_persistence=True):
    host = MagicMock()
    if with_persistence:
        host.persist_feature_enablement = AsyncMock()
        host.clear_feature_enablement = AsyncMock()
        host.get_enablement_deltas = AsyncMock(return_value=[])
    else:
        # A host lacking the foundation: remove the attrs so hasattr is False.
        del host.persist_feature_enablement
    return host


def _feature(host=None, *, manager=None, gateway=None) -> MCPAgent:
    feat = MCPAgent(host if host is not None else _host())
    feat.manager = manager
    feat.gateway_manager = gateway
    return feat


class TestPersistHelpers:
    @pytest.mark.asyncio
    async def test_persist_server_writes_delta(self):
        host = _host()
        feat = _feature(host)
        await feat._persist_server("fetch", "enabled", metadata={"mode": "gateway"})
        host.persist_feature_enablement.assert_awaited_once()
        args, kwargs = host.persist_feature_enablement.await_args
        assert args[0] == "mcp_server" and args[1] == "fetch" and args[2] == "enabled"
        assert kwargs["metadata"] == {"mode": "gateway"}

    @pytest.mark.asyncio
    async def test_forget_server_clears_delta(self):
        host = _host()
        feat = _feature(host)
        await feat._forget_server("fetch")
        host.clear_feature_enablement.assert_awaited_once_with("mcp_server", "fetch")

    @pytest.mark.asyncio
    async def test_no_persistence_support_is_noop(self):
        feat = _feature(_host(with_persistence=False))
        assert feat._supports_enablement_persistence() is False
        # must not raise
        await feat._persist_server("fetch", "enabled")
        await feat._forget_server("fetch")


class TestRestoreOnStartup:
    @pytest.mark.asyncio
    async def test_restore_gateway_servers(self, monkeypatch):
        monkeypatch.setattr(feat_mod, "check_docker_mcp_available", lambda: True)
        host = _host()
        host.get_enablement_deltas = AsyncMock(return_value=[
            {"name": "fetch", "state": "enabled", "metadata": {"mode": "gateway"}},
            {"name": "time", "state": "enabled", "metadata": {"mode": "gateway"}},
            {"name": "old", "state": "disabled", "metadata": {"mode": "gateway"}},
        ])
        feat = _feature(host)
        feat.gateway_start = AsyncMock()
        await feat.post_all_features_loaded(host)
        feat.gateway_start.assert_awaited_once()
        # only the enabled gateway servers, comma-joined
        assert set(feat.gateway_start.await_args[0][0].split(",")) == {"fetch", "time"}

    @pytest.mark.asyncio
    async def test_restore_container_servers(self, monkeypatch):
        monkeypatch.setattr(feat_mod, "check_docker_mcp_available", lambda: False)
        host = _host()
        host.get_enablement_deltas = AsyncMock(return_value=[
            {"name": "c1", "state": "enabled",
             "metadata": {"mode": "container", "image": "org/img:1", "args": None}},
        ])
        feat = _feature(host)
        feat.load_tool = AsyncMock()
        await feat.post_all_features_loaded(host)
        feat.load_tool.assert_awaited_once_with("org/img:1", None)

    @pytest.mark.asyncio
    async def test_restore_noop_when_no_deltas(self):
        host = _host()
        host.get_enablement_deltas = AsyncMock(return_value=[])
        feat = _feature(host)
        feat.gateway_start = AsyncMock()
        feat.load_tool = AsyncMock()
        await feat.post_all_features_loaded(host)
        feat.gateway_start.assert_not_awaited()
        feat.load_tool.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_restore_noop_without_persistence(self):
        feat = _feature(_host(with_persistence=False))
        # must not raise even though there's no store
        await feat.post_all_features_loaded(feat.agent)


class TestUnloadForgets:
    @pytest.mark.asyncio
    async def test_unload_clears_persistence(self):
        host = _host()
        manager = MagicMock()
        manager.stop_tool = AsyncMock()
        feat = _feature(host, manager=manager)
        await feat.unload_tool("mcp_fetch_abc")
        host.clear_feature_enablement.assert_awaited_once_with("mcp_server", "mcp_fetch_abc")
