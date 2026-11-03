"""Native sessions remain owned across Apps failures and configuration races."""

import asyncio
import json

from mcp_types import CLIENT_CAPABILITIES_META_KEY
import pytest

from kestrel_feature_mcp import feature as feature_module
from kestrel_feature_mcp.connection import MCPConnection
from kestrel_feature_mcp.feature import MCPAgent, MCPFeatureClosingError
from kestrel_feature_mcp.manager import MCPToolManager
from kestrel_sdk.tools.result import ToolResultStatus
from tests.unit.test_mcp_apps_host import native_apps_host as native_apps_host
from tests.unit.test_remote_mcp import RegistryHost, remote_peer as remote_peer


async def test_failed_retirement_hook_still_closes_its_actual_native_transport(mcp_http_server):
    failure = PermissionError("owned retirement failure")
    attempts = []
    async def before_close(connection):
        attempts.append(connection)
        if len(attempts) == 1:
            raise failure
    connection = MCPConnection(mcp_http_server.url, before_close=before_close)
    try:
        await connection.connect()
        owner = connection._task
        with pytest.raises(PermissionError) as caught:
            await connection.close()
        assert caught.value is failure
        assert not connection.is_connected and owner.done() and connection._task is None
    finally:
        await connection.close()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_apps_cleanup_failure_does_not_skip_native_remote_cleanup(remote_peer, monkeypatch):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    loaded = await feature.load_tool(remote_peer.url)
    assert loaded.status is ToolResultStatus.OK
    connection = feature._remote_connections[loaded.data["connection"]].connection
    original = feature._close_apps
    async def fail_once():
        monkeypatch.setattr(feature, "_close_apps", original)
        raise PermissionError("owned Apps cleanup failure")
    monkeypatch.setattr(feature, "_close_apps", fail_once)
    try:
        with pytest.raises(PermissionError, match="owned Apps cleanup"):
            await feature.shutdown()
        assert not connection.is_connected and not feature._remote_connections
        assert not feature.agent.registered
    finally:
        try:
            await feature.shutdown()
        finally:
            await connection.close()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_cancellation_during_apps_cleanup_still_settles_native_remotes(remote_peer, monkeypatch):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    loaded = await feature.load_tool(remote_peer.url)
    assert loaded.status is ToolResultStatus.OK
    connection = feature._remote_connections[loaded.data["connection"]].connection
    original = feature._close_apps
    entered = asyncio.Event()
    async def interrupted():
        monkeypatch.setattr(feature, "_close_apps", original)
        entered.set()
        await asyncio.Future()
    monkeypatch.setattr(feature, "_close_apps", interrupted)
    stopping = asyncio.create_task(feature.shutdown())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        stopping.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stopping
        assert not connection.is_connected and not feature._remote_connections
        assert not feature.agent.registered
    finally:
        stopping.cancel()
        await asyncio.gather(stopping, return_exceptions=True)
        try:
            await feature.shutdown()
        finally:
            await connection.close()


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.parametrize("recovery", ["shutdown", "initialize"])
async def test_observed_maintenance_failure_does_not_poison_reenable(native_apps_host, recovery):
    b = native_apps_host
    previous, worker = b.feature._apps_host, b.feature._apps_maintenance
    batch = b.feature._apps_publications._batches["mcp:composition"]
    def fail_once():
        batch.is_current = lambda: True
        raise PermissionError("owned maintenance failure")
    batch.is_current = fail_once
    with pytest.raises(PermissionError, match="owned maintenance failure"):
        await asyncio.wait_for(asyncio.shield(worker), 5)
    with pytest.raises(PermissionError, match="owned maintenance failure"):
        await getattr(b.feature, recovery)()
    assert b.feature._apps_host is None and previous.retired
    await b.feature.initialize()
    assert b.feature._apps_host is not previous and not b.feature._apps_maintenance.done()


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
async def test_empty_manager_uses_current_apps_factory_after_configuration(native_apps_host, mcp_http_server):
    b = native_apps_host
    await b.connection.close()
    configuration = await b.feature.get_config()
    await b.feature.set_config({"apps": {"enabled": False}})
    # This test exercises native readiness transport, without Docker operations.
    b.feature.manager = MCPToolManager(owner_did=b.agent.did, docker_client=None,
                                       **b.feature._manager_connection_settings())
    await b.feature.set_config(configuration)
    start = len(mcp_http_server.requests)
    url = mcp_http_server.url.split(":")
    assert await b.feature.manager._check_mcp_ready("127.0.0.1", int(url[-1].split("/")[0]))
    messages = [json.loads(body) for _, body in mcp_http_server.requests[start:]
                if body and json.loads(body).get("method") == "server/discover"]
    assert messages[0]["params"]["_meta"][CLIENT_CAPABILITIES_META_KEY]["extensions"]["io.modelcontextprotocol/ui"] == {}


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_configuration_cannot_admit_a_remote_start_from_an_earlier_generation(remote_peer, monkeypatch):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    original = feature_module.assert_safe_url
    async def paused_validation(*args, **kwargs):
        entered.set()
        await release.wait()
        return await original(*args, **kwargs)
    monkeypatch.setattr(feature_module, "assert_safe_url", paused_validation)
    loading = asyncio.create_task(feature.load_tool(remote_peer.url))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        await feature.set_config({"apps": {"max_views": 16}})
        release.set()
        result = await asyncio.wait_for(loading, 5)
        assert result.status is ToolResultStatus.ERROR and "generation" in result.error
        assert not feature._remote_connections and not remote_peer.peer.requests
    finally:
        release.set()
        await asyncio.gather(loading, return_exceptions=True)
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
async def test_shutdown_cannot_be_followed_by_configuration_starting_a_new_host(native_apps_host):
    b = native_apps_host
    configuration = await b.feature.get_config()
    await b.feature.shutdown()
    with pytest.raises(MCPFeatureClosingError):
        await b.feature.set_config(configuration)
    assert b.feature._apps_host is None


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
async def test_shutdown_fences_configuration_that_is_already_retiring_its_host(native_apps_host, monkeypatch):
    b = native_apps_host
    await b.connection.close()
    previous = b.feature._apps_host
    entered, release = asyncio.Event(), asyncio.Event()
    before = asyncio.all_tasks()
    original = previous.close
    async def paused_close():
        entered.set()
        await release.wait()
        await original()
    monkeypatch.setattr(previous, "close", paused_close)
    changed = await b.feature.get_config()
    changed["apps"]["maintenance_seconds"] = 2.0
    configuring = asyncio.create_task(b.feature.set_config(changed))
    stopping = None
    try:
        await asyncio.wait_for(entered.wait(), 5)
        stopping = asyncio.create_task(b.feature.shutdown())
        await asyncio.sleep(0)
        release.set()
        configured, stopped = await asyncio.gather(configuring, stopping, return_exceptions=True)
        assert isinstance(configured, MCPFeatureClosingError) and stopped is None
        assert b.feature._apps_host is None and all(host.retired for host in b.agent._mcp_apps_hosts)
    finally:
        release.set()
        await asyncio.gather(configuring, *([stopping] if stopping else []), return_exceptions=True)
        # Reproduction on broken source can orphan a new worker during shutdown.
        workers = [task for task in asyncio.all_tasks() - before
                   if task.get_name() == "mcp-apps-private-retention"]
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        for host in b.agent._mcp_apps_hosts:
            if not host.retired:
                await host.close()


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
async def test_failed_host_attachment_releases_the_original_core_slot(native_apps_host, monkeypatch):
    b = native_apps_host
    await b.connection.close()
    configuration = await b.feature.get_config()
    await b.feature.set_config({"apps": {"enabled": False}})
    original = b.agent.create_mcp_apps_host
    owners = []
    def failed_attachment(*args, **kwargs):
        host = original(*args, **kwargs)
        owners.append(host)
        def attach(_publications):
            raise PermissionError("owned attachment failure")
        host.attach = attach
        return host
    monkeypatch.setattr(b.agent, "create_mcp_apps_host", failed_attachment)
    try:
        with pytest.raises(PermissionError, match="owned attachment failure"):
            await b.feature.set_config(configuration)
        assert len(owners) == 1 and owners[0].retired and b.feature._apps_host is None
        with pytest.raises(MCPFeatureClosingError, match="not initialized"):
            b.feature._new_mcp_connection("http://127.0.0.1:1/mcp")
        monkeypatch.setattr(b.agent, "create_mcp_apps_host", original)
        await b.feature.set_config(configuration)
        assert b.feature._apps_host is not None and b.feature._apps_host is not owners[0]
    finally:
        for host in owners:
            if not host.retired:
                await host.close()


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
async def test_reenable_retries_a_partially_closed_original_apps_owner(native_apps_host, monkeypatch):
    b = native_apps_host
    previous = b.feature._apps_host
    original = previous.close
    attempts = []
    async def fail_once():
        attempts.append(True)
        if len(attempts) == 1:
            raise PermissionError("owned partial close")
        await original()
    monkeypatch.setattr(previous, "close", fail_once)
    with pytest.raises(PermissionError, match="owned partial close"):
        await b.feature.shutdown()
    assert b.feature._apps_host is previous and not previous.retired
    await b.feature.initialize()
    assert previous.retired and b.feature._apps_host is not previous
    assert not b.feature._apps_maintenance.done()
