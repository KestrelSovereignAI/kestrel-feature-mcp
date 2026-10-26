"""Remote loading uses native TLS/MCP and the existing governed mount surface."""

import asyncio
import json
import socket
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpcore2
import httpx2
import pytest

from kestrel_feature_mcp.feature import MCPAgent
from kestrel_sdk.tools.result import ToolResultStatus


class RegistryHost:
    def __init__(self, did="did:test:remote"):
        self.agent_id = did
        self.registered = {}
        self.saved = {}

    def register_dynamic_tools(self, owner, tools):
        self.registered[owner] = list(tools)
        return len(tools)

    def unregister_dynamic_tools(self, owner):
        return len(self.registered.pop(owner, []))

    async def persist_feature_enablement(self, kind, name, state, *, actor, metadata):
        self.saved[name] = {"name": name, "state": state, "metadata": metadata}

    async def clear_feature_enablement(self, kind, name):
        self.saved.pop(name, None)

    async def get_enablement_deltas(self, kind):
        return list(self.saved.values())


@pytest.fixture
async def remote_peer(mcp_http_server, monkeypatch):
    peer = mcp_http_server
    port = int(peer.url.split(":")[-1].split("/")[0])
    state = SimpleNamespace(peer=peer, url=f"https://remote.example:{port}/mcp",
                            dials=[], resolutions=[], answers=["8.8.8.8"])
    def dns(host, requested_port, *, type, proto):
        assert host == "remote.example" and requested_port == port
        state.resolutions.append((host, requested_port))
        return [(socket.AF_INET, type, proto, "", (answer, requested_port))
                for answer in state.answers]
    original = httpcore2.AnyIOBackend.connect_tcp
    server_port = port
    async def dial(backend, host, port, **kwargs):
        state.dials.append((host, port))
        assert host == "8.8.8.8" and port == server_port
        return await original(backend, "127.0.0.1", port, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setattr(httpcore2.AnyIOBackend, "connect_tcp", dial)
    monkeypatch.setenv("SSL_CERT_FILE", peer.settings["certificate_file"])
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    return state


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_remote_load_call_list_and_unload_need_no_docker(remote_peer, monkeypatch):
    import docker
    def forbidden(*args, **kwargs):
        raise AssertionError("Remote MCP touched Docker")
    monkeypatch.setattr(docker, "from_env", forbidden)
    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.OK, result.to_dict()
        assert feature.manager is None
        assert result.data["via"] == "remote"
        assert result.data["protocol_version"] == "2026-07-28"
        owner = next(iter(host.registered))
        assert owner.startswith("mcp:remote:")
        wrapper = next(t for t in host.registered[owner] if t._real_name == "echo")
        called = await wrapper.execute(text="real remote side effect")
        assert remote_peer.peer.witness == ["real remote side effect"]
        assert called["status"] == "ok"
        listed = await feature.list_tools()
        assert listed.status is ToolResultStatus.OK
        assert {t["name"] for t in listed.data["tools"]} == {"echo", "fail"}
        assert listed.data["remotes"][0]["connected"]
        assert (await feature.unload_tool(result.data["connection"])).status is ToolResultStatus.OK
        assert not host.registered and not host.saved
    finally:
        await feature.shutdown()
    assert remote_peer.dials and len(remote_peer.resolutions) == 1
    assert set(remote_peer.peer.server_names) == {"remote.example"}
    messages = []
    for scope, raw in remote_peer.peer.requests:
        if not raw:
            continue
        message = json.loads(raw)
        headers = dict(scope["headers"])
        assert headers[b"host"].decode() == remote_peer.url.split("/")[2]
        assert headers[b"mcp-method"].decode() == message["method"]
        assert b"mcp-session-id" not in headers
        assert b"authorization" not in headers
        if message["method"] == "tools/call":
            assert headers[b"mcp-name"] == b"echo"
        messages.append(message["method"])
    assert messages == ["server/discover", "tools/list", "tools/call"]


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_same_instance_reenable_restores_remote_and_retires_old_callers(remote_peer):
    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    try:
        loaded = await feature.load_tool(remote_peer.url)
        assert loaded.status is ToolResultStatus.OK
        name = loaded.data["connection"]
        owner = "mcp:remote:" + name
        old_connection = feature._remote_connections[name].connection
        old_wrapper = next(t for t in host.registered[owner] if t._real_name == "echo")
        # Repeated initialization of a live instance must preserve custody.
        await feature.initialize()
        assert feature._remote_connections[name].connection is old_connection
        await feature.shutdown()
        assert not old_connection.is_connected and not host.registered
        assert name in host.saved
        await feature.initialize()
        await feature.post_all_features_loaded()
        assert set(feature._remote_connections) == {name}
        assert feature._remote_connections[name].connection is not old_connection
        rejected = await old_wrapper.execute(text="stale-before-reenable")
        assert remote_peer.peer.witness == []
        assert rejected["status"] == "error"
        wrapper = next(t for t in host.registered[owner] if t._real_name == "echo")
        result = await wrapper.execute(text="after-same-instance-reenable")
        assert remote_peer.peer.witness == ["after-same-instance-reenable"]
        assert result["status"] == "ok"
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("selector", [
    "http://remote.example/mcp", "https://127.0.0.1/mcp", "https://169.254.169.254/mcp",
    "https://user:password@remote.example/mcp", "https://[not-ipv6]/mcp",
    "file:///etc/passwd", "https:relative", "https://remote.example/mcp#fragment",
])
async def test_unsafe_remote_endpoint_never_dials_or_mounts(remote_peer, selector):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    try:
        result = await feature.load_tool(selector)
        assert result.status is ToolResultStatus.ERROR
        assert remote_peer.dials == remote_peer.resolutions == []
        assert remote_peer.peer.witness == []
        assert not feature._remote_connections and not feature.agent.registered
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("answers", [["127.0.0.1"], ["8.8.8.8", "127.0.0.1"]])
async def test_any_nonpublic_dns_answer_refuses_the_whole_endpoint(remote_peer, answers):
    remote_peer.answers = answers
    feature = MCPAgent(RegistryHost())
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.ERROR
        assert "non-public" in result.error
        assert remote_peer.resolutions and remote_peer.dials == []
        assert not feature._remote_connections and not feature.agent.registered
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_dns_rebinding_after_connection_cannot_change_the_dial(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        assert (await feature.load_tool(remote_peer.url)).status is ToolResultStatus.OK
        remote_peer.answers = ["127.0.0.1"]
        wrapper = next(t for ts in feature.agent.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="pinned request")
        assert remote_peer.peer.witness == ["pinned request"]
        assert result["status"] == "ok"
        assert len(remote_peer.resolutions) == 1
        assert {ip for ip, port in remote_peer.dials} == {"8.8.8.8"}
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "certificate_host": "wrong.example"}], indirect=True)
async def test_wrong_certificate_fails_before_http_and_retires_owner(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.ERROR
        assert not feature._remote_connections and not feature.agent.registered
        assert remote_peer.peer.requests == []
        assert remote_peer.peer.witness == []
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [
    {"tls": True, "http_status": 401}, {"tls": True, "http_status": 307},
], indirect=True)
async def test_auth_challenge_and_redirect_do_not_start_an_auth_flow_or_follow(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.ERROR
        assert not feature._remote_connections and not feature.agent.registered
        assert remote_peer.peer.requests
        assert all(scope["method"] == "POST" and scope["path"] == "/mcp"
                   for scope, body in remote_peer.peer.requests)
        assert {host for host, port in remote_peer.resolutions} == {"remote.example"}
        assert remote_peer.peer.witness == []
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "empty_tools": True}], indirect=True)
async def test_empty_remote_catalog_is_partial_but_connected(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.PARTIAL
        assert result.data["tools"] == []
        listed = await feature.list_tools()
        assert listed.status is ToolResultStatus.OK
        assert listed.data["remotes"][0]["connected"]
        assert listed.data["remotes"][0]["tool_count"] == 0
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_reload_retires_the_original_bound_caller(remote_peer):
    host = RegistryHost()
    feature = MCPAgent(host)
    try:
        first = await feature.load_tool(remote_peer.url)
        old = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
        original = feature._remote_connections[first.data["connection"]].connection
        second = await feature.load_tool(remote_peer.url)
        assert second.data["connection"] == first.data["connection"]
        assert original._task is None and not original.is_connected
        result = await old.execute(text="stale")
        assert remote_peer.peer.witness == []
        assert result["status"] == "error" and "changed; rediscover" in result["error"]
        current = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
        result = await current.execute(text="fresh")
        assert remote_peer.peer.witness == ["fresh"]
        assert result["status"] == "ok"
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_same_endpoint_has_independent_agent_owners(remote_peer):
    first = MCPAgent(RegistryHost("did:test:first"))
    second = MCPAgent(RegistryHost("did:test:second"))
    try:
        one = await first.load_tool(remote_peer.url)
        two = await second.load_tool(remote_peer.url)
        assert one.data["connection"] != two.data["connection"]
        assert set(first.agent.registered).isdisjoint(second.agent.registered)
        assert (await first.unload_tool(remote_peer.url)).status is ToolResultStatus.OK
        wrapper = next(t for ts in second.agent.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="other agent remains connected")
        assert remote_peer.peer.witness == ["other agent remains connected"]
        assert result["status"] == "ok"
    finally:
        await first.shutdown()
        await second.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_saved_unauthenticated_endpoint_restores_and_explicit_unload_clears_it(remote_peer):
    host = RegistryHost()
    first, restored = MCPAgent(host), MCPAgent(host)
    try:
        await first.initialize()
        one = await first.load_tool(remote_peer.url)
        await first.shutdown()
        assert host.saved and not host.registered
        await restored.initialize()
        await restored.post_all_features_loaded()
        assert set(restored._remote_connections) == {one.data["connection"]}
        assert len(host.registered) == 1
        assert (await restored.unload_tool(remote_peer.url)).status is ToolResultStatus.OK
        assert not host.saved and not restored._remote_connections
    finally:
        await first.shutdown()
        await restored.shutdown()


async def test_restore_rejects_invalid_saved_url(caplog):
    host = RegistryHost()
    host.saved["mcp-remote-forged"] = {"name": "mcp-remote-forged", "state": "enabled",
        "metadata": {"mode": "remote", "url": None, "auth": "none"}}
    feature = MCPAgent(host)
    await feature.initialize()
    try:
        await feature.post_all_features_loaded()
        assert not feature._remote_connections and not host.registered
        assert "Failed to restore remote" in caplog.text
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_wrong_agent_saved_identity_is_refused_before_dns(remote_peer, caplog):
    first = MCPAgent(RegistryHost("did:test:first"))
    second = MCPAgent(RegistryHost("did:test:second"))
    try:
        assert (await first.load_tool(remote_peer.url)).status is ToolResultStatus.OK
        second.agent.saved = dict(first.agent.saved)
        before = list(remote_peer.resolutions)
        await second.post_all_features_loaded()
        assert remote_peer.resolutions == before
        assert not second._remote_connections and not second.agent.registered
        assert "does not match this agent" in caplog.text
    finally:
        await first.shutdown()
        await second.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_persistence_error_withdraws_handles_and_closes_transport(remote_peer):
    host = RegistryHost()
    async def broken(*args, **kwargs):
        raise OSError("enablement storage is unavailable")
    host.persist_feature_enablement = broken
    feature = MCPAgent(host)
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.ERROR
        assert "enablement storage" in result.error
        assert not feature._remote_connections and not host.registered
        assert remote_peer.peer.witness == []
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_unmount_failure_still_closes_transport_and_invalidates_caller(remote_peer):
    host = RegistryHost()
    feature = MCPAgent(host)
    try:
        result = await feature.load_tool(remote_peer.url)
        wrapper = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
        connection = feature._remote_connections[result.data["connection"]].connection
        original = host.unregister_dynamic_tools
        def broken(owner):
            raise OSError("registry unavailable")
        host.unregister_dynamic_tools = broken
        with pytest.raises(OSError, match="registry unavailable"):
            await feature.unload_tool(result.data["connection"])
        assert connection._task is None and not feature._remote_connections
        failed = await wrapper.execute(text="must not execute")
        assert remote_peer.peer.witness == []
        assert failed["status"] == "error"
        host.unregister_dynamic_tools = original
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "discover_delay": 0.2}], indirect=True)
@pytest.mark.parametrize("shutdown", [False, True])
async def test_abandoned_remote_startup_cannot_publish_or_leak_an_owner(remote_peer, shutdown):
    feature = MCPAgent(RegistryHost())
    loading = asyncio.create_task(feature.load_tool(remote_peer.url))
    await asyncio.wait_for(remote_peer.peer.settings["discover_started"].wait(), 2)
    connection = next(iter(feature._remote_connections.values())).connection
    try:
        if shutdown:
            closing = asyncio.create_task(feature.shutdown())
            result = await loading
            await closing
            assert result.status is ToolResultStatus.ERROR
        else:
            loading.cancel()
            with pytest.raises(asyncio.CancelledError):
                await loading
        assert connection._task is None
        assert not feature._remote_connections and not feature.agent.registered
        assert not feature._remote_lifecycle
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_concurrent_reloads_leave_only_one_published_connection(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        results = await asyncio.gather(*(feature.load_tool(remote_peer.url) for _ in range(3)))
        assert all(result.status is ToolResultStatus.OK for result in results)
        assert len({result.data["connection"] for result in results}) == 1
        assert len(feature._remote_connections) == len(feature.agent.registered) == 1
        assert not feature._remote_lifecycle
        wrapper = next(t for ts in feature.agent.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="latest concurrent connection")
        assert remote_peer.peer.witness == ["latest concurrent connection"]
        assert result["status"] == "ok"
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_noop_host_write_is_not_reported_as_persisted(remote_peer):
    host = RegistryHost()
    async def noop(*args, **kwargs):
        return None
    host.persist_feature_enablement = noop
    feature = MCPAgent(host)
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.ERROR
        assert "did not retain" in result.error
        assert not feature._remote_connections and not host.registered
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_noop_host_removal_cannot_claim_the_connection_will_stay_disabled(remote_peer):
    host = RegistryHost()
    feature = MCPAgent(host)
    try:
        loaded = await feature.load_tool(remote_peer.url)
        async def noop(*args, **kwargs):
            return None
        host.clear_feature_enablement = noop
        result = await feature.unload_tool(loaded.data["connection"])
        assert result.status is ToolResultStatus.ERROR
        assert "did not remove" in result.error
        assert not feature._remote_connections and not host.registered
        assert host.saved
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "reject_call": True}], indirect=True)
async def test_native_rpc_rejection_before_execution_has_a_known_outcome(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        assert (await feature.load_tool(remote_peer.url)).status is ToolResultStatus.OK
        wrapper = next(t for ts in feature.agent.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="must-not-execute")
        assert remote_peer.peer.witness == []
        assert result["status"] == "error"
        assert "rejected before execution" in result["error"]
        assert result.get("data", {}).get("execution_outcome") != "unknown"
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "drop_tool_result": True}], indirect=True)
async def test_lost_tool_response_is_unknown_and_is_never_replayed(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        assert (await feature.load_tool(remote_peer.url)).status is ToolResultStatus.OK
        wrapper = next(t for ts in feature.agent.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="executed-but-response-lost")
        assert remote_peer.peer.witness == ["executed-but-response-lost"]
        assert result["status"] == "error"
        assert result["data"]["execution_outcome"] == "unknown"
        assert "do not replay" in result["error"].lower()
        calls = [json.loads(body) for scope, body in remote_peer.peer.requests
                 if body and json.loads(body)["method"] == "tools/call"]
        assert len(calls) == 1
    finally:
        # A real truncated response may also surface its original protocol
        # error while the SDK owner exits. Rejoin only that finished owner;
        # deadline and programming failures must still fail this test.
        try:
            await feature.shutdown()
        except* httpx2.RemoteProtocolError:
            await feature.shutdown()
        assert not feature._remote_connections


@pytest.mark.parametrize("mcp_http_server", [
    {"tls": True, "input_required": kind}
    for kind in ("sampling", "roots", "elicitation", "state")
], indirect=True)
async def test_unsupported_input_never_continues_or_loses_the_unknown_outcome(remote_peer):
    feature = MCPAgent(RegistryHost())
    try:
        assert (await feature.load_tool(remote_peer.url)).status is ToolResultStatus.OK
        wrapper = next(t for ts in feature.agent.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="work-before-input")
        assert remote_peer.peer.settings["input_witness_file"].read_text().splitlines() == ["executed-before-input"]
        calls = [json.loads(body) for scope, body in remote_peer.peer.requests
                 if body and json.loads(body)["method"] == "tools/call"]
        assert len(calls) == 1
        assert result["status"] == "error"
        assert result["data"]["execution_outcome"] == "unknown"
        assert "Do not replay" in result["error"]
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_unload_with_slow_store_invalidates_captured_remote_before_io(remote_peer):
    host = RegistryHost()
    feature = MCPAgent(host)
    entered, release = asyncio.Event(), asyncio.Event()
    unloading = None
    original_clear = host.clear_feature_enablement
    try:
        loaded = await feature.load_tool(remote_peer.url)
        assert loaded.status.value == "ok"
        wrapper = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
        async def slow_clear(*args, **kwargs):
            entered.set()
            await release.wait()
            await original_clear(*args, **kwargs)
        host.clear_feature_enablement = slow_clear
        unloading = asyncio.create_task(feature.unload_tool(loaded.data["connection"]))
        await asyncio.wait_for(entered.wait(), 2)
        result = await wrapper.execute(text="executed-during-unload")
        assert remote_peer.peer.witness == []
        assert result["status"] == "error" and "changed; rediscover" in result["error"]
    finally:
        release.set()
        if unloading is not None:
            await unloading
        await feature.shutdown()

@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("shutdown", [False, True])
async def test_catalog_is_not_callable_before_persistence_ack(remote_peer, shutdown):
    host = RegistryHost()
    feature = MCPAgent(host)
    entered, release = asyncio.Event(), asyncio.Event()
    original_persist = host.persist_feature_enablement
    async def slow_persist(*args, **kwargs):
        entered.set()
        await release.wait()
        await original_persist(*args, **kwargs)
    host.persist_feature_enablement = slow_persist
    loading = asyncio.create_task(feature.load_tool(remote_peer.url))
    closing = None
    try:
        await asyncio.wait_for(entered.wait(), 2)
        captured = [t for ts in host.registered.values() for t in ts if t._real_name == "echo"]
        if shutdown:
            closing = asyncio.create_task(feature.shutdown())
            async def await_closing():
                while not feature._closing:
                    await asyncio.sleep(0)
            await asyncio.wait_for(await_closing(), 2)
        if captured:
            await captured[0].execute(text="executed-before-persistence-ack")
        assert remote_peer.peer.witness == []
        assert not host.registered
        release.set()
        loaded = await loading
        if shutdown:
            await closing
            assert loaded.status.value == "error" and "shutting down" in loaded.error
            assert not host.registered and not feature._remote_connections
            assert host.saved
            restored = MCPAgent(host)
            try:
                await restored.initialize()
                await restored.post_all_features_loaded()
                wrapper = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
                called = await wrapper.execute(text="restored-after-aborted-load")
                assert remote_peer.peer.witness == ["restored-after-aborted-load"]
                assert called["status"] == "ok"
            finally:
                await restored.shutdown()
            assert "enablement remains saved" in loaded.error
            assert "restore after restart" in loaded.error
        else:
            assert loaded.status.value == "ok"
            wrapper = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
            called = await wrapper.execute(text="executed-after-persistence-ack")
            assert remote_peer.peer.witness == ["executed-after-persistence-ack"]
            assert called["status"] == "ok"
    finally:
        release.set()
        await loading
        if closing is not None:
            await closing
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("readonly", [False, True])
@pytest.mark.parametrize("read_failure", [False, pytest.param(True, id="read-fails")])
async def test_restore_reads_existing_enablement_without_rewriting_it(
    remote_peer, tmp_path, readonly, read_failure, monkeypatch, caplog,
):
    from kestrel_sdk.storage.database import QueryError
    from kestrel_feature_mcp.manager import container_name_for_image
    from kestrel_feature_mcp.remote import remote_name_for_url
    host = RegistryHost()
    remote_name = remote_name_for_url(remote_peer.url, host.agent_id)
    rows = [
        (remote_name, "enabled", {"mode": "remote", "url": remote_peer.url, "auth": "none"}),
        ("gateway-next", "enabled", {"mode": "gateway"}),
        (container_name_for_image("org/img:1", host.agent_id), "enabled",
         {"mode": "container", "image": "org/img:1", "args": None}),
    ]
    path = tmp_path / "enablement.sqlite"
    with sqlite3.connect(path) as setup:
        setup.execute("CREATE TABLE enablement (name TEXT PRIMARY KEY, state TEXT, metadata TEXT)")
        setup.executemany("INSERT INTO enablement VALUES (?, ?, ?)",
                          [(name, state, json.dumps(metadata)) for name, state, metadata in rows])
    store = sqlite3.connect(f"{path.as_uri()}?mode={'ro' if readonly else 'rw'}", uri=True)
    writes = []
    reads = 0
    async def read(kind):
        nonlocal reads
        reads += 1
        if read_failure and reads == 2:
            # Real SQL failure, exposed through the SDK's backend error contract.
            try:
                store.execute("SELECT * FROM unavailable_enablement_table")
            except sqlite3.Error as error:
                raise QueryError(str(error)) from error
        return [{"name": name, "state": state, "metadata": json.loads(metadata)}
                for name, state, metadata in store.execute("SELECT name, state, metadata FROM enablement ORDER BY rowid")]
    async def persist(kind, name, state, *, actor, metadata):
        writes.append(name)
        store.execute("INSERT OR REPLACE INTO enablement VALUES (?, ?, ?)",
                      (name, state, json.dumps(metadata)))
        store.commit()
    host.get_enablement_deltas = read
    host.persist_feature_enablement = persist
    feature = MCPAgent(host)
    feature.manager = SimpleNamespace(owner_did=host.agent_id, owned_containers={}, aclose=AsyncMock())
    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    feature.gateway_start = AsyncMock()
    feature._load_via_container = AsyncMock()
    try:
        await feature.initialize()
        await feature.post_all_features_loaded()
        if read_failure:
            assert not host.registered and not feature._remote_connections
            assert remote_peer.peer.witness == []
            assert "Failed to restore remote MCP " + remote_name in caplog.text
            assert "unavailable_enablement_table" in caplog.text
        else:
            wrapper = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
            result = await wrapper.execute(text="restored-from-existing-row")
            assert remote_peer.peer.witness == ["restored-from-existing-row"]
            assert result["status"] == "ok"
        # These spies prove branch ordering; separate Docker suites prove I/O.
        feature.gateway_start.assert_awaited_once_with("gateway-next")
        feature._load_via_container.assert_awaited_once_with("org/img:1", None)
        assert writes == []
        assert [(r["name"], r["state"], r["metadata"]) for r in await read("mcp_server")] == rows
    finally:
        await feature.shutdown()
        store.close()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_reenable_does_not_abandon_failed_shutdown_custody(remote_peer, monkeypatch):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    loaded = await feature.load_tool(remote_peer.url)
    assert loaded.status is ToolResultStatus.OK
    name = loaded.data["connection"]
    connection = feature._remote_connections[name].connection
    close = connection.close

    async def cannot_close():
        raise RuntimeError("Owned transport close has not settled")

    monkeypatch.setattr(connection, "close", cannot_close)
    try:
        with pytest.raises(RuntimeError, match="has not settled"):
            await feature.shutdown()
        with pytest.raises(RuntimeError, match="has not settled"):
            await feature.initialize()
        assert feature._remote_connections[name].connection is connection
        assert feature._closing and not feature.agent.registered
        monkeypatch.setattr(connection, "close", close)
        await feature.initialize()
        assert not connection.is_connected and not feature._remote_connections
        await feature.post_all_features_loaded()
        wrapper = next(t for ts in feature.agent.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="after-custody-settled")
        assert remote_peer.peer.witness == ["after-custody-settled"]
        assert result["status"] == "ok"
    finally:
        monkeypatch.setattr(connection, "close", close)
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("error_type", [RuntimeError, asyncio.CancelledError])
async def test_restore_does_not_suppress_programming_errors_or_cancellation(remote_peer, error_type):
    from kestrel_feature_mcp.remote import remote_name_for_url

    host = RegistryHost()
    name = remote_name_for_url(remote_peer.url, host.agent_id)
    host.saved[name] = {"name": name, "state": "enabled", "metadata": {
        "mode": "remote", "url": remote_peer.url, "auth": "none"}}
    reads = 0

    async def read(kind):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise error_type("Unexpected restore interruption")
        return list(host.saved.values())

    host.get_enablement_deltas = read
    feature = MCPAgent(host)
    await feature.initialize()
    try:
        with pytest.raises(error_type, match="Unexpected restore interruption"):
            await feature.post_all_features_loaded()
        assert not feature._remote_connections and not host.registered
        assert remote_peer.peer.witness == []
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_post_ack_mount_rejection_discloses_saved_enablement(remote_peer):
    host = RegistryHost()
    register = host.register_dynamic_tools
    def reject(owner, tools):
        raise ValueError("Host rejected the advertised catalog")
    host.register_dynamic_tools = reject
    feature = MCPAgent(host)
    try:
        loaded = await feature.load_tool(remote_peer.url)
        assert remote_peer.peer.witness == []
        assert loaded.status is ToolResultStatus.ERROR
        assert host.saved and not host.registered and not feature._remote_connections
        host.register_dynamic_tools = register
        await feature.post_all_features_loaded()
        wrapper = next(t for ts in host.registered.values() for t in ts if t._real_name == "echo")
        result = await wrapper.execute(text="restored-after-rejected-mount")
        assert remote_peer.peer.witness == ["restored-after-rejected-mount"]
        assert result["status"] == "ok"
        assert "enablement remains saved" in loaded.error
        assert "restore after restart" in loaded.error
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
async def test_restore_rechecks_enablement_removed_during_discovery(remote_peer, monkeypatch, caplog):
    from kestrel_feature_mcp.connection import MCPConnection
    from kestrel_feature_mcp.remote import remote_name_for_url
    host = RegistryHost()
    name = remote_name_for_url(remote_peer.url, host.agent_id)
    host.saved[name] = {"name": name, "state": "enabled", "metadata": {
        "mode": "remote", "url": remote_peer.url, "auth": "none"}}
    connect = MCPConnection.connect
    async def remove_during_discovery(connection):
        tools = await connect(connection)
        await host.clear_feature_enablement("mcp_server", name)
        return tools
    monkeypatch.setattr(MCPConnection, "connect", remove_during_discovery)
    feature = MCPAgent(host)
    try:
        await feature.initialize()
        await feature.post_all_features_loaded()
        assert remote_peer.peer.witness == []
        assert not host.saved and not host.registered and not feature._remote_connections
        assert "did not retain MCP enablement" in caplog.text
        assert "enablement remains saved" not in caplog.text
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("field", ["state", "metadata"])
async def test_mismatched_enablement_readback_never_publishes_a_catalog(remote_peer, field):
    host = RegistryHost()
    original_persist = host.persist_feature_enablement
    async def corrupting_persist(kind, name, state, *, actor, metadata):
        await original_persist(kind, name, state, actor=actor, metadata=metadata)
        if field == "state":
            host.saved[name]["state"] = "disabled"
        else:
            host.saved[name]["metadata"] = {**metadata, "auth": "oauth"}
    host.persist_feature_enablement = corrupting_persist
    feature = MCPAgent(host)
    try:
        result = await feature.load_tool(remote_peer.url)
        assert remote_peer.peer.witness == []
        assert result.status is ToolResultStatus.ERROR
        assert "did not retain" in result.error
        assert "enablement remains saved" not in result.error
        assert not host.registered and not feature._remote_connections
    finally:
        await feature.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("unsupported", [
    {"auth": "oauth"}, {"auth": None}, {"headers": {"Authorization": "synthetic-secret"}},
])
async def test_restore_refuses_unsupported_saved_configuration_before_dns(remote_peer, unsupported, caplog):
    host = RegistryHost()
    first = MCPAgent(host)
    loaded = await first.load_tool(remote_peer.url)
    assert loaded.status is ToolResultStatus.OK
    await first.shutdown()
    name = loaded.data["connection"]
    host.saved[name]["metadata"] = {**host.saved[name]["metadata"], **unsupported}
    before = len(remote_peer.resolutions)
    restored = MCPAgent(host)
    try:
        await restored.initialize()
        await restored.post_all_features_loaded()
        assert remote_peer.peer.witness == []
        assert not host.registered and not restored._remote_connections
        assert len(remote_peer.resolutions) == before
        assert "Refusing unsupported" in caplog.text
    finally:
        await restored.shutdown()


@pytest.mark.parametrize("mcp_http_server", [{"tls": True}], indirect=True)
@pytest.mark.parametrize("producer", ["load", "restore"])
@pytest.mark.parametrize("missing", ["register_dynamic_tools", "unregister_dynamic_tools"])
async def test_unsupported_remote_host_is_refused_before_dns_or_persistence(remote_peer, producer, missing, caplog):
    from kestrel_feature_mcp.remote import remote_name_for_url
    host = RegistryHost()
    setattr(host, missing, None)
    if producer == "restore":
        name = remote_name_for_url(remote_peer.url, host.agent_id)
        host.saved[name] = {"name": name, "state": "enabled", "metadata": {
            "mode": "remote", "url": remote_peer.url, "auth": "none"}}
    saved = dict(host.saved)
    feature = MCPAgent(host)
    try:
        if producer == "load":
            result = await feature.load_tool(remote_peer.url)
            assert result.status is ToolResultStatus.ERROR
            assert "governed dynamic tool registry" in result.error
        else:
            await feature.post_all_features_loaded()
            assert "governed dynamic tool registry" in caplog.text
    finally:
        await feature.shutdown()
        assert remote_peer.peer.witness == []
        assert not remote_peer.resolutions and not remote_peer.dials
        assert host.saved == saved
        assert not host.registered and not feature._remote_connections


@pytest.mark.parametrize("mcp_http_server", [{"tls": True, "apps_tools": True}], indirect=True)
async def test_remote_discovery_preserves_the_standard_tool_record(remote_peer):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    try:
        result = await feature.load_tool(remote_peer.url)
        assert result.status is ToolResultStatus.OK, result.to_dict()
        assert "status_view" in result.data["tools"]
        listed = await feature.list_tools()
        actual = next(tool for tool in listed.data["tools"] if tool["name"] == "status_view")
        expected = next(tool for tool in await remote_peer.peer.mcp.list_tools()
                        if tool.name == "status_view")
        expected_wire = expected.model_dump(mode="json", by_alias=True, exclude_none=True)
        assert actual.pop("connection") == result.data["connection"]
        assert actual.pop("via") == "remote"
        assert actual.pop("url") == remote_peer.url
        assert actual.pop("protocol_version") == "2026-07-28"
        assert actual == expected_wire
        listed = await feature.list_tools()
        relisted = next(tool for tool in listed.data["tools"] if tool["name"] == "status_view")
        assert relisted["_meta"] == expected_wire["_meta"]
    finally:
        await feature.shutdown()
