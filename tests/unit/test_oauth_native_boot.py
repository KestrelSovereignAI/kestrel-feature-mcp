"""Full native agent boot discovers OAuth and retains its original storage owner."""
import asyncio
import socket
import traceback
import aiosqlite
import pytest
from kestrel_sovereign.inception_service import create_kestrel_identity_async
from kestrel_sovereign.kestrel_agent import KestrelAgent
from kestrel_sovereign.llm.service import LLMService
from kestrel_sovereign.multi_agent.config import MANDATORY_FEATURES
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_sovereign.testing.native_shutdown_budget import shutdown_fixture_agent

@pytest.mark.timeout(60)
async def test_native_full_boot_loads_actual_oauth_feature_and_resolves_original_storage(tmp_path, monkeypatch, owned_oauth_key):
    connections = []
    native_connect = aiosqlite.connect

    def observe_connection(*args, **kwargs):
        connection = native_connect(*args, **kwargs)
        connections.append((connection, ''.join(traceback.format_stack(limit=10))))
        return connection

    monkeypatch.setattr(aiosqlite, 'connect', observe_connection)
    network_attempts = []
    def refuse_network(*args, **kwargs):
        network_attempts.append(True)
        raise AssertionError('This native bootstrap must not open a network connection')
    monkeypatch.setattr(socket.socket, 'connect', refuse_network)
    monkeypatch.setattr(socket.socket, 'connect_ex', refuse_network)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('KESTREL_DATA_KEY', owned_oauth_key.read_text().strip())
    monkeypatch.setenv('KESTREL_HOME', str(tmp_path))
    monkeypatch.setenv('KESTREL_DB_PATH', str(tmp_path))
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    (tmp_path / 'kestrel.toml').write_text('[llm]\nroute_priority=[]\n')
    async def audit(_prompt):
        return {'risk_level': 1, 'reasoning': 'Owned fixture genesis; no tool approval granted.'}
    identity = await create_kestrel_identity_async(output_dir=str(tmp_path), is_test_instance=True,
        agent_name='OwnedOAuthBoot', did_web_domain='owned-oauth-boot.invalid', genesis_auditor=audit,
        genesis_audit_provenance='test:3679-owned-native-boot')
    service = LLMService(agent_data_dir=tmp_path)
    agent = KestrelAgent(did=identity.agent_did, storage_path=str(tmp_path / 'kestrel_prime.db'),
        llm_service=service, allowed_features={'MCPAgent'}, sync_enabled=False)
    try:
        await agent.initialize()
        assert {type(feature).__name__ for feature in agent.features.values()} == MANDATORY_FEATURES | {'MCPAgent'}
        feature = next(feature for feature in agent.features.values() if type(feature).__name__ == 'MCPAgent')
        await feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0}})
        host = feature._oauth_host
        assert isinstance(host.database, SQLiteBackend)
        assert host.database is agent._raw_storage.db.backend
        assert not host.retired and not feature._oauth_maintenance.done()
        assert feature.get_router() is not None
    finally:
        await asyncio.wait_for(shutdown_fixture_agent(agent), 30)
        await service.close()
    unretired = [(connection, stack) for connection, stack in connections if connection._thread.is_alive()]
    try:
        assert not unretired, 'Native boot left SQLite workers unretired:\n' + '\n'.join(
            connection._thread.name + '\n' + stack for connection, stack in unretired)
    finally:
        # Failing lifecycle assertions still physically retire this fixture's
        # owned connections; cleanup cannot make the assertion pass.
        for connection, _ in unretired:
            await connection.close()
            connection._thread.join(timeout=2)
    assert network_attempts == []
