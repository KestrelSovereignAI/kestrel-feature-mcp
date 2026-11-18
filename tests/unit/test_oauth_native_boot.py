"""Full native agent boot discovers OAuth and retains its original storage owner."""
import asyncio
import socket
import traceback
import aiosqlite
import pytest
from kestrel_sdk.payer_policy import PayerKind, PayerPolicy, PayerSpec
from kestrel_sovereign.inception_service import create_kestrel_identity_async
from kestrel_sovereign.kestrel_agent import KestrelAgent
from kestrel_sovereign.llm.service import LLMService, PolicyDeniedError
from kestrel_sovereign.multi_agent.config import MANDATORY_FEATURES
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_sovereign.testing.native_shutdown_budget import shutdown_fixture_agent

@pytest.mark.timeout(60)
@pytest.mark.parametrize('bedrock_credentials', [False, True])
async def test_native_full_boot_loads_actual_oauth_feature_and_resolves_original_storage(tmp_path, monkeypatch, owned_oauth_key, bedrock_credentials):
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
    aws_config = tmp_path / 'owned-aws-config'
    aws_config.write_text('')
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', str(aws_config))
    monkeypatch.setenv('AWS_CONFIG_FILE', str(aws_config))
    for key in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                'AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_WEB_IDENTITY_TOKEN_FILE',
                'AWS_ROLE_ARN', 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',
                'AWS_CONTAINER_CREDENTIALS_FULL_URI', 'AWS_REGION', 'AWS_DEFAULT_REGION'):
        monkeypatch.delenv(key, raising=False)
    if bedrock_credentials:
        monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'owned-test-only')
        monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'owned-test-only-not-a-real-key')
        monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')
    (tmp_path / 'kestrel.toml').write_text('[llm]\nroute_priority=[]\n')
    async def audit(_prompt):
        return {'risk_level': 1, 'reasoning': 'Owned fixture genesis; no tool approval granted.'}
    identity = await create_kestrel_identity_async(output_dir=str(tmp_path), is_test_instance=True,
        agent_name='OwnedOAuthBoot', did_web_domain='owned-oauth-boot.invalid', genesis_auditor=audit,
        genesis_audit_provenance='test:3679-owned-native-boot')
    service = LLMService(agent_data_dir=tmp_path)
    policy = PayerPolicy.model_validate({**PayerPolicy.host_env_default().model_dump(),
        'llm': PayerSpec(vendor='local', kind=PayerKind.NONE),
        'storage': PayerSpec(vendor='local-disk', kind=PayerKind.HOST_ENV)})
    agent = KestrelAgent(did=identity.agent_did, storage_path=str(tmp_path / 'kestrel_prime.db'),
        llm_service=service, allowed_features={'MCPAgent'}, sync_enabled=False, payer_policy=policy)
    try:
        await agent.initialize()
        assert service.disabled
        if bedrock_credentials:
            assert any(provider['vendor'] == 'bedrock' for provider in service.providers)
        with pytest.raises(PolicyDeniedError):
            await service.generate(system_prompt='Owned no-LLM boot', user_prompt='Must be refused')
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
