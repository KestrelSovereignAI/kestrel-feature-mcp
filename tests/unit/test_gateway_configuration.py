"""Real filesystem contracts for the process-private native Docker configuration."""

import json
from pathlib import Path

import pytest

from kestrel_feature_mcp.gateway import DockerMCPGateway, DockerMCPGatewayError


@pytest.mark.asyncio
@pytest.mark.parametrize("document", [
    None,
    {},
    {"features": None, "cliPluginsExtraDirs": None},
    {"features": {"dynamic-tools": "enabled", "other": "enabled"}, "cliPluginsExtraDirs": ["original"]},
])
async def test_private_configuration_preserves_original_and_native_nullable_fields(tmp_path, monkeypatch, document):
    source = tmp_path / "docker"
    source.mkdir()
    original = source / "config.json"
    if document is not None:
        original.write_text(json.dumps(document))
    before = original.read_bytes() if original.exists() else None
    monkeypatch.setenv("DOCKER_CONFIG", str(source))
    gateway = DockerMCPGateway()
    try:
        gateway._prepare_gateway_configuration()
        private = gateway._config_directory
        actual = json.loads((private / "config.json").read_text())
        assert private.stat().st_mode & 0o777 == 0o700
        assert (private / "config.json").stat().st_mode & 0o777 == 0o600
        assert actual["features"]["dynamic-tools"] == "disabled"
        assert str(source / "cli-plugins") in actual["cliPluginsExtraDirs"]
        if document and document.get("features"):
            assert actual["features"]["other"] == "enabled"
            assert "original" in actual["cliPluginsExtraDirs"]
        assert Path(gateway._process_env["DOCKER_CONFIG"]) == private
        assert (original.read_bytes() if original.exists() else None) == before
        await gateway.stop()
        assert not private.exists() and gateway._process_env is None
        assert (original.read_bytes() if original.exists() else None) == before
    finally:
        await gateway.stop()


@pytest.mark.parametrize("body,message", [
    ("{", "not valid JSON"),
    ("[]", "JSON object"),
    ('{"features": []}', "features must be an object or null"),
    ('{"cliPluginsExtraDirs": {}}', "cliPluginsExtraDirs must be a string array or null"),
    ('{"cliPluginsExtraDirs": [1]}', "cliPluginsExtraDirs must be a string array or null"),
])
def test_invalid_configuration_fails_before_allocating_private_resources(tmp_path, monkeypatch, body, message):
    source = tmp_path / "docker"
    source.mkdir()
    original = source / "config.json"
    original.write_text(body)
    monkeypatch.setenv("DOCKER_CONFIG", str(source))
    gateway = DockerMCPGateway()
    with pytest.raises(DockerMCPGatewayError, match=message):
        gateway._prepare_gateway_configuration()
    assert original.read_text() == body
    assert gateway._config_directory is None and gateway._profile_id is None
    assert not (source / "mcp").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("certificate_path", [None, "", "explicit-certificate-directory"])
async def test_private_configuration_preserves_native_docker_tls_certificate_lookup(tmp_path, monkeypatch, certificate_path):
    source = tmp_path / "docker"
    source.mkdir()
    monkeypatch.setenv("DOCKER_CONFIG", str(source))
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    if certificate_path is None:
        monkeypatch.delenv("DOCKER_CERT_PATH", raising=False)
    else:
        monkeypatch.setenv("DOCKER_CERT_PATH", certificate_path)
    gateway = DockerMCPGateway()
    try:
        gateway._prepare_gateway_configuration()
        actual = gateway._process_env.get("DOCKER_CERT_PATH")
        assert actual == (certificate_path or str(source))
    finally:
        await gateway.stop()
