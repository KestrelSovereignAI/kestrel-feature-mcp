"""Catalog validation cannot silently select a retired transport."""

import tomllib

import pytest

from kestrel_feature_mcp.registry import MCPRegistry


@pytest.mark.parametrize("field,value", [("transport", "sse"), ("transport", "unknown"),
                                         ("type", "unknown"), ("categories", ["unknown"])])
def test_invalid_catalog_entry_fails_explicitly(tmp_path, field, value):
    catalog = tmp_path / "catalog.toml"
    catalog.write_text(f"[servers.example]\n{field} = {value!r}\n")
    with pytest.raises(ValueError, match="example"):
        MCPRegistry(catalog)


def test_missing_catalog_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        MCPRegistry(tmp_path / "missing.toml")


def test_malformed_catalog_is_an_error(tmp_path):
    catalog = tmp_path / "catalog.toml"
    catalog.write_text("[servers.broken\n")
    with pytest.raises(tomllib.TOMLDecodeError):
        MCPRegistry(catalog)


@pytest.mark.asyncio
async def test_docker_catalog_uses_structured_current_cli_and_preserves_names(monkeypatch):
    import json
    from subprocess import CompletedProcess
    from kestrel_feature_mcp.registry import list_docker_catalog_servers

    def run(command, **kwargs):
        assert command == ["docker", "mcp", "catalog", "show", "example/catalog:v2", "--format", "json", "--pull", "missing"]
        return CompletedProcess(command, 0, stdout=json.dumps({"servers": [
            {"snapshot": {"server": {"name": "fetch", "description": "Fetch web content"}}},
            {"snapshot": {"server": {"name": "CaseSensitive", "description": ""}}},
        ]}))

    monkeypatch.setenv("KESTREL_MCP_DOCKER_CATALOG", "example/catalog:v2")
    monkeypatch.setattr("kestrel_feature_mcp.registry.subprocess.run", run)
    assert await list_docker_catalog_servers() == [
        {"name": "fetch", "description": "Fetch web content"},
        {"name": "CaseSensitive", "description": ""},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["command", "timeout", "missing", "malformed", "shape"])
@pytest.mark.parametrize("query", [None, "fetch"])
async def test_unreadable_docker_catalog_is_failed_not_an_empty_success(monkeypatch, failure, query):
    import subprocess
    from unittest.mock import MagicMock
    from kestrel_sdk.tools.result import ToolResultStatus
    from kestrel_feature_mcp.feature import MCPAgent

    def run(command, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 1)
        if failure == "missing":
            raise FileNotFoundError("docker missing")
        return subprocess.CompletedProcess(command, 1 if failure == "command" else 0,
            stdout="not json" if failure == "malformed" else '{"servers": [{}]}', stderr="catalog unavailable")

    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    monkeypatch.setattr("kestrel_feature_mcp.registry.subprocess.run", run)
    feature = MCPAgent(MagicMock())
    feature.gateway_manager = None
    result = await feature.docker_catalog_search(query)
    assert result.status is ToolResultStatus.ERROR
    assert "catalog" in result.error.lower()
    assert not result.data or "enabled" not in result.data


@pytest.mark.asyncio
async def test_docker_catalog_summary_reports_only_this_gateway_configuration(monkeypatch):
    import json
    from subprocess import CompletedProcess
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from kestrel_sdk.tools.result import ToolResultStatus
    from kestrel_feature_mcp.feature import MCPAgent

    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    monkeypatch.setattr("kestrel_feature_mcp.registry.subprocess.run", lambda command, **kwargs:
        CompletedProcess(command, 0, stdout=json.dumps({"servers": []})))
    feature = MCPAgent(MagicMock())
    feature.gateway_manager = SimpleNamespace(gateway=SimpleNamespace(requested_servers={"time"}))
    result = await feature.docker_catalog_search()
    assert result.status is ToolResultStatus.OK
    assert result.data == {"available": 0, "requested": ["time"]}
    assert "enabled" not in result.confirmation.lower()
