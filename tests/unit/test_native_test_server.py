"""The container fixture itself must use the current official server SDK."""

import importlib.util
from pathlib import Path

import pytest
from mcp import Client


@pytest.mark.asyncio
async def test_container_fixture_tools_run_on_mcp2():
    path = Path(__file__).parents[1] / "integration/mcp_test_server/server.py"
    spec = importlib.util.spec_from_file_location("native_container_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    async with Client(module.mcp, mode="2026-07-28") as client:
        result = await client.call_tool("add", {"a": 3, "b": 7})
        assert not result.is_error
        assert result.structured_content == {"result": 10}
        failure = await client.call_tool("calculate", {"expression": "__import__('os')"})
        assert "Unsupported expression type" in failure.content[0].text
