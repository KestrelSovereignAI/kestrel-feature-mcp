"""Unit tests for ``MCPToolManager`` reconnect behavior.

Regression chain (Emma's MCP lifecycle dogfood):
- ``connect_to_tool`` did a bare ``return`` (None) on the already-connected
  branch, so re-loading a running container made ``MCPFeature.load_tool`` crash
  on ``[t.name for t in tools]`` ('NoneType' object is not iterable) and report
  a false failure.
- The caller (``load_tool``) restarts an already-running container for a clean
  state first, so the cached SSE session is stale — returning the cached tools
  would report success over a dead connection. The fix tears the stale session
  down (``_drop_stale_session``) and reconnects fresh.
"""

import asyncio

import pytest

from kestrel_feature_mcp.manager import MCPToolManager


def _manager_without_docker() -> MCPToolManager:
    # The reconnect-teardown path never touches Docker; build the instance
    # without the Docker-requiring __init__ so this runs in CI.
    return MCPToolManager.__new__(MCPToolManager)


@pytest.mark.asyncio
async def test_drop_stale_session_cancels_task_and_forgets_entry():
    mgr = _manager_without_docker()

    async def _idle():
        await asyncio.sleep(3600)

    stale_task = asyncio.ensure_future(_idle())
    await asyncio.sleep(0)  # let it start
    mgr.active_tools = {
        "mcp-test": {"tools": [object()], "task": stale_task}
    }

    await mgr._drop_stale_session("mcp-test")

    # Entry forgotten so a fresh connect can rebind, and the stale session
    # task is cancelled (no leaked connection to the dead process).
    assert "mcp-test" not in mgr.active_tools
    assert stale_task.cancelled()


@pytest.mark.asyncio
async def test_drop_stale_session_is_a_noop_when_not_connected():
    mgr = _manager_without_docker()
    mgr.active_tools = {}
    # Must not raise when there's nothing to drop.
    await mgr._drop_stale_session("never-loaded")
    assert mgr.active_tools == {}


@pytest.mark.asyncio
async def test_drop_stale_session_handles_missing_task_key():
    mgr = _manager_without_docker()
    mgr.active_tools = {"mcp-test": {"tools": []}}  # no 'task'
    await mgr._drop_stale_session("mcp-test")
    assert "mcp-test" not in mgr.active_tools
