"""Actual Core chat -> parent AppBridge -> opaque App -> governed native MCP."""

import asyncio
import json
import os
from pathlib import Path

import kestrel_sovereign
from kestrel_sovereign import server as core_server
import pytest
import uvicorn
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from tests.browser.conftest import REPOSITORY


pytestmark = [pytest.mark.apps_browser, pytest.mark.timeout(60), pytest.mark.parametrize("mcp_http_server", [{
    "apps_tools": True, "apps_execution_tools": True, "app_mutate_visibility": ["model", "app"],
    "advertised_tool_contracts": {"echo": {"meta": {"ui": {"visibility": ["model"]}}}},
}], indirect=True)]


async def test_core_chat_renders_native_apps_and_retires_their_original_views(
    native_apps_host, mcp_http_server, core_listener, apps_host_origin, monkeypatch,
):
    b = native_apps_host
    monkeypatch.setattr(core_server, "SERVE_UI", True)
    build = await asyncio.create_subprocess_exec("node", "web/test-support/parent-browser-build.mjs", "host",
        cwd=REPOSITORY, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    host_entry, build_errors = await asyncio.wait_for(build.communicate(), 10)
    assert build.returncode == 0, build_errors.decode()
    parent_entry = (REPOSITORY / "kestrel_feature_mcp/apps_sandbox/parent-entry.js").read_bytes()

    @b.app.get("/")
    async def page():
        return HTMLResponse('<!doctype html><body><script type="module" src="/js/parent-test.js"></script>')

    @b.app.get("/js/parent-test.js")
    async def host_script():
        return Response(host_entry, media_type="text/javascript")

    @b.app.get("/js/mcp-apps-parent.js")
    async def feature_script():
        return Response(parent_entry, media_type="text/javascript")

    static = Path(kestrel_sovereign.__file__).parent / "static"
    b.app.mount("/js", StaticFiles(directory=static / "js"))
    b.app.mount("/shared", StaticFiles(directory=static / "shared"))
    server = uvicorn.Server(uvicorn.Config(b.app, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[core_listener]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("owned Core HTTP listener exited before startup")
                await asyncio.sleep(0.01)
        child = await asyncio.create_subprocess_exec("node", "web/test-support/parent-browser-driver.mjs",
            apps_host_origin, cwd=REPOSITORY, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={key: os.environ[key] for key in ("PATH", "HOME", "PLAYWRIGHT_BROWSERS_PATH") if key in os.environ})
        try:
            output, errors = await asyncio.wait_for(child.communicate(), 40)
            assert child.returncode == 0, (output + errors).decode()[-6000:]
            assert all(json.loads(output).values())
        finally:
            if child.returncode is None:
                child.terminate()
                await asyncio.wait_for(child.wait(), 5)
        async with asyncio.timeout(5):
            while b.feature._apps_host._views:
                await asyncio.sleep(0.01)
        assert mcp_http_server.witness == ["initial-once", "browser-app-once"]
        rows = await b.backend.fetch_all("SELECT session_id,result_status FROM a2a_tool_dispatches")
        assert [tuple(row) for row in rows] == [("original-chat", "success"), ("original-chat", "success")]
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
