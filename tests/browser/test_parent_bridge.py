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
from kestrel_sovereign.features.security.permissions import PermissionLevel

from tests.browser.conftest import REPOSITORY


pytestmark = [pytest.mark.apps_browser, pytest.mark.timeout(60), pytest.mark.parametrize("mcp_http_server", [{
    "apps_tools": True, "apps_execution_tools": True, "app_mutate_visibility": ["model", "app"],
    "advertised_tool_contracts": {"echo": {"meta": {"ui": {"visibility": ["model"]}}}},
}], indirect=True)]


async def browser_event(child):
    async with asyncio.timeout(5):
        line = await child.stdout.readline()
    assert line, 'Original browser exited before its campaign checkpoint'
    return json.loads(line)


async def continue_browser(child):
    child.stdin.write(b'continue\n')
    await child.stdin.drain()


@pytest.mark.parametrize('permission', ['allow', 'ask', 'deny'])
async def test_core_chat_renders_native_apps_and_retires_their_original_views(
    native_apps_host, mcp_http_server, core_listener, apps_host_origin, monkeypatch, permission,
):
    b = native_apps_host
    monkeypatch.setattr(core_server, "SERVE_UI", True)
    build = await asyncio.create_subprocess_exec("node", "web/test-support/parent-browser-build.mjs", "host",
        cwd=REPOSITORY, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    host_entry, build_errors = await asyncio.wait_for(build.communicate(), 10)
    assert build.returncode == 0, build_errors.decode()

    @b.app.get("/")
    async def page():
        return HTMLResponse('<!doctype html><body><script type="module" src="/js/parent-test.js"></script>')

    @b.app.get("/js/parent-test.js")
    async def host_script():
        return Response(host_entry, media_type="text/javascript")

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
            apps_host_origin, permission, cwd=REPOSITORY,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={key: os.environ[key] for key in ("PATH", "HOME", "PLAYWRIGHT_BROWSERS_PATH") if key in os.environ})
        expected = ['initial-once']
        try:
            assert await browser_event(child) == dict(event='initial-rendered')
            assert mcp_http_server.witness == expected
            source = next(item for item in b.feature._apps_publications._batches['mcp:composition'].tools
                          if item.tool.native_tool.name == 'app_mutate')
            if permission != 'allow':
                await b.permissions.set_permission('mcp:composition', source.binding.name,
                    PermissionLevel.ASK if permission == 'ask' else PermissionLevel.DENY)
            await continue_browser(child)
            if permission != 'allow':
                previous = None
                for index, approved in enumerate([True, False], 1):
                    event = asyncio.create_task(browser_event(child))
                    approval = asyncio.create_task(b.requests.get()) if permission == 'ask' else None
                    try:
                        if approval is not None:
                            async with asyncio.timeout(5):
                                done, _ = await asyncio.wait({event, approval}, return_when=asyncio.FIRST_COMPLETED)
                            assert mcp_http_server.witness == expected, (
                                'Unapproved browser App produced an external effect')
                            assert approval in done, 'Browser App completed without its original Core approval'
                            request = await approval
                            assert (request.feature_name, request.tool_name) == ('mcp:composition', source.binding.name)
                            assert not event.done(), 'Browser App completed ahead of its original approval'
                            if previous is not None:
                                assert not await b.queue.submit_decision(previous.id, True, scope='once')
                                assert mcp_http_server.witness == expected
                            assert await b.queue.submit_decision(request.id, approved, scope='once')
                            previous = request
                            if approved:
                                expected.append('browser-app-once')
                        try:
                            response = await event
                        finally:
                            assert mcp_http_server.witness == expected, (
                                'Denied browser App produced an external effect')
                        assert response == dict(event='call-completed', index=index,
                            refused=permission == 'deny' or index == 2)
                        await continue_browser(child)
                    finally:
                        pending = [event, *([approval] if approval is not None else [])]
                        for original in pending:
                            if not original.done():
                                original.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
            output, errors = await asyncio.wait_for(child.communicate(), 40)
            if permission == 'allow':
                expected += ['browser-app-once', 'browser-app-once']
            assert mcp_http_server.witness == expected, 'Denied browser App produced an external effect'
            assert child.returncode == 0, (output + errors).decode()[-6000:]
            assert all(json.loads(output).values())
        finally:
            b.queue.cancel_all()
            child.stdin.close()
            # EOF asks the original Node/Playwright owner to close. The caller
            # owns the entire container namespace if shutdown cannot finish.
            await asyncio.wait_for(child.communicate(), 5)
        async with asyncio.timeout(5):
            while b.feature._apps_host._views:
                await asyncio.sleep(0.01)
        assert mcp_http_server.witness == expected
        rows = await b.backend.fetch_all(
            "SELECT agent_did,session_id,tool_name,result_status FROM a2a_tool_dispatches ORDER BY id")
        statuses = {
            'allow': ['success', 'success', 'success'],
            'ask': ['success', 'success', 'policy_denied'],
            'deny': ['success', 'policy_denied', 'policy_denied'],
        }[permission]
        assert [tuple(row) for row in rows] == [
            (b.agent.did, "original-chat", source.binding.name, status) for status in statuses
        ], 'Original App dispatch audits did not preserve their decision, tool and session'
        decisions = [row['decision'] for row in reversed(await b.permissions.get_audit_log())
                     if row['feature'] == 'mcp:composition']
        assert decisions == {
            'allow': ['auto_allowed', 'auto_allowed', 'auto_allowed'],
            'ask': ['auto_allowed', 'user_approved', 'user_denied'],
            'deny': ['auto_allowed', 'auto_denied', 'auto_denied'],
        }[permission]
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
