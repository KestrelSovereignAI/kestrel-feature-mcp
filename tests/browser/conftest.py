"""Native MCP and Core fixtures; browser helpers own only temporary listeners."""

import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest
import pytest_asyncio

from tests.unit.conftest import mcp_http_server as mcp_http_server
from tests.unit.test_mcp_apps_host import native_apps_host as native_apps_host


REPOSITORY = Path(__file__).resolve().parents[2]


@pytest.fixture
def core_listener():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        yield listener


@pytest.fixture
def apps_host_origin(core_listener):
    return f"http://127.0.0.1:{core_listener.getsockname()[1]}"


@pytest.fixture
def app_resource_html():
    result = subprocess.run(["node", "web/test-support/parent-browser-build.mjs"], cwd=REPOSITORY,
                            capture_output=True, text=True, check=True)
    return result.stdout


@pytest_asyncio.fixture
async def apps_sandbox_url(tmp_path, apps_host_origin):
    config = tmp_path / "sandbox.json"
    config.write_text(json.dumps({"listen": {"host": "127.0.0.1", "port": 0}, "sandbox": {
        "hostOrigin": apps_host_origin, "maxMessageBytes": 2_097_152, "maxHtmlBytes": 1_048_576,
        "policy": {},
    }}))
    with (tmp_path / "sandbox-stderr.log").open("wb") as errors:
        child = await asyncio.create_subprocess_exec("node",
            str(REPOSITORY / "kestrel_feature_mcp/apps_sandbox/sandbox-service.mjs"), "--config", str(config),
            env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)},
            stdout=asyncio.subprocess.PIPE, stderr=errors)
        try:
            ready = json.loads(await asyncio.wait_for(child.stdout.readline(), 10))
            assert ready["event"] == "mcp-apps-sandbox-listening"
            yield f'http://127.0.0.1:{ready["address"]["port"]}/proxy'
        finally:
            if child.returncode is None:
                child.terminate()
            try:
                assert await asyncio.wait_for(child.wait(), 5) == 0
            except TimeoutError:
                child.kill()
                await child.wait()
                raise
