"""A fresh Core and Feature process can deliver an original chat's native Task."""

import asyncio
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys

from tests.unit.test_task_observation import (
    credential_boundary as credential_boundary, oauth_peers as oauth_peers,
    oauth_runtime as oauth_runtime, pytestmark, start_task,
)


async def test_fresh_process_observes_and_delivers_the_original_task(oauth_runtime, tmp_path):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    peer.created_at = peer.last_updated_at = datetime.now(UTC).isoformat()
    _, original = await start_task(b)
    part, = b.task_parts
    await b.feature._close_tasks()
    await b.feature._close_oauth()
    assert b.feature._task_runtime is b.feature._oauth_runtime is None
    peer.status = 'completed'
    exchanges = b.peer.requests.count(('POST', '/token'))
    configuration = {
        'root': str(tmp_path),
        'database': str(b.path),
        'agent_did': b.agent.did,
        'oauth_policy': b.app.state.mcp_oauth_policy.model_dump(mode='json'),
        'server_url': b.peer.selection.server_url,
        'issuer': b.peer.selection.issuer,
        'certificate': os.environ['SSL_CERT_FILE'],
        'session_id': 'credential-chat',
        'handle': original.handle,
        'reference': part['data']['reference'],
    }
    program = Path(__file__).resolve().parents[1] / 'oauth_acceptance/task_restart_child.py'
    child = await asyncio.create_subprocess_exec(sys.executable, '-B', str(program),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(child.communicate(json.dumps(configuration).encode()), 20)
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()
    assert child.returncode == 0, stderr.decode()
    result = json.loads(stdout)
    assert result['status'] == 'completed'
    assert result['result']['content'] == [{'type': 'text', 'text': 'actual deferred result'}]
    assert peer.calls == ['started', 'get']
    assert b.peer.requests.count(('POST', '/token')) == exchanges
