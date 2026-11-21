"""Drive production Task wire types against the published Everything server."""

import asyncio
import logging
import os
from pathlib import Path
import socket

from kestrel_feature_mcp.connection import MCPConnection, bind_tool_caller
from kestrel_feature_mcp.input_requests import plan_mcp_inputs, validate_form_responses
from kestrel_feature_mcp.tasks_protocol import (
    CancelTaskRequest, CreateTaskResult, GetTaskRequest, TaskIdParams,
    TasksExtension, UpdateTaskParams, UpdateTaskRequest,
)
from tests.conformance.client import load_profile


async def _unexpected_input(*_args):
    raise RuntimeError('Only the explicit operator Task form may receive input')


async def _wait_for(bound, task_id, status):
    while True:
        response = await bound.request_task(GetTaskRequest(params=TaskIdParams(task_id=task_id)),
            require_authority=bound.require_current)
        assert response.task_id == task_id
        if response.status == status:
            return response
        assert response.status == 'working'
        await asyncio.sleep((response.poll_interval_ms or 250) / 1000)


async def _exchange(url):
    connection = MCPConnection(url, extensions=[TasksExtension(_unexpected_input)],
        elicitation_callback=_unexpected_input, connect_timeout=5, call_timeout=5, close_timeout=5)
    try:
        tools = await connection.connect()
        assert connection.protocol_version == load_profile()['protocol_version']
        assert connection.supports_task_claims
        bound = bind_tool_caller(connection, lambda: connection.is_connected, 'official-everything',
            tool_names=[tool.name for tool in tools])
        tool = 'simulate-research-query'
        initial = await bound(tool, {'topic': 'Python', 'ambiguous': True},
            require_authority=bound.require_current, allow_claimed=True)
        assert isinstance(initial, CreateTaskResult) and initial.status == 'working'
        waiting = await _wait_for(bound, initial.task_id, 'input_required')
        requests = {key: value.model_dump(mode='json', by_alias=True, exclude_none=True)
            for key, value in waiting.input_requests.items()}
        plan = plan_mcp_inputs(requests, allow_blocking=True)
        assert set(plan.operator_requests) == {'clarification'}
        responses = validate_form_responses(plan, {'clarification': {
            'action': 'accept', 'content': {'interpretation': 'programming'},
        }})
        update = await bound.request_task(UpdateTaskRequest(params=UpdateTaskParams(
            task_id=initial.task_id, input_responses=responses)), require_authority=bound.require_current)
        assert update.result_type == 'complete'
        completed = await _wait_for(bound, initial.task_id, 'completed')
        assert 'Python (programming)' in completed.result['content'][0]['text']

        other = await bound(tool, {'topic': 'Independent cancellation test'},
            require_authority=bound.require_current, allow_claimed=True)
        assert isinstance(other, CreateTaskResult) and other.task_id != initial.task_id
        cancellation = await bound.request_task(CancelTaskRequest(params=TaskIdParams(task_id=other.task_id)),
            require_authority=bound.require_current)
        assert cancellation.result_type == 'complete'
        await _wait_for(bound, other.task_id, 'cancelled')
    finally:
        await connection.close()


async def run():
    launcher = Path(__file__).with_name('node_modules') / '.bin/mcp-server-everything'
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    server = await asyncio.create_subprocess_exec(str(launcher), 'streamableHttp',
        env={'PATH': os.environ['PATH'], 'HOST': '127.0.0.1', 'PORT': str(port)},
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE)
    try:
        starting = await asyncio.wait_for(server.stderr.readline(), 10)
        address = f'127.0.0.1:{port}'
        assert starting.decode().strip() == f'MCP Streamable HTTP Server listening on {address}'
        await asyncio.wait_for(_exchange(f'http://{address}/mcp'), 25)
    finally:
        if server.returncode is None:
            server.terminate()
            try:
                await asyncio.wait_for(server.wait(), 5)
            except TimeoutError:
                server.kill()
                await server.wait()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
    logging.getLogger(__name__).info('Everything Task input, completion and cancellation passed')
