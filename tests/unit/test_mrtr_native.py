"""State-only continuations cross real native HTTP without hidden retries."""

import asyncio
from collections import defaultdict
from types import SimpleNamespace
import json

from mcp import types
from mcp.server import Server
from mcp.shared.exceptions import MCPError
import pytest

from kestrel_sdk.resources import ResourceOutcomeUnknown

from kestrel_feature_mcp.connection import MCPConnection, MCPCallOutcomeUnknownError, bind_tool_caller
from tests.http_peers import serve_http


@pytest.fixture
async def mrtr_peer(tmp_path):
    peer = SimpleNamespace(rounds=defaultdict(list), wire=[], effects=[], first=asyncio.Event(),
        release=asyncio.Event(), states=['opaque/Δ\r\nstate', ''], delay=0, failure=None, invalid_result=None,
        requested_inputs=None, hold=False, infinite=False, state_for=lambda key, state: state)

    async def list_tools(ctx, params):
        return types.ListToolsResult(tools=[types.Tool(name='work', input_schema={'type': 'object'})])

    async def respond(ctx, params):
        key = params.arguments.get('key', 'work') if ctx.method == 'tools/call' else params.uri
        rounds = peer.rounds[key]
        rounds.append(params.model_dump(mode='json', by_alias=True, exclude_none=True))
        count = len(rounds)
        peer.effects.append((key, count))
        peer.first.set()
        if peer.hold and count == 1:
            await peer.release.wait()
        await asyncio.sleep(peer.delay)
        if peer.failure is not None and count > 1:
            raise MCPError(peer.failure, 'Rejected after previous work')
        if peer.requested_inputs is not None:
            return types.InputRequiredResult(input_requests=peer.requested_inputs, request_state='private-input-state')
        if peer.infinite or count <= len(peer.states):
            state = peer.state_for(key, peer.states[(count - 1) % len(peer.states)])
            return types.InputRequiredResult(input_requests={}, request_state=state)
        if ctx.method == 'tools/call':
            return types.CallToolResult(content=[types.TextContent(type='text', text=key)])
        return types.ReadResourceResult(contents=[types.TextResourceContents(uri=params.uri,
            mime_type='text/html;profile=mcp-app', text='<!doctype html><p>Done</p>')])

    server = Server('independent-state-only-peer', on_list_tools=list_tools,
        on_call_tool=respond, on_read_resource=respond)
    app = server.streamable_http_app(stateless_http=True, json_response=True)

    async def recorded(scope, receive, send):
        body = bytearray()
        async def read():
            message = await receive()
            body.extend(message.get('body', b''))
            return message
        pending = None
        async def write(message):
            nonlocal pending
            invalid = (peer.invalid_result and body and json.loads(body).get('method')
                in {'tools/call', 'resources/read'})
            if not invalid:
                return await send(message)
            if message['type'] == 'http.response.start':
                pending = message
                return
            assert message['type'] == 'http.response.body' and not message.get('more_body')
            wire = json.loads(message['body'])
            wire['result'] = {'resultType': 'input_required', 'inputRequests': {}}
            if peer.invalid_result == 'malformed-state':
                wire['result']['requestState'] = {'private': 'opaque-wire-secret'}
            rewritten = json.dumps(wire).encode()
            headers = [(k, v) for k, v in pending['headers'] if k.lower() != b'content-length']
            await send({**pending, 'headers': [*headers, (b'content-length', str(len(rewritten)).encode())]})
            await send({**message, 'body': rewritten})
        try:
            await app(scope, read, write)
        finally:
            if body:
                peer.wire.append((scope, json.loads(body)))
    async with serve_http(recorded, tmp_path / 'mrtr-peer') as http:
        peer.url = http.url + '/mcp'
        yield peer


async def invoke(connection, kind):
    caller = bind_tool_caller(connection, lambda: True, 'native-state-only')
    if kind == 'tool':
        return await caller('work', {'key': 'work', 'nested': {'original': True}})
    return await caller.read_resource('ui://work/view.html')


@pytest.mark.parametrize('kind', ['tool', 'resource'])
async def test_state_only_echoes_latest_opaque_and_empty_state_with_fresh_ids(mrtr_peer, kind):
    connection = MCPConnection(mrtr_peer.url)
    try:
        await connection.connect()
        result = await invoke(connection, kind)
        assert result.result_type == 'complete'
        method = 'tools/call' if kind == 'tool' else 'resources/read'
        calls = [m for _, m in mrtr_peer.wire if m['method'] == method]
        assert len(calls) == 3
        assert len({m['id'] for m in calls}) == 3
        assert [m['params'].get('requestState') for m in calls] == [None, *mrtr_peer.states]
        assert 'requestState' not in calls[0]['params']
        assert all('inputResponses' not in m['params'] for m in calls)
        assert all(not m['params']['_meta']['io.modelcontextprotocol/clientCapabilities'].get('elicitation') for m in calls)
        if kind == 'tool':
            assert all(m['params']['arguments'] == calls[0]['params']['arguments'] for m in calls)
        else:
            assert all(m['params']['uri'] == 'ui://work/view.html' for m in calls)
    finally:
        await connection.close()


@pytest.mark.parametrize('maximum', [0, 2])
async def test_state_only_cap_stops_and_preserves_prior_execution_uncertainty(mrtr_peer, maximum):
    mrtr_peer.infinite = True
    connection = MCPConnection(mrtr_peer.url, max_state_only_rounds=maximum)
    try:
        await connection.connect()
        with pytest.raises(MCPCallOutcomeUnknownError, match='unknown'):
            await invoke(connection, 'tool')
        assert len(mrtr_peer.rounds['work']) == maximum + 1
        assert len(mrtr_peer.effects) == maximum + 1
    finally:
        await connection.close()


@pytest.mark.parametrize('code', [types.INVALID_PARAMS, types.HEADER_MISMATCH])
async def test_later_rejection_cannot_prove_prior_rounds_effect_free(mrtr_peer, code):
    mrtr_peer.failure = code
    connection = MCPConnection(mrtr_peer.url)
    try:
        await connection.connect()
        with pytest.raises(MCPCallOutcomeUnknownError, match='unknown'):
            await invoke(connection, 'tool')
        assert len(mrtr_peer.effects) == 2
        assert connection.is_connected is (code != types.HEADER_MISMATCH)
    finally:
        await connection.close()


async def test_continuation_uses_argument_snapshot_and_per_call_state(mrtr_peer):
    mrtr_peer.hold = True
    mrtr_peer.state_for = lambda key, state: None if state is None else key + ':' + state
    connection = MCPConnection(mrtr_peer.url)
    tasks = []
    try:
        await connection.connect()
        args = {'key': 'first', 'nested': {'original': True}}
        caller = bind_tool_caller(connection, lambda: True, 'parallel-original')
        first = asyncio.create_task(caller('work', args))
        tasks.append(first)
        await mrtr_peer.first.wait()
        args['nested']['original'] = False
        args['key'] = 'changed'
        second = asyncio.create_task(caller('work', {'key': 'second'}))
        tasks.append(second)
        mrtr_peer.release.set()
        results = await asyncio.gather(*tasks)
        assert [r.content[0].text for r in results] == ['first', 'second']
        assert len(mrtr_peer.rounds['first']) == len(mrtr_peer.rounds['second']) == 3
        assert 'changed' not in mrtr_peer.rounds
        for key in ('first', 'second'):
            assert [r.get('requestState') for r in mrtr_peer.rounds[key]] == [
                None, key + ':' + mrtr_peer.states[0], key + ':']
        assert all(r['arguments'] == {'key': 'first', 'nested': {'original': True}}
            for r in mrtr_peer.rounds['first'])
    finally:
        mrtr_peer.release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await connection.close()


@pytest.mark.parametrize('kind', ['tool', 'resource'])
async def test_original_owner_and_admission_are_rechecked_before_each_continuation(mrtr_peer, kind):
    connection = MCPConnection(mrtr_peer.url)
    admissions = []
    def check():
        admissions.append(len(mrtr_peer.effects))
        if len(mrtr_peer.effects) == 1:
            raise ValueError('Original authority withdrawn')
    try:
        await connection.connect()
        caller = bind_tool_caller(connection, lambda: True, 'original', continuation_check=check)
        expected = MCPCallOutcomeUnknownError if kind == 'tool' else ResourceOutcomeUnknown
        with pytest.raises(expected):
            if kind == 'tool':
                await caller('work', {'key': 'work'})
            else:
                await caller.read_resource('ui://work/view.html')
        assert admissions == [0, 1]
        assert len(mrtr_peer.effects) == 1
    finally:
        await connection.close()


async def test_cancellation_during_continuation_backoff_never_sends_another_round(mrtr_peer):
    connection = MCPConnection(mrtr_peer.url)
    entered = asyncio.Event()
    def check():
        if mrtr_peer.effects:
            entered.set()
    operation = None
    try:
        await connection.connect()
        caller = bind_tool_caller(connection, lambda: True, 'cancelled', continuation_check=check)
        operation = asyncio.create_task(caller('work', {'key': 'work'}))
        await entered.wait()
        operation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await operation
        assert len(mrtr_peer.effects) == 1
    finally:
        if operation is not None and not operation.done():
            operation.cancel()
        if operation is not None:
            await asyncio.gather(operation, return_exceptions=True)
        await connection.close()


async def test_whole_call_deadline_covers_all_rounds_and_backoff(mrtr_peer):
    mrtr_peer.delay = .09
    connection = MCPConnection(mrtr_peer.url, call_timeout=.16,
        state_only_backoff_initial=.01, state_only_backoff_max=.01)
    try:
        await connection.connect()
        with pytest.raises(MCPCallOutcomeUnknownError):
            await invoke(connection, 'tool')
        assert len(mrtr_peer.effects) == 2
    finally:
        await connection.close()


@pytest.mark.parametrize('kind', ['sampling', 'roots', 'elicitation'])
async def test_unadvertised_input_is_refused_without_fulfillment_or_state_leak(mrtr_peer, kind):
    requests = {
        'sampling': types.CreateMessageRequest(params=types.CreateMessageRequestParams(
            messages=[types.SamplingMessage(role='user', content=types.TextContent(type='text', text='private question'))],
            max_tokens=16)),
        'roots': types.ListRootsRequest(),
        'elicitation': types.ElicitRequest(params=types.ElicitRequestFormParams(
            message='private question', requested_schema={'type': 'object', 'properties': {}})),
    }
    mrtr_peer.requested_inputs = {'private-key': requests[kind]}
    connection = MCPConnection(mrtr_peer.url)
    try:
        await connection.connect()
        with pytest.raises(MCPCallOutcomeUnknownError) as caught:
            await invoke(connection, 'tool')
        assert len(mrtr_peer.effects) == 1
        assert not any(secret in str(caught.value) for secret in ['private-input-state', 'private-key', 'private question'])
    finally:
        await connection.close()


async def test_reconnection_during_backoff_never_borrows_the_replacement_client(mrtr_peer):
    connection = MCPConnection(mrtr_peer.url)
    entered = asyncio.Event()
    def check():
        if mrtr_peer.effects:
            entered.set()
    operation = None
    try:
        await connection.connect()
        caller = bind_tool_caller(connection, lambda: True, 'original-session', continuation_check=check)
        operation = asyncio.create_task(caller('work', {'key': 'work'}))
        await entered.wait()
        await connection.close()
        await connection.connect()
        with pytest.raises(MCPCallOutcomeUnknownError):
            await operation
        assert not caller.is_current
        assert len(mrtr_peer.effects) == 1
    finally:
        if operation is not None and not operation.done():
            operation.cancel()
        if operation is not None:
            await asyncio.gather(operation, return_exceptions=True)
        await connection.close()


@pytest.mark.parametrize('field,value', [
    ('max_state_only_rounds', True), ('max_state_only_rounds', -1),
    ('max_state_only_rounds', 1.5), ('max_state_only_rounds', 10001),
    ('state_only_backoff_initial', 0), ('state_only_backoff_initial', float('nan')),
    ('state_only_backoff_initial', float('inf')), ('state_only_backoff_max', 0),
    ('state_only_backoff_max', float('nan')), ('state_only_backoff_max', float('inf')),
])
def test_invalid_continuation_budgets_refused_before_transport(field, value):
    with pytest.raises(ValueError, match='state-only'):
        MCPConnection('http://127.0.0.1:1/mcp', **{field: value})


def test_backoff_initial_cannot_exceed_its_ceiling():
    with pytest.raises(ValueError, match='state-only'):
        MCPConnection('http://127.0.0.1:1/mcp', state_only_backoff_initial=1, state_only_backoff_max=.1)


@pytest.mark.parametrize('kind', ['tool', 'resource'])
async def test_low_level_call_without_original_authority_never_continues(mrtr_peer, kind):
    from kestrel_sdk.resources import ResourceOutcomeUnknown
    connection = MCPConnection(mrtr_peer.url)
    try:
        await connection.connect()
        with pytest.raises(MCPCallOutcomeUnknownError if kind == 'tool' else ResourceOutcomeUnknown):
            if kind == 'tool':
                await connection.call_tool('work', {'key': 'work'})
            else:
                await connection.read_resource('ui://work/view.html', incarnation=connection.incarnation)
        assert len(mrtr_peer.effects) == 1
    finally:
        await connection.close()


@pytest.mark.parametrize('kind', ['tool', 'resource'])
async def test_owner_lost_after_terminal_response_never_returns_native_result(mrtr_peer, kind):
    mrtr_peer.states, mrtr_peer.hold = [], True
    connection = MCPConnection(mrtr_peer.url)
    owner, operation = {'current': True}, None
    try:
        await connection.connect()
        caller = bind_tool_caller(connection, lambda: owner['current'], 'terminal-owner')
        operation = asyncio.create_task(caller('work', {'key': 'work'}) if kind == 'tool'
            else caller.read_resource('ui://work/view.html'))
        await mrtr_peer.first.wait()
        owner['current'] = False
        mrtr_peer.release.set()
        with pytest.raises(MCPCallOutcomeUnknownError if kind == 'tool' else ValueError):
            await operation
        assert len(mrtr_peer.effects) == 1
    finally:
        mrtr_peer.release.set()
        if operation is not None:
            if not operation.done():
                operation.cancel()
            await asyncio.gather(operation, return_exceptions=True)
        await connection.close()


@pytest.mark.parametrize('kind', ['tool', 'resource'])
@pytest.mark.parametrize('shape', ['empty-map-without-state', 'malformed-state'])
async def test_native_sdk_invalid_intermediate_is_unknown_and_not_echoed_or_leaked(mrtr_peer, kind, shape):
    import traceback
    mrtr_peer.invalid_result = shape
    connection = MCPConnection(mrtr_peer.url)
    try:
        await connection.connect()
        with pytest.raises(MCPCallOutcomeUnknownError if kind == 'tool' else ResourceOutcomeUnknown) as caught:
            await invoke(connection, kind)
        assert len(mrtr_peer.effects) == 1
        assert 'opaque-wire-secret' not in str(caught.value)
        if kind == 'resource':
            assert 'opaque-wire-secret' not in ''.join(traceback.format_exception(caught.value))
    finally:
        await connection.close()
