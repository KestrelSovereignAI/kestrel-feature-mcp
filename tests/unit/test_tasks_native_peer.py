"""Typed client extension against an independently defined native SDK peer."""
import asyncio
from copy import deepcopy
import json

import pytest
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp import types
from mcp.client.extension import ClientExtension, UnexpectedClaimedResult
from mcp.server.extension import Extension, MethodBinding
from pydantic import TypeAdapter, ValidationError

from kestrel_feature_mcp.input_requests import plan_mcp_inputs, validate_form_responses
from kestrel_feature_mcp.connection import MCPConnection, MCPCallOutcomeUnknownError, MCP_REQUEST_ERRORS, bind_tool_caller
from kestrel_feature_mcp.input_requests import MCPInputResume, MCPInputSuspension
from kestrel_feature_mcp.oauth_credentials import TaskOperationAuth
from kestrel_feature_mcp.oauth_policy import GrantRejected, ResourceGrantRejected
from kestrel_sdk.resources import ResourceConflict, ResourceUnsupported
from mcp.shared.exceptions import MCPError

from kestrel_feature_mcp.tasks_protocol import (
    CancelTaskRequest, CreateTaskResult, DetailedTaskResult, GetTaskRequest,
    TaskAcknowledgement, TaskIdParams, TasksExtension, UpdateTaskParams,
    UpdateTaskRequest,
)


class PeerTaskParams(types.RequestParams):
    task_id: str


class PeerInputParams(PeerTaskParams):
    input_responses: types.InputResponses


class NativeTasksPeer(Extension):
    identifier = "io.modelcontextprotocol/tasks"

    def __init__(self):
        self.calls = []
        self.tool_requests = []
        self.tool_name = "echo"
        self.status = "working"
        self.task_id = "opaque/task:1"
        self.created_at = "2026-11-04T00:00:00Z"
        self.last_updated_at = "2026-11-04T00:00:01Z"
        self.ttl_ms = 60000
        self.poll_interval_ms = 100
        self.before_response = None
        self.require_input = False
        self.reject_code = None
        self.return_ordinary = False
        self.return_error = False
        self.tool_reject_code = None
        self.input_rounds = 1
        self.omit_complete_discriminator = False
        self.last_complete_body = None

    def state(self):
        return {"resultType": "complete", "taskId": self.task_id,
            "status": self.status, "createdAt": self.created_at,
            "lastUpdatedAt": self.last_updated_at, "ttlMs": self.ttl_ms,
            "pollIntervalMs": self.poll_interval_ms}

    async def intercept_tool_call(self, params, ctx, call_next):
        if params.name != self.tool_name:
            return await call_next(ctx)
        self.tool_requests.append(params.model_dump(mode='json', by_alias=True, exclude_unset=True))
        if self.tool_reject_code is not None:
            raise MCPError(self.tool_reject_code, 'Owned native tool request rejected')
        if self.require_input:
            if params.request_state is None:
                return self.form('native-mrtr-state')
            assert params.request_state in {'native-mrtr-state', 'native-mrtr-state-2'}
            assert params.input_responses['form'].content == {'label': 'native input'}
            if self.input_rounds == 2 and params.request_state == 'native-mrtr-state':
                return self.form('native-mrtr-state-2')
        self.calls.append("started")
        if self.return_ordinary:
            result = await call_next(ctx)
            if self.omit_complete_discriminator:
                assert isinstance(result, types.CallToolResult)
                native = result.model_dump(mode='json', by_alias=True, exclude_none=True)
                native.pop('resultType', None)
                self.last_complete_body = native
                return native
            return result
        if self.return_error:
            return types.CallToolResult(result_type='complete',
                content=[types.TextContent(type='text', text='Owned native tool error')], is_error=True)
        return {**self.state(), "resultType": "task"}

    def form(self, state):
        return types.InputRequiredResult(request_state=state, input_requests={
            'form': types.ElicitRequest.model_validate({'method': 'elicitation/create', 'params': {
                'mode': 'form', 'message': 'Choose a label', 'requestedSchema': {'type': 'object',
                    'properties': {'label': {'type': 'string'}}, 'required': ['label']}}})})

    async def respond(self, result):
        return result if self.before_response is None else await self.before_response(result)

    def require_request(self, params):
        assert params.task_id == self.task_id
        if self.reject_code is not None:
            raise MCPError(self.reject_code, 'Task request rejected before execution')

    async def get(self, ctx, params):
        self.require_request(params)
        self.calls.append("get")
        state = self.state()
        if self.status == "input_required":
            state["inputRequests"] = {"form": {"method": "elicitation/create", "params": {
                "mode": "form", "message": "Choose a label", "requestedSchema": {
                    "type": "object", "properties": {"label": {"type": "string"}},
                    "required": ["label"]}}}}
        if self.status == "completed":
            state["result"] = {"resultType": "complete", "content": [
                {"type": "text", "text": "actual deferred result"}],
                "structuredContent": {"result": "actual deferred result"}}
        return await self.respond(state)

    async def update(self, ctx, params):
        self.require_request(params)
        assert params.input_responses["form"].action == "accept"
        assert params.input_responses["form"].content == {"label": "native input"}
        self.calls.append("update")
        self.status = "completed"
        return await self.respond({"resultType": "complete"})

    async def cancel(self, ctx, params):
        self.require_request(params)
        self.calls.append("cancel")
        return await self.respond({"resultType": "complete"})

    def methods(self):
        return [MethodBinding(method=method, params_type=shape, handler=handler,
            protocol_versions=frozenset({"2026-07-28"})) for method, shape, handler in [
                ("tasks/get", PeerTaskParams, self.get),
                ("tasks/update", PeerInputParams, self.update),
                ("tasks/cancel", PeerTaskParams, self.cancel)]]


async def no_implicit_resolution(result, context):
    raise AssertionError("one-round native calls must not replay or poll implicitly")


class IndependentTasksExtension(ClientExtension):
    """The same public capability identifier without Kestrel class identity."""
    identifier = TasksExtension.identifier

    def claims(self):
        return TasksExtension(no_implicit_resolution).claims()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
async def test_task_observation_auth_has_one_original_sdk_read(mcp_http_server):
    peer = mcp_http_server.settings["extensions"][0]
    fetched = []

    async def access_token():
        fetched.append(True)
        return "synthetic-observation"

    auth = TaskOperationAuth(mcp_http_server.url, GetTaskRequest(params=TaskIdParams(task_id=peer.task_id)),
        read_access_token=access_token, check_current=lambda: None)
    connection = MCPConnection(mcp_http_server.url, auth=auth,
        extensions=[TasksExtension(no_implicit_resolution)])
    try:
        assert "echo" in {tool.name for tool in await connection.connect()}
        async with httpx2.AsyncClient(auth=auth, trust_env=False) as direct:
            before = len(fetched), len(mcp_http_server.requests)
            with pytest.raises(GrantRejected, match="cannot leave the selected resource"):
                await direct.get(mcp_http_server.url + "/other")
            assert (len(fetched), len(mcp_http_server.requests)) == before
            for message in (
                {"method": "tasks/get", "params": {"taskId": peer.task_id}},
                {"method": "tools/call", "params": {"name": "echo", "arguments": {"text": "refused"}}},
                {"result": {}},
            ):
                before = len(fetched), len(mcp_http_server.requests)
                with pytest.raises(GrantRejected, match="only send its original Task request"):
                    await direct.post(mcp_http_server.url, json={"jsonrpc": "2.0", "id": 5, **message})
                assert (len(fetched), len(mcp_http_server.requests)) == before
            auth.arm()
            before = len(fetched), len(mcp_http_server.requests)
            with pytest.raises(GrantRejected, match="unique JSON object fields"):
                await direct.post(mcp_http_server.url, content=(
                    b'{"jsonrpc":"2.0","id":8,"method":"tasks/get","params":{"taskId":"owned","taskId":"owned"}}'))
            assert (len(fetched), len(mcp_http_server.requests)) == before
            foreign = auth.request
            foreign.params.task_id = "another-task"
            for message in (
                foreign.model_dump(mode="json", by_alias=True, exclude_none=True),
                {"method": "tasks/cancel", "params": {"taskId": peer.task_id}},
                {"method": "tasks/update", "params": {"taskId": peer.task_id, "inputResponses": {}}},
                {"method": "tasks/get", "params": {"taskId": peer.task_id, "unexpected": "field"}},
            ):
                before = len(fetched), len(mcp_http_server.requests)
                with pytest.raises(GrantRejected, match="only send its original Task request"):
                    await direct.post(mcp_http_server.url, json={"jsonrpc": "2.0", "id": 7, **message})
                assert (len(fetched), len(mcp_http_server.requests)) == before

            observed = await connection.request_task(auth.request, incarnation=connection.incarnation,
                round_check=lambda: None)
            assert observed.task_id == peer.task_id and observed.status == "working"
            request, = [(scope, json.loads(body)) for scope, body in mcp_http_server.requests
                if body and json.loads(body).get("method") == "tasks/get"]
            scope, message = request
            assert dict(scope["headers"])[b"authorization"] == b"Bearer synthetic-observation"
            assert message["params"]["taskId"] == peer.task_id
            capabilities = message["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
            assert set(capabilities["extensions"]) == {TasksExtension.identifier}
            assert not capabilities.get("elicitation")
            with pytest.raises(GrantRejected, match="one request"):
                auth.arm()
            before = len(fetched), len(mcp_http_server.requests)
            with pytest.raises(GrantRejected, match="only send its original Task request"):
                await direct.post(mcp_http_server.url, json=message)
            assert (len(fetched), len(mcp_http_server.requests)) == before
    finally:
        await connection.close()
    assert peer.calls == ["get"] and not mcp_http_server.witness


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize("kind", ["update", "cancel"])
async def test_native_task_mutation_auth_spends_only_the_exact_request(mcp_http_server, kind):
    peer = mcp_http_server.settings["extensions"][0]
    request = (UpdateTaskRequest(params=UpdateTaskParams(task_id=peer.task_id,
        input_responses={"form": types.ElicitResult(action="accept", content={"label": "native input"})}))
        if kind == "update" else CancelTaskRequest(params=TaskIdParams(task_id=peer.task_id)))

    async def access_token():
        return "owned-native-task-operator"

    auth = TaskOperationAuth(mcp_http_server.url, request,
        read_access_token=access_token, check_current=lambda: None)
    async with httpx2.AsyncClient(auth=auth, trust_env=False) as direct:
        connection = MCPConnection(mcp_http_server.url, auth=auth,
            extensions=[TasksExtension(no_implicit_resolution)])
        try:
            await connection.connect()
            auth.arm()
            before = len(mcp_http_server.requests)
            foreign = request.model_copy(deep=True)
            if kind == "update":
                foreign.params.input_responses["form"].content["label"] = "unapproved change"
            else:
                foreign.params.task_id = "another-task"
            with pytest.raises(GrantRejected, match="only send its original Task request"):
                await direct.post(mcp_http_server.url, json={"jsonrpc": "2.0", "id": 20,
                    **foreign.model_dump(mode="json", by_alias=True, exclude_none=True)})
            assert len(mcp_http_server.requests) == before
            ack = await connection.request_task(auth.request, incarnation=connection.incarnation,
                round_check=lambda: None)
            assert ack.result_type == "complete"
            scope, message = next((scope, json.loads(body)) for scope, body in mcp_http_server.requests
                if body and json.loads(body).get("method") == request.method)
            assert dict(scope["headers"])[b"mcp-name"].decode() == peer.task_id
            before = len(mcp_http_server.requests)
            with pytest.raises(GrantRejected, match="only send its original Task request"):
                await direct.post(mcp_http_server.url, json=message)
            assert len(mcp_http_server.requests) == before
        finally:
            await connection.close()
    assert peer.calls == [kind]


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
async def test_concurrent_task_reads_cannot_share_one_observation_borrow(mcp_http_server):
    peer = mcp_http_server.settings["extensions"][0]
    entered, release = asyncio.Event(), asyncio.Event()
    hold_token = False

    async def access_token():
        if hold_token:
            entered.set()
            await release.wait()
        return "synthetic-observation"

    auth = TaskOperationAuth(mcp_http_server.url, GetTaskRequest(params=TaskIdParams(task_id=peer.task_id)),
        read_access_token=access_token, check_current=lambda: None)
    connection = MCPConnection(mcp_http_server.url, auth=auth,
        extensions=[TasksExtension(no_implicit_resolution)])
    try:
        await connection.connect()
        auth.arm()
        hold_token = True
        before = len(mcp_http_server.requests)
        first = asyncio.create_task(connection.request_task(auth.request,
            incarnation=connection.incarnation, round_check=lambda: None))
        async with httpx2.AsyncClient(auth=auth, trust_env=False) as client:
            try:
                async with asyncio.timeout(5):
                    await entered.wait()
                message = {"jsonrpc": "2.0", "id": 16,
                    **auth.request.model_dump(mode="json", by_alias=True, exclude_none=True)}
                with pytest.raises(GrantRejected, match="only send its original Task request"):
                    await client.post(mcp_http_server.url, json=message)
                assert len(mcp_http_server.requests) == before
            finally:
                release.set()
                observed = await first
        assert observed.task_id == peer.task_id and observed.status == "working"
    finally:
        await connection.close()
    assert peer.calls == ["get"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 401, 403])
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
async def test_task_resource_rejection_fences_only_its_observation_auth(mcp_http_server, status):
    peer = mcp_http_server.settings["extensions"][0]
    fetched = []

    async def access_token():
        fetched.append(True)
        return "synthetic-observation"

    auth = TaskOperationAuth(mcp_http_server.url, GetTaskRequest(params=TaskIdParams(task_id=peer.task_id)),
        read_access_token=access_token, check_current=lambda: None)
    connection = MCPConnection(mcp_http_server.url, auth=auth,
        extensions=[TasksExtension(no_implicit_resolution)], call_timeout=2)
    try:
        await connection.connect()
        transport = connection._task
        auth.arm()
        mcp_http_server.settings["http_status"] = status
        sent_before = len(mcp_http_server.requests)
        with pytest.raises((*MCP_REQUEST_ERRORS, ExceptionGroup)):
            await connection.request_task(auth.request, incarnation=connection.incarnation,
                round_check=lambda: None)
        assert len(mcp_http_server.requests) == sent_before + 1
        assert peer.calls == []
        with pytest.raises(ResourceGrantRejected):
            auth.require_resource()
        with pytest.raises(ResourceGrantRejected):
            auth.arm()
        before = len(fetched), len(mcp_http_server.requests)
        async with httpx2.AsyncClient(auth=auth, trust_env=False) as client:
            with pytest.raises(ResourceGrantRejected):
                await client.get(mcp_http_server.url)
        assert (len(fetched), len(mcp_http_server.requests)) == before
    finally:
        try:
            await connection.close()
        except* ResourceGrantRejected:
            pass
    assert connection._task is None and transport.done()
    failure = transport.exception()
    assert isinstance(failure, ExceptionGroup)
    refused, unexpected = failure.split(ResourceGrantRejected)
    assert refused is not None and unexpected is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize("scenario", ["input-and-completion", "cooperative-cancel", "unclaimed"])
@pytest.mark.parametrize("task_id,expected_header", [
    ("opaque/task:1", b"opaque/task:1"),
    ("opaque/Δ:1", b"=?base64?b3BhcXVlL86UOjE=?="),
    ("opaque\r\nInjected:1", b"=?base64?b3BhcXVlDQpJbmplY3RlZDox?="),
])
@pytest.mark.parametrize("ttl_ms", [60000, None])
async def test_sdk_claim_and_current_task_verbs_cross_real_http_without_tool_replay(
    mcp_http_server, scenario, task_id, expected_header, ttl_ms, official_tasks_schema,
):
    peer = mcp_http_server.settings["extensions"][0]
    peer.task_id = task_id
    peer.ttl_ms = ttl_ms
    input_callbacks = []

    async def elicitation(context, params):
        input_callbacks.append(params)
        return types.ElicitResult(action="decline")

    async with httpx2.AsyncClient(trust_env=False, follow_redirects=False) as http_client, Client(
        streamable_http_client(mcp_http_server.url, http_client=http_client),
        extensions=[TasksExtension(no_implicit_resolution)],
        elicitation_callback=elicitation, input_required_max_rounds=0,
    ) as client:
        session = client.session
        if scenario == "unclaimed":
            with pytest.raises(UnexpectedClaimedResult) as unresolved:
                await session.call_tool("echo", {"text": "accepted once"})
            created = unresolved.value.result
        else:
            created = await session.call_tool("echo", {"text": "accepted once"},
                allow_claimed=True)
        assert isinstance(created, CreateTaskResult)
        assert created.task_id == peer.task_id and created.status == "working"
        assert created.ttl_ms == ttl_ms
        assert peer.calls == ["started"]
        state = await session.send_request(GetTaskRequest(
            params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
        assert state.status == "working"
        if scenario == "input-and-completion":
            peer.status = "input_required"
            state = await session.send_request(GetTaskRequest(
                params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
            assert state.input_requests["form"].method == "elicitation/create"
            plan = plan_mcp_inputs(state.input_requests, allow_blocking=True)
            assert peer.calls.count("update") == 0
            with pytest.raises(ValueError, match="original schema"):
                validate_form_responses(plan, {"form": {"action": "accept", "content": {"label": 42}}})
            assert peer.calls.count("update") == 0
            answers = validate_form_responses(plan, {"form": {"action": "accept", "content": {"label": "native input"}}})
            update = UpdateTaskRequest(params=UpdateTaskParams(
                task_id=created.task_id, input_responses={**answers, **plan.declines}))
            wire = update.model_dump(mode="json", by_alias=True, exclude_none=True)
            assert set(wire["params"]) == {"taskId", "inputResponses"}
            assert wire["params"]["inputResponses"]["form"] == {"action": "accept", "content": {"label": "native input"}}
            official_tasks_schema("UpdateTaskRequest", {"jsonrpc": "2.0", "id": 1,
                **update.model_dump(mode="json", by_alias=True, exclude_none=True)})
            ack = await session.send_request(update, TaskAcknowledgement)
            assert ack.result_type == "complete"
            state = await session.send_request(GetTaskRequest(
                params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
            assert state.status == "completed"
            assert state.result.get("resultType") == "complete"
            result = types.CallToolResult.model_validate(state.result, by_alias=True, by_name=False)
            assert result.content[0].text == "actual deferred result"
        elif scenario == "cooperative-cancel":
            ack = await session.send_request(CancelTaskRequest(
                params=TaskIdParams(task_id=created.task_id)), TaskAcknowledgement)
            assert ack.result_type == "complete"
            state = await session.send_request(GetTaskRequest(
                params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
            assert state.status == "working"  # acknowledgement does not prove cancellation
            peer.status = "cancelled"
            state = await session.send_request(GetTaskRequest(
                params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
            assert state.status == "cancelled"
        assert peer.calls.count("started") == 1
        assert not mcp_http_server.witness  # the native task did not invoke echo inline
        messages = [(scope, json.loads(body)) for scope, body in mcp_http_server.requests if body]
        assert sum(message["method"] == "tools/call" for _, message in messages) == 1
        task_requests = {"tasks/get": "GetTaskRequest", "tasks/update": "UpdateTaskRequest",
            "tasks/cancel": "CancelTaskRequest"}
        for scope, message in messages:
            capabilities = message["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
            assert "io.modelcontextprotocol/tasks" in capabilities["extensions"]
            assert "form" in capabilities["elicitation"]
            if message["method"].startswith("tasks/"):
                official_tasks_schema(task_requests[message["method"]], message)
                header = dict(scope["headers"])[b"mcp-name"]
                assert b"\r" not in header and b"\n" not in header
                assert header == expected_header
        assert input_callbacks == []  # the host owns explicit input admission


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize("ttl_ms", [60000, None])
async def test_high_level_native_client_resolves_one_claim_without_replaying_the_tool(
    mcp_http_server, ttl_ms,
):
    peer = mcp_http_server.settings["extensions"][0]
    peer.ttl_ms = ttl_ms
    resolved = []

    async def resolve(created, context):
        assert isinstance(created, CreateTaskResult)
        assert created.ttl_ms == ttl_ms and created.task_id == peer.task_id
        assert context.session is client.session and context.tool_name == "echo"
        assert context.read_timeout_seconds == 3
        resolved.append(created.task_id)
        current = await context.session.send_request(GetTaskRequest(
            params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
        assert current.status == "working"
        peer.status = "completed"
        current = await context.session.send_request(GetTaskRequest(
            params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
        assert current.status == "completed"
        assert current.result.get("resultType") == "complete"
        return types.CallToolResult.model_validate(current.result, by_alias=True, by_name=False)

    async with httpx2.AsyncClient(trust_env=False, follow_redirects=False) as http_client, Client(
        streamable_http_client(mcp_http_server.url, http_client=http_client),
        extensions=[TasksExtension(resolve)], input_required_max_rounds=0,
    ) as client:
        await client.list_tools()
        result = await client.call_tool("echo", {"text": "accepted once"}, read_timeout_seconds=3)
        assert resolved == [peer.task_id], "owning Task resolver was not called"
        assert result.content[0].text == "actual deferred result" and not result.is_error
        assert result.structured_content == {"result": "actual deferred result"}
    assert resolved == [peer.task_id]
    assert peer.calls == ["started", "get", "get"]
    messages = [json.loads(body) for _, body in mcp_http_server.requests if body]
    assert sum(message["method"] == "tools/call" for message in messages) == 1
    assert not mcp_http_server.witness


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
async def test_native_sdk_wire_claim_rejects_python_field_names(mcp_http_server, monkeypatch):
    from pydantic import ValidationError

    peer = mcp_http_server.settings["extensions"][0]
    original = peer.state

    def invalid_wire():
        wire = original()
        wire["task_id"] = wire.pop("taskId")
        return wire

    monkeypatch.setattr(peer, "state", invalid_wire)
    rejected = False
    try:
        async with httpx2.AsyncClient(trust_env=False, follow_redirects=False) as http_client, Client(
            streamable_http_client(mcp_http_server.url, http_client=http_client),
            extensions=[TasksExtension(no_implicit_resolution)], input_required_max_rounds=0,
        ) as client:
            await client.session.call_tool("echo", {"text": "accepted once"}, allow_claimed=True)
    except* ValidationError as errors:
        pending = list(errors.exceptions)
        while pending:
            error = pending.pop()
            if isinstance(error, BaseExceptionGroup):
                pending.extend(error.exceptions)
            else:
                assert isinstance(error, ValidationError)
                assert any(item["loc"][-1:] == ("taskId",) and item["type"] == "missing"
                    for item in error.errors())
        rejected = True
    assert rejected, "Native wire accepted a Python-only task_id alias"
    assert peer.calls == ["started"] and not mcp_http_server.witness


def native_task_request(verb, task_id):
    if verb == 'update':
        return UpdateTaskRequest(params=UpdateTaskParams(task_id=task_id,
            input_responses={'form': types.ElicitResult(action='accept', content={'label': 'native input'})}))
    request_type = GetTaskRequest if verb == 'get' else CancelTaskRequest
    return request_type(params=TaskIdParams(task_id=task_id))


def native_task_messages(server):
    return [json.loads(body) for _, body in server.requests if body
        and json.loads(body).get('method', '').startswith('tasks/')]


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize('task_id', ['', 'opaque/task:1', 'opaque/Δ:1', 'opaque\r\nInjected:1'])
@pytest.mark.parametrize('ttl_ms', [60000, None])
async def test_connection_owns_native_claim_and_all_task_verbs(mcp_http_server, task_id, ttl_ms, official_tasks_schema):
    peer = mcp_http_server.settings['extensions'][0]
    peer.task_id, peer.ttl_ms = task_id, ttl_ms
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)])
    try:
        tools = await connection.connect()
        bound = bind_tool_caller(connection, lambda: True, 'native-task-owner', tool_names=[t.name for t in tools])
        def authority():
            assert bound.is_current
        created = None
        try:
            created = await bound('echo', {'text': 'accepted once'}, require_authority=authority, allow_claimed=True)
        except MCPCallOutcomeUnknownError:
            pass
        assert isinstance(created, CreateTaskResult) and created.task_id == task_id and created.ttl_ms == ttl_ms
        # A Tasks-capable call still accepts the real ordinary result variant.
        ordinary = await bound('fail', {}, require_authority=authority, allow_claimed=True)
        assert isinstance(ordinary, types.CallToolResult) and ordinary.is_error
        state = await bound.request_task(native_task_request('get', task_id), require_authority=authority)
        assert state.status == 'working'
        peer.status = 'input_required'
        state = await bound.request_task(native_task_request('get', task_id), require_authority=authority)
        assert state.input_requests['form'].method == 'elicitation/create'
        ack = await bound.request_task(native_task_request('update', task_id), require_authority=authority)
        assert isinstance(ack, TaskAcknowledgement) and ack.result_type == 'complete'
        state = await bound.request_task(native_task_request('get', task_id), require_authority=authority)
        assert state.status == 'completed' and state.result['content'][0]['text'] == 'actual deferred result'
        peer.status = 'working'
        ack = await bound.request_task(native_task_request('cancel', task_id), require_authority=authority)
        assert isinstance(ack, TaskAcknowledgement)
        state = await bound.request_task(native_task_request('get', task_id), require_authority=authority)
        assert state.status == 'working', 'A cancellation acknowledgement falsely completed the Task'
        peer.status = 'cancelled'
        state = await bound.request_task(native_task_request('get', task_id), require_authority=authority)
        assert state.status == 'cancelled'
    finally:
        await connection.close()
    assert peer.calls == ['started', 'get', 'get', 'update', 'get', 'cancel', 'get', 'get']
    assert not mcp_http_server.witness
    names = {'tasks/get': 'GetTaskRequest', 'tasks/update': 'UpdateTaskRequest', 'tasks/cancel': 'CancelTaskRequest'}
    for message in native_task_messages(mcp_http_server):
        official_tasks_schema(names[message['method']], message)
        assert message['params']['taskId'] == task_id
        assert 'requestState' not in message['params']
    headers = [dict(scope['headers'])[b'mcp-name'] for scope, body in mcp_http_server.requests
        if body and json.loads(body).get('method', '').startswith('tasks/')]
    assert len(set(headers)) == 1 and all(b'\r' not in header and b'\n' not in header for header in headers)
    assert sum(json.loads(body).get('method') == 'tools/call' for _, body in mcp_http_server.requests if body) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize('pause', [False, True])
async def test_connection_keeps_native_task_claim_after_actual_mrtr_round(mcp_http_server, pause):
    peer = mcp_http_server.settings['extensions'][0]
    peer.require_input = True
    checkpoint = []
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)])
    try:
        await connection.connect()
        bound = bind_tool_caller(connection, lambda: True, 'native-mrtr-to-task')
        async def handle(native):
            checkpoint.append(native.model_copy(deep=True))
            if pause:
                return MCPInputSuspension('owned-input-reference', 'owned-chat')
            return {'form': types.ElicitResult(action='accept', content={'label': 'native input'})}
        result = await bound('echo', {'text': 'accepted once'}, require_authority=bound.require_current,
            input_handler=handle, allow_claimed=True)
        if pause:
            assert isinstance(result, MCPInputSuspension)
            resume = MCPInputResume.seal(checkpoint[0], {'form': types.ElicitResult(
                action='accept', content={'label': 'native input'})})
            result = await bound('echo', {'text': 'accepted once'}, require_authority=bound.require_current,
                input_handler=handle, resume=resume, allow_claimed=True)
        assert isinstance(result, CreateTaskResult) and result.task_id == peer.task_id
    finally:
        await connection.close()
    assert len(checkpoint) == 1 and peer.calls == ['started'] and not mcp_http_server.witness
    messages = [json.loads(body) for _, body in mcp_http_server.requests if body
        and json.loads(body).get('method') == 'tools/call']
    assert len(messages) == 2 and 'requestState' not in messages[0]['params']
    assert messages[1]['params']['requestState'] == checkpoint[0].request_state
    assert messages[1]['params']['inputResponses']['form']['content'] == {'label': 'native input'}
    assert not native_task_messages(mcp_http_server), 'Connection implicitly polled a deferred Task'


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [
    {'extensions': [NativeTasksPeer()]}, {}, {'extensions': [NativeTasksPeer()], 'legacy': True},
], indirect=True)
async def test_task_support_requires_native_local_and_server_negotiation(mcp_http_server):
    for extension in (None, TasksExtension(no_implicit_resolution), IndependentTasksExtension()):
        configured = extension is not None
        connection = MCPConnection(mcp_http_server.url,
            extensions=[extension] if configured else [])
        try:
            await connection.connect()
            bound = bind_tool_caller(connection, lambda: True, 'native-negotiation')
            supported = configured and bool(mcp_http_server.settings.get('extensions')) and not mcp_http_server.settings.get('legacy')
            if supported:
                refusal = None
                try:
                    await bound('echo', {'text': 'not admitted'})
                except (ResourceUnsupported, MCPCallOutcomeUnknownError, MCPError) as error:
                    refusal = error
                assert isinstance(refusal, ResourceUnsupported), 'Tasks capability reached wire without explicit claim handling'
                assert 'explicit native claim' in str(refusal)
                with pytest.raises(ResourceUnsupported, match='current host authority'):
                    await connection.call_tool('echo', {'text': 'not admitted'}, allow_claimed=True)
                with pytest.raises(ResourceUnsupported, match='current host authority'):
                    await bound('echo', {'text': 'not admitted'}, allow_claimed=True)
            else:
                with pytest.raises(ResourceUnsupported, match='native negotiated extension'):
                    await bound.request_task(native_task_request('get', 'opaque/task:1'), require_authority=bound.require_current)
                if not configured or mcp_http_server.settings.get('legacy'):
                    with pytest.raises(ResourceUnsupported, match='native negotiated extension'):
                        await bound('echo', {'text': 'not admitted'}, allow_claimed=True,
                            require_authority=bound.require_current)
        finally:
            await connection.close()
    assert not native_task_messages(mcp_http_server) and not mcp_http_server.witness
    assert not any(json.loads(body).get('method') == 'tools/call' for _, body in mcp_http_server.requests if body)


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize('verb', ['get', 'update', 'cancel'])
@pytest.mark.parametrize('change', ['request', 'authority', 'registration'])
async def test_bound_task_custody_survives_real_awaited_admission(mcp_http_server, verb, change):
    peer = mcp_http_server.settings['extensions'][0]
    entered, release = asyncio.Event(), asyncio.Event()
    current, authorized = True, True
    async def admit():
        entered.set()
        await release.wait()
    def authority():
        if not authorized:
            raise ResourceConflict('Original host authority was withdrawn')
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)])
    try:
        await connection.connect()
        bound = bind_tool_caller(connection, lambda: current, 'admitted-task-owner', admit=admit)
        request = native_task_request(verb, peer.task_id)
        expected = deepcopy(request.model_dump(mode='json', by_alias=True, exclude_none=True))
        task = asyncio.create_task(bound.request_task(request, require_authority=authority))
        async with asyncio.timeout(5):
            await entered.wait()
            if change == 'request':
                request.params.task_id = 'substituted-task'
                if verb == 'update':
                    request.params.input_responses['form'].content['label'] = 'substituted-answer'
            elif change == 'authority':
                authorized = False
            else:
                current = False
            release.set()
            if change == 'request':
                outcome_error = None
                try:
                    await task
                except (MCPError, MCPCallOutcomeUnknownError) as error:
                    outcome_error = error
                message, = native_task_messages(mcp_http_server)
                assert {key: value for key, value in message['params'].items() if key != '_meta'} == expected['params']
                assert outcome_error is None, 'Original native request was not accepted'
            else:
                with pytest.raises((ResourceConflict, ValueError)):
                    await task
                assert not native_task_messages(mcp_http_server), 'Task was sent after its original authority expired'
        assert peer.calls == ([verb] if change == 'request' else [])
    finally:
        release.set()
        await connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize('verb', ['get', 'update', 'cancel'])
@pytest.mark.parametrize('failure', ['withdraw', 'timeout', 'cancel', 'native-error', 'invalid-result'])
async def test_task_transport_keeps_one_native_outcome_without_replay(mcp_http_server, verb, failure):
    peer = mcp_http_server.settings['extensions'][0]
    entered, release = asyncio.Event(), asyncio.Event()
    authorized = True
    def authority():
        if not authorized:
            raise ResourceConflict('Original host authority was withdrawn')
    async def before_response(result):
        nonlocal authorized
        entered.set()
        if failure in {'timeout', 'cancel'}:
            await release.wait()
        if failure == 'withdraw':
            authorized = False
        if failure == 'native-error':
            raise MCPError(types.INTERNAL_ERROR, 'Native operation has no readable acknowledgement')
        if failure == 'invalid-result':
            return {**result, 'resultType': 'invalid-task-response'}
        return result
    peer.before_response = before_response
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)], call_timeout=0.5)
    task = None
    try:
        await connection.connect()
        bound = bind_tool_caller(connection, lambda: True, 'task-failure-owner')
        task = asyncio.create_task(bound.request_task(native_task_request(verb, peer.task_id), require_authority=authority))
        async with asyncio.timeout(5):
            await entered.wait()
            if failure == 'cancel':
                task.cancel('original Task request cancellation')
            error, delivered = None, False
            try:
                await task
                delivered = True
            except (asyncio.CancelledError, MCPError, MCPCallOutcomeUnknownError,
                    ResourceConflict, ValueError, TimeoutError) as observed:
                error = observed
            assert not delivered, 'Unconfirmed native Task outcome became a delivered result'
            if failure == 'cancel':
                assert isinstance(error, asyncio.CancelledError), 'Original cancellation identity was replaced'
                assert error.args == ('original Task request cancellation',)
            elif verb != 'get':
                assert isinstance(error, MCPCallOutcomeUnknownError), 'Unconfirmed Task mutation lost its unknown outcome'
                assert 'do not replay' in str(error)
            elif failure == 'withdraw':
                assert isinstance(error, ResourceConflict)
            elif failure == 'timeout':
                assert isinstance(error, TimeoutError)
            elif failure == 'native-error':
                assert isinstance(error, MCPError) and error.code == types.INTERNAL_ERROR
            else:
                assert isinstance(error, ValidationError)
    finally:
        release.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await connection.close()
    assert peer.calls == [verb], 'Task transport resent a native operation'
    message, = native_task_messages(mcp_http_server)
    assert message['method'] == 'tasks/' + verb
    assert not mcp_http_server.witness


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
async def test_task_requests_require_current_authority_and_the_exact_native_contract_before_admission(mcp_http_server):
    admissions = []
    async def admit():
        admissions.append('admitted')
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)])
    try:
        await connection.connect()
        bound = bind_tool_caller(connection, lambda: True, 'closed-native-requests', admit=admit)
        with pytest.raises(TypeError, match='current host authority'):
            await bound.request_task(native_task_request('cancel', 'opaque/task:1'), require_authority=None)
        with pytest.raises(TypeError, match='current host authority'):
            await connection.request_task(native_task_request('cancel', 'opaque/task:1'),
                incarnation=connection.incarnation, round_check=None)
        with pytest.raises(TypeError, match='native Tasks'):
            await bound.request_task(types.CallToolRequest(params=types.CallToolRequestParams(name='echo')),
                require_authority=bound.require_current)
        with pytest.raises(ValidationError) as invalid:
            await bound.request_task(GetTaskRequest.model_construct(params=None),
                require_authority=bound.require_current)
        assert invalid.value.errors()[0]['loc'] == ('params',)
        assert not admissions, 'Invalid Task operation reached credential admission'
        assert not native_task_messages(mcp_http_server), 'Invalid Task operation reached the wire'
    finally:
        await connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize('verb', ['get', 'update', 'cancel'])
@pytest.mark.parametrize('phase', ['before', 'after'])
async def test_direct_task_request_rechecks_incarnation_after_its_host_callback(mcp_http_server, verb, phase, monkeypatch):
    # Fault the local connection stamp, never SDK behavior or native wire. A
    # host callback must not make a result current after retiring its owner.
    peer = mcp_http_server.settings['extensions'][0]
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)])
    checks, delivered = 0, False
    def check():
        nonlocal checks
        checks += 1
        if checks == (1 if phase == 'before' else 2):
            monkeypatch.setattr(connection, '_incarnation', None)
    try:
        await connection.connect()
        try:
            await connection.request_task(native_task_request(verb, peer.task_id),
                incarnation=connection.incarnation, round_check=check)
            delivered = True
        except (ValueError, ConnectionError, MCPCallOutcomeUnknownError):
            pass
        assert not delivered, 'Native Task result was delivered after its host callback retired the original connection'
    finally:
        await connection.close()
    assert peer.calls == ([] if phase == 'before' else [verb])


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{}, {'legacy': True}], indirect=True)
async def test_tasks_client_keeps_ordinary_servers_usable(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)])
    try:
        await connection.connect()
        bound = bind_tool_caller(connection, lambda: True, 'ordinary-result-owner')
        result = await bound('echo', {'text': 'ordinary result'}, require_authority=bound.require_current,
            allow_claimed=not bool(mcp_http_server.settings.get('legacy')))
        assert isinstance(result, types.CallToolResult) and result.content[0].text == 'ordinary result'
    finally:
        await connection.close()
    assert mcp_http_server.witness == ['ordinary result'] and not native_task_messages(mcp_http_server)


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize('verb', ['get', 'update', 'cancel'])
@pytest.mark.parametrize('code', [types.INVALID_PARAMS, types.METHOD_NOT_FOUND, types.HEADER_MISMATCH])
async def test_native_task_refusal_is_not_reclassified_or_resent(mcp_http_server, verb, code):
    peer = mcp_http_server.settings['extensions'][0]
    peer.reject_code = code
    connection = MCPConnection(mcp_http_server.url, extensions=[TasksExtension(no_implicit_resolution)])
    try:
        await connection.connect()
        bound = bind_tool_caller(connection, lambda: True, 'refused-task-owner')
        with pytest.raises(MCPError) as rejected:
            await bound.request_task(native_task_request(verb, peer.task_id), require_authority=bound.require_current)
        assert rejected.value.code == code
        assert connection.is_connected == (code != types.HEADER_MISMATCH)
    finally:
        await connection.close()
    assert not peer.calls and not mcp_http_server.witness
    message, = native_task_messages(mcp_http_server)
    assert message['method'] == 'tasks/' + verb


@pytest.mark.asyncio
@pytest.mark.parametrize('mcp_http_server', [{'extensions': [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize('changed_after_adoption', [False, True])
async def test_claim_guard_keeps_the_extension_membership_consumed_by_the_sdk(mcp_http_server, changed_after_adoption):
    extension = IndependentTasksExtension()
    if not changed_after_adoption:
        extension.identifier = 'example.com/other-extension'
    connection = MCPConnection(mcp_http_server.url, extensions=[extension])
    try:
        await connection.connect()
        if changed_after_adoption:
            extension.identifier = 'example.com/other-extension'
        assert connection.supports_task_claims is changed_after_adoption
        bound = bind_tool_caller(connection, lambda: True, 'adopted-capability-owner')
        if changed_after_adoption:
            refusal = None
            try:
                await bound('echo', {'text': 'no native claim handling'})
            except (ResourceUnsupported, MCPCallOutcomeUnknownError) as error:
                refusal = error
            assert isinstance(refusal, ResourceUnsupported), 'Live extension metadata disabled the guard after SDK adoption'
            assert not mcp_http_server.settings['extensions'][0].calls
            created = await bound('echo', {'text': 'accepted once'}, require_authority=bound.require_current,
                allow_claimed=True)
            assert isinstance(created, CreateTaskResult)
            current = await bound.request_task(native_task_request('get', created.task_id),
                require_authority=bound.require_current)
            assert current.status == 'working'
            messages = [json.loads(body) for _, body in mcp_http_server.requests if body
                and json.loads(body).get('method') == 'tools/call']
            message, = messages
            assert 'io.modelcontextprotocol/tasks' in message['params']['_meta'][
                'io.modelcontextprotocol/clientCapabilities']['extensions']
        else:
            with pytest.raises(ResourceUnsupported):
                await bound.request_task(native_task_request('get', 'opaque/task:1'),
                    require_authority=bound.require_current)
            assert not native_task_messages(mcp_http_server)
    finally:
        await connection.close()
    assert not connection.supports_task_claims
