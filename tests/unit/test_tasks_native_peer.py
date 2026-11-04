"""Typed client extension against an independently defined native SDK peer."""
import json

import pytest
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp import types
from mcp.client.extension import UnexpectedClaimedResult
from mcp.server.extension import Extension, MethodBinding
from pydantic import TypeAdapter

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
        self.status = "working"
        self.task_id = "opaque/task:1"

    def state(self):
        return {"resultType": "complete", "taskId": self.task_id,
            "status": self.status, "createdAt": "2026-11-04T00:00:00Z",
            "lastUpdatedAt": "2026-11-04T00:00:01Z", "ttlMs": 60000,
            "pollIntervalMs": 100}

    async def intercept_tool_call(self, params, ctx, call_next):
        if params.name != "echo":
            return await call_next(ctx)
        self.calls.append("started")
        return {**self.state(), "resultType": "task"}

    async def get(self, ctx, params):
        assert params.task_id == self.task_id
        self.calls.append("get")
        state = self.state()
        if self.status == "input_required":
            state["inputRequests"] = {"form": {"method": "elicitation/create", "params": {
                "mode": "form", "message": "Choose a label", "requestedSchema": {
                    "type": "object", "properties": {"label": {"type": "string"}},
                    "required": ["label"]}}}}
        if self.status == "completed":
            state["result"] = {"resultType": "complete", "content": [
                {"type": "text", "text": "actual deferred result"}]}
        return state

    async def update(self, ctx, params):
        assert params.task_id == self.task_id
        assert params.input_responses["form"].action == "accept"
        assert params.input_responses["form"].content == {"label": "native input"}
        self.calls.append("update")
        self.status = "completed"
        return {"resultType": "complete"}

    async def cancel(self, ctx, params):
        assert params.task_id == self.task_id
        self.calls.append("cancel")
        return {"resultType": "complete"}

    def methods(self):
        return [MethodBinding(method=method, params_type=shape, handler=handler,
            protocol_versions=frozenset({"2026-07-28"})) for method, shape, handler in [
                ("tasks/get", PeerTaskParams, self.get),
                ("tasks/update", PeerInputParams, self.update),
                ("tasks/cancel", PeerTaskParams, self.cancel)]]


async def no_implicit_resolution(result, context):
    raise AssertionError("one-round native calls must not replay or poll implicitly")


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"extensions": [NativeTasksPeer()]}], indirect=True)
@pytest.mark.parametrize("scenario", ["input-and-completion", "cooperative-cancel", "unclaimed"])
@pytest.mark.parametrize("task_id,expected_header", [
    ("opaque/task:1", b"opaque/task:1"),
    ("opaque/Δ:1", b"=?base64?b3BhcXVlL86UOjE=?="),
    ("opaque\r\nInjected:1", b"=?base64?b3BhcXVlDQpJbmplY3RlZDox?="),
])
async def test_sdk_claim_and_current_task_verbs_cross_real_http_without_tool_replay(
    mcp_http_server, scenario, task_id, expected_header,
):
    peer = mcp_http_server.settings["extensions"][0]
    peer.task_id = task_id
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
        assert peer.calls == ["started"]
        state = await session.send_request(GetTaskRequest(
            params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
        assert state.status == "working"
        if scenario == "input-and-completion":
            peer.status = "input_required"
            state = await session.send_request(GetTaskRequest(
                params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
            assert state.input_requests["form"].method == "elicitation/create"
            ack = await session.send_request(UpdateTaskRequest(params=UpdateTaskParams(
                task_id=created.task_id, input_responses={"form": types.ElicitResult(
                    action="accept", content={"label": "native input"})})), TaskAcknowledgement)
            assert ack.result_type == "complete"
            state = await session.send_request(GetTaskRequest(
                params=TaskIdParams(task_id=created.task_id)), TypeAdapter(DetailedTaskResult))
            assert state.status == "completed"
            result = types.CallToolResult.model_validate(state.result)
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
        for scope, message in messages:
            capabilities = message["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
            assert "io.modelcontextprotocol/tasks" in capabilities["extensions"]
            assert "form" in capabilities["elicitation"]
            if message["method"].startswith("tasks/"):
                header = dict(scope["headers"])[b"mcp-name"]
                assert b"\r" not in header and b"\n" not in header
                assert header == expected_header
        assert input_callbacks == []  # the host owns explicit input admission
