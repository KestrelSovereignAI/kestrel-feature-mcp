"""Native io.modelcontextprotocol/tasks (2026-07-28) extension contracts.

These types use the SDK's public Result/Request extension surface. The SDK's
similarly named 2025 Task types are a different wire and are not used here.
Task admission, polling and operator authority belong to the owning host.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from mcp import types
from mcp.client.extension import ClaimContext, ClientExtension, ResultClaim
from pydantic import ConfigDict, Field

EXTENSION_ID = "io.modelcontextprotocol/tasks"
PROTOCOL_VERSIONS = frozenset({"2026-07-28"})
TaskStatus = Literal["working", "input_required", "completed", "cancelled", "failed"]


class TaskFields(types.Result):
    """Shared flat task fields; no wrapped ``task`` or legacy TTL aliases."""
    model_config = ConfigDict(strict=True)
    task_id: str
    status: TaskStatus
    status_message: str | None = None
    created_at: str
    last_updated_at: str
    ttl_ms: int | None
    poll_interval_ms: int | None = None


class CreateTaskResult(TaskFields):
    result_type: Literal["task"]


class _GetTaskResult(TaskFields):
    result_type: Literal["complete"]


class WorkingTaskResult(_GetTaskResult):
    status: Literal["working"]


class InputRequiredTaskResult(_GetTaskResult):
    status: Literal["input_required"]
    input_requests: types.InputRequests


class CompletedTaskResult(_GetTaskResult):
    status: Literal["completed"]
    result: dict


class FailedTaskResult(_GetTaskResult):
    status: Literal["failed"]
    error: types.ErrorData


class CancelledTaskResult(_GetTaskResult):
    status: Literal["cancelled"]


DetailedTaskResult = Annotated[
    WorkingTaskResult | InputRequiredTaskResult | CompletedTaskResult
    | FailedTaskResult | CancelledTaskResult,
    Field(discriminator="status"),
]


class TaskIdParams(types.RequestParams):
    model_config = ConfigDict(strict=True)
    task_id: str


class GetTaskRequest(types.Request[TaskIdParams, Literal["tasks/get"]]):
    method: Literal["tasks/get"] = "tasks/get"
    # The SDK mirrors the extension task ID into the native Mcp-Name header.
    name_param = "taskId"


class UpdateTaskParams(TaskIdParams):
    input_responses: types.InputResponses


class UpdateTaskRequest(types.Request[UpdateTaskParams, Literal["tasks/update"]]):
    method: Literal["tasks/update"] = "tasks/update"
    name_param = "taskId"


class CancelTaskRequest(types.Request[TaskIdParams, Literal["tasks/cancel"]]):
    method: Literal["tasks/cancel"] = "tasks/cancel"
    name_param = "taskId"


class TaskAcknowledgement(types.Result):
    result_type: Literal["complete"]


class TasksExtension(ClientExtension):
    """Opt in only when the caller owns a complete continuation resolver.

    One-round ClientSession callers may request the typed claim directly;
    high-level Client callers delegate its completion to this same owner.
    Constructing this extension does not enable it on an MCP connection.
    """
    identifier = EXTENSION_ID

    def __init__(self, resolve: Callable[[CreateTaskResult, ClaimContext], Awaitable[types.CallToolResult]]):
        if not callable(resolve):
            raise TypeError("MCP Tasks require a host-owned continuation resolver")
        self._resolve = resolve

    def claims(self):
        return (ResultClaim(result_type="task", model=CreateTaskResult,
            resolve=self._resolve, protocol_versions=PROTOCOL_VERSIONS),)
