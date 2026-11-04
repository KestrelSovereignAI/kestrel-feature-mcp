"""Current native Task contracts checked against the immutable official schema."""
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from mcp import types
from mcp.client.extension import ResultClaim
from pydantic import TypeAdapter, ValidationError

from kestrel_feature_mcp.tasks_protocol import (
    EXTENSION_ID, PROTOCOL_VERSIONS, CancelTaskRequest, CreateTaskResult,
    DetailedTaskResult, GetTaskRequest, TaskAcknowledgement, TaskIdParams,
    TasksExtension, UpdateTaskParams, UpdateTaskRequest,
)


@pytest.fixture
def official_schema():
    root = Path(__file__).parents[1] / "spec/tasks-2026-07-28"
    provenance = json.loads((root / "provenance.json").read_text())
    for name, original in [("schema.json", "schema/2026-07-28/schema.json"), ("LICENSE", "LICENSE")]:
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == provenance["files"][original]["sha256"]
    schema = json.loads((root / "schema.json").read_text())
    assert schema["$id"] == "https://modelcontextprotocol.io/ext-tasks/2026-07-28/schema.json"
    def validate(definition, value):
        Draft202012Validator({**schema, "$ref": "#/$defs/" + definition}).validate(value)
    return validate


def task(status="working", result_type="complete"):
    return {"resultType": result_type, "taskId": "opaque/task:1", "status": status,
        "createdAt": "2026-11-04T01:00:00Z", "lastUpdatedAt": "2026-11-04T01:01:00Z",
        "ttlMs": 60000, "pollIntervalMs": 100, "_meta": {"private": "kept-native"}}


@pytest.mark.parametrize("status", ["working", "input_required", "completed", "failed", "cancelled"])
def test_native_claim_is_flat_and_matches_official_schema(official_schema, status):
    wire = task(status, "task")
    parsed = CreateTaskResult.model_validate(wire)
    assert parsed.task_id == "opaque/task:1"
    assert parsed.model_dump(mode="json", by_alias=True, exclude_none=True) == wire
    official_schema("CreateTaskResult", wire)
    assert issubclass(CreateTaskResult, types.Result)


@pytest.mark.parametrize("status,payload", [
    ("working", {}), ("input_required", {"inputRequests": {}}),
    ("completed", {"result": {"resultType": "complete", "content": []}}),
    ("failed", {"error": {"code": -32603, "message": "execution failed"}}),
    ("cancelled", {}),
])
def test_native_get_is_status_specific_and_preserves_final_payload(official_schema, status, payload):
    wire = {**task(status), **payload}
    parsed = TypeAdapter(DetailedTaskResult).validate_python(wire)
    assert parsed.model_dump(mode="json", by_alias=True, exclude_none=True) == wire
    official_schema("GetTaskResult", wire)


@pytest.mark.parametrize("status", ["completed", "input_required", "failed"])
def test_get_requires_the_payload_for_its_status(status):
    with pytest.raises(ValidationError):
        TypeAdapter(DetailedTaskResult).validate_python(task(status))


@pytest.mark.parametrize("bad", [
    {"task": {"taskId": "legacy", "status": "working", "ttl": 60000}},
    {**task(result_type="task"), "ttlMs": "60000"},
    {k: v for k, v in task(result_type="task").items() if k != "resultType"},
    {k: v for k, v in task(result_type="task").items() if k != "ttlMs"},
    {**task(result_type="task"), "resultType": "complete"},
])
def test_no_old_wire_or_coerced_claim(bad):
    with pytest.raises(ValidationError):
        CreateTaskResult.model_validate(bad)


@pytest.mark.parametrize("native_request,definition,method", [
    (GetTaskRequest(params=TaskIdParams(task_id="opaque/task:1")), "GetTaskRequest", "tasks/get"),
    (UpdateTaskRequest(params=UpdateTaskParams(task_id="opaque/task:1", input_responses={})), "UpdateTaskRequest", "tasks/update"),
    (CancelTaskRequest(params=TaskIdParams(task_id="opaque/task:1")), "CancelTaskRequest", "tasks/cancel"),
])
def test_native_requests_and_name_header_contract(official_schema, native_request, definition, method):
    wire = native_request.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert wire["method"] == method
    assert wire["params"]["taskId"] == "opaque/task:1"
    assert native_request.name_param == "taskId"
    official_schema(definition, {"jsonrpc": "2.0", "id": 1, **wire})


@pytest.mark.parametrize("definition", ["UpdateTaskResult", "CancelTaskResult"])
def test_mutation_acknowledgement_is_complete_not_a_task_state(official_schema, definition):
    wire = {"resultType": "complete"}
    assert TaskAcknowledgement.model_validate(wire).model_dump(by_alias=True, exclude_none=True) == wire
    official_schema(definition, wire)


def test_claim_uses_the_native_sdk_extension_registry_without_legacy_protocols():
    async def resolve(result, context):
        raise AssertionError("construction must not resolve or replay")
    extension = TasksExtension(resolve)
    [claim] = extension.claims()
    assert isinstance(claim, ResultClaim)
    assert extension.identifier == EXTENSION_ID == "io.modelcontextprotocol/tasks"
    assert extension.settings() == {}
    assert claim.model is CreateTaskResult and claim.resolve is resolve
    assert claim.protocol_versions == PROTOCOL_VERSIONS == frozenset({"2026-07-28"})
    assert claim.result_type == "task" and claim.method == "tools/call"
    with pytest.raises(TypeError, match="host-owned"):
        TasksExtension(None)
