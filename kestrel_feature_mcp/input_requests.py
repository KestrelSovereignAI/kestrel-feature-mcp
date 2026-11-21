"""Classify native MRTR and Task inputs without invoking callbacks or granting authority."""

from dataclasses import dataclass, field
import json

from jsonschema.exceptions import SchemaError
from mcp import types
from pydantic import TypeAdapter
from pydantic_core import to_jsonable_python
from referencing.exceptions import Unresolvable

from .schema_validation import matches_schema


@dataclass(frozen=True)
class InputDecision:
    """A required host audit decision, separate from its standard wire reply."""

    request_id: str = field(repr=False)
    reason: str


@dataclass(frozen=True)
class MCPInputPlan:
    """Sealed native input requests; returned SDK objects are independent copies.

    This plan supplies neither execution authority nor an acknowledged audit.
    The host must persist/audit its decisions before sending any responses.
    Roots and sampling remain unsupported and never become human prompts.
    """

    _requests: bytes = field(repr=False)
    _form_ids: tuple[str, ...] = field(repr=False)
    _url_ids: tuple[str, ...] = field(repr=False)
    _unsupported_ids: tuple[str, ...] = field(repr=False)
    allow_blocking: bool

    @property
    def input_requests(self) -> types.InputRequests:
        return TypeAdapter(types.InputRequests).validate_json(self._requests)

    @property
    def operator_requests(self) -> dict[str, types.ElicitRequest]:
        requests = self.input_requests
        return {key: requests[key] for key in self._form_ids} if self.allow_blocking else {}

    @property
    def unsupported_requests(self) -> dict[str, types.InputRequest]:
        requests = self.input_requests
        return {key: requests[key] for key in self._unsupported_ids}

    @property
    def decisions(self) -> tuple[InputDecision, ...]:
        return (
            *(InputDecision(key, 'url_mode_declined') for key in self._url_ids),
            *(InputDecision(key, 'no_approver') for key in self._form_ids if not self.allow_blocking),
        )

    @property
    def declines(self) -> dict[str, types.ElicitResult]:
        return {decision.request_id: types.ElicitResult(action='decline') for decision in self.decisions}


def plan_mcp_inputs(requests: types.InputRequests, *, allow_blocking: bool) -> MCPInputPlan:
    """Keep machine declines distinct from modern form input requiring a host."""
    if type(requests) is not dict:
        raise TypeError('MCP input planning requires a native input request map')
    if not isinstance(allow_blocking, bool):
        raise TypeError('MCP operator interaction requires an explicit boolean policy')
    adapter = TypeAdapter(types.InputRequests)
    try:
        # JSON mode would silently turn non-finite schema values into null.
        plain = adapter.dump_python(adapter.validate_python(requests), mode='python',
            by_alias=True, exclude_none=True, warnings='error')
        plain = to_jsonable_python(plain, inf_nan_mode='constants')
        sealed = json.dumps(plain, allow_nan=False).encode()
        native = adapter.validate_json(sealed)
    except ValueError:
        raise ValueError('Invalid native MCP input request map') from None
    forms, urls, unsupported = [], [], []
    for key, request in native.items():
        if isinstance(request, types.ElicitRequest):
            if isinstance(request.params, types.ElicitRequestFormParams):
                forms.append(key)
            elif isinstance(request.params, types.ElicitRequestURLParams):
                urls.append(key)
            else:
                raise TypeError('Unsupported native MCP elicitation request mode')
        else:
            unsupported.append(key)
    return MCPInputPlan(sealed,
        tuple(forms), tuple(urls), tuple(unsupported), allow_blocking)


@dataclass(frozen=True)
class MCPInputSuspension:
    """A host checkpoint reference, never a final native MCP result."""

    reference: str
    session_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class MCPInputResume:
    """Detached standard SDK content; the caller must supply fresh authority."""

    _checkpoint: str = field(repr=False)
    _responses: bytes = field(repr=False)

    @classmethod
    def seal(cls, checkpoint: types.InputRequiredResult, responses: dict[str, types.InputResponse]):
        if not isinstance(checkpoint, types.InputRequiredResult):
            raise TypeError('MCP resume requires the original native checkpoint')
        adapter = TypeAdapter(types.InputResponses)
        native = adapter.validate_python(responses)
        if set(native) != set(checkpoint.input_requests):
            raise ValueError('MCP resume responses must match every outstanding input key')
        return cls(checkpoint.model_dump_json(by_alias=True, exclude_none=True),
            adapter.dump_json(native, by_alias=True, exclude_none=True))

    @property
    def request_state(self) -> str | None:
        return types.InputRequiredResult.model_validate_json(self._checkpoint).request_state

    @property
    def responses(self) -> types.InputResponses:
        return TypeAdapter(types.InputResponses).validate_json(self._responses)


def validate_form_responses(plan: MCPInputPlan, value: dict) -> dict[str, types.ElicitResult]:
    """Validate only the original form keys and schema, without echoing secrets."""
    requests = plan.operator_requests
    if type(value) is not dict or set(value) != set(requests):
        raise ValueError('MCP form responses must match the outstanding operator inputs')
    results = {}
    for key, raw in value.items():
        if type(raw) is not dict or set(raw) - {'action', 'content'} or raw.get('action') not in {'accept', 'decline', 'cancel'}:
            raise ValueError('Invalid MCP form response')
        if raw['action'] != 'accept' and 'content' in raw:
            raise ValueError('Declined MCP forms must not contain input')
        if raw['action'] == 'accept':
            schema = requests[key].params.requested_schema
            try:
                valid = matches_schema(schema, raw.get('content', {}))
            except (SchemaError, Unresolvable):
                raise ValueError('MCP form schema is invalid or requires an unavailable reference') from None
            if not valid:
                raise ValueError('MCP form response does not satisfy the original schema')
        # Serialization strips references to the submitted mutable object.
        try:
            results[key] = types.ElicitResult.model_validate_json(json.dumps(raw, allow_nan=False))
        except ValueError:
            raise ValueError('Invalid MCP form response') from None
    return results
