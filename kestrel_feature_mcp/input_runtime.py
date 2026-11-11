"""Native form continuations through Core's durable, authenticated input host."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from functools import partial
import hashlib
import json
from uuid import uuid4
from weakref import WeakKeyDictionary, WeakValueDictionary

from mcp import types
from mcp.client.session import ClientRequestContext
from mcp.shared.exceptions import MCPError
from kestrel_sdk.resources import ResourceConflict, ResourceError, ResourceOutcomeUnknown
from kestrel_sdk.tools import DeferredToolResult
from kestrel_sdk.tools.result import ToolResult
from pydantic import BaseModel, ConfigDict, Field

from .apps_execution import MCPAppInputRequired
from .connection import BoundMCPCaller
from .input_requests import MCPInputResume, MCPInputSuspension, plan_mcp_inputs, validate_form_responses


class InputSettings(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    enabled: bool = False
    host: dict = Field(default_factory=dict)


@dataclass
class _Resume:
    registered: object
    record: object
    responses: dict
    active: bool = True
    claim: object = None
    received: bool = False
    suspension: MCPInputSuspension | None = None


class MCPInputRuntime:
    def __init__(self, feature, host):
        self.feature, self.host = feature, host
        self._registrations = {}
        self._resuming = ContextVar('native_mcp_original_resume', default=None)
        self._view_tokens = WeakKeyDictionary()
        self._views = WeakValueDictionary()

    def register(self, owner, registered):
        self._registrations[owner] = tuple(registered)

    def unregister(self, owner):
        self._registrations.pop(owner, None)

    def _registered(self, tool):
        for batch in self._registrations.values():
            for registered in batch:
                if registered.tool is tool and registered.binding.is_current:
                    return registered
        raise ResourceConflict('Original MCP input tool registration is unavailable')

    def _contract(self, registered):
        tool = registered.tool
        caller = tool.bound_caller
        if not isinstance(caller, BoundMCPCaller):
            raise TypeError('MCP input requires a native bound connection')
        caller.require_current()
        value = {'connection': caller.name, 'url': caller.connection.url,
            'protocol': caller.connection.protocol_version,
            'tool': tool.native_tool.model_dump(mode='json', by_alias=True, exclude_none=True)}
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
            allow_nan=False).encode()).hexdigest()

    def _lookup(self, record):
        for batch in self._registrations.values():
            for registered in batch:
                if (registered.binding.name == record.payload['handle']
                        and registered.binding.is_current and registered.tool.bound_caller.is_current
                        and registered.tool.bound_caller.name == record.binding.connection_id
                        and self._contract(registered) == record.binding.contract_digest):
                    return registered
        raise ResourceConflict('Original MCP input connection or tool contract is unavailable')

    async def inline_decline(self, context, params, *, connection_id):
        await self.host.audit_inline_decline(connection_id, str(context.request_id))
        return types.ElicitResult(action='decline')

    async def before_call(self, tool, arguments, invocation):
        registered = self._registered(tool)
        options = {'input_handler': partial(self._handle, registered, arguments, invocation)}
        active = self._resuming.get()
        if active is None:
            return options
        if (not active.active or active.registered is not registered or active.claim is not None
                or arguments != active.record.payload['arguments']):
            raise ResourceConflict('Original MCP input continuation changed')
        # Core calls this only inside a newly admitted, normally approved tool.
        # The durable CAS precedes the first continuation request on the wire.
        active.claim = await self.host.claim_response(active.record, active.responses)
        native = types.InputRequiredResult.model_validate(active.record.payload['native'])
        options['resume'] = MCPInputResume.seal(native, {
            key: types.ElicitResult.model_validate(value) for key, value in active.responses.items()})
        return options

    def received(self, tool, result):
        active = self._resuming.get()
        if active is not None:
            if not active.active or active.registered.tool is not tool or active.claim is None:
                raise ResourceConflict('Original MCP input response owner changed')
            active.received = True
            active.suspension = result if isinstance(result, MCPInputSuspension) else None

    async def _handle(self, registered, arguments, invocation, native):
        origin = self.host.origin()
        plan = plan_mcp_inputs(native, allow_blocking=origin.allow_blocking)
        decisions = [(decision.request_id, decision.reason) for decision in plan.decisions]
        decisions.extend((key, 'unsupported_input') for key in plan.unsupported_requests)
        if decisions:
            digest = hashlib.sha256(native.model_dump_json(by_alias=True, exclude_none=True).encode()).hexdigest()
            await self.host.audit(origin, digest, decisions)
        for key, request in plan.unsupported_requests.items():
            session = registered.tool.bound_caller.connection._require_client().session
            result = await session.dispatch_input_request(
                ClientRequestContext(session=session, request_id=key), request)
            if isinstance(result, types.ErrorData):
                raise MCPError.from_error_data(result)
            raise ResourceConflict('Unsupported MCP input was unexpectedly fulfilled')
        if not plan.operator_requests:
            return plan.declines
        payload = {'handle': registered.binding.name, 'arguments': arguments,
            'native': native.model_dump(mode='json', by_alias=True, exclude_none=True),
            'server_url': registered.tool.bound_caller.connection.url}
        if invocation is not None:
            view = invocation.view
            token = self._view_tokens.get(view)
            if token is None:
                token = uuid4().hex
                self._view_tokens[view] = token
                self._views[token] = view
            payload['app_view'] = token
        reference = await self.host.suspend(origin,
            connection_id=registered.tool.bound_caller.name, contract_digest=self._contract(registered),
            method='tools/call', payload=payload)
        return MCPInputSuspension(reference, origin.session_id)

    def defer_suspension(self, tool, suspension, projection):
        def publish():
            context = deferred.publication_context
            if (context is None or context.agent_id != self.feature.agent.did
                    or context.session_id != suspension.session_id):
                return []
            self.host.require_current()
            tool.bound_caller.require_current()
            return [{'type': 'mcp_input', 'data': {'reference': suspension.reference,
                'session_id': context.session_id}}]
        deferred = DeferredToolResult(projection, publish=publish)
        return deferred

    def describe(self, record):
        native = types.InputRequiredResult.model_validate(record.payload['native'])
        plan = plan_mcp_inputs(native, allow_blocking=True)
        available = True
        try:
            self._lookup(record)
        except ResourceConflict:
            available = False
        view_token = record.payload.get('app_view')
        if view_token is not None:
            view = self._views.get(view_token)
            available = available and view is not None and not view.is_closed
        return {'tool': record.payload['handle'], 'connection': record.binding.connection_id,
            'server_url': record.payload['server_url'],
            'continuation': record.continuation,
            'resumable': available, 'forms': {key: request.params.model_dump(mode='json',
                by_alias=True, exclude_none=True) for key, request in plan.operator_requests.items()}}

    async def respond(self, record, responses, *, operation_id):
        registered = self._lookup(record)
        native = types.InputRequiredResult.model_validate(record.payload['native'])
        plan = plan_mcp_inputs(native, allow_blocking=True)
        answers = {**validate_form_responses(plan, responses), **plan.declines}
        encoded = {key: result.model_dump(mode='json', by_alias=True, exclude_none=True)
            for key, result in answers.items()}
        context = _Resume(registered, record, encoded)
        if self._resuming.get() is not None:
            raise ResourceConflict('Nested MCP input continuation is unavailable')
        token = self._resuming.set(context)
        app_result = None
        try:
            view_token = record.payload.get('app_view')
            if view_token is None:
                projected = await registered.binding.invoke(record.payload['arguments'],
                    session_id=record.binding.session_id, operation_id=operation_id, source='mcp-input')
            else:
                view = self._views.get(view_token)
                if view is None or view.is_closed:
                    raise ResourceConflict('Original MCP App View expired; the continuation is not resumable')
                async with self.host.borrow_app_view(view):
                    try:
                        native_result = await view.executor.invoke(view, registered.tool.native_tool.name,
                            record.payload['arguments'], operation_id=operation_id, input_reference=record.request_id)
                    except MCPAppInputRequired:
                        projected = ToolResult.partial('MCP tool requires another operator input',
                            'No final result has been received; do not repeat the original call').to_dict()
                    else:
                        app_result = native_result.model_dump(mode='json', by_alias=True, exclude_none=True)
                        from .dynamic_tools import extract_mcp_result
                        text, is_error = extract_mcp_result(native_result)
                        projected = (ToolResult.failed(text or 'MCP tool reported an error') if is_error
                            else ToolResult.ok(text or 'MCP tool completed')).to_dict()
            if context.claim is None:
                current = await self.host.current_record(record)
                return {'request_id': record.request_id, 'state': current.state, 'tool_result': projected}
            if not context.received:
                raise ResourceConflict('MCP continuation returned no native result; do not replay')
            continuation = {
                'next_request_id': None if context.suspension is None else context.suspension.reference,
                'tool_result': projected}
            settled = await self.host.settle_response(context.claim, state='RESOLVED', continuation=continuation)
            result = {'request_id': record.request_id, 'state': settled.state, **continuation}
            if app_result is not None:
                result['app_result'] = app_result
            return result
        except (ResourceError, ValueError, TimeoutError) as error:
            if context.claim is not None:
                # Validation ended before the durable claim. Later failures
                # can follow a completed native effect; never invite resubmit.
                raise ResourceOutcomeUnknown('MCP continuation result is unconfirmed; do not replay') from error
            raise
        finally:
            context.active = False
            self._resuming.reset(token)
