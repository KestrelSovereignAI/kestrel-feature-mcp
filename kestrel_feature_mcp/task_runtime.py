"""Native Task claims under Core's original governed handler custody.

This component is private until the provider and Apps acceptance gates pass.
It shares the confirmed tool batch and original-method Input runtime; there
is no alternative tool registry, response route or MCP wire adapter.
"""

from mcp import types
from kestrel_sdk.resources import ResourceConflict, ResourceOutcomeUnknown, ResourceUnsupported, observed_outcome_unknown
from pydantic import BaseModel, ConfigDict, Field

from .connection import BoundMCPCaller, _rejected_before_execution
from .input_requests import MCPInputSuspension
from .tasks_protocol import CreateTaskResult, TasksExtension
from .tool_contract import capture_tool_contract


class TaskSettings(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, allow_inf_nan=False)
    host: dict = Field(default_factory=dict)
    maintenance_seconds: float = Field(default=1.0, gt=0, le=60)


class MCPTaskRuntime:
    def __init__(self, feature, host, input_runtime):
        if input_runtime is None or input_runtime.host is not host.input_host:
            raise TypeError('Native Tasks require the same original-method Input runtime')
        self.feature, self.host, self.input_runtime = feature, host, input_runtime
        self._registrations = {}

    def register(self, owner, registered):
        self._registrations[owner] = tuple(registered)

    def unregister(self, owner):
        self._registrations.pop(owner, None)

    async def _unowned_resolver(self, claim, context):
        raise ResourceUnsupported('MCP Task claims require the original governed tool dispatch')

    def extension(self):
        return TasksExtension(self._unowned_resolver)

    def _registered(self, tool):
        for batch in self._registrations.values():
            for registered in batch:
                if registered.tool is tool and registered.binding.is_current:
                    return registered
        raise ResourceConflict('Original Task tool registration is unavailable')

    async def begin(self, tool):
        caller = tool.bound_caller
        if not isinstance(caller, BoundMCPCaller) or not caller.connection.supports_task_claims:
            return None
        registered = self._registered(tool)
        await caller.admit()
        identity = caller.authorization_identity
        registered.binding.require_current()
        contract = capture_tool_contract(tool.native_tool, connection_name=caller.name,
            url=caller.connection.url, protocol=caller.connection.protocol_version)
        return await self.host.admit(registered.binding, connection_name=caller.name,
            authorization_id=identity, contract=contract.canonical_json)

    def authority(self, round, caller, original_check):
        identity = round.authorization_identity
        def check():
            caller.require_current()
            if caller.authorization_identity != identity:
                raise ResourceConflict('Original Task OAuth authorization generation changed')
            if original_check is not None:
                original_check()
            round.require_wire()
        return check

    async def received(self, round, result):
        if isinstance(result, MCPInputSuspension):
            round.finish_suspension(result.reference)
            return None
        if isinstance(result, CreateTaskResult):
            return await round.attach(result.model_dump(mode='json', by_alias=True, exclude_unset=True))
        if isinstance(result, types.CallToolResult):
            await round.settle_result(result.model_dump(mode='json', by_alias=True, exclude_unset=True))
            return None
        round.unknown()
        raise ResourceOutcomeUnknown('Native MCP call returned no supported original Task outcome')

    async def _refuse(self, round, error, **evidence):
        try:
            await round.refuse(**evidence)
        except ResourceOutcomeUnknown as retirement:
            raise ResourceOutcomeUnknown('Original Task refusal retains native uncertainty') from BaseExceptionGroup(
                'Original MCP request and uncertain custody retirement', [error, retirement])

    async def rejected(self, round, error):
        if observed_outcome_unknown(error):
            raise ResourceOutcomeUnknown('Original Task dispatch retains native control or uncertainty') from error
        if not round.dispatch_started:
            await self._refuse(round, error)
            return
        if _rejected_before_execution(error):
            def native_errors(original):
                if isinstance(original, BaseExceptionGroup):
                    return [value for child in original.exceptions for value in native_errors(child)]
                return [original.error.model_dump(mode='json', by_alias=True, exclude_unset=True)]
            await self._refuse(round, error, native_errors=native_errors(error))
            return
        round.unknown()
        raise ResourceOutcomeUnknown('Original Task dispatch returned no confirmed outcome') from error
