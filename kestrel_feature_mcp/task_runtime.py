"""Native Task claims under Core's original governed handler custody.

This component is private until the provider and Apps acceptance gates pass.
It shares the confirmed tool batch and original-method Input runtime; there
is no alternative tool registry, response route or MCP wire adapter.
"""

from functools import partial
import logging

from mcp import types
from mcp.shared.exceptions import MCPError
from kestrel_sdk.resources import ResourceConflict, ResourceError, ResourceOutcomeUnknown, ResourceUnsupported, observed_outcome_unknown
from kestrel_sdk.security.exceptions import SSRFError
from kestrel_sdk.tools import DeferredToolResult, NativeAction, ToolResult
from pydantic import BaseModel, ConfigDict, Field

from ._lifecycle import MCPFeatureClosingError, run_cleanup_steps
from .connection import (
    MCP_CONNECTION_ERRORS, BoundMCPCaller, MCPConnection, connection_lifecycle, _rejected_before_execution,
)
from .input_requests import MCPInputSuspension, plan_mcp_inputs, validate_form_responses
from .oauth_credentials import TaskOperationAuth
from .oauth_policy import GrantRejected, TaskObservationBlocked
from .tasks_protocol import (
    CancelTaskRequest, CreateTaskResult, GetTaskRequest, TaskIdParams, TasksExtension,
    UpdateTaskParams, UpdateTaskRequest,
)
from .tool_contract import capture_tool_contract


logger = logging.getLogger(__name__)


class TaskSettings(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, allow_inf_nan=False)
    host: dict = Field(default_factory=dict)
    maintenance_seconds: float = Field(default=1.0, gt=0, le=60)
    observe: bool = False


class MCPTaskRuntime:
    def __init__(self, feature, host, input_runtime):
        if input_runtime is None or input_runtime.host is not host.input_host:
            raise TypeError('Native Tasks require the same original-method Input runtime')
        self.feature, self.host, self.input_runtime = feature, host, input_runtime
        self._registrations = {}
        self._observations = {}
        self._observation_lifecycle = {}

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
        lease = caller.authorization_lease
        if lease.connection_id != caller.name:
            raise ResourceConflict('Original Task connection does not match its OAuth lease')
        identity = caller.authorization_identity
        registered.binding.require_current()
        contract = capture_tool_contract(tool.native_tool, connection_name=caller.name,
            url=caller.connection.url, protocol=caller.connection.protocol_version)
        return await self.host.admit(registered.binding, authorization_lease=lease,
            authorization_id=identity, contract=contract.canonical_json)

    async def maintain(self, *, observe):
        for handle in await self.host.maintain(observe=observe):
            try:
                await self.observe(handle, scheduled=True)
            except* (ResourceError, MCPFeatureClosingError, GrantRejected, SSRFError,
                    *MCP_CONNECTION_ERRORS) as error:
                logger.debug('MCP Task observation did not finish (%s)', type(error).__name__)

    @staticmethod
    def defer_result(task_round, projection):
        def publish():
            reference = task_round.publish_result(deferred.publication_context)
            return [] if reference is None else [{'type': 'mcp_task', 'data': reference}]

        deferred = DeferredToolResult(projection, publish=publish)
        return deferred

    def native_actions(self, tool):
        caller = tool.bound_caller
        if not isinstance(caller, BoundMCPCaller) or not caller.connection.supports_task_claims:
            return {}
        handler = partial(self.mutate, tool)
        return {
            'update': NativeAction('update', 'tasks/update',
                b'{"type":"object","properties":{"inputResponses":{"type":"object","minProperties":1}},'
                b'"required":["inputResponses"],"additionalProperties":false}', handler),
            'cancel': NativeAction('cancel', 'tasks/cancel',
                b'{"type":"object","additionalProperties":false}', handler),
        }

    async def invoke_mutation(self, tool, handle, *, session_id, operation_id, kind, arguments):
        registered = self._registered(tool)
        caller = tool.bound_caller
        caller.require_current()
        contract = capture_tool_contract(tool.native_tool, connection_name=caller.name,
            url=caller.connection.url, protocol=caller.connection.protocol_version)
        return await self.host.actions.invoke(registered.binding, handle=handle, session_id=session_id,
            operation_id=operation_id, contract_digest=contract.digest, kind=kind, arguments=arguments)

    def action_tool(self, record):
        for batch in self._registrations.values():
            for registered in batch:
                if registered.binding.name == record.binding.tool_name and registered.binding.is_current:
                    return registered.tool
        raise ResourceConflict('Original MCP Task tool registration is unavailable')

    @staticmethod
    def describe_inputs(record):
        plan = plan_mcp_inputs(record.pending_inputs, allow_blocking=True)
        return {key: request.params.model_dump(mode='json', by_alias=True, exclude_none=True)
            for key, request in plan.operator_requests.items()}

    async def mutate(self, tool, context, arguments):
        self.feature._require_oauth_ready()
        oauth = self.feature._oauth_runtime
        registered = self._registered(tool)
        mutation = self.host.actions.round(registered.binding, context, arguments)
        async with oauth.host.borrow_task_mutation(mutation) as lease:
            async with lease.operation() as check:
                request = self._mutation_request(mutation, context.action, arguments)
                connection, auth, contract, current_grant = await self._prepare_task_connection(
                    context.task_handle, lease, oauth, check, request, pace=False)
                close = partial(self._retire_observation, context.task_handle, connection)
                try:
                    await self._connect_task(connection, contract, check)
                    await current_grant()
                    await mutation.reserve()
                    mutation.start_wire()
                    auth.arm()
                    result = await connection.request_task(auth.request,
                        incarnation=connection.incarnation, round_check=check)
                    try:
                        await current_grant()
                        await mutation.acknowledge(
                            result.model_dump(mode='json', by_alias=True, exclude_unset=True))
                    except ResourceConflict as error:
                        raise ResourceOutcomeUnknown(
                            'MCP Task mutation acknowledgement could not be confirmed; do not replay'
                        ) from error
                except BaseException as error:
                    await run_cleanup_steps([(True, close)], failure=error)
                    raise
                await close()
                check()
                return ToolResult.ok('MCP Task request acknowledged', data={'acknowledged': True}).to_dict()

    @staticmethod
    def _mutation_request(mutation, kind, arguments):
        original = mutation.record
        task_id = original.remote_task_id
        if kind == 'cancel':
            return CancelTaskRequest(params=TaskIdParams(task_id=task_id))
        requested = arguments['inputResponses']
        pending = original.pending_inputs
        if not requested.keys() <= pending.keys():
            raise ResourceConflict('Original MCP Task input requests are unavailable')
        plan = plan_mcp_inputs({key: pending[key] for key in requested}, allow_blocking=True)
        responses = validate_form_responses(plan, requested)
        return UpdateTaskRequest(params=UpdateTaskParams(task_id=task_id, input_responses=responses))

    async def _prepare_task_connection(self, handle, lease, oauth, check, request, *, pace):
        policy = lease.policy
        if handle in self._observations or len(self._observations) >= policy.max_operations:
            raise ResourceConflict('Original MCP Task transports still need retirement')
        self._observations[handle] = None
        try:
            endpoint, contract, token, current_grant = await oauth.task_grant_binding(lease, check, pace=pace)
            auth = TaskOperationAuth(endpoint.url, request, read_access_token=token, check_current=check)
            connection = MCPConnection(endpoint, auth=auth, extensions=[self.extension()],
                connect_timeout=policy.network_seconds, call_timeout=policy.network_seconds,
                close_timeout=oauth.settings.close_seconds)
            self._observations[handle] = connection
            return connection, auth, contract, current_grant
        finally:
            if self._observations[handle] is None:
                del self._observations[handle]

    @staticmethod
    async def _connect_task(connection, contract, check):
        await connection.connect()
        check()
        if connection.protocol_version != contract.connection[2]:
            raise ResourceConflict('Original MCP Task revision was not negotiated')

    async def observe(self, handle, *, scheduled=False):
        """Read and retain one native Task result on a dedicated connection."""
        self.feature._require_oauth_ready()
        oauth = self.feature._oauth_runtime
        async with oauth.host.borrow_task_observation(self.host, handle, scheduled=scheduled) as lease:
            async with lease.operation() as check:
                if scheduled and lease.scheduled_observation_expired():
                    return await lease.block('remote_expired')
                request = GetTaskRequest(params=TaskIdParams(task_id=lease.remote_task_id))
                try:
                    connection, auth, contract, current_grant = await self._prepare_task_connection(
                        handle, lease, oauth, check, request, pace=True)
                except TaskObservationBlocked as blocked:
                    await lease.block(blocked.reason)
                    raise
                close = partial(self._retire_observation, handle, connection)
                try:
                    await self._connect_task(connection, contract, check)
                    auth.arm()
                    try:
                        result = await connection.request_task(auth.request,
                            incarnation=connection.incarnation, round_check=check)
                    except MCPError as error:
                        if error.code == types.INVALID_PARAMS:
                            await lease.block('remote_unavailable')
                        raise
                    await current_grant()
                    withheld = ('contract_drift' if result.status == 'completed'
                        and not contract.completion_conforms(result.result) else None)
                    retained = await lease.record(
                        result.model_dump(mode='json', by_alias=True, exclude_unset=True), withheld=withheld)
                except BaseException as error:
                    steps = [(True, close)]
                    if auth.resource_rejected and isinstance(error, Exception):
                        steps.append((True, partial(lease.block, 'resource_rejected')))
                    if isinstance(error, TaskObservationBlocked):
                        steps.append((True, partial(lease.block, error.reason)))
                    await run_cleanup_steps(steps, failure=error)
                    raise
                await close()
                check()
                return retained

    @property
    def has_observation_owners(self):
        return bool(self._observations)

    async def _retire_observation(self, handle, connection):
        async with connection_lifecycle(self._observation_lifecycle, handle):
            if self._observations.get(handle) is not connection:
                return
            try:
                await connection.close()
            finally:
                if not connection.owns_transport:
                    del self._observations[handle]

    async def close_observations(self):
        await run_cleanup_steps([
            (True, partial(self._retire_observation, handle, connection))
            for handle, connection in tuple(self._observations.items())
            if connection is not None
        ])

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
