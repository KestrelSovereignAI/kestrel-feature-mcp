"""Lifecycle owner for the official MCP client's Streamable HTTP connections."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from copy import deepcopy
import math
import logging
import hashlib
import json
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from functools import partial

import httpx2
from anyio import BrokenResourceError, ClosedResourceError, EndOfStream
from pydantic import TypeAdapter, ValidationError
from mcp.shared.exceptions import MCPError
from mcp.client import InputRequiredRoundsExceededError
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client
from kestrel_sdk.security.outbound import ValidatedOutboundURL, pinned_httpx2_async_transport
from kestrel_sdk.resources import ResourceError, ResourceOutcomeUnknown, ResourceUnsupported, observed_outcome_unknown

from .constants import CALL_TOOL_TIMEOUT, SESSION_CONNECT_TIMEOUT_DEFAULT, SESSION_CLOSE_TIMEOUT_DEFAULT, RESPONSE_MAX_BYTES_DEFAULT
from .constants import STATE_ONLY_MAX_ROUNDS_DEFAULT, STATE_ONLY_BACKOFF_INITIAL_DEFAULT, STATE_ONLY_BACKOFF_MAX_DEFAULT
from .http_limits import MCPResponseBudget, MCPResponseLimitError, identity_accept_encoding
from .tool_contract import MCPToolContractError, validate_tool_contract
from ._lifecycle import call_synchronous_callback, run_cleanup_steps
from .input_requests import MCPInputResume, MCPInputSuspension
from .tasks_protocol import (
    EXTENSION_ID as TASKS_EXTENSION_ID, PROTOCOL_VERSIONS as TASKS_PROTOCOL_VERSIONS,
    CancelTaskRequest, DetailedTaskResult, GetTaskRequest, TaskAcknowledgement,
    UpdateTaskRequest,
)


logger = logging.getLogger(__name__)

MCP_CONNECTION_ERRORS = (
    MCPError, InputRequiredRoundsExceededError, MCPResponseLimitError, httpx2.HTTPError, TimeoutError, OSError, ValidationError,
    BrokenResourceError, ClosedResourceError, EndOfStream,
)

MCP_REQUEST_ERRORS = (*MCP_CONNECTION_ERRORS, RuntimeError, ValueError, ResourceError)


@dataclass
class _RequestProgress:
    sent: bool = False
    intermediate: bool = False


class MCPCallOutcomeUnknownError(ResourceOutcomeUnknown):
    """A call returned no valid result; its external effects are unconfirmed."""


class MCPPeerNegotiationError(RuntimeError, ResourceError):
    """The native SDK rejected the peer's protocol revision."""


class MCPToolCatalogError(MCPToolContractError, ResourceError):
    """A connected peer returned an unusable tool catalog."""


def _task_request_snapshot(request: GetTaskRequest | UpdateTaskRequest | CancelTaskRequest):
    """Validate and detach a closed native request before credential admission."""
    if type(request) not in (GetTaskRequest, UpdateTaskRequest, CancelTaskRequest):
        raise TypeError('A native Tasks get, update or cancel request is required')
    return type(request).model_validate(request.model_dump(mode='python', by_alias=True,
        exclude_none=True), by_alias=True, by_name=False)


def _rejected_before_execution(error: BaseException) -> bool:
    if observed_outcome_unknown(error):
        return False
    if isinstance(error, BaseExceptionGroup):
        return all(_rejected_before_execution(child) for child in error.exceptions)
    # The SDK also emits PARSE_ERROR and INVALID_REQUEST locally when a
    # response is unreadable or invalid. Those codes cannot establish that
    # the remote tool did not already execute.
    return isinstance(error, MCPError) and error.code in {
        types.METHOD_NOT_FOUND, types.INVALID_PARAMS, types.HEADER_MISMATCH,
    }


def require_owner_did(owner_did: str) -> str:
    if (not isinstance(owner_did, str) or not owner_did.startswith("did:")
            or not owner_did[4:] or any(char.isspace() for char in owner_did)):
        raise ValueError("An agent DID is required for MCP connection ownership")
    return owner_did


def connection_digest(resource: str, owner_did: str) -> str:
    identity = json.dumps([require_owner_did(owner_did), resource], separators=(",", ":"))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


@dataclass
class ConnectionLifecycleGate:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


@asynccontextmanager
async def connection_lifecycle(gates: dict, name: str):
    """Keep one gate for holders and waiters; unrelated resources progress."""
    gate = gates.get(name)
    if gate is None:
        gate = ConnectionLifecycleGate()
        gates[name] = gate
    gate.users += 1
    try:
        async with gate.lock:
            yield
    finally:
        gate.users -= 1
        if gate.users == 0:
            del gates[name]


@dataclass(frozen=True)
class BoundMCPCaller:
    """One advertised connection lifetime, never a grant to execute tools."""

    connection: MCPConnection
    name: str
    incarnation: object
    _owner_is_current: Callable[[], bool] = field(repr=False)
    tool_names: frozenset[str] | None = None
    _admit: Callable[[], Awaitable[None]] | None = field(default=None, repr=False)
    _continuation_check: Callable[[], None] | None = field(default=None, repr=False)
    _authorization_identity: Callable[[], str] | None = field(default=None, repr=False)
    _authorization_lease: object | None = field(default=None, repr=False)

    @property
    def is_current(self) -> bool:
        return self._owner_is_current() and self.connection.incarnation is self.incarnation

    def require_current(self) -> None:
        if not self.is_current:
            raise ValueError(f"MCP connection {self.name} changed; rediscover its tools before calling")

    async def _admitted(self):
        self.require_current()
        if self._admit is not None:
            await self._admit()
            self.require_current()

    async def admit(self):
        """Admit the actual credential before reading its durable generation."""
        await self._admitted()

    @property
    def authorization_identity(self):
        self.require_current()
        if self._authorization_identity is None:
            raise ResourceUnsupported('MCP Tasks require an admitted OAuth authorization generation')
        identity = self._authorization_identity()
        self.require_current()
        return identity

    @property
    def authorization_lease(self):
        self.require_current()
        if self._authorization_lease is None:
            raise ResourceUnsupported('MCP Tasks require their original OAuth connection lease')
        return self._authorization_lease

    def _require_round(self, require_authority):
        self.require_current()
        if self._continuation_check is not None:
            self._continuation_check()
        if require_authority is not None:
            require_authority()
        self.require_current()

    async def __call__(self, tool_name: str, arguments: dict | None = None, *, require_authority=None,
                       input_handler=None, resume: MCPInputResume | None = None, allow_claimed: bool = False,
                       before_send=None):
        if allow_claimed is True and not callable(require_authority):
            raise ResourceUnsupported('MCP Task claims require current host authority')
        await self._admitted()
        if self.tool_names is not None and tool_name not in self.tool_names:
            raise ValueError(f"Unknown tool: {tool_name}. Available: {sorted(self.tool_names)}")
        return await self.connection.call_tool(tool_name, arguments or {},
            round_check=partial(self._require_round, require_authority), input_handler=input_handler,
            resume=resume, allow_claimed=allow_claimed,
            **({} if before_send is None else {'before_send': before_send}))

    async def request_task(self, request: GetTaskRequest | UpdateTaskRequest | CancelTaskRequest, *, require_authority):
        """One native Task verb on the original connection, under fresh authority.

        The host owns durable pre-wire mutation custody and permission. This
        transport binding and a task ID are not substitutes for either one.
        """
        if not callable(require_authority):
            raise TypeError('MCP Task operations require current host authority')
        request = _task_request_snapshot(request)
        self._require_round(require_authority)
        await self._admitted()
        return await self.connection.request_task(request, incarnation=self.incarnation,
            round_check=partial(self._require_round, require_authority))

    async def read_resource(self, uri: str, *, require_authority=None,
                            input_handler=None, resume: MCPInputResume | None = None):
        await self._admitted()
        result = await self.connection.read_resource(uri, incarnation=self.incarnation,
            round_check=partial(self._require_round, require_authority), input_handler=input_handler, resume=resume)
        self.require_current()
        return result


def bind_tool_caller(connection, is_current: Callable[[], bool], name: str, *, tool_names=None,
                     admit=None, continuation_check=None, authorization_identity=None,
                     authorization_lease=None):
    """Bind the advertised connection, never a later replacement's transport."""
    incarnation = connection.incarnation
    if incarnation is None:
        raise ConnectionError("MCP connection is not connected")
    return BoundMCPCaller(
        connection=connection, name=name, incarnation=incarnation,
        _owner_is_current=is_current,
        tool_names=frozenset(tool_names) if tool_names is not None else None,
        _admit=admit,
        _continuation_check=continuation_check,
        _authorization_identity=authorization_identity,
        _authorization_lease=authorization_lease,
    )


def describe_tools(client, tools, **labels) -> list[dict]:
    """Retain the SDK's standard Tool record alongside host connection labels."""
    return [{**tool.model_dump(mode="json", by_alias=True, exclude_none=True),
             **labels, "protocol_version": client.protocol_version}
            for tool in tools]


class _ConnectionResources(AsyncExitStack):
    """Exit SDK resources on their owner task with a whole-shutdown deadline."""

    def __init__(self, timeout: float):
        super().__init__()
        self._timeout = timeout

    async def __aexit__(self, exc_type, exc_value, traceback):
        async with asyncio.timeout(self._timeout):
            return await super().__aexit__(exc_type, exc_value, traceback)


class _ShutdownDeadline:
    """A graceful deadline that outlives a cancelled shutdown caller."""

    def __init__(self, task: asyncio.Task, timeout: float):
        self.expired = False
        self._task = task
        self._timer = asyncio.get_running_loop().call_later(timeout, self._expire)

    def _expire(self):
        if not self._task.done():
            self.expired = True
            logger.warning("MCP graceful shutdown deadline expired; cancelling SDK cleanup")
            self._task.cancel()

    def cancel(self):
        self._timer.cancel()


class MCPConnection:
    """Keep the SDK's transport and client contexts in one owned task.

    AnyIO transport contexts must enter and exit on the same task. Callers may
    use the client from their turn, but connection teardown stays with its
    owner. Failed startup, timeout and caller cancellation all join that owner.
    """

    def __init__(
        self,
        url: str | ValidatedOutboundURL,
        *,
        headers: Mapping[str, str] | None = None,
        auth: httpx2.Auth | None = None,
        connect_timeout: float = SESSION_CONNECT_TIMEOUT_DEFAULT,
        call_timeout: float = CALL_TOOL_TIMEOUT,
        close_timeout: float = SESSION_CLOSE_TIMEOUT_DEFAULT,
        response_max_bytes: int = RESPONSE_MAX_BYTES_DEFAULT,
        max_state_only_rounds: int = STATE_ONLY_MAX_ROUNDS_DEFAULT,
        state_only_backoff_initial: float = STATE_ONLY_BACKOFF_INITIAL_DEFAULT,
        state_only_backoff_max: float = STATE_ONLY_BACKOFF_MAX_DEFAULT,
        extensions=None,
        before_close=None,
        elicitation_callback=None,
    ) -> None:
        if not all(math.isfinite(value) and value > 0
                   for value in (connect_timeout, call_timeout, close_timeout)):
            raise ValueError("MCP connection, call and shutdown timeouts must be finite positive numbers")
        if type(max_state_only_rounds) is not int or not 0 <= max_state_only_rounds <= 10000:
            raise ValueError("MCP state-only round limit must be an integer from 0 to 10000")
        if (any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                for value in (state_only_backoff_initial, state_only_backoff_max))
                or state_only_backoff_initial > state_only_backoff_max):
            raise ValueError("MCP state-only backoff must be finite positive numbers, initial no larger than maximum")
        self._max_state_only_rounds = max_state_only_rounds
        self._state_only_backoff_initial = state_only_backoff_initial
        self._state_only_backoff_max = state_only_backoff_max
        self._outbound = url if isinstance(url, ValidatedOutboundURL) else None
        self.url = url.url if self._outbound is not None else url
        self._response_budget = MCPResponseBudget(response_max_bytes)
        request_headers = httpx2.Headers(headers)
        request_headers["Accept-Encoding"] = identity_accept_encoding(request_headers.get("accept-encoding"))
        self._headers = dict(request_headers)
        self._auth = auth
        self._extensions = tuple(extensions or ())
        self._task_extension_registered = False
        if elicitation_callback is not None and not callable(elicitation_callback):
            raise TypeError('MCP elicitation callback must be callable')
        self._elicitation_callback = elicitation_callback
        if before_close is not None and not callable(before_close):
            raise TypeError("MCP connection retirement must be callable")
        self._before_close = before_close
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self._close_timeout = close_timeout
        self._client: Client | None = None
        self._task: asyncio.Task[None] | None = None
        self._ready: asyncio.Future[Client] | None = None
        self._shutdown: _ShutdownDeadline | None = None
        self._incarnation: object | None = None

    @property
    def is_connected(self) -> bool:
        return (
            self._incarnation is not None
            and self._client is not None
            and self._task is not None
            and not self._task.done()
            and not self._task.cancelling()
            and self._shutdown is None
        )

    @property
    def owns_transport(self) -> bool:
        """Whether this connection still retains its original transport task."""
        return self._task is not None

    @property
    def protocol_version(self) -> str | None:
        """The published revision selected by the SDK's standard negotiation."""
        return self._client.protocol_version if self.is_connected else None

    @property
    def supports_task_claims(self) -> bool:
        """Diagnose the adopted native capability; this grants no authority."""
        return (self.is_connected and self._has_tasks_extension()
            and self.protocol_version in TASKS_PROTOCOL_VERSIONS)

    @property
    def incarnation(self) -> object | None:
        """Opaque lifetime of this active session; never a bearer credential."""
        return self._incarnation if self.is_connected else None

    def require_incarnation(self, incarnation: object) -> None:
        """Refuse closed or replaced sessions without selecting a new client."""
        if incarnation is None or self.incarnation is not incarnation:
            raise ValueError("MCP connection changed; rediscover its tools and reopen its views")

    def _owner_finished(self, task: asyncio.Task[None]) -> None:
        # Always observe the task outcome, including a failure after startup.
        # Deliver startup failures to connect immediately instead of waiting
        # for the connection timeout and hiding the original error.
        if self._shutdown is not None:
            self._shutdown.cancel()
        error = None if task.cancelled() else task.exception()
        if error is not None:
            logger.warning("MCP connection owner failed", exc_info=error)
        if self._ready is not None and not self._ready.done():
            if error is not None:
                self._ready.set_exception(error)
            else:
                self._ready.cancel()

    async def _run(self) -> None:
        try:
            async with _ConnectionResources(self._close_timeout) as resources:
                http_client = await resources.enter_async_context(httpx2.AsyncClient(
                    headers=self._headers,
                    auth=self._auth,
                    # Socket acquisition/writes are bounded; SDK/host deadlines
                    # own reads and pagination. Resource exit also has a whole
                    # deadline, including a handshake peer's session DELETE.
                    timeout=httpx2.Timeout(self._connect_timeout, read=None),
                    follow_redirects=False,
                    trust_env=False,
                    event_hooks={"response": [self._response_budget]},
                    transport=(pinned_httpx2_async_transport(self._outbound)
                               if self._outbound is not None else None),
                ))
                transport = streamable_http_client(self.url, http_client=http_client,
                    max_sse_event_size=self._response_budget.max_bytes)
                # Client consumes declarative extension descriptors synchronously
                # at construction. Later metadata changes cannot revoke its ad.
                tasks_registered = any(extension.identifier == TASKS_EXTENSION_ID
                    for extension in self._extensions)
                client_context = Client(
                    transport,
                    cache=None,
                    extensions=self._extensions,
                    elicitation_callback=self._elicitation_callback,
                    # The host owns state-only rounds and authority checks.
                    # Operator inputs require a separate governed surface.
                    input_required_max_rounds=0,
                )
                try:
                    client = await resources.enter_async_context(client_context)
                except* RuntimeError as errors:
                    # The SDK currently reports these negotiation verdicts
                    # as plain RuntimeError. Preserve other runtime failures.
                    _, unexpected = errors.split(lambda error: type(error) is RuntimeError
                        and len(error.args) == 1 and isinstance(error.args[0], str)
                        and error.args[0].startswith((
                            "Unsupported protocol version from the server: ",
                            "No mutually supported modern protocol version (server: ",
                        )))
                    if unexpected is not None:
                        raise
                    raise MCPPeerNegotiationError("MCP peer offered an unsupported protocol revision") from None
                self._task_extension_registered = tasks_registered
                self._client = client
                if self._ready is not None and not self._ready.done():
                    self._ready.set_result(client)
                await asyncio.Future()
        finally:
            self._client = None
            self._task_extension_registered = False

    async def _close_failed_startup(self, exc_type, exc_value, traceback):
        if exc_type is not None and issubclass(exc_type, (TimeoutError, asyncio.CancelledError)):
            try:
                # Register the original interruption with the same cleanup
                # owner before a later caller withdrawal can interrupt its
                # join. Cancellation must retain that original deadline in
                # its explicit evidence, not only implicit handling context.
                await self.close(failure=exc_value)
            except* MCP_CONNECTION_ERRORS as cleanup_error:
                # Preserve the operation deadline/caller cancellation. A late
                # SDK write into a closed transport is secondary cleanup evidence.
                logger.warning("MCP startup interrupted; original deadline and cleanup evidence retained", exc_info=cleanup_error)
        else:
            await self.close()
        return False

    async def connect(self) -> list[types.Tool]:
        if self._task is not None:
            raise RuntimeError("MCP connection already started; close it before reconnecting")
        self._incarnation = object()
        self._ready = asyncio.get_running_loop().create_future()
        self._task = asyncio.create_task(self._run(), name="mcp-connection")
        self._task.add_done_callback(self._owner_finished)
        async with AsyncExitStack() as startup:
            startup.push_async_exit(self._close_failed_startup)
            try:
                async with asyncio.timeout(self._connect_timeout):
                    await self._ready
            except TimeoutError as error:
                raise TimeoutError("MCP connection deadline exceeded") from error
            tools = await self.list_tools()
            startup.pop_all()
            return tools

    def _require_client(self) -> Client:
        if not self.is_connected or self._client is None:
            raise ConnectionError("MCP connection is not connected")
        return self._client

    async def list_tools(self) -> list[types.Tool]:
        async def collect() -> list[types.Tool]:
            tools: list[types.Tool] = []
            cursor: str | None = None
            seen: set[str] = set()
            seen_names: set[str] = set()
            while True:
                result = await self._require_client().list_tools(cursor=cursor)
                next_cursor = result.next_cursor
                if next_cursor is not None and next_cursor in seen:
                    raise MCPToolCatalogError("MCP server repeated its tools/list cursor")
                for tool in result.tools:
                    try:
                        validate_tool_contract(tool)
                    except MCPToolContractError as error:
                        raise MCPToolCatalogError(str(error)) from error
                    if tool.name in seen_names:
                        raise MCPToolCatalogError(f"Duplicate MCP tool name {tool.name!r} in catalog")
                    seen_names.add(tool.name)
                tools.extend(result.tools)
                cursor = next_cursor
                if cursor is None:
                    return tools
                seen.add(cursor)

        return await asyncio.wait_for(collect(), timeout=self._call_timeout)

    async def _complete(self, invoke, *, incarnation, round_check, progress,
                        input_handler=None, resume: MCPInputResume | None = None, before_send=None):
        """Drive native rounds, or return promptly after a durable host pause."""
        if resume is not None and (type(resume) is not MCPInputResume or round_check is None):
            raise ResourceUnsupported('MCP resume requires fresh host authority')
        if resume is not None:
            progress.intermediate = True
        state, responses, rounds = (None, None, 0) if resume is None else (
            resume.request_state, resume.responses, 0)
        delay = self._state_only_backoff_initial
        async with asyncio.timeout(self._call_timeout):
            while True:
                self.require_incarnation(incarnation)
                if round_check is not None:
                    round_check()
                if not progress.sent and before_send is not None:
                    call_synchronous_callback(before_send, label='request admission')
                progress.sent = True
                result = await invoke(state, responses)
                if isinstance(result, types.InputRequiredResult):
                    progress.intermediate = True
                self.require_incarnation(incarnation)
                if round_check is not None:
                    round_check()
                if not isinstance(result, types.InputRequiredResult):
                    return result
                if result.input_requests:
                    if input_handler is None or round_check is None:
                        raise ResourceUnsupported("MCP operator inputs require a governed host input surface")
                    action = await input_handler(result)
                    self.require_incarnation(incarnation)
                    round_check()
                    if isinstance(action, MCPInputSuspension):
                        return action
                    responses = MCPInputResume.seal(result, action).responses
                else:
                    responses = None
                if round_check is None:
                    raise ResourceUnsupported("MCP continuations require original host authority")
                if rounds >= self._max_state_only_rounds:
                    raise InputRequiredRoundsExceededError(self._max_state_only_rounds)
                # Opaque and local to this invocation, never inspected or
                # accumulated across rounds. Native validation owns its shape.
                state = result.request_state
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._state_only_backoff_max)
                rounds += 1

    async def read_resource(self, uri: str, *, incarnation: object, round_check=None,
                            input_handler=None, resume: MCPInputResume | None = None):
        """Read through the originating native client, with a whole deadline.

        View ownership and the exact advertised resource association belong to
        the Apps host. This method preserves the authenticated transport and
        its session lifetime; it never fetches a resource URI over HTTP.
        """
        self.require_incarnation(incarnation)
        client = self._require_client()
        progress = _RequestProgress()
        async def invoke(state, responses):
            return await client.session.read_resource(uri, request_state=state, input_responses=responses,
                allow_input_required=True)
        try:
            result = await self._complete(invoke, incarnation=incarnation,
                round_check=round_check, progress=progress, input_handler=input_handler, resume=resume)
        except (ExceptionGroup, *MCP_REQUEST_ERRORS) as error:
            if isinstance(error, ExceptionGroup):
                _, unexpected = error.split(MCP_REQUEST_ERRORS)
                if unexpected is not None:
                    raise
            if progress.intermediate or isinstance(error, ValidationError):
                # Pydantic validation text can include an untrusted opaque
                # state. Expose only the canonical safe resource outcome.
                raise ResourceOutcomeUnknown("MCP resource returned no confirmed final result; do not replay") from None
            raise
        self.require_incarnation(incarnation)
        return result

    def _has_tasks_extension(self):
        return self._task_extension_registered

    def _require_tasks(self, *, server_capability=True):
        client = self._require_client()
        capabilities = client.session.server_capabilities
        if (not self.supports_task_claims
                or (server_capability and (capabilities is None
                    or TASKS_EXTENSION_ID not in (capabilities.extensions or {})))):
            raise ResourceUnsupported('MCP Tasks require the native negotiated extension')
        return client

    async def request_task(self, request: GetTaskRequest | UpdateTaskRequest | CancelTaskRequest, *, incarnation, round_check):
        """One typed SDK request; no polling, continuation, refresh or resend."""
        if not callable(round_check):
            raise TypeError('MCP Task operations require current host authority')
        request = _task_request_snapshot(request)
        self.require_incarnation(incarnation)
        client = self._require_tasks()
        round_check()
        self.require_incarnation(incarnation)
        mutation = type(request) is not GetTaskRequest
        result_type = TaskAcknowledgement if mutation else TypeAdapter(DetailedTaskResult)
        try:
            async with asyncio.timeout(self._call_timeout):
                result = await client.session.send_request(request, result_type)
                self.require_incarnation(incarnation)
                round_check()
                self.require_incarnation(incarnation)
                return result
        except (ExceptionGroup, *MCP_REQUEST_ERRORS) as error:
            self._retire_changed_contract(error)
            if isinstance(error, ExceptionGroup):
                _, unexpected = error.split(MCP_REQUEST_ERRORS)
                if unexpected is not None:
                    raise
            if not mutation or _rejected_before_execution(error):
                raise
            raise MCPCallOutcomeUnknownError(
                'MCP Task mutation returned no confirmed acknowledgement; do not replay'
            ) from error

    async def call_tool(self, name: str, arguments: dict | None = None, *, round_check=None,
                        input_handler=None, resume: MCPInputResume | None = None, allow_claimed: bool = False,
                        before_send=None):
        if before_send is not None and not callable(before_send):
            raise TypeError('MCP request admission requires a synchronous callback')
        client = self._require_client()
        if type(allow_claimed) is not bool:
            raise TypeError('Native claimed-result handling must be explicit')
        if allow_claimed:
            # Declaring a client capability still permits an ordinary result
            # from a server which does not implement the extension.
            self._require_tasks(server_capability=False)
            if not callable(round_check):
                raise ResourceUnsupported('MCP Task claims require current host authority')
        elif self.supports_task_claims:
            # The SDK stamps registered extensions on every eligible request.
            # Refuse before wire if this caller cannot retain a native claim.
            raise ResourceUnsupported('MCP Tasks-capable calls require explicit native claim handling')
        incarnation = self.incarnation
        arguments = deepcopy(arguments or {})
        progress = _RequestProgress()
        async def invoke(state, responses):
            # The public one-round API retains native headers and output
            # validation, without the high-level schema-refresh resend.
            return await client.session.call_tool(name, arguments,
                request_state=state, input_responses=responses, allow_input_required=True,
                allow_claimed=allow_claimed)
        # ClientSession.validate_tool_result documents plain RuntimeError for
        # output-schema failures after execution. Preserve uncertainty rather
        # than treating an unreadable result as proof the tool did not run.
        try:
            return await self._complete(invoke, incarnation=incarnation,
                round_check=round_check, progress=progress, input_handler=input_handler, resume=resume,
                before_send=before_send)
        except (ExceptionGroup, *MCP_REQUEST_ERRORS) as error:
            if not progress.sent:
                raise
            self._retire_changed_contract(error)
            if isinstance(error, ExceptionGroup):
                _, unexpected = error.split(MCP_REQUEST_ERRORS)
                if unexpected is not None:
                    raise
            if not progress.intermediate and _rejected_before_execution(error):
                raise
            raise MCPCallOutcomeUnknownError(
                f"MCP tool {name!r} returned no confirmed result; its execution outcome is unknown. "
                "Do not replay it without policy approval and an explicit idempotency or safe-repeat guarantee."
            ) from error

    def _retire_changed_contract(self, error: BaseException) -> None:
        """Withdraw an admitted catalog when the peer rejects its contract."""
        def mismatch(candidate: BaseException) -> bool:
            return isinstance(candidate, MCPError) and candidate.code == types.HEADER_MISMATCH

        if mismatch(error) or (isinstance(error, BaseExceptionGroup)
                and error.subgroup(mismatch) is not None):
            self._incarnation = None

    async def close(self, *, failure: BaseException | None = None) -> None:
        steps = []
        if self._before_close is not None:
            steps.append((True, partial(self._before_close, self)))
        steps.append((True, self._close_transport))
        await run_cleanup_steps(steps, failure=failure)

    async def _close_transport(self) -> None:
        task = self._task
        if task is None:
            return
        already_done = task.done()
        if not already_done and self._shutdown is None:
            # Task.cancelling() also counts SDK/AnyIO cancellation. Track OUR
            # shutdown explicitly, so its cleanup is never mistaken for ours.
            self._shutdown = _ShutdownDeadline(task, self._close_timeout)
            task.cancel()
        try:
            # A partially-entered SDK client can clean up inside __aenter__,
            # before our resource stack's __aexit__ starts. The independent
            # graceful timer interrupts that cleanup even if this caller
            # abandons the join. Forced cleanup gets one further bounded budget.
            await asyncio.wait(
                {task}, timeout=self._close_timeout + self._close_timeout,
            )
            expired = self._shutdown is not None and self._shutdown.expired
            if not task.done() or (expired and not already_done):
                error = TimeoutError(
                    "MCP shutdown deadline exceeded while closing SDK resources"
                )
                if task.done() and not task.cancelled():
                    raise error from task.exception()
                raise error
            # A historical transport failure is observed by the owner callback,
            # rather than masquerading as a new cleanup error.
            if not task.cancelled() and not already_done:
                task.result()
        finally:
            if task.done():
                if self._shutdown is not None:
                    self._shutdown.cancel()
                self._shutdown = None
                self._task = None
                self._ready = None
                self._client = None
