"""
MCP Feature Agent - Manages Model Context Protocol (MCP) tools.

This feature connects to public HTTPS endpoints, Docker MCP gateways, and
custom container servers through the official MCP client. All discovered tools
mount through the host's governed dynamic-tool registry.
"""

import asyncio
from contextlib import AsyncExitStack
from functools import wraps
import logging
import json
from urllib.parse import urlsplit
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from kestrel_sdk.features.base import Feature, tool
from kestrel_sdk.tools.base import ToolCategory
from kestrel_sdk.tools.result import ToolResult
from kestrel_sdk.security.exceptions import SSRFError
from kestrel_sdk.security.outbound import assert_safe_url
from kestrel_sdk.storage.database import DatabaseError
from .connection import MCPConnection, MCP_CONNECTION_ERRORS, bind_tool_caller, connection_lifecycle, require_owner_did
from .constants import SESSION_CONNECT_TIMEOUT_DEFAULT
from .remote import RemoteMCPServer, RemoteMCPError, connection_error_message, remote_name_for_url, remote_owner
from .dynamic_tools import build_wrappers
from .images import normalize_image_ref
from .registry import (
    get_registry,
    MCPRegistry,
    check_docker_mcp_available,
    search_docker_catalog,
    list_docker_catalog_servers,
    DockerCatalogError,
)

# Docker managers are imported only when their mode is requested.
if TYPE_CHECKING:
    from .manager import MCPToolManager, MCPGatewayManager
    from .official_registry import OfficialRegistryClient

logger = logging.getLogger(__name__)

# Dynamic-tool registry owner keys (see ToolRegistryMixin.register_dynamic_tools).
# Gateway-mounted tools share one owner (the gateway aggregates many servers and
# does not attribute tools per-server); each container is its own owner.
_GATEWAY_OWNER = "mcp:gateway"


class MCPFeatureClosingError(RuntimeError):
    """A connection start belongs to a feature generation that is closing."""


_REMOTE_LOAD_ERRORS = MCP_CONNECTION_ERRORS + (
    SSRFError, ValueError, RemoteMCPError, MCPFeatureClosingError,
)


def _serialize_docker_operation(*, starts: bool):
    """Join Docker mutations before shutdown; cleanup remains usable when closed."""
    def decorate(method):
        @wraps(method)
        async def operation(self, *args, **kwargs):
            generation = self._lifecycle_generation
            try:
                if starts:
                    self._require_open(generation)
                async with self._docker_operations:
                    if starts:
                        self._require_open(generation)
                    return await method(self, *args, **kwargs)
            except MCPFeatureClosingError as error:
                return ToolResult.failed(str(error))
        return operation
    return decorate


def _container_owner(container_name: str) -> str:
    return f"mcp:container:{container_name}"


def _selector_failure(selector: str) -> Optional[ToolResult]:
    if not isinstance(selector, str) or not selector or selector != selector.strip():
        return ToolResult.failed("An MCP server selector must be a non-empty string without surrounding whitespace")
    return None


def _is_remote_selector(selector: str) -> bool:
    return "://" in selector or selector.lower().startswith(("http:", "https:"))


def _loaded_tool_result(confirmation: str, *, data: dict) -> ToolResult:
    """Discovery succeeds independently of the host retaining callable handles."""
    if data["mounted"] < len(data["tools"]):
        return ToolResult.partial(
            confirmation,
            f"Host registry retained {data['mounted']} of {len(data['tools'])} discovered MCP tools; "
            "only retained handles can be called. Free registry capacity and reload the server.",
            data=data,
        )
    return ToolResult.ok(confirmation, data=data)


def _official_record_blocks(records: list[dict[str, Any]]) -> list[str]:
    lines = ["Official MCP Registry results:"]
    for record in records:
        server = record["server"]
        status = record.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {}).get("status", "unspecified")
        block = [
            f"- server: {json.dumps(server['name'], ensure_ascii=True)}; "
            f"version: {json.dumps(server['version'], ensure_ascii=True)}; "
            f"status: {json.dumps(status, ensure_ascii=True)}",
            f"  description: {json.dumps(server['description'], ensure_ascii=True)}",
        ]
        for remote in server.get("remotes", []):
            support = " (unsupported transport)" if remote["type"] != "streamable-http" else ""
            block.append(f"  {remote['type']}{support}: {json.dumps(remote['url'], ensure_ascii=True)}")
        for package in server.get("packages", []):
            block.append(
                f"  Package: {json.dumps(package['registryType'], ensure_ascii=True)} / "
                f"{json.dumps(package['identifier'], ensure_ascii=True)}"
            )
        lines.append("\n".join(block))
    if not records:
        lines.append("No conforming server records are available on this page.")
    return lines


class MCPAgent(Feature):
    """
    A Feature Agent that manages Model Context Protocol (MCP) tools.
    It encapsulates the complexity of Docker container management and tool discovery,
    providing a high-level interface for the main KestrelAgent.
    """

    def __init__(self, agent):
        super().__init__(agent)
        self._official_registry: OfficialRegistryClient | None = None
        self.manager = None
        self.gateway_manager: Optional["MCPGatewayManager"] = None
        self._remote_connections: dict[str, RemoteMCPServer] = {}
        self._remote_lifecycle: dict = {}
        self._docker_initialization = asyncio.Lock()
        self._docker_operations = asyncio.Lock()
        self._lifecycle_transition = asyncio.Lock()
        self._lifecycle_generation = 0
        self._owner_did: str | None = None
        self._closing = False

    @property
    def tool_description(self) -> str:
        return (
            "Discover MCP servers in the official Registry, Docker and local catalogs; "
            "load MCP tools from HTTPS endpoints or Docker images, "
            "list available tools, call tools on running servers, and unload servers"
        )

    async def initialize(self):
        owner_did = require_owner_did(self.agent.agent_id)
        async with self._lifecycle_transition:
            if self._closing:
                # A soft disable retains this instance. Finish failed cleanup
                # before reopening; live initialization retains its resources.
                await self._shutdown_connections()
                async with self._docker_initialization:
                    self.manager = None
            self._owner_did = owner_did
            self._closing = False
        logger.info("MCPAgent initialized; Docker connects only for container operations.")

    def _require_open(self, generation: int | None = None) -> None:
        if self._closing or (generation is not None and generation != self._lifecycle_generation):
            raise MCPFeatureClosingError("MCP feature is shutting down")

    def _connection_owner_did(self) -> str:
        return self._owner_did or require_owner_did(self.agent.agent_id)

    async def _ensure_container_manager(self) -> bool:
        async with self._docker_initialization:
            self._require_open()
            if self.manager is None:
                from .manager import MCPToolManager, DockerDaemonUnavailableError

                try:
                    self.manager = await MCPToolManager.create(owner_did=self._connection_owner_did())
                except DockerDaemonUnavailableError as error:
                    logger.warning("Local Docker daemon unavailable; Docker MCP tools are disabled: %s", error)
                    return False
            self._require_open()
            return True

    # =========================================================================
    # Dynamic tool mounting — make a server's tools first-class LLM tools
    # =========================================================================

    def _host_supports_dynamic_tools(self) -> bool:
        """Whether the host exposes the dynamic-tool registry (#1979 PR2).

        MCP execution requires the host's governed dynamic-tool path.
        """
        agent = getattr(self, "agent", None)
        return (
            agent is not None
            and callable(getattr(agent, "register_dynamic_tools", None))
            and callable(getattr(agent, "unregister_dynamic_tools", None))
        )

    def _mount_tools(self, owner: str, handle_prefix: str, tool_dicts, caller) -> int:
        """Mount a set of MCP tools into the host registry under ``owner``.

        Idempotent refresh: any previously-mounted tools for ``owner`` are
        dropped first, then the current set is registered. Returns the number
        of tools mounted. A host without a dynamic registry is unsupported.
        """
        if not self._host_supports_dynamic_tools():
            raise RuntimeError("MCP execution requires the host's governed dynamic tool registry")
        self.agent.unregister_dynamic_tools(owner)
        wrappers = build_wrappers(handle_prefix, tool_dicts, caller)
        return self.agent.register_dynamic_tools(owner, wrappers)

    def _unmount_tools(self, owner: str) -> int:
        """Remove all tools mounted under ``owner`` (inverse of _mount_tools)."""
        if not self._host_supports_dynamic_tools():
            return 0
        return self.agent.unregister_dynamic_tools(owner)

    # --- catalog validation (honesty: don't "enable" a name that can't exist) -

    async def _known_catalog_servers(self) -> Optional[set]:
        """Known catalog names, or None when Docker metadata is unavailable.

        A missing catalog cannot prove that a requested name is invalid. Only
        readable metadata gates names; local configuration errors still fail.
        """
        docker_names: set = set()
        try:
            catalog = await list_docker_catalog_servers()
            docker_names = {s["name"] for s in catalog if s.get("name")}
        except DockerCatalogError as exc:
            logger.warning("Docker MCP catalog unavailable for validation: %s", exc)
        if not docker_names:
            # Unverifiable — never reject gateway names from the local
            # subset alone.
            return None
        known = set(docker_names)
        known.update(entry.name for entry in get_registry().list_all())
        return known

    async def _reject_unknown_servers(
        self, requested: List[str],
    ) -> Optional[ToolResult]:
        """Return a ``failed`` ToolResult naming any requested server that
        is absent from every resolvable catalog, else ``None`` (proceed).

        No-op when the catalog is unverifiable (see _known_catalog_servers)."""
        known = await self._known_catalog_servers()
        if known is None:
            return None
        unknown = [s for s in requested if s not in known]
        if not unknown:
            return None
        return ToolResult.failed(
            f"Unknown MCP server(s): {', '.join(unknown)}. "
            "Not found in the Docker MCP catalog or the local registry, so "
            "they cannot be enabled. Search with `!mcp-docker-catalog <query>`.",
            data={"unknown_servers": unknown, "requested": requested},
        )

    # --- enablement persistence (survives restart via the host DB) ----------

    def _supports_enablement_persistence(self) -> bool:
        """Whether the host exposes the per-agent enablement-delta store.

        Provided by the feature_enablement foundation. Older hosts lack it, so
        enable/disable still works for the session but won't survive a restart.
        """
        agent = getattr(self, "agent", None)
        return agent is not None and hasattr(agent, "persist_feature_enablement")

    async def _persist_server(self, name: str, state: str, *, metadata=None) -> bool:
        """Record desired state; storage errors must not claim persistence."""
        if not self._supports_enablement_persistence():
            return False
        await self.agent.persist_feature_enablement(
            "mcp_server", name, state, actor="agent", metadata=metadata,
        )
        return True

    async def _forget_server(self, name: str) -> None:
        """Drop an MCP server's persisted enablement (explicit removal)."""
        if not self._supports_enablement_persistence():
            return
        await self.agent.clear_feature_enablement("mcp_server", name)

    async def _forget_all_gateway_servers(self) -> None:
        """Clear every persisted gateway-mode server (explicit gateway disable).

        ``gateway_stop`` is the off switch — symmetric with container unload — so
        it must clear persistence; otherwise a stop followed by restart would
        re-start the gateway and "off" would be impossible. Container deltas are
        left untouched.
        """
        if not self._supports_enablement_persistence():
            return
        try:
            prior = await self.agent.get_enablement_deltas("mcp_server")
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not read MCP servers to clear on stop: %s", e)
            return
        for d in prior:
            if (d.get("metadata") or {}).get("mode") == "gateway":
                await self._forget_server(d["name"])

    async def _reconcile_gateway_persistence(self, server_list) -> None:
        """Make persisted gateway servers reflect EXACTLY ``server_list``.

        ``gateway_start`` replaces the running gateway, so it is authoritative
        for the gateway's server set: forget any previously-persisted gateway
        server no longer in the list (else a restart would restore servers the
        current gateway dropped), then persist the new set. ``gateway_enable``
        stays additive.
        """
        if not self._supports_enablement_persistence():
            return
        desired = set(server_list)
        try:
            prior = await self.agent.get_enablement_deltas("mcp_server")
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not read prior MCP servers for reconcile: %s", e)
            prior = []
        prior_gateway = {
            d["name"] for d in prior
            if (d.get("metadata") or {}).get("mode") == "gateway"
        }
        for stale in prior_gateway - desired:
            await self._forget_server(stale)
        for srv in server_list:
            await self._persist_server(srv, "enabled", metadata={"mode": "gateway"})

    def _mount_gateway_tools(self) -> int:
        """(Re)mount the connected gateway's full tool set under the gateway owner.

        Used after start/enable — the gateway aggregates servers and reports a
        flat tool list, so we refresh the whole owner each time. The caller
        binds the connection that advertised these schemas; a pending approval
        must not follow a later gateway reconfiguration.
        """
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return 0
        tool_dicts = self.gateway_manager.get_all_tools()
        return self._mount_tools(
            _GATEWAY_OWNER, "gateway", tool_dicts,
            self.gateway_manager.tool_caller(),
        )

    async def _resolve_load_route(self, server: str) -> tuple[str, str]:
        """Resolve ``server`` to ``("gateway", catalog_name)`` or
        ``("container", image_ref)``.

        Routing (the #12 unification): stdio servers need the gateway's
        stdio->Streamable-HTTP conversion, so they go through it; native-HTTP
        images (e.g. the test server, custom Kestrel images) keep the direct
        per-container path that serves their own HTTP endpoint.

        - A registry entry (looked up by name, or by tag-normalized image ref)
          routes by its transport: ``requires_wrapper`` (stdio, non-builtin) ->
          gateway by catalog name; otherwise container by the entry's *image*
          (so a catalog name like ``test-server`` runs its real image, not the
          name).
        - An image reference (contains ``/`` or ``:``) not matching a registry
          entry is a native-HTTP container, with the implicit tag made explicit.
        - A bare name not in the local registry is a Docker-catalog server only
          if the Docker catalog actually knows it; otherwise it is treated as a
          local/custom image (preserving direct-container loads). When the
          catalog is unverifiable, default to the container path so an offline
          host never misroutes a valid local image to the gateway.
        """
        if _is_remote_selector(server):
            return ("remote", server)
        registry = get_registry()
        entry = registry.get(server)
        if entry is None and ("/" in server or ":" in server):
            target = normalize_image_ref(server)
            for candidate in registry.list_all():
                refs = {
                    normalize_image_ref(ref)
                    for ref in (candidate.image, candidate.full_image) if ref
                }
                if target in refs:
                    entry = candidate
                    break
        if entry is not None:
            if entry.requires_wrapper:
                return ("gateway", entry.name)
            return ("container", normalize_image_ref(entry.full_image or entry.image or server))
        if "/" in server or ":" in server:
            return ("container", normalize_image_ref(server))
        known = await self._known_catalog_servers()
        if known is not None and server in known:
            return ("gateway", server)  # bare name the Docker catalog knows
        return ("container", normalize_image_ref(server))

    @tool(
        name="mcp_load_server",
        description=(
            "Load an MCP server by catalog name (e.g. 'time', 'fetch', "
            "'sequentialthinking'), Docker image, or public HTTPS endpoint. "
            "Remote endpoints use native Streamable HTTP without Docker."
        ),
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-load"
    )
    async def load_tool(self, server: str, args: List[str] = None) -> ToolResult:
        """Load an MCP server.

        Routes catalog/stdio servers through the gateway (Streamable HTTP) and
        native-HTTP images through the per-container path; see _gateway_target.
        Returns a success message with the available tools.
        """
        invalid = _selector_failure(server)
        if invalid is not None:
            return invalid
        generation = self._lifecycle_generation
        try:
            self._require_open(generation)
            route, target = await self._resolve_load_route(server)
            self._require_open(generation)
        except MCPFeatureClosingError as error:
            return ToolResult.failed(str(error))
        if route == "remote":
            if args is not None:
                return ToolResult.failed("Remote MCP endpoints do not accept container command arguments")
            return await self._load_via_remote(target)
        if route == "gateway":
            return await self._load_via_gateway(target)
        return await self._load_via_container(target, args)

    async def _retire_remote(self, name: str) -> None:
        record = self._remote_connections.get(name)
        if record is not None:
            record.tools = None
            await record.connection.close()
            del self._remote_connections[name]

    async def _read_server_delta(self, name: str) -> dict | None:
        reader = getattr(self.agent, "get_enablement_deltas", None)
        if not callable(reader):
            raise RemoteMCPError("Host enablement API cannot confirm its saved connection")
        return next((row for row in await reader("mcp_server") if row["name"] == name), None)

    async def _load_remote_connection(self, url: str, expected_name: str | None) -> ToolResult:
        invalid = _selector_failure(url)
        if invalid is not None:
            raise RemoteMCPError(invalid.error)
        if not self._host_supports_dynamic_tools():
            raise RemoteMCPError("MCP execution requires the host's governed dynamic tool registry")
        if urlsplit(url).fragment:
            raise RemoteMCPError("Remote MCP endpoints must not contain URL fragments")
        owner_did = self._connection_owner_did()
        if expected_name is not None and remote_name_for_url(url, owner_did) != expected_name:
            raise RemoteMCPError("Stored MCP connection identifier does not match this agent's ownership")
        async with asyncio.timeout(SESSION_CONNECT_TIMEOUT_DEFAULT):
            endpoint = await assert_safe_url(url, allowed_schemes=("https",))
        name = remote_name_for_url(endpoint.url, owner_did)
        if expected_name is not None and name != expected_name:
            raise RemoteMCPError("Stored MCP endpoint is not canonical; reconnect it explicitly")
        async with connection_lifecycle(self._remote_lifecycle, name):
            self._require_open()
            owner = remote_owner(name)
            self._unmount_tools(owner)
            await self._retire_remote(name)
            record = RemoteMCPServer(name, endpoint, MCPConnection(endpoint))
            self._remote_connections[name] = record
            published = False
            persistent = False
            try:
                discovered = await record.connection.connect()
                self._require_open()
                metadata = {"mode": "remote", "url": endpoint.url, "auth": "none"}
                # Restore reads existing desired state; it must not require a
                # redundant write or change the saved row's audit metadata.
                persisted = (expected_name is not None or
                             await self._persist_server(name, "enabled", metadata=metadata))
                if persisted:
                    saved = await self._read_server_delta(name)
                    if (saved is None or saved["state"] != "enabled"
                            or saved.get("metadata") != metadata):
                        raise RemoteMCPError("Host did not retain MCP enablement; initialize its durable store")
                persistent = persisted
                self._require_open()
                record.tools = discovered
                caller = bind_tool_caller(
                    record.connection,
                    lambda: (self._remote_connections.get(name) is record and record.tools is not None),
                    name,
                )
                mounted = self._mount_tools(
                    owner, f"remote_{name[-12:]}", record.tool_descriptions(), caller,
                )
                tools = [tool.name for tool in record.tools]
                data = {"connection": name, "url": endpoint.url, "via": "remote", "auth": "none",
                        "tools": tools, "mounted": mounted, "persistent": persistent,
                        "protocol_version": record.connection.protocol_version}
                published = True
                summary = f"Connected to {endpoint.url}. Tools: {', '.join(tools)}. Mounted {mounted}."
                if not persistent:
                    summary += " This host does not persist enablement; this connection lasts for this session."
                if not tools:
                    return ToolResult.partial(summary, "The server advertised an empty tool catalog.", data=data)
                return _loaded_tool_result(summary, data=data)
            except* _REMOTE_LOAD_ERRORS as errors:
                if persistent:
                    raise RemoteMCPError(
                        f"{connection_error_message(errors)}; enablement remains saved and will "
                        "restore after restart. Unload the saved connection to disable it."
                    ) from errors
                raise
            finally:
                if not published:
                    try:
                        self._unmount_tools(owner)
                    finally:
                        await self._retire_remote(name)

    async def _load_via_remote(self, url: str, *, expected_name: str | None = None) -> ToolResult:
        failure = None
        try:
            result = await self._load_remote_connection(url, expected_name)
        except* _REMOTE_LOAD_ERRORS as errors:
            failure = connection_error_message(errors)
        if failure is not None:
            return ToolResult.failed(f"Failed to connect remote MCP server: {failure}")
        return result

    async def _unload_remote(self, name: str) -> ToolResult:
        async with connection_lifecycle(self._remote_lifecycle, name):
            record = self._remote_connections.get(name)
            retained = False
            try:
                if record is not None:
                    record.tools = None
                unmounted = self._unmount_tools(remote_owner(name))
                await self._forget_server(name)
                if self._supports_enablement_persistence():
                    retained = await self._read_server_delta(name) is not None
            finally:
                await self._retire_remote(name)
            if retained:
                return ToolResult.failed(
                    "Remote connection closed, but the host did not remove its saved enablement; "
                    "it could reconnect after restart. Repair the store and unload it again.",
                    data={"connection": name, "unmounted": unmounted},
                )
            if record is None:
                return ToolResult.failed(f"No remote MCP server named '{name}' is loaded.",
                                         data={"connection": name, "unmounted": unmounted})
            return ToolResult.ok(f"Disconnected {record.endpoint.url}",
                                 data={"connection": name, "unmounted": unmounted})

    @_serialize_docker_operation(starts=True)
    async def _load_via_container(self, image_name: str, args: List[str] = None) -> ToolResult:
        """Per-container load path for native-HTTP MCP images."""
        from .manager import container_name_for_image

        if not await self._ensure_container_manager():
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")
        requested_name = container_name_for_image(image_name, self.manager.owner_did)
        self._unmount_tools(_container_owner(requested_name))
        failure_context = {"container": requested_name, "image": image_name}
        published = False
        try:
            container_name = await self.manager.start_tool_container(
                image_name, container_name=requested_name, command=args,
            )
            self._require_open()
            tools = await self.manager.connect_to_tool(container_name)
            self._require_open()
            # Mount the container's tools as first-class LLM tools. The caller
            # closure binds the container; the host registry routes the call
            # through the connection that advertised the tool's real MCP name.
            tool_dicts = [
                t for t in (self.manager.get_all_tools() or [])
                if t.get("container") == container_name
            ]
            tool_names = [tool.name for tool in tools]
            owner = _container_owner(container_name)
            # Persist so this container is auto-restored on restart.
            await self._persist_server(
                container_name, "enabled",
                metadata={"mode": "container", "image": image_name, "args": args},
            )
            self._require_open()
            mounted = self._mount_tools(
                owner, normalize_image_ref(image_name), tool_dicts,
                self.manager.tool_caller(container_name),
            )
            data = {
                "container": container_name, "image": image_name,
                "tools": tool_names, "mounted": mounted,
            }
            published = True
            if not tool_names:
                return ToolResult.partial(
                    f"Connected to {image_name} as {container_name}; no tools were advertised.",
                    "The server advertised an empty tool catalog.",
                    data=data,
                )
            mount_note = (
                f" Mounted {mounted} as callable tools."
                if mounted else
                " No callable tools were retained by the host registry."
            )
            return _loaded_tool_result(
                f"Loaded {image_name} as {container_name}. Tools: {', '.join(tool_names)}."
                + mount_note,
                data=data,
            )
        except (TimeoutError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to load tool {image_name}: {e}")
            return ToolResult.failed(f"Failed to load MCP tool: {str(e)}", data=failure_context)
        except Exception as e:
            logger.error(f"Unexpected error loading tool {image_name}: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to load MCP tool: {str(e)}", data=failure_context)

        finally:
            if not published:
                self._unmount_tools(_container_owner(requested_name))

    async def _retire_gateway(self):
        """Retire an owned gateway even when its MCP transport already died."""
        gateway = self.gateway_manager
        try:
            if gateway is not None:
                await gateway.stop()
        finally:
            self._unmount_tools(_GATEWAY_OWNER)
        self.gateway_manager = None

    @_serialize_docker_operation(starts=True)
    async def _load_via_gateway(self, server_name: str) -> ToolResult:
        """Load a single catalog/stdio server through the shared gateway.

        Starts the gateway if it is not running yet, otherwise enables the
        server additively on the existing one — so repeated ``mcp_load_server``
        calls accumulate servers in one gateway instead of fighting over it.
        Persists ``mode=gateway`` so it is restored on restart by the same path
        as the gateway verbs.
        """
        if self.gateway_manager is None and not check_docker_mcp_available():
            return ToolResult.failed(
                "Docker MCP Toolkit not installed.\n\n"
                "Please install Docker Desktop 29+ with MCP Toolkit enabled."
            )
        # Honesty gate: never "load" a name the catalog says can't exist (#9).
        rejection = await self._reject_unknown_servers([server_name])
        if rejection is not None:
            return rejection

        published = False
        changed = False
        try:
            from .manager import MCPGatewayManager
            from .gateway import DockerMCPGatewayError, DockerMCPNotInstalledError

            changed = True
            if self.gateway_manager is not None and self.gateway_manager.is_connected:
                # The gateway reports a flat aggregated tool list, so the only
                # honest per-server signal is the before/after delta.
                before = set((self.gateway_manager.tools or {}).keys())
                self._unmount_tools(_GATEWAY_OWNER)
                tools = await self.gateway_manager.enable_server(server_name)
            else:
                await self._retire_gateway()
                self._require_open()
                self.gateway_manager = MCPGatewayManager()
                before = set()
                tools = await self.gateway_manager.start([server_name])

            self._require_open()
            tool_names = [t.name for t in tools]
            new_tools = sorted(set(tool_names) - before)
            await self._persist_server(
                server_name, "enabled", metadata={"mode": "gateway"},
            )
            self._require_open()
            mounted = self._mount_gateway_tools()
            data = {
                "server": server_name,
                "tools": tool_names,
                "new_tools": new_tools,
                "mounted": mounted,
                "via": "gateway",
            }
            published = True
            # A real load that adds no NEW tools is indistinguishable from a
            # no-op unless we say so — surface it as PARTIAL, not a confident
            # "Loaded" (#9 honesty contract).
            if not new_tools:
                return ToolResult.partial(
                    f"Requested {server_name} via the gateway, but it added 0 new "
                    f"tools (it may need credentials/configuration, or its tools "
                    f"were already present). Gateway total: {len(tool_names)} tools.",
                    f"{server_name} contributed no new tools",
                    data=data,
                )
            return _loaded_tool_result(
                f"Requested {server_name} via the gateway — added {len(new_tools)} "
                f"tool(s): {', '.join(new_tools[:10])}"
                + (f" (+{len(new_tools) - 10} more)" if len(new_tools) > 10 else "")
                + f"\n\n**Gateway total:** {len(tool_names)} tools"
                + (f" ({mounted} mounted as callable tools)" if mounted else ""),
                data=data,
            )
        except (DockerMCPGatewayError, DockerMCPNotInstalledError) as e:
            logger.error(f"Gateway load failed for {server_name}: {e}")
            return ToolResult.failed(f"Failed to load {server_name}: {str(e)}")
        except asyncio.TimeoutError:
            logger.error(f"Timeout loading {server_name} via gateway")
            return ToolResult.failed(f"Failed to load {server_name}: Connection timeout")
        except Exception as e:
            logger.error(f"Unexpected error loading {server_name} via gateway: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to load {server_name}: {str(e)}")

        finally:
            if changed and not published:
                self._unmount_tools(_GATEWAY_OWNER)

    @tool(
        name="mcp_list_servers",
        description="List all running MCP servers and their tools.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-list"
    )
    async def list_tools(self) -> ToolResult:
        """
        Lists all currently loaded MCP tools.
        """
        tools = list(self.manager.get_all_tools() or []) if self.manager is not None else []
        if self.gateway_manager is not None and self.gateway_manager.is_connected:
            tools.extend({**tool, "container": "gateway"}
                         for tool in self.gateway_manager.get_all_tools())
        containers = []
        if self.manager is not None:
            for name, info in self.manager.owned_containers.items():
                connection, catalog = info["connection"], info["tools"]
                containers.append({
                    "container": name, "catalog_ready": catalog is not None,
                    "connected": bool(connection is not None and connection.is_connected),
                    "tool_count": len(catalog) if catalog is not None else None,
                })
        remotes = []
        for name, record in self._remote_connections.items():
            tools.extend(record.tool_descriptions())
            remotes.append({"connection": name, "url": record.endpoint.url,
                            "catalog_ready": record.tools is not None,
                            "connected": record.connection.is_connected,
                            "protocol_version": record.connection.protocol_version,
                            "tool_count": len(record.tools) if record.tools is not None else None})
        data = {"tools": tools, "containers": containers, "remotes": remotes}
        response = "Available MCP Tools:\n" if tools else "No MCP tools loaded.\n"
        for tool in tools:
            identity = tool.get("connection", tool.get("container", "?"))
            response += f"- [{identity}] {tool['name']}: {tool.get('description', '')}\n"
        for title, records, field in (("MCP containers", containers, "container"),
                                      ("Remote MCP servers", remotes, "connection")):
            if records:
                response += "\n" + title + ":\n"
                for record in records:
                    count = record["tool_count"] if record["catalog_ready"] else "unknown"
                    state = "connected" if record["connected"] else "disconnected"
                    response += f"- [{record[field]}] {state}, {count} tool(s)\n"
        if any(not record["connected"] or not record["catalog_ready"] for record in containers + remotes):
            return ToolResult.partial(response, "An owned MCP connection is not ready for tool calls.", data=data)
        return ToolResult.ok(response, data=data)

    @tool(
        name="mcp_unload_server",
        description="Unload (stop) an MCP server.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-unload"
    )
    async def unload_tool(self, container_name: str) -> ToolResult:
        """Unload (stop) an MCP server.

        Symmetric with load: a server currently enabled on the gateway is
        disabled there; otherwise the per-container path stops the container.
        """
        invalid = _selector_failure(container_name)
        if invalid is not None:
            return invalid
        remote = next((name for name, record in self._remote_connections.items()
                       if container_name in (name, record.endpoint.url)), None)
        if remote is not None:
            return await self._unload_remote(remote)
        if container_name.startswith("mcp-remote-"):
            return await self._unload_remote(container_name)
        if _is_remote_selector(container_name):
            return ToolResult.failed("No loaded remote MCP connection has that endpoint")
        return await self._unload_docker(container_name)

    @_serialize_docker_operation(starts=False)
    async def _unload_docker(self, container_name: str) -> ToolResult:
        if self.manager is None and self.gateway_manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")
        owned = self.manager.owned_containers if self.manager is not None else {}

        # Resolve the same image-to-resource identity used by load, and only
        # select records this manager actually owns. Exact identifiers win.
        if container_name not in owned:
            gwm = self.gateway_manager
            if len(owned) or (gwm is not None and gwm.is_connected):
                route, resolved = await self._resolve_load_route(container_name)
                if route == "container" and len(owned):
                    from .manager import container_name_for_image

                    candidate = container_name_for_image(resolved, self.manager.owner_did)
                    if candidate in owned:
                        container_name = candidate

                gwm = self.gateway_manager
                if container_name not in owned and gwm is not None and gwm.is_connected:
                    enabled = getattr(getattr(gwm, "gateway", None), "requested_servers", set())
                    gw_name = resolved if route == "gateway" else None
                    target = container_name if container_name in enabled else gw_name if gw_name in enabled else None
                    if target is not None:
                        return await self._unload_via_gateway(target)

        if self.manager is None:
            return ToolResult.failed(f"No MCP server named '{container_name}' is loaded.")

        # Withdraw callable handles and desired configuration before teardown;
        # a failed close must never advertise a destroyed container's tools.
        unmounted = self._unmount_tools(_container_owner(container_name))
        await self._forget_server(container_name)
        try:
            stopped = await self.manager.stop_tool(container_name)
            if not stopped:
                # Nothing was loaded under that name — report the no-op
                # honestly instead of a confident "Unloaded" (#9, finding #4).
                # Persistence/mount cleanup still ran in case stale state
                # lingered, so note whether that removed anything.
                cleanup = (
                    f" (cleared {unmounted} stale mounted tool(s))"
                    if unmounted else ""
                )
                return ToolResult.failed(
                    f"No MCP server named '{container_name}' is loaded; "
                    f"nothing to unload{cleanup}.",
                    data={"container": container_name, "stopped": False,
                          "unmounted": unmounted},
                )
            return ToolResult.ok(
                f"Unloaded {container_name}",
                data={"container": container_name, "stopped": True,
                      "unmounted": unmounted},
            )
        except ValueError as e:
            logger.error(f"Tool not found: {container_name}")
            return ToolResult.failed(f"Failed to unload tool: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to unload tool {container_name}: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to unload tool: {str(e)}")

    async def _unload_via_gateway(self, server_name: str) -> ToolResult:
        """Disable a gateway-loaded server (inverse of _load_via_gateway).

        Disabling the last server stops the gateway entirely; otherwise the
        gateway reconnects with the remaining servers and the aggregate mount
        is refreshed. Persistence is cleared either way so the server is not
        auto-restored.
        """
        gwm = self.gateway_manager
        self._unmount_tools(_GATEWAY_OWNER)
        await self._forget_server(server_name)
        try:
            remaining = [
                s for s in gwm.gateway.requested_servers if s != server_name
            ]
            if remaining:
                await gwm.disable_server(server_name)
                mounted = self._mount_gateway_tools()
            else:
                # Last server — tear the gateway down rather than leave an empty
                # one running, and drop the aggregate mount.
                await self._retire_gateway()
                mounted = 0
            return ToolResult.ok(
                f"Unloaded {server_name} (gateway). "
                + (f"{len(remaining)} server(s) still loaded; {mounted} tool(s) mounted."
                   if remaining else "Gateway stopped (no servers remaining)."),
                data={"server": server_name, "via": "gateway",
                      "remaining": remaining, "mounted": mounted},
            )
        except Exception as e:
            logger.error(f"Failed to unload gateway server {server_name}: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to unload {server_name}: {str(e)}")

    def _get_official_registry(self) -> "OfficialRegistryClient":
        """Construct only on an official request, never during tool introspection."""
        from .official_registry import OfficialRegistryClient

        if self._official_registry is None:
            self._official_registry = OfficialRegistryClient()
        return self._official_registry

    async def _official_registry_page(
        self, query: str | None, *, cursor: str | None, limit: int | None,
    ) -> ToolResult:
        from .official_registry import OfficialRegistryError

        try:
            options = {"cursor": cursor}
            if limit is not None:
                options["limit"] = limit
            page = await self._get_official_registry().search(query, **options)
        except OfficialRegistryError as error:
            return ToolResult.failed(str(error), data={"source": "official"})
        lines = _official_record_blocks(page.servers)
        if page.next_cursor is not None:
            lines.insert(1, "Next cursor: " + json.dumps(page.next_cursor, ensure_ascii=True))
        data = {
            "source": "official", "registry_url": page.registry_url, "result": page.payload,
        }
        rejected = page.rejected_records
        if rejected:
            data["rejected_records"] = rejected
            lines.append("Rejected records: " + json.dumps(
                [{"index": item["index"], "name": item["name"]} for item in rejected],
                ensure_ascii=True,
            ))
            return ToolResult.partial(page.settings.render(lines), page.settings.schema_error(page.problems), data=data)
        return ToolResult.ok(page.settings.render(lines), data=data)

    @tool(
        name="mcp_search",
        description="Search the official MCP Registry by server name, or select source='local' for bundled capability/category search.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-search"
    )
    async def search_servers(
        self, query: str, source: str = "official",
        cursor: str | None = None, limit: int | None = None,
    ) -> ToolResult:
        """
        Search the MCP server catalog for servers matching a query.

        Args:
            query: Official server-name substring, or local capability/category
            source: Explicit catalog; entries never override another source
            cursor: Official registry's opaque next-page cursor
            limit: Official registry page size (1 to 100, default 20); omit for local

        Returns:
            List of matching MCP servers with their details.
        """
        if source == "official":
            return await self._official_registry_page(query, cursor=cursor, limit=limit)
        if source != "local" or cursor is not None or limit is not None:
            return ToolResult.failed("Select source='official' or source='local'; only the official source accepts a cursor or limit.")
        registry = get_registry()
        matches = registry.search(query)

        if not matches:
            return ToolResult.ok(
                f"No MCP servers found matching '{query}'.\n\nTip: Use `!mcp-catalog` to see all available servers.",
                data={"source": "local", "query": query, "matches": []},
            )

        lines = [f"**MCP servers matching '{query}':**\n"]
        for server in matches:
            type_marker = "builtin" if server.is_builtin else "docker"
            private_marker = " [private]" if server.private else ""
            tools_preview = ", ".join(server.tools[:3])
            if len(server.tools) > 3:
                tools_preview += f" (+{len(server.tools) - 3} more)"

            lines.append(f"[{type_marker}] **{server.name}**{private_marker}")
            lines.append(f"   {server.description}")
            lines.append(f"   Tools: {tools_preview}")
            if not server.is_builtin:
                lines.append(f"   Load: `!mcp-load {server.image}`")
            lines.append("")

        return ToolResult.ok(
            "\n".join(lines),
            data={"source": "local", "query": query, "matches": [s.name for s in matches]},
        )

    @tool(
        name="mcp_catalog",
        description="List a page of the official MCP Registry, or select source='local' for the bundled catalog.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-catalog"
    )
    async def show_catalog(
        self, source: str = "official",
        cursor: str | None = None, limit: int | None = None,
    ) -> ToolResult:
        """
        Display a page of the official registry, or the full local catalog.

        Args:
            source: Explicit official or local catalog
            cursor: Exact opaque next-page cursor returned by the official registry
            limit: Official registry page size, from 1 to 100 (default 20); omit for local

        Returns:
            Formatted list of all available MCP servers.
        """
        if source == "official":
            return await self._official_registry_page(None, cursor=cursor, limit=limit)
        if source != "local" or cursor is not None or limit is not None:
            return ToolResult.failed("Select source='official' or source='local'; only the official source accepts a cursor or limit.")
        registry = get_registry()
        return ToolResult.ok(
            registry.format_catalog(),
            data={"source": "local", "servers": [s.name for s in registry.list_all()]},
        )

    @tool(
        name="mcp_server_info",
        description="Get an official MCP Registry server by namespaced name and version, or select source='local' for a bundled entry.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-info"
    )
    async def server_info(
        self, server_name: str, source: str = "official",
        version: str = "latest",
    ) -> ToolResult:
        """
        Get detailed information about a specific MCP server.

        Args:
            server_name: Official namespaced name, or a local catalog name
            source: Explicit catalog; there is no cross-source name fallback
            version: Official version, or 'latest' to resolve the current version

        Returns:
            Detailed server information including tools and requirements.
        """
        if source == "official":
            from .official_registry import OfficialRegistryError

            try:
                record = await self._get_official_registry().get(server_name, version=version)
            except OfficialRegistryError as error:
                return ToolResult.failed(str(error), data={"source": "official"})
            data = {
                "source": "official", "registry_url": record.registry_url, "result": record.payload,
            }
            if record.problems:
                problems = [problem.to_dict() for problem in record.problems]
                data["problems"] = problems
                return ToolResult.partial(
                    "Registry record was rejected by the published schema; inspect data.result for its metadata.",
                    record.settings.schema_error(record.problems), data=data,
                )
            return ToolResult.ok(record.settings.render(_official_record_blocks([record.require_valid()])), data=data)
        if source != "local" or version != "latest":
            return ToolResult.failed("Select source='official' or source='local'; only the official source accepts a version.")
        registry = get_registry()
        server = registry.get(server_name)

        if not server:
            similar = registry.search(server_name)
            if similar:
                suggestions = ", ".join(s.name for s in similar[:3])
                return ToolResult.failed(
                    f"Server '{server_name}' not found. Did you mean: {suggestions}?"
                )
            return ToolResult.failed(
                f"Server '{server_name}' not found. Use `!mcp-catalog` to see available servers."
            )

        return ToolResult.ok(
            registry.format_server_info(server),
            data={"source": "local", "server": server.name},
        )

    # =========================================================================
    # Gateway Mode Commands (Recommended)
    # =========================================================================

    @tool(
        name="mcp_gateway_start",
        description="Start Docker MCP Gateway with specified servers. Access 311+ MCP servers.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-start"
    )
    @_serialize_docker_operation(starts=True)
    async def gateway_start(self, servers: str = "fetch") -> ToolResult:
        """
        Start the Docker MCP Gateway with specified servers.

        The gateway provides unified access to 311+ MCP servers from Docker's catalog
        with automatic stdio->Streamable HTTP conversion.

        Args:
            servers: Comma-separated list of server names (e.g., "fetch,sqlite")

        Returns:
            Status message with available tools.
        """
        if not check_docker_mcp_available():
            return ToolResult.failed(
                "Docker MCP Toolkit not installed.\n\n"
                "Please install Docker Desktop 29+ with MCP Toolkit enabled.\n"
                "See: https://docs.docker.com/desktop/extensions/mcp/"
            )

        published = False
        changed = False
        try:
            from .manager import MCPGatewayManager
            from .gateway import DockerMCPGatewayError, DockerMCPNotInstalledError

            server_list = [s.strip() for s in servers.split(",") if s.strip()]
            if not server_list:
                return ToolResult.failed(
                    "No servers specified. Provide a comma-separated server "
                    "list, e.g. `fetch,sqlite`."
                )

            # Honesty gate: never "enable" a name the catalog says can't
            # exist (#9). Validate BEFORE tearing down the running gateway,
            # so a bad request doesn't disrupt a working one.
            rejection = await self._reject_unknown_servers(server_list)
            if rejection is not None:
                return rejection

            changed = True
            await self._retire_gateway()
            self._require_open()
            self.gateway_manager = MCPGatewayManager()
            tools = await self.gateway_manager.start(server_list)

            self._require_open()
            tool_names = [t.name for t in tools]
            # Docker exposes an aggregated tool catalog, not per-server
            # readiness. Persist desired configuration, never an invented
            # observed-enabled set.
            await self._reconcile_gateway_persistence(server_list)
            self._require_open()
            mounted = self._mount_gateway_tools()

            mount_note = (
                f"\n\n**Mounted {mounted} tools** — call them directly."
                if mounted else
                "\n\nNo callable tools were retained by the host registry."
            )
            tools_line = (
                f"**Tools:** {', '.join(tool_names[:10])}"
                + (f" (+{len(tool_names) - 10} more)" if len(tool_names) > 10 else "")
                if tool_names else "**Tools:** none mounted"
            )
            data = {
                "requested": server_list,
                "tools": tool_names,
                "mounted": mounted,
            }
            # Requested server names and observed tools are different facts.
            summary = (
                f"**Requested:** {', '.join(server_list)}\n"
                f"{tools_line}" + mount_note
            )
            published = True
            if not tool_names:
                return ToolResult.partial(
                    f"Gateway started but mounted 0 tools from "
                    f"{len(server_list)} requested server(s). The servers may "
                    f"need credentials or configuration.\n\n{summary}",
                    "no tools mounted from the requested servers",
                    data=data,
                )
            return _loaded_tool_result(
                f"Gateway started with {len(tool_names)} tools.\n\n{summary}",
                data=data,
            )

        except (DockerMCPGatewayError, DockerMCPNotInstalledError) as e:
            logger.error(f"Gateway error: {e}")
            return ToolResult.failed(f"Failed to start gateway: {str(e)}")
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout starting gateway: {e}")
            return ToolResult.failed("Failed to start gateway: Connection timeout")
        except Exception as e:
            logger.error(f"Unexpected error starting gateway: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to start gateway: {str(e)}")

        finally:
            if changed and not published:
                self._unmount_tools(_GATEWAY_OWNER)

    @tool(
        name="mcp_gateway_stop",
        description="Stop the Docker MCP Gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-stop"
    )
    @_serialize_docker_operation(starts=False)
    async def gateway_stop(self) -> ToolResult:
        """Stop the Docker MCP Gateway."""
        # stop = explicit disable: clear persisted gateway servers FIRST and
        # unconditionally, so auto-restore can be turned off even when the
        # gateway isn't currently connected (Docker absent at restore, a crash,
        # or deltas left from a prior run). Otherwise "off" would be impossible.
        await self._forget_all_gateway_servers()

        had_owner = self.gateway_manager is not None
        try:
            await self._retire_gateway()
            return ToolResult.ok("Gateway stopped." if had_owner else "Gateway is not running.")
        except asyncio.CancelledError:
            logger.info("Gateway stop cancelled")
            raise
        except Exception as e:
            logger.error(f"Failed to stop gateway: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to stop gateway: {str(e)}")

    @tool(
        name="mcp_gateway_tools",
        description="List tools available through the Docker MCP Gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-tools"
    )
    async def gateway_tools(self) -> ToolResult:
        """List all tools available through the gateway."""
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.failed("Gateway not running. Use `!mcp-gateway-start` first.")

        tools = self.gateway_manager.get_all_tools()
        if not tools:
            return ToolResult.ok("No tools available.", data={"tools": []})

        lines = [f"**Gateway Tools ({len(tools)} available):**\n"]
        for t in tools:
            desc = t.get('description', 'No description')[:80]
            lines.append(f"- **{t['name']}**: {desc}")

        return ToolResult.ok(
            "\n".join(lines),
            data={"tools": [t['name'] for t in tools]},
        )

    @tool(
        name="mcp_gateway_enable",
        description="Enable an additional server in the gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-enable"
    )
    async def gateway_enable(self, server_name: str) -> ToolResult:
        """
        Enable an additional server in the gateway.

        Args:
            server_name: Name of the server to enable
        """
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.failed("Gateway not running. Use `!mcp-gateway-start` first.")

        return await self._load_via_gateway(server_name)

    @tool(
        name="mcp_docker_catalog",
        description="Search Docker's MCP catalog (311+ servers).",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-docker-catalog"
    )
    async def docker_catalog_search(self, query: str = None) -> ToolResult:
        """
        Search or list servers from Docker's MCP catalog.

        Args:
            query: Optional search term (leave empty to see summary)
        """
        if not check_docker_mcp_available():
            return ToolResult.failed(
                "Docker MCP Toolkit not installed.\n\n"
                "Please install Docker Desktop 29+ with MCP Toolkit enabled."
            )

        try:
            if not query:
                servers = await list_docker_catalog_servers()
                gateway = self.gateway_manager
                requested = sorted(gateway.gateway.requested_servers) if gateway else []
                return ToolResult.ok(
                    f"Docker MCP catalog: {len(servers)} servers available.\n\n"
                    f"**Requested by this gateway:** {', '.join(requested) or 'none'}",
                    data={"available": len(servers), "requested": requested},
                )
            results = await search_docker_catalog(query)
        except DockerCatalogError as error:
            return ToolResult.failed(str(error))
        if not results:
            return ToolResult.ok(
                f"No servers found matching '{query}'.",
                data={"query": query, "results": []},
            )

        lines = [f"**Docker MCP servers matching '{query}':**\n"]
        for s in results[:15]:
            desc = s.get('description', 'No description')[:100]
            lines.append(f"- **{s['name']}**: {desc}")

        if len(results) > 15:
            lines.append(f"\n... and {len(results) - 15} more")

        lines.append("\n\nUse `!mcp-gateway-start <server>` to start with a specific server.")
        return ToolResult.ok(
            "\n".join(lines),
            data={"query": query, "results": [s['name'] for s in results]},
        )

    async def post_all_features_loaded(self, agent=None):
        """Auto-restore MCP servers this agent previously enabled.

        Reads the persisted ``mcp_server`` enablement deltas (foundation) and
        re-starts the gateway / re-loads containers so an ``enable`` survives a
        restart. A host without the enablement store restores nothing. Known
        database failures are reported without blocking unrelated remote rows
        or later gateway/container restore. Unexpected remote errors and
        cancellation propagate.
        """
        if not self._supports_enablement_persistence():
            return
        try:
            deltas = await self.agent.get_enablement_deltas("mcp_server")
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not read persisted MCP servers: %s", e)
            return

        enabled = [d for d in deltas if d.get("state") == "enabled"]
        if not enabled:
            return

        def _mode(d):
            return (d.get("metadata") or {}).get("mode")

        gateway_servers = [d["name"] for d in enabled if _mode(d) == "gateway"]
        containers = [d for d in enabled if _mode(d) == "container"]
        for saved in (d for d in enabled if _mode(d) == "remote"):
            metadata = saved["metadata"]
            if (metadata.get("auth") != "none"
                    or set(metadata) - {"mode", "url", "auth"}):
                logger.error("Refusing unsupported authentication/configuration for remote MCP %s", saved["name"])
                continue
            try:
                result = await self._load_via_remote(metadata.get("url"), expected_name=saved["name"])
                if result.status.value == "error":
                    logger.error("Failed to restore remote MCP %s: %s", saved["name"], result.error)
            except* DatabaseError as errors:
                logger.error("Failed to restore remote MCP %s: %s",
                             saved["name"], connection_error_message(errors))

        if gateway_servers and check_docker_mcp_available():
            try:
                await self.gateway_start(",".join(gateway_servers))
                logger.info(
                    "Restored %d persisted MCP gateway server(s): %s",
                    len(gateway_servers), gateway_servers,
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to restore MCP gateway servers %s: %s",
                               gateway_servers, e)

        if containers and not await self._ensure_container_manager():
            logger.warning("Cannot restore MCP containers: agent-bound container manager is unavailable")
            return

        for d in containers:
            image = (d.get("metadata") or {}).get("image")
            if not image:
                continue
            try:
                from .manager import container_name_for_image

                expected_name = container_name_for_image(image, self.manager.owner_did)
                if d["name"] != expected_name:
                    raise ValueError(
                        "Stored MCP connection identifier does not match this agent's ownership. "
                        "Remove that saved connection and reconnect it explicitly."
                    )
                await self._load_via_container(image, (d.get("metadata") or {}).get("args"))
                logger.info("Restored persisted MCP container from image %s", image)
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to restore MCP container %s: %s", image, e)

    async def shutdown(self):
        """Attempt every owned cleanup, then propagate any cleanup failure."""
        self._closing = True
        self._lifecycle_generation += 1
        async with self._lifecycle_transition:
            self._closing = True
            await self._shutdown_connections()

    async def _shutdown_connections(self):
        # Starts hold the operations gate through persistence/publication. The
        # initialization gate also joins direct manager acquisition, so no
        # client can appear after the cleanup snapshot and escape custody.
        async with self._docker_operations, self._docker_initialization:
            await self._release_connections()

    async def _release_connections(self):
        manager = self.manager

        async def close_drained_manager():
            # Failed stops retain their records AND the client needed to retry.
            # Closing that client would make re-enable lose cleanup custody.
            if not manager.owned_containers:
                await manager.aclose()

        async def stop_remote(name):
            async with connection_lifecycle(self._remote_lifecycle, name):
                try:
                    await self._retire_remote(name)
                finally:
                    self._unmount_tools(remote_owner(name))

        async def stop_container(name):
            try:
                await manager.stop_tool(name)
            finally:
                self._unmount_tools(_container_owner(name))

        # The stack attempts all callbacks even if an earlier resource fails
        # or its caller is cancelled. Docker closes after the server owners.
        async with AsyncExitStack() as cleanup:
            if manager is not None:
                cleanup.push_async_callback(close_drained_manager)
                for name in reversed(list(manager.owned_containers)):
                    cleanup.push_async_callback(stop_container, name)
            for name in reversed(list(self._remote_connections)):
                cleanup.push_async_callback(stop_remote, name)
            cleanup.push_async_callback(self._retire_gateway)
