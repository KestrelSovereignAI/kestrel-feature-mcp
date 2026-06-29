"""
MCP Feature Agent - Manages Model Context Protocol (MCP) tools.

This feature provides two modes of operation:

1. **Gateway Mode (Recommended)**: Uses Docker MCP Gateway for unified access
   to 311+ MCP servers. Commands: !mcp-gateway-start, !mcp-gateway-stop

2. **Container Mode (Legacy)**: Direct container management for custom servers.
   Commands: !mcp-load, !mcp-unload

Gateway mode is recommended as it provides access to all servers regardless
of their native transport protocol.
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from kestrel_sdk.features.base import Feature, tool
from kestrel_sdk.tools.base import ToolCategory
from kestrel_sdk.tools.result import ToolResult
from .dynamic_tools import build_wrappers, extract_mcp_result as _extract_mcp_result
from .registry import (
    get_registry,
    MCPRegistry,
    check_docker_mcp_available,
    search_docker_catalog,
    list_enabled_docker_servers,
    format_docker_catalog_summary,
)

# Lazy import to avoid loading MCP/anyio at module import time
# This prevents pytest from hanging due to anyio event loop issues
if TYPE_CHECKING:
    from .manager import MCPToolManager, MCPGatewayManager

logger = logging.getLogger(__name__)

# Dynamic-tool registry owner keys (see ToolRegistryMixin.register_dynamic_tools).
# Gateway-mounted tools share one owner (the gateway aggregates many servers and
# does not attribute tools per-server); each legacy container is its own owner.
_GATEWAY_OWNER = "mcp:gateway"


def _container_owner(container_name: str) -> str:
    return f"mcp:container:{container_name}"


class MCPAgent(Feature):
    """
    A Feature Agent that manages Model Context Protocol (MCP) tools.
    It encapsulates the complexity of Docker container management and tool discovery,
    providing a high-level interface for the main KestrelAgent.
    """

    @property
    def tool_description(self) -> str:
        return (
            "Manage Model Context Protocol (MCP) servers - load MCP tools from Docker images, "
            "list available tools, call tools on running servers, and unload servers"
        )

    async def initialize(self):
        try:
            # Lazy import to avoid loading MCP/anyio at module import time
            from .manager import MCPToolManager, MCPGatewayManager
            self.manager = MCPToolManager()
            self.gateway_manager: Optional["MCPGatewayManager"] = None
            logger.info("MCPAgent initialized.")
        except RuntimeError as e:
            # Docker not available - expected in some environments
            logger.warning(f"MCPAgent initialization failed (likely Docker unavailable): {e}")
            logger.info("MCPAgent disabled - Docker tools will not be available")
            self.manager = None
            self.gateway_manager = None
        except Exception as e:
            logger.warning(f"Unexpected error initializing MCPAgent: {e}", exc_info=True)
            logger.info("MCPAgent disabled - Docker tools will not be available")
            self.manager = None
            self.gateway_manager = None

    # =========================================================================
    # Dynamic tool mounting — make a server's tools first-class LLM tools
    # =========================================================================

    def _host_supports_dynamic_tools(self) -> bool:
        """Whether the host exposes the dynamic-tool registry (#1979 PR2).

        Older hosts lack it; we degrade gracefully to dispatcher-only (the
        ``mcp_gateway_call`` / ``mcp_call_tool`` indirection) rather than fail.
        """
        agent = getattr(self, "agent", None)
        return (
            agent is not None
            and hasattr(agent, "register_dynamic_tools")
            and hasattr(agent, "unregister_dynamic_tools")
        )

    def _mount_tools(self, owner: str, handle_prefix: str, tool_dicts, caller) -> int:
        """Mount a set of MCP tools into the host registry under ``owner``.

        Idempotent refresh: any previously-mounted tools for ``owner`` are
        dropped first, then the current set is registered. Returns the number
        of tools mounted (0 when the host has no dynamic registry).
        """
        if not self._host_supports_dynamic_tools():
            return 0
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
        """Authoritative set of gateway-enableable server names, or ``None``
        when that set is unverifiable.

        The Docker MCP catalog (311+ servers) is the authoritative
        namespace for gateway servers; the local curated registry is only
        a small Kestrel-specific subset. Validation therefore GATES on the
        Docker catalog: it is consulted only when the catalog actually
        produced results. ``list_docker_catalog_servers()`` returns ``[]``
        (not an error) when ``docker mcp catalog show`` times out, fails,
        or Docker is absent — in that case the set is unverifiable and we
        return ``None`` so callers SKIP validation. Crucially we do NOT
        fall back to the small local registry to reject names: a valid
        Docker server absent from that subset would be false-rejected,
        blocking most of the catalog (codex review P2). When the Docker
        catalog IS present, the local registry only *widens* the allowed
        set (union), which can never cause a false rejection.

        Callers MUST treat ``None`` as "unverifiable" and skip validation —
        a false rejection is its own honesty violation. A non-empty set
        means a requested name absent from it provably cannot be enabled,
        so the lifecycle verb rejects it rather than reporting a phantom
        success (#9).
        """
        docker_names: set = set()
        try:
            from .registry import list_docker_catalog_servers
            catalog = await list_docker_catalog_servers()
            docker_names = {s["name"] for s in catalog if s.get("name")}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Docker MCP catalog unavailable for validation: %s", exc)
        if not docker_names:
            # Unverifiable — never reject gateway names from the local
            # subset alone.
            return None
        known = set(docker_names)
        try:
            known.update(entry.name for entry in get_registry().list_all())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Local MCP registry unavailable for validation: %s", exc)
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

    async def _persist_server(self, name: str, state: str, *, metadata=None) -> None:
        """Record an MCP server's enablement (kind='mcp_server') so a restart
        can auto-restore it. Best-effort: never fail the tool call on a
        persistence error."""
        if not self._supports_enablement_persistence():
            return
        try:
            await self.agent.persist_feature_enablement(
                "mcp_server", name, state, actor="agent", metadata=metadata,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to persist MCP server '%s' (%s): %s", name, state, e)

    async def _forget_server(self, name: str) -> None:
        """Drop an MCP server's persisted enablement (explicit removal)."""
        if not self._supports_enablement_persistence():
            return
        try:
            await self.agent.clear_feature_enablement("mcp_server", name)
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to clear persisted MCP server '%s': %s", name, e)

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
        reads ``self.gateway_manager`` at call time so it always targets the
        current connection.
        """
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return 0
        tool_dicts = self.gateway_manager.get_all_tools()
        return self._mount_tools(
            _GATEWAY_OWNER, "gateway", tool_dicts,
            lambda name, arguments: self.gateway_manager.call_tool(name, arguments),
        )

    @staticmethod
    def _normalize_image_ref(ref: Optional[str]) -> Optional[str]:
        """Add the implicit ``:latest`` tag so ``mcp/time`` and ``mcp/time:latest``
        compare equal (Docker treats an untagged ref as ``:latest``)."""
        if not ref:
            return ref
        last = ref.rsplit("/", 1)[-1]
        return ref if ":" in last else f"{ref}:latest"

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
          entry is a raw native-HTTP container, used as-is.
        - A bare name not in the local registry is a Docker-catalog server only
          if the Docker catalog actually knows it; otherwise it is treated as a
          local/custom image (preserving direct-container loads). When the
          catalog is unverifiable, default to the container path so an offline
          host never misroutes a valid local image to the gateway.
        """
        registry = get_registry()
        entry = registry.get(server)
        if entry is None and ("/" in server or ":" in server):
            target = self._normalize_image_ref(server)
            for candidate in registry.list_all():
                refs = {
                    self._normalize_image_ref(candidate.image),
                    self._normalize_image_ref(candidate.full_image),
                }
                if target in refs:
                    entry = candidate
                    break
        if entry is not None:
            if entry.requires_wrapper:
                return ("gateway", entry.name)
            return ("container", entry.full_image or entry.image or server)
        if "/" in server or ":" in server:
            return ("container", server)  # raw native-HTTP image, as given
        known = await self._known_catalog_servers()
        if known is not None and server in known:
            return ("gateway", server)  # bare name the Docker catalog knows
        return ("container", server)  # bare name -> local/custom image

    @tool(
        name="mcp_load_server",
        description=(
            "Load an MCP server by catalog name (e.g. 'time', 'fetch', "
            "'sequentialthinking') or Docker image. Stdio servers load via the "
            "gateway; native-HTTP images run as their own container."
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
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        route, target = await self._resolve_load_route(server)
        if route == "gateway":
            return await self._load_via_gateway(target)
        return await self._load_via_container(target, args)

    async def _load_via_container(self, image_name: str, args: List[str] = None) -> ToolResult:
        """Per-container load path for native-HTTP MCP images."""
        try:
            container_name = await self.manager.start_tool_container(image_name, command=args)
            tools = await self.manager.connect_to_tool(container_name)
            # Mount the container's tools as first-class LLM tools. The caller
            # closure binds the container; the host registry routes the call
            # back through manager.call_tool with the tool's real MCP name.
            tool_dicts = [
                t for t in (self.manager.get_all_tools() or [])
                if t.get("container") == container_name
            ]
            # connect_to_tool returns the tool objects; be defensive if a path
            # ever yields None/empty by falling back to the authoritative mounted
            # set (get_all_tools) so load never false-fails on name extraction.
            if tools:
                tool_names = [t.name for t in tools]
            else:
                tool_names = [t.get("name") for t in tool_dicts if t.get("name")]
            owner = _container_owner(container_name)
            mounted = self._mount_tools(
                owner, container_name, tool_dicts,
                lambda name, arguments, c=container_name: self.manager.call_tool(c, name, arguments),
            )
            # Persist so this container is auto-restored on restart.
            await self._persist_server(
                container_name, "enabled",
                metadata={"mode": "container", "image": image_name, "args": args},
            )
            mount_note = (
                f" Mounted {mounted} as callable tools."
                if mounted else
                " (Call them via mcp_call_tool — host has no dynamic registry.)"
            )
            return ToolResult.ok(
                f"Loaded {image_name} as {container_name}. Tools: {', '.join(tool_names)}."
                + mount_note,
                data={
                    "container": container_name, "image": image_name,
                    "tools": tool_names, "mounted": mounted,
                },
            )
        except (TimeoutError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to load tool {image_name}: {e}")
            return ToolResult.failed(f"Failed to load MCP tool: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error loading tool {image_name}: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to load MCP tool: {str(e)}")

    async def _load_via_gateway(self, server_name: str) -> ToolResult:
        """Load a single catalog/stdio server through the shared gateway.

        Starts the gateway if it is not running yet, otherwise enables the
        server additively on the existing one — so repeated ``mcp_load_server``
        calls accumulate servers in one gateway instead of fighting over it.
        Persists ``mode=gateway`` so it is restored on restart by the same path
        as the gateway verbs.
        """
        if not check_docker_mcp_available():
            return ToolResult.failed(
                "Docker MCP Toolkit not installed.\n\n"
                "Please install Docker Desktop 29+ with MCP Toolkit enabled."
            )
        # Honesty gate: never "load" a name the catalog says can't exist (#9).
        rejection = await self._reject_unknown_servers([server_name])
        if rejection is not None:
            return rejection

        try:
            from .manager import MCPGatewayManager
            from .gateway import DockerMCPGatewayError, DockerMCPNotInstalledError

            if self.gateway_manager is not None and self.gateway_manager.is_connected:
                # The gateway reports a flat aggregated tool list, so the only
                # honest per-server signal is the before/after delta.
                before = set((self.gateway_manager.tools or {}).keys())
                tools = await self.gateway_manager.enable_server(server_name)
            else:
                self.gateway_manager = MCPGatewayManager()
                before = set()
                tools = await self.gateway_manager.start([server_name])

            tool_names = [t.name for t in tools]
            new_tools = sorted(set(tool_names) - before)
            mounted = self._mount_gateway_tools()
            # Persist/report against the gateway's AUTHORITATIVE enabled set:
            # enable_server can fail to add the requested server yet reconnect to
            # the prior servers and return their tools, so a naive persist would
            # auto-restore a server that never loaded (#9 honesty).
            enabled_now = getattr(
                getattr(self.gateway_manager, "gateway", None), "enabled_servers", set()
            )
            if server_name not in enabled_now:
                return ToolResult.failed(
                    f"Could not load {server_name} via the gateway — it did not "
                    f"enable (it may need credentials/configuration). The gateway "
                    f"is still serving {len(tool_names)} tool(s) from other servers.",
                    data={"server": server_name, "enabled": sorted(enabled_now),
                          "tools": tool_names, "via": "gateway"},
                )
            await self._persist_server(
                server_name, "enabled", metadata={"mode": "gateway"},
            )
            data = {
                "server": server_name,
                "tools": tool_names,
                "new_tools": new_tools,
                "mounted": mounted,
                "via": "gateway",
            }
            # A real load that adds no NEW tools is indistinguishable from a
            # no-op unless we say so — surface it as PARTIAL, not a confident
            # "Loaded" (#9 honesty contract).
            if not new_tools:
                return ToolResult.partial(
                    f"Loaded {server_name} via the gateway, but it added 0 new "
                    f"tools (it may need credentials/configuration, or its tools "
                    f"were already present). Gateway total: {len(tool_names)} tools.",
                    f"{server_name} contributed no new tools",
                    data=data,
                )
            return ToolResult.ok(
                f"Loaded {server_name} via the gateway — added {len(new_tools)} "
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
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        # Both load paths count: per-container tools AND gateway-loaded tools
        # (mcp_load_server now routes stdio servers through the gateway, so a
        # listing that ignored the gateway would falsely read as empty).
        tools = list(self.manager.get_all_tools() or [])
        if self.gateway_manager is not None and self.gateway_manager.is_connected:
            for t in self.gateway_manager.get_all_tools():
                tools.append({**t, "container": "gateway"})

        if not tools:
            return ToolResult.ok("No MCP tools loaded.", data={"tools": []})

        response = "Available MCP Tools:\n"
        for t in tools:
            response += f"- [{t.get('container', '?')}] {t['name']}: {t.get('description', '')}\n"
        return ToolResult.ok(response, data={"tools": tools})

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
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        gwm = self.gateway_manager
        if gwm is not None and gwm.is_connected:
            enabled = getattr(getattr(gwm, "gateway", None), "enabled_servers", set())
            # Accept the catalog name OR the same image alias the load accepted
            # (e.g. `mcp/time` -> `time`), so load/unload stay symmetric.
            route, resolved = await self._resolve_load_route(container_name)
            gw_name = resolved if route == "gateway" else None
            target = (
                container_name if container_name in enabled
                else gw_name if gw_name in enabled
                else None
            )
            if target is not None:
                return await self._unload_via_gateway(target)

        try:
            stopped = await self.manager.stop_tool(container_name)
            unmounted = self._unmount_tools(_container_owner(container_name))
            # Explicit removal — forget it so it isn't auto-restored on restart.
            await self._forget_server(container_name)
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
        try:
            remaining = [
                s for s in gwm.gateway.enabled_servers if s != server_name
            ]
            if remaining:
                await gwm.disable_server(server_name)
                mounted = self._mount_gateway_tools()
            else:
                # Last server — tear the gateway down rather than leave an empty
                # one running, and drop the aggregate mount.
                await gwm.stop()
                self._unmount_tools(_GATEWAY_OWNER)
                self.gateway_manager = None
                mounted = 0
            await self._forget_server(server_name)
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

    @tool(
        name="mcp_call_tool",
        description="Call a tool on a specific MCP server.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-call"
    )
    async def call_tool(self, container_name: str, tool_name: str, args: Dict[str, Any]) -> ToolResult:
        """Call a tool on a loaded server.

        ``mcp_list_servers`` lists gateway-loaded tools under the synthetic
        container ``"gateway"``; route that identifier to the gateway so every
        listed tool is actually callable through this verb (container tools
        still dispatch through the per-container manager).
        """
        if self.manager is None:
            return ToolResult.failed("MCP tools are not available (Docker not accessible)")

        try:
            if container_name == "gateway":
                gwm = self.gateway_manager
                if gwm is None or not gwm.is_connected:
                    return ToolResult.failed("Gateway not running; no 'gateway' tools to call.")
                result = await gwm.call_tool(tool_name, args)
            else:
                result = await self.manager.call_tool(container_name, tool_name, args)
            text, is_error = _extract_mcp_result(result)
            if is_error:
                return ToolResult.failed(
                    f"Tool '{tool_name}' reported an error:\n{text}",
                    data={"container": container_name, "tool": tool_name},
                )
            return ToolResult.ok(
                f"Result:\n{text}",
                data={"container": container_name, "tool": tool_name},
            )
        except ValueError as e:
            logger.error(f"Tool not found or invalid arguments: {e}")
            return ToolResult.failed(f"Tool execution failed: {str(e)}")
        except Exception as e:
            logger.error(f"Tool execution failed: {e}", exc_info=True)
            return ToolResult.failed(f"Tool execution failed: {str(e)}")

    @tool(
        name="mcp_search",
        description="Search available MCP servers by capability, name, or category.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-search"
    )
    async def search_servers(self, query: str) -> ToolResult:
        """
        Search the MCP server catalog for servers matching a query.

        Args:
            query: Search term - matches against name, description, tools, and categories

        Returns:
            List of matching MCP servers with their details.
        """
        registry = get_registry()
        matches = registry.search(query)

        if not matches:
            return ToolResult.ok(
                f"No MCP servers found matching '{query}'.\n\nTip: Use `!mcp-catalog` to see all available servers.",
                data={"query": query, "matches": []},
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
            data={"query": query, "matches": [s.name for s in matches]},
        )

    @tool(
        name="mcp_catalog",
        description="List all available MCP servers in the catalog.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-catalog"
    )
    async def show_catalog(self) -> ToolResult:
        """
        Display the full MCP server catalog.

        Returns:
            Formatted list of all available MCP servers.
        """
        registry = get_registry()
        return ToolResult.ok(
            registry.format_catalog(),
            data={"servers": [s.name for s in registry.list_all()]},
        )

    @tool(
        name="mcp_server_info",
        description="Get detailed information about a specific MCP server.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-info"
    )
    async def server_info(self, server_name: str) -> ToolResult:
        """
        Get detailed information about a specific MCP server.

        Args:
            server_name: Name of the server (e.g., "postgres", "fetch")

        Returns:
            Detailed server information including tools and requirements.
        """
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
            data={"server": server.name},
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
    async def gateway_start(self, servers: str = "fetch") -> ToolResult:
        """
        Start the Docker MCP Gateway with specified servers.

        The gateway provides unified access to 311+ MCP servers from Docker's catalog
        with automatic stdio->SSE conversion.

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

            if self.gateway_manager and self.gateway_manager.is_connected:
                await self.gateway_manager.stop()
                self._unmount_tools(_GATEWAY_OWNER)

            self.gateway_manager = MCPGatewayManager()
            tools = await self.gateway_manager.start(server_list)

            tool_names = [t.name for t in tools]
            mounted = self._mount_gateway_tools()
            # The gateway's ACTUAL enabled set is authoritative — a requested
            # server can fail to enable while the gateway still starts with
            # the subset. Persist that set (stale servers forgotten) AND
            # report against it so we never claim a server is running that
            # the gateway dropped.
            actual_set = getattr(getattr(self.gateway_manager, "gateway", None),
                                 "enabled_servers", None)
            actual = sorted(actual_set) if actual_set else list(server_list)
            await self._reconcile_gateway_persistence(actual)
            not_enabled = [s for s in server_list if s not in set(actual)]

            mount_note = (
                f"\n\n**Mounted {mounted} tools** — call them directly."
                if mounted else
                "\n\nUse `!mcp-gateway-call <tool> <args>` to call tools."
            )
            tools_line = (
                f"**Tools:** {', '.join(tool_names[:10])}"
                + (f" (+{len(tool_names) - 10} more)" if len(tool_names) > 10 else "")
                if tool_names else "**Tools:** none mounted"
            )
            data = {
                "requested": server_list,
                "enabled": actual,
                "not_enabled": not_enabled,
                "tools": tool_names,
                "mounted": mounted,
            }
            # The gateway aggregates servers behind a flat tool list and does
            # NOT attribute tools per server, so we can't prove which server
            # produced which tool. Report only what IS verifiable — the
            # gateway's enabled set and the real tool count — and flag a
            # PARTIAL (not a blanket "ok") whenever the effect is short of
            # the request: no tools at all, or a requested server the gateway
            # didn't end up enabling. Callers inspect `Tools:` for coverage.
            summary = (
                f"**Requested:** {', '.join(server_list)}\n"
                f"**Gateway enabled:** {', '.join(actual) or 'none'}\n"
                f"{tools_line}" + mount_note
            )
            if not tool_names:
                return ToolResult.partial(
                    f"Gateway started but mounted 0 tools from "
                    f"{len(server_list)} requested server(s). The servers may "
                    f"need credentials or configuration.\n\n{summary}",
                    "no tools mounted from the requested servers",
                    data=data,
                )
            if not_enabled:
                return ToolResult.partial(
                    f"Gateway started with {len(tool_names)} tools, but "
                    f"{len(not_enabled)} requested server(s) were not enabled: "
                    f"{', '.join(not_enabled)}.\n\n{summary}",
                    f"requested servers not enabled: {', '.join(not_enabled)}",
                    data=data,
                )
            return ToolResult.ok(
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

    @tool(
        name="mcp_gateway_stop",
        description="Stop the Docker MCP Gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-stop"
    )
    async def gateway_stop(self) -> ToolResult:
        """Stop the Docker MCP Gateway."""
        # stop = explicit disable: clear persisted gateway servers FIRST and
        # unconditionally, so auto-restore can be turned off even when the
        # gateway isn't currently connected (Docker absent at restore, a crash,
        # or deltas left from a prior run). Otherwise "off" would be impossible.
        await self._forget_all_gateway_servers()

        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.ok("Gateway is not running.")

        try:
            await self.gateway_manager.stop()
            self.gateway_manager = None
            self._unmount_tools(_GATEWAY_OWNER)
            return ToolResult.ok("Gateway stopped.")
        except asyncio.CancelledError:
            logger.info("Gateway stop cancelled")
            return ToolResult.failed("Gateway stop cancelled")
        except Exception as e:
            logger.error(f"Failed to stop gateway: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to stop gateway: {str(e)}")

    @tool(
        name="mcp_gateway_call",
        description="Call a tool through the Docker MCP Gateway.",
        category=ToolCategory.SYSTEM,
        command_prefix="!mcp-gateway-call"
    )
    async def gateway_call(self, tool_name: str, arguments: Dict[str, Any] = None) -> ToolResult:
        """
        Call a tool through the gateway.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments as JSON object
        """
        if self.gateway_manager is None or not self.gateway_manager.is_connected:
            return ToolResult.failed("Gateway not running. Use `!mcp-gateway-start` first.")

        try:
            result = await self.gateway_manager.call_tool(tool_name, arguments or {})
            text, is_error = _extract_mcp_result(result)
            if is_error:
                return ToolResult.failed(
                    f"**{tool_name}** reported an error:\n\n{text}",
                    data={"tool": tool_name},
                )
            return ToolResult.ok(
                f"**{tool_name}** result:\n\n{text}",
                data={"tool": tool_name},
            )

        except (ValueError, RuntimeError) as e:
            logger.error(f"Gateway tool call failed: {e}")
            return ToolResult.failed(f"Tool call failed: {str(e)}")
        except Exception as e:
            logger.error(f"Gateway tool call failed: {e}", exc_info=True)
            return ToolResult.failed(f"Tool call failed: {str(e)}")

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

        # Honesty gate: reject a name the catalog says can't exist (#9).
        rejection = await self._reject_unknown_servers([server_name])
        if rejection is not None:
            return rejection

        try:
            # Snapshot the tool inventory so we can prove this server
            # actually contributed: enable_server reconnects and returns
            # the gateway's FULL flat list (all servers), so the only
            # honest per-server signal is the before/after delta.
            before = set((self.gateway_manager.tools or {}).keys())
            tools = await self.gateway_manager.enable_server(server_name)
            tool_names = [t.name for t in tools]
            new_tools = sorted(set(tool_names) - before)
            mounted = self._mount_gateway_tools()
            await self._persist_server(server_name, "enabled", metadata={"mode": "gateway"})
            data = {
                "server": server_name,
                "tools": tool_names,
                "new_tools": new_tools,
                "mounted": mounted,
            }
            # A real enable that mounts no NEW tools is indistinguishable
            # from a no-op to the caller unless we say so — surface it as
            # PARTIAL instead of a confident "Enabled" (#9, finding #3).
            if not new_tools:
                return ToolResult.partial(
                    f"Enabled {server_name}, but it added 0 new tools "
                    f"(it may need credentials/configuration, or its tools "
                    f"were already present). Gateway total: {len(tool_names)} "
                    f"tools.",
                    f"{server_name} contributed no new tools",
                    data=data,
                )
            return ToolResult.ok(
                f"Enabled {server_name} — added {len(new_tools)} tool(s): "
                f"{', '.join(new_tools[:10])}"
                + (f" (+{len(new_tools) - 10} more)" if len(new_tools) > 10 else "")
                + f"\n\n**Gateway total:** {len(tool_names)} tools"
                + (f" ({mounted} mounted as callable tools)" if mounted else ""),
                data=data,
            )
        except (ValueError, RuntimeError) as e:
            logger.error(f"Failed to enable server: {e}")
            return ToolResult.failed(f"Failed to enable {server_name}: {str(e)}")
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout enabling server: {e}")
            return ToolResult.failed(f"Failed to enable {server_name}: Connection timeout")
        except Exception as e:
            logger.error(f"Unexpected error enabling server: {e}", exc_info=True)
            return ToolResult.failed(f"Failed to enable {server_name}: {str(e)}")

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

        if not query:
            summary = format_docker_catalog_summary()
            enabled = await list_enabled_docker_servers()
            enabled_str = ", ".join(enabled) if enabled else "none"
            return ToolResult.ok(
                f"{summary}\n\n**Currently enabled:** {enabled_str}",
                data={"enabled": enabled},
            )

        results = await search_docker_catalog(query)
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
        restart. Best-effort and fully guarded: a host without the enablement
        store, or without Docker MCP, simply restores nothing — startup is never
        blocked.
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

        for d in containers:
            image = (d.get("metadata") or {}).get("image")
            if not image:
                continue
            try:
                await self.load_tool(image, (d.get("metadata") or {}).get("args"))
                logger.info("Restored persisted MCP container from image %s", image)
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to restore MCP container %s: %s", image, e)

    async def shutdown(self):
        """Stops all active tools, gateway, and closes the Docker client."""
        if self.gateway_manager and self.gateway_manager.is_connected:
            try:
                await self.gateway_manager.stop()
            except asyncio.CancelledError:
                logger.info("Gateway stop cancelled during shutdown")
            except Exception as e:
                logger.warning(f"Error stopping gateway: {e}", exc_info=True)
            self.gateway_manager = None
        self._unmount_tools(_GATEWAY_OWNER)

        if self.manager is None:
            return

        active_containers = list(self.manager.active_tools.keys())
        for container in active_containers:
            await self.manager.stop_tool(container)
            self._unmount_tools(_container_owner(container))

        self.manager.close()
