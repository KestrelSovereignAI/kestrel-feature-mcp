"""Remote connection records; URL and egress policy belong to the shared SDK."""

from dataclasses import dataclass
import json

from mcp import types
from kestrel_sdk.security.outbound import ValidatedOutboundURL

from .connection import MCPConnection, connection_digest, describe_tools


class RemoteMCPError(RuntimeError):
    """Remote connection configuration or lifecycle cannot be completed."""


def connection_error_message(error: BaseException) -> str:
    if isinstance(error, BaseExceptionGroup):
        return "; ".join(connection_error_message(child) for child in error.exceptions)
    return str(error)


def remote_name_for_url(canonical_url: str, owner_did: str, *, principal_id: str | None = None) -> str:
    resource = canonical_url if principal_id is None else json.dumps(
        ['oauth', principal_id, canonical_url], separators=(',', ':'))
    return "mcp-remote-" + connection_digest(resource, owner_did)


def remote_owner(name: str) -> str:
    return "mcp:remote:" + name


@dataclass
class RemoteMCPServer:
    name: str
    endpoint: ValidatedOutboundURL
    connection: MCPConnection
    tools: list[types.Tool] | None = None
    credential: object | None = None

    @property
    def owner(self) -> str:
        return remote_owner(self.name)

    def tool_descriptions(self) -> list[dict]:
        return describe_tools(self.connection, self.tools or [],
                              connection=self.name, via="remote", url=self.endpoint.url)
