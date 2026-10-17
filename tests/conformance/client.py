"""Drive the production connection through selected official MCP scenarios."""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import sys

from kestrel_feature_mcp.connection import MCPConnection


def validate_target(scenario: str, version: str) -> None:
    if scenario not in {"tools_call", "request-metadata"}:
        raise ValueError(f"Unsupported Kestrel conformance scenario: {scenario!r}")
    if version != "2026-07-28":
        raise ValueError(f"Kestrel conformance requires the 2026-07-28 wire, received {version!r}")


async def run_scenario(server_url: str, scenario: str, version: str) -> None:
    validate_target(scenario, version)
    connection = MCPConnection(server_url)
    try:
        tools = await connection.connect()
        if connection.protocol_version != version:
            raise RuntimeError(f"Expected MCP {version}, negotiated {connection.protocol_version}")
        # The tool-call fixture advertises add_numbers. The metadata fixture
        # intentionally advertises no tools and answers generic tool requests.
        if scenario == "tools_call" and "add_numbers" not in {tool.name for tool in tools}:
            raise RuntimeError("The official tool-call fixture did not advertise add_numbers")
        result = await connection.call_tool("add_numbers", {"a": 5, "b": 3})
        if result.is_error:
            raise RuntimeError(f"The conformance tool call failed: {result}")
    finally:
        await connection.close()


def main() -> None:
    if len(sys.argv) != 2:
        raise ValueError("Pass the conformance server URL as the only argument")
    logging.basicConfig(level=logging.INFO)
    logging.getLogger(__name__).info("Exercising MCPConnection from %s", inspect.getfile(MCPConnection))
    asyncio.run(run_scenario(
        sys.argv[1], os.environ["MCP_CONFORMANCE_SCENARIO"],
        os.environ["MCP_CONFORMANCE_PROTOCOL_VERSION"],
    ))


if __name__ == "__main__":
    main()
