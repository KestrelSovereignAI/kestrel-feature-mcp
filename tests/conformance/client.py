"""Drive the production connection through selected official MCP scenarios."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import sys
from pathlib import Path

from kestrel_feature_mcp.connection import MCPConnection


def load_profile() -> dict:
    """Use the same frozen wire and scenario selection in CI and this driver."""
    profile = json.loads(Path(__file__).with_name("profile.json").read_text())
    if not isinstance(profile, dict) or not isinstance(profile.get("protocol_version"), str) or not profile["protocol_version"]:
        raise ValueError("Conformance profile requires a protocol_version wire")
    scenarios = profile.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios or any(not isinstance(item, str) or not item for item in scenarios):
        raise ValueError("Conformance profile requires nonempty scenario names")
    if len(set(scenarios)) != len(scenarios):
        raise ValueError("Conformance profile contains duplicate scenarios")
    return profile


def validate_target(scenario: str, version: str) -> None:
    profile = load_profile()
    if scenario not in profile["scenarios"]:
        raise ValueError(f"Unsupported Kestrel conformance scenario: {scenario!r}")
    if version != profile["protocol_version"]:
        raise ValueError(f"Kestrel conformance requires the {profile['protocol_version']} wire, received {version!r}")


def custom_header_calls() -> list[dict]:
    """Consume the official harness's fixture arguments without reimplementing encoding."""
    raw = os.environ.get("MCP_CONFORMANCE_CONTEXT")
    if raw is None:
        raise ValueError("The custom-header fixture requires MCP_CONFORMANCE_CONTEXT context")
    try:
        context = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("The custom-header fixture context is not valid JSON") from error
    calls = context.get("toolCalls") if isinstance(context, dict) else None
    if not isinstance(calls, list) or not calls:
        raise ValueError("The custom-header fixture context requires nonempty toolCalls")
    for call in calls:
        if not isinstance(call, dict) or not isinstance(call.get("name"), str) or not call["name"]:
            raise ValueError("The custom-header fixture toolCalls require tool names")
        if not isinstance(call.get("arguments"), dict):
            raise ValueError("The custom-header fixture toolCalls require object arguments")
    return calls


async def run_scenario(server_url: str, scenario: str, version: str) -> None:
    validate_target(scenario, version)
    if scenario == "http-custom-headers":
        calls = custom_header_calls()
    elif scenario == "http-standard-headers":
        # The official runner scores only the first call of each method.
        calls = [{"name": name, "arguments": {}} for name in ("my-hyphenated-tool", "test_headers")]
    elif scenario == "http-invalid-tool-headers":
        calls = [{"name": "valid_tool", "arguments": {"region": "us-west1"}}]
    elif scenario == "json-schema-ref-no-deref":
        calls = []
    elif scenario in {"tools_call", "request-metadata"}:
        calls = [{"name": "add_numbers", "arguments": {"a": 5, "b": 3}}]
    else:
        raise ValueError(f"No native driver for conformance scenario: {scenario!r}")
    connection = MCPConnection(server_url)
    try:
        tools = await connection.connect()
        if connection.protocol_version != version:
            raise RuntimeError(f"Expected MCP {version}, negotiated {connection.protocol_version}")
        # The tool-call fixture advertises add_numbers. The metadata fixture
        # intentionally advertises no tools and answers generic tool requests.
        if scenario != "request-metadata":
            required = {call["name"] for call in calls}
            if scenario == "json-schema-ref-no-deref":
                required.add("lookup_user")
            missing = required - {tool.name for tool in tools}
            if missing:
                raise RuntimeError(f"The official {scenario} fixture did not advertise {', '.join(sorted(missing))}")
        # Assert the SDK's rejection instead of filtering fixture names here.
        # Without this, the harness would score uncalled invalid tools green.
        if scenario == "http-invalid-tool-headers" and {tool.name for tool in tools} != {"valid_tool"}:
            raise RuntimeError("The official invalid-header fixture exposed an unexpected native catalog")
        for call in calls:
            result = await connection.call_tool(call["name"], call["arguments"])
            if result.is_error:
                raise RuntimeError(f"The conformance tool call failed: {result}")
        if scenario == "http-standard-headers":
            await connection.read_resource("file:///path/to/file%20name.txt", incarnation=connection.incarnation)
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
