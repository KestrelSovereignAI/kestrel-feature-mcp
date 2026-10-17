"""Read the official MCP Registry's versioned discovery contract."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib.resources import files
import json
import math
import os
from typing import Any
from urllib.parse import quote, urlsplit

import httpx2
from jsonschema import Draft202012Validator
from kestrel_sdk.security.outbound import (
    SSRFError,
    assert_safe_url,
    pinned_httpx2_async_transport,
)


class OfficialRegistryError(RuntimeError):
    """The selected registry could not supply valid discovery metadata."""


def _reject_json_constant(value: str) -> None:
    raise OfficialRegistryError(f"MCP Registry response contains an invalid JSON constant: {value}")


@dataclass(frozen=True)
class RegistrySettings:
    api_url: str = "https://registry.modelcontextprotocol.io/v0.1"
    timeout: float = 30.0
    max_response_bytes: int = 2 * 1024 * 1024

    def __post_init__(self) -> None:
        try:
            origin = urlsplit(self.api_url)
            port = origin.port
        except (ValueError, UnicodeError) as error:
            raise OfficialRegistryError("Invalid MCP Registry API URL") from error
        if (
            origin.scheme != "https" or not origin.hostname
            or origin.username is not None or origin.password is not None
            or origin.query or origin.fragment or port == 0
        ):
            raise OfficialRegistryError(
                "MCP Registry API URL must use HTTPS without credentials, query or fragment"
            )
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise OfficialRegistryError("MCP Registry timeout must be finite and positive")
        if type(self.max_response_bytes) is not int or self.max_response_bytes <= 0:
            raise OfficialRegistryError("MCP Registry response limit must be a positive integer")

    @classmethod
    def from_environment(cls) -> RegistrySettings:
        try:
            timeout = float(os.environ.get("KESTREL_MCP_REGISTRY_TIMEOUT", "30"))
            size = int(os.environ.get("KESTREL_MCP_REGISTRY_MAX_BYTES", "2097152"))
        except ValueError as error:
            raise OfficialRegistryError("Invalid MCP Registry timeout or response limit") from error
        return cls(
            api_url=os.environ.get("KESTREL_MCP_REGISTRY_URL", cls.api_url),
            timeout=timeout,
            max_response_bytes=size,
        )


@dataclass
class RegistryPage:
    registry_url: str
    payload: dict[str, Any]

    @property
    def servers(self) -> list[dict[str, Any]]:
        return self.payload["servers"]

    @property
    def next_cursor(self) -> str | None:
        return self.payload.get("metadata", {}).get("nextCursor") or None


class OfficialRegistryClient:
    """Bounded HTTPS requests; published JSON objects remain the source of truth.

    Discovery never fetches a server's endpoint, installs a package or supplies
    a credential. A page is explicit: the caller chooses whether to request its
    next opaque cursor instead of silently downloading the entire registry.
    """

    def __init__(self, settings: RegistrySettings | None = None):
        self.settings = settings if settings is not None else RegistrySettings.from_environment()
        resource = files("kestrel_feature_mcp").joinpath("registry_openapi_2025_12_01.json")
        with resource.open("r", encoding="utf-8") as stream:
            contract = json.load(stream)
        self._components = contract["components"]
        self._schemas = self._components["schemas"]

    def _validate(self, payload: Any, component: str) -> None:
        schema = {"$ref": f"#/components/schemas/{component}", "components": self._components}
        error = next(Draft202012Validator(schema).iter_errors(payload), None)
        if error is not None:
            raise OfficialRegistryError(
                f"MCP Registry schema error at {error.json_path} ({error.validator})"
            )

    def _segment(self, value: str, field: str) -> str:
        schema = self._schemas["ServerDetail"]["properties"][field]
        error = next(Draft202012Validator(schema).iter_errors(value), None)
        if error is not None or not value:
            raise OfficialRegistryError(f"Invalid MCP Registry server {field}")
        try:
            encoded = quote(value, safe="")
        except UnicodeError as error:
            raise OfficialRegistryError(f"Invalid MCP Registry server {field} encoding") from error
        # Literal dot segments are normalized by HTTP clients before sending.
        return "%2E" * len(encoded) if encoded in (".", "..") else encoded

    async def _get(self, path: str, *, component: str, params: dict[str, Any] | None = None) -> Any:
        url = self.settings.api_url.rstrip("/") + path
        try:
            async with asyncio.timeout(self.settings.timeout):
                validated = await assert_safe_url(url, allowed_schemes=("https",))
                transport = pinned_httpx2_async_transport(validated)
                async with httpx2.AsyncClient(
                    transport=transport, timeout=self.settings.timeout,
                    follow_redirects=False, trust_env=False,
                ) as client:
                    async with client.stream("GET", url, params=params) as response:
                        response.raise_for_status()
                        body = bytearray()
                        chunk_size = min(65536, self.settings.max_response_bytes + 1)
                        async for chunk in response.aiter_bytes(chunk_size=chunk_size):
                            body.extend(chunk)
                            if len(body) > self.settings.max_response_bytes:
                                raise OfficialRegistryError("MCP Registry response exceeds its byte limit")
                payload = await asyncio.to_thread(json.loads, body, parse_constant=_reject_json_constant)
                await asyncio.to_thread(self._validate, payload, component)
                return payload
        except TimeoutError as error:
            raise OfficialRegistryError("MCP Registry request exceeded its deadline") from error
        except (SSRFError, httpx2.HTTPError, httpx2.InvalidURL, UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise OfficialRegistryError(f"MCP Registry request failed: {error}") from error

    async def search(
        self, query: str | None = None, *, cursor: str | None = None, limit: int = 20,
    ) -> RegistryPage:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise OfficialRegistryError("MCP Registry page size must be an integer from 1 to 100")
        if cursor is not None and (not isinstance(cursor, str) or not cursor):
            raise OfficialRegistryError("MCP Registry cursor must be a nonempty opaque string")
        if query is not None and (not isinstance(query, str) or not query.strip()):
            raise OfficialRegistryError("MCP Registry search must be a nonempty string")
        params: dict[str, Any] = {"version": "latest", "limit": limit}
        if query is not None:
            params["search"] = query
        if cursor is not None:
            params["cursor"] = cursor
        payload = await self._get("/servers", component="ServerList", params=params)
        count = len(payload["servers"])
        if count > limit:
            raise OfficialRegistryError("MCP Registry exceeded the requested page size")
        if payload.get("metadata", {}).get("count", count) != count:
            raise OfficialRegistryError("MCP Registry page count does not match its records")
        next_cursor = payload.get("metadata", {}).get("nextCursor")
        if cursor is not None and next_cursor == cursor:
            raise OfficialRegistryError("MCP Registry repeated its pagination cursor")
        return RegistryPage(self.settings.api_url.rstrip("/"), payload)

    async def get(self, server_name: str, *, version: str = "latest") -> dict[str, Any]:
        name_segment = self._segment(server_name, "name")
        version_segment = self._segment(version, "version")
        payload = await self._get(f"/servers/{name_segment}/versions/{version_segment}", component="ServerResponse")
        if payload["server"]["name"] != server_name:
            raise OfficialRegistryError("MCP Registry returned a different server identity")
        if version != "latest" and payload["server"]["version"] != version:
            raise OfficialRegistryError("MCP Registry returned a different server version")
        return payload
