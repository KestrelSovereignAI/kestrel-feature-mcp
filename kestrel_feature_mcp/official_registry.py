"""Read the official MCP Registry's versioned discovery contract."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from importlib.resources import files
import json
import math
import os
from typing import Any, Iterable
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
    max_problem_chars: int = 256
    max_problems_per_record: int = 4
    max_text_chars: int = 8192

    def __post_init__(self) -> None:
        try:
            origin = urlsplit(self.api_url)
            port = origin.port
        except (ValueError, UnicodeError) as error:
            raise OfficialRegistryError("Invalid MCP Registry API URL") from error
        if (
            origin.scheme != "https" or not origin.hostname
            or origin.username is not None or origin.password is not None
            or "?" in self.api_url or "#" in self.api_url or port == 0
        ):
            raise OfficialRegistryError(
                "MCP Registry API URL must use HTTPS without credentials, query or fragment"
            )
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise OfficialRegistryError("MCP Registry timeout must be finite and positive")
        if type(self.max_response_bytes) is not int or self.max_response_bytes <= 0:
            raise OfficialRegistryError("MCP Registry response limit must be a positive integer")
        if type(self.max_problem_chars) is not int or self.max_problem_chars < 64:
            raise OfficialRegistryError("MCP Registry diagnostic limit must be an integer of at least 64")
        if type(self.max_problems_per_record) is not int or self.max_problems_per_record <= 0:
            raise OfficialRegistryError("MCP Registry diagnostic count must be a positive integer")
        if type(self.max_text_chars) is not int or self.max_text_chars < 256:
            raise OfficialRegistryError("MCP Registry text limit must be an integer of at least 256")

    def diagnostic(self, value: str) -> str:
        """Bound schema paths, instance reprs and rejected names at one boundary."""
        suffix = " [truncated]"
        if len(value) <= self.max_problem_chars:
            return value
        return value[:self.max_problem_chars - len(suffix)] + suffix

    def render(self, lines: Iterable[str]) -> str:
        """Keep complete record blocks; an omitted opaque value is never shortened."""
        notice = "Display blocks omitted; inspect the complete payload (data.result for tools)."
        budget = self.max_text_chars - len(notice) - 1
        selected = []
        omitted = False
        used = 0
        for line in lines:
            size = len(line) + bool(selected)
            if used + size <= budget:
                selected.append(line)
                used += size
            else:
                omitted = True
        if omitted:
            selected.append(notice)
        return "\n".join(selected)

    def schema_error(self, problems: Iterable[RegistryProblem]) -> str:
        return self.render([
            "MCP Registry schema error:",
            *(json.dumps({"index": p.record_index, **p.to_dict()}, ensure_ascii=True) for p in problems),
        ])

    @classmethod
    def from_environment(cls) -> RegistrySettings:
        try:
            timeout = float(os.environ.get("KESTREL_MCP_REGISTRY_TIMEOUT", "30"))
            size = int(os.environ.get("KESTREL_MCP_REGISTRY_MAX_BYTES", "2097152"))
            problem_chars = int(os.environ.get("KESTREL_MCP_REGISTRY_PROBLEM_CHARS", str(cls.max_problem_chars)))
            problem_count = int(os.environ.get("KESTREL_MCP_REGISTRY_PROBLEMS_PER_RECORD", str(cls.max_problems_per_record)))
            text_chars = int(os.environ.get("KESTREL_MCP_REGISTRY_TEXT_CHARS", str(cls.max_text_chars)))
        except ValueError as error:
            raise OfficialRegistryError("Invalid MCP Registry timeout or response limit") from error
        return cls(
            api_url=os.environ.get("KESTREL_MCP_REGISTRY_URL", cls.api_url),
            timeout=timeout,
            max_response_bytes=size,
            max_problem_chars=problem_chars, max_problems_per_record=problem_count, max_text_chars=text_chars,
        )


@dataclass
class RegistryPage:
    registry_url: str
    payload: dict[str, Any]
    problems: tuple[RegistryProblem, ...] = ()
    settings: RegistrySettings = field(default_factory=RegistrySettings)

    @property
    def servers(self) -> list[dict[str, Any]]:
        rejected = {problem.record_index for problem in self.problems}
        return [record for index, record in enumerate(self.payload["servers"]) if index not in rejected]

    @property
    def rejected_records(self) -> list[dict[str, Any]]:
        rejected = []
        for index in sorted({problem.record_index for problem in self.problems}):
            record = self.payload["servers"][index]
            server = record.get("server") if isinstance(record, dict) else None
            name = server.get("name") if isinstance(server, dict) else None
            rejected.append({
                "index": index, "name": self.settings.diagnostic(name) if isinstance(name, str) else None,
                "problems": [p.to_dict() for p in self.problems if p.record_index == index],
            })
        return rejected

    @property
    def next_cursor(self) -> str | None:
        return self.payload.get("metadata", {}).get("nextCursor") or None


@dataclass(frozen=True)
class RegistryProblem:
    record_index: int
    path: str
    keyword: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "keyword": self.keyword, "detail": self.detail}


@dataclass
class RegistryRecord:
    registry_url: str
    payload: dict[str, Any]
    problems: tuple[RegistryProblem, ...] = ()
    settings: RegistrySettings = field(default_factory=RegistrySettings)

    def require_valid(self) -> dict[str, Any]:
        """Refuse a record rejected during this inspection."""
        if self.problems:
            raise OfficialRegistryError(self.settings.schema_error(self.problems))
        return self.payload


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
        self._validators = {
            component: Draft202012Validator({
                "$ref": f"#/components/schemas/{component}", "components": self._components,
            })
            for component in ("ServerList", "ServerResponse")
        }
        self._validators.update({
            field: Draft202012Validator(self._schemas["ServerDetail"]["properties"][field])
            for field in ("name", "version")
        })

    def _validate(self, payload: Any, component: str) -> tuple[RegistryProblem, ...]:
        problems = []
        counts: dict[int, int] = {}
        for error in self._validators[component].iter_errors(payload):
            path = tuple(error.absolute_path)
            index = 0
            if component == "ServerList":
                if len(path) < 2 or path[0] != "servers" or type(path[1]) is not int:
                    raise OfficialRegistryError(
                        "MCP Registry schema error at "
                        + json.dumps(self.settings.diagnostic(error.json_path), ensure_ascii=True)
                        + f" ({error.validator})"
                    )
                index = path[1]
            counts[index] = counts.get(index, 0) + 1
            if counts[index] <= self.settings.max_problems_per_record:
                problems.append(RegistryProblem(
                    index, self.settings.diagnostic(error.json_path), error.validator,
                    self.settings.diagnostic(error.message),
                ))
        # Retain a rejection for every invalid record, even after its detail cap.
        # A page-wide cap could accidentally admit records whose errors were dropped.
        for index, count in counts.items():
            omitted = count - self.settings.max_problems_per_record
            if omitted > 0:
                problems.append(RegistryProblem(index, "$", "omitted", f"{omitted} additional schema errors omitted"))
        return tuple(problems)

    def _segment(self, value: str, field: str) -> str:
        error = next(self._validators[field].iter_errors(value), None)
        if error is not None or not value:
            raise OfficialRegistryError(f"Invalid MCP Registry server {field}")
        try:
            encoded = quote(value, safe="")
        except UnicodeError as error:
            raise OfficialRegistryError(f"Invalid MCP Registry server {field} encoding") from error
        # Literal dot segments are normalized by HTTP clients before sending.
        return "%2E" * len(encoded) if encoded in (".", "..") else encoded

    async def _get(
        self, path: str, *, component: str, params: dict[str, Any] | None = None,
        max_records: int | None = None,
    ) -> tuple[Any, tuple[RegistryProblem, ...]]:
        url = self.settings.api_url.rstrip("/") + path
        try:
            async with asyncio.timeout(self.settings.timeout):
                validated = await assert_safe_url(url, allowed_schemes=("https",))
                transport = pinned_httpx2_async_transport(validated)
                async with httpx2.AsyncClient(
                    transport=transport, timeout=self.settings.timeout,
                    follow_redirects=False, trust_env=False,
                ) as client:
                    async with client.stream("GET", validated.url, params=params) as response:
                        response.raise_for_status()
                        body = bytearray()
                        chunk_size = min(65536, self.settings.max_response_bytes + 1)
                        async for chunk in response.aiter_bytes(chunk_size=chunk_size):
                            body.extend(chunk)
                            if len(body) > self.settings.max_response_bytes:
                                raise OfficialRegistryError("MCP Registry response exceeds its byte limit")
                payload = await asyncio.to_thread(json.loads, body, parse_constant=_reject_json_constant)
                if (max_records is not None and isinstance(payload, dict)
                        and isinstance(payload.get("servers"), list)
                        and len(payload["servers"]) > max_records):
                    raise OfficialRegistryError("MCP Registry exceeded the requested page size")
                problems = await asyncio.to_thread(self._validate, payload, component)
                return payload, problems
        except TimeoutError as error:
            raise OfficialRegistryError("MCP Registry request exceeded its deadline") from error
        except (SSRFError, httpx2.HTTPError, httpx2.InvalidURL, UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise OfficialRegistryError("MCP Registry request failed: " + self.settings.diagnostic(str(error))) from error

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
        payload, problems = await self._get("/servers", component="ServerList", params=params, max_records=limit)
        count = len(payload["servers"])
        if payload.get("metadata", {}).get("count", count) != count:
            raise OfficialRegistryError("MCP Registry page count does not match its records")
        next_cursor = payload.get("metadata", {}).get("nextCursor")
        if cursor is not None and next_cursor == cursor:
            raise OfficialRegistryError("MCP Registry repeated its pagination cursor")
        return RegistryPage(self.settings.api_url.rstrip("/"), payload, problems, self.settings)

    async def get(self, server_name: str, *, version: str = "latest") -> RegistryRecord:
        name_segment = self._segment(server_name, "name")
        version_segment = self._segment(version, "version")
        payload, problems = await self._get(f"/servers/{name_segment}/versions/{version_segment}", component="ServerResponse")
        if not isinstance(payload, dict) or not isinstance(payload.get("server"), dict):
            raise OfficialRegistryError("MCP Registry returned an invalid server response")
        if payload["server"].get("name") != server_name:
            raise OfficialRegistryError("MCP Registry returned a different server identity")
        if version != "latest" and payload["server"].get("version") != version:
            raise OfficialRegistryError("MCP Registry returned a different server version")
        return RegistryRecord(self.settings.api_url.rstrip("/"), payload, problems, self.settings)
