"""Expose selectable Registry endpoints without opening a remote connection."""

from ipaddress import ip_address
import re
from typing import Annotated

import httpx2
import idna
from kestrel_sdk.operator import OperatorAuthorizationError
from kestrel_sdk.security.outbound import SSRFError, validate_outbound_url
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from ._lifecycle import MCPFeatureClosingError
from .http_limits import identity_accept_encoding
from .oauth_policy import GrantRejected, _origin
from .official_registry import OfficialRegistryError, registry_server_name_validator


MAX_CONNECTOR_URL = 4096
MAX_CONNECTOR_NAME = 200
MAX_ENDPOINT_CHOICES = 40
MAX_ENDPOINTS_EXAMINED = 200
NO_STORE = {"Cache-Control": "private, no-store"}


def _selectable_url(url):
    if len(url) > MAX_CONNECTOR_URL or any(char.isspace() or char in r"{}\?#" for char in url):
        return False
    try:
        _origin(url)
        parsed = httpx2.URL(url)
        host = parsed.host
    except (GrantRejected, httpx2.InvalidURL, UnicodeError):
        return False
    if str(parsed) != url or parsed.port == 0 or host.rstrip('.').split('.')[-1] == 'localhost':
        return False
    try:
        ip_address(host)
    except ValueError:
        try:
            last_label = idna.encode(host).decode("ascii").rstrip(".").rsplit(".", 1)[-1]
        except UnicodeError:
            return False
        if last_label.isdigit():
            return False
        if last_label.startswith("0x"):
            return any(char not in "0123456789abcdef" for char in last_label[2:])
        return True
    try:
        return validate_outbound_url(url, allowed_schemes=("https",)).url == url
    except SSRFError:
        return False


class ConnectorPreset(BaseModel):
    """An operator-supplied endpoint and scopes that prefill the consent form."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    name: str = Field(min_length=1, max_length=MAX_CONNECTOR_NAME)
    title: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=500)
    url: str = Field(max_length=MAX_CONNECTOR_URL)
    scopes: list[Annotated[str, StringConstraints(
        max_length=256, pattern=r"^[\x21\x23-\x5B\x5D-\x7E]+$",
    )]] = Field(min_length=1, max_length=32)

    @field_validator("name")
    @classmethod
    def validate_name(cls, name):
        if name.strip() != name or not registry_server_name_validator().is_valid(name):
            raise ValueError("Connector presets require a Registry server name")
        return name

    @field_validator("url")
    @classmethod
    def validate_url(cls, url):
        if not _selectable_url(url):
            raise ValueError("Connector presets require an exact HTTPS endpoint")
        return url

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, scopes):
        if len(set(scopes)) != len(scopes):
            raise ValueError("Connector preset scopes must be unique")
        return scopes


def _needs_extra_header(header):
    if not header.get("isRequired"):
        return False
    name = header["name"].casefold()
    value = header.get("value")
    values = [value] if value is not None else header.get("choices", [None])
    if name == "authorization":
        return not any(value is None or re.fullmatch(r"(?i:bearer) \{[^{}]+\}", value) for value in values)
    if name == "accept-encoding":
        for value in values:
            try:
                identity_accept_encoding(value)
            except ValueError:
                continue
            return False
    return True


def _registry_choices(page, by_identity):
    choices = {}
    examined = 0
    for entry in page.servers:
        server = entry["server"]
        lifecycle = entry.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
        if lifecycle.get("status") == "deleted":
            continue
        for remote in server.get("remotes", []):
            examined += 1
            if examined > MAX_ENDPOINTS_EXAMINED:
                return list(choices.values()), True
            if (remote["type"] != "streamable-http" or not _selectable_url(remote["url"])
                    or any(_needs_extra_header(header) for header in remote.get("headers", []))):
                continue
            name, url = server["name"], remote["url"]
            if len(choices) == MAX_ENDPOINT_CHOICES and (name, url) not in choices:
                return list(choices.values()), True
            choice = by_identity.get((name, url)) or {
                "name": name, "title": _display_text(server.get("title") or name),
                "description": _display_text(server["description"]), "url": url, "scopes": [],
            }
            if lifecycle.get("status") == "deprecated":
                choice = {**choice, "deprecated": True,
                          "status_message": _display_text(lifecycle.get("statusMessage", ""))}
            choices[name, url] = choice
    return list(choices.values()), False


def _display_text(value):
    # Escaped lone surrogates can pass JSON Schema but cannot be sent as UTF-8.
    return value.encode("utf-8", errors="replace").decode("utf-8")


def connector_catalog_router(registry, configured_presets, current_host_check):
    from fastapi import APIRouter, HTTPException, Query, Request, Response

    router = APIRouter(prefix="/api/mcp/connectors", tags=["mcp-connectors"])

    @router.get("/catalog")
    async def catalog(request: Request, response: Response,
                      q: str | None = Query(None, max_length=MAX_CONNECTOR_NAME),
                      cursor: str | None = Query(None, min_length=1)):
        response.headers.update(NO_STORE)
        service = getattr(request.app.state, "request_authentication", None)
        if service is None:
            raise HTTPException(status_code=403, detail="Current Console authentication is required.", headers=NO_STORE)
        try:
            with service.bind(request, require_csrf=False) as authentication:
                check_host = current_host_check(request)
                check_host()
                if q is None:
                    if cursor is not None:
                        raise HTTPException(status_code=422, detail="Search before requesting another page.")
                    return {"connectors": [preset.model_dump() for preset in configured_presets()], "next_cursor": None}
                if len(q.strip()) < 3:
                    raise HTTPException(status_code=422, detail="Enter at least three characters.")
                page = await registry().search(q, cursor=cursor)
                authentication.require_current()
                check_host()
                if page.next_cursor is not None:
                    page.next_cursor.encode("utf-8")
                by_identity = {(preset.name, preset.url): preset.model_dump() for preset in configured_presets()}
                choices, truncated = _registry_choices(page, by_identity)
                return {"connectors": choices, "next_cursor": page.next_cursor,
                        "rejected_records": len(page.rejected_records), "truncated": truncated}
        except OperatorAuthorizationError:
            raise HTTPException(status_code=403, detail="Current Console authentication is required.",
                                headers=NO_STORE) from None
        except MCPFeatureClosingError:
            raise HTTPException(status_code=404, detail="MCP OAuth is unavailable.", headers=NO_STORE) from None
        except (OfficialRegistryError, UnicodeError):
            raise HTTPException(status_code=502, detail="The MCP Registry search failed.", headers=NO_STORE) from None

    return router
