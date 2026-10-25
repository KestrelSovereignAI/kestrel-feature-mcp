"""Own one RFC 8252 listener before opening a vendor's authorization page."""

from __future__ import annotations

import asyncio
import secrets
from urllib.parse import parse_qs, urlsplit

from mcp.shared.auth import AuthorizationCodeResult


class CallbackRejected(ValueError):
    """A local callback cannot complete the selected authorization attempt."""


class LoopbackCallback:
    """Bounded, one-use callback; no request target or credential is logged."""

    def __init__(self, redirect_uri: str, issuer: str, *, timeout: float,
                 max_connections: int = 32):
        url = urlsplit(redirect_uri)
        if (url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port
                or url.username or url.password or url.query or url.fragment
                or not url.path.startswith("/")):
            raise CallbackRejected("The published callback must be an exact IPv4 loopback URL")
        if not 0 < timeout < float("inf"):
            raise CallbackRejected("Callback timeout must be finite and positive")
        if type(max_connections) is not int or max_connections < 1:
            raise CallbackRejected("Callback connection budget must be a positive integer")
        self.redirect_uri = redirect_uri
        self.issuer = issuer
        self.timeout = timeout
        self.max_connections = max_connections
        self._url = url
        self._state: str | None = None
        self._server: asyncio.Server | None = None
        self._result: asyncio.Future[AuthorizationCodeResult] | None = None
        self._tasks: set[asyncio.Task] = set()
        self._accepted = False

    async def __aenter__(self):
        self._result = asyncio.get_running_loop().create_future()
        # A busy published port is a failure; a different redirect is a new client.
        self._server = await asyncio.start_server(
            self._connected, "127.0.0.1", self._url.port, limit=8192,
            reuse_address=False,
        )
        return self

    async def __aexit__(self, *exc):
        assert self._server is not None and self._result is not None
        self._server.close()
        await self._server.wait_closed()
        # Handlers have a two-second I/O budget and own their writers.
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks))
        if not self._result.done():
            self._result.cancel()
        elif not self._result.cancelled():
            self._result.exception()  # Observe a denial even if its caller was cancelled.

    def arm(self, state: str) -> None:
        if self._server is None or not self._server.is_serving():
            raise CallbackRejected("The callback listener must be owned before authorization")
        if self._state is not None or not state:
            raise CallbackRejected("An authorization attempt can only be armed once")
        self._state = state

    async def result(self) -> AuthorizationCodeResult:
        if self._result is None or self._state is None:
            raise CallbackRejected("No authorization attempt is waiting for a callback")
        async with asyncio.timeout(self.timeout):
            return await asyncio.shield(self._result)

    def _connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if len(self._tasks) >= self.max_connections:
            assert self._server is not None and self._result is not None
            self._server.close()
            writer.close()
            if not self._result.done():
                self._result.set_exception(CallbackRejected(
                    "Callback connection budget exceeded; restart authorization"))
            return
        task = asyncio.create_task(self._handle(reader, writer), name="mcp-oauth-callback")
        self._tasks.add(task)
        # Keep completed tasks until exit so their exceptions are actually joined.

    def _accept(self, raw: bytes) -> tuple[int, bytes]:
        try:
            lines = raw.decode("ascii").split("\r\n")
            method, target, protocol = lines[0].split(" ")
            headers: dict[str, list[str]] = {}
            for line in lines[1:]:
                if not line:
                    continue
                name, value = line.split(":", 1)
                headers.setdefault(name.lower(), []).append(value.strip())
            url = urlsplit(target)
            query = parse_qs(url.query, keep_blank_values=True, max_num_fields=32)
        except (UnicodeError, ValueError):
            return 400, b"Callback rejected."
        if (method != "GET" or protocol not in {"HTTP/1.0", "HTTP/1.1"}
                or len(target) > 4096 or url.scheme or url.netloc or url.fragment
                or url.path != self._url.path
                or headers.get("host") != [self._url.netloc]
                or headers.get("content-length", ["0"]) != ["0"]
                or "transfer-encoding" in headers
                or any(len(values) != 1 for values in query.values())
                or not self._state or len(query.get("state", [])) != 1
                or not secrets.compare_digest(query["state"][0], self._state)
                or query.get("iss") != [self.issuer]):
            return 400, b"Callback rejected."
        assert self._result is not None
        if self._accepted or self._result.done():
            return 409, b"Authorization attempt already completed."
        if query.get("error") and "code" not in query:
            self._accepted = True
            self._result.set_exception(CallbackRejected("The vendor denied authorization"))
            return 200, b"Authorization declined. Return to Kestrel."
        if not query.get("code", [""])[0] or "error" in query:
            return 400, b"Callback rejected."
        self._accepted = True
        self._result.set_result(AuthorizationCodeResult(
            code=query["code"][0], state=query["state"][0], iss=query["iss"][0],
        ))
        return 200, b"Authorization received. Return to Kestrel."

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            async with asyncio.timeout(2):
                raw = await reader.readuntil(b"\r\n\r\n")
                status, body = self._accept(raw)
                header = (f"HTTP/1.1 {status} Callback\r\nContent-Length: {len(body)}\r\n"
                          "Content-Type: text/plain; charset=utf-8\r\n"
                          "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n"
                          "Content-Security-Policy: default-src 'none'\r\n"
                          "Connection: close\r\n\r\n").encode("ascii")
                writer.write(header + body)
                await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                ConnectionError):
            pass  # Invalid or abandoned clients cannot complete the result future.
        finally:
            writer.close()
            try:
                async with asyncio.timeout(2):
                    await writer.wait_closed()
            except (TimeoutError, ConnectionError):
                pass
