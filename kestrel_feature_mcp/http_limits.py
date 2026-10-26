"""HTTP body budgets before the native SDK buffers or decodes a response."""

import httpx2


class MCPResponseLimitError(httpx2.StreamError):
    """An untrusted response exceeded the configured transport contract."""


class _ResponseStream(httpx2.AsyncByteStream):
    def __init__(self, response, max_bytes):
        self._stream = response.stream
        self._max_bytes = max_bytes
        self._encoding = response.headers.get("content-encoding", "identity").strip().lower()
        self._length = response.headers.get("content-length")
        self._is_sse = response.headers.get("content-type", "").partition(";")[0].strip().lower() == "text/event-stream"
        self._closed = False

    async def __aiter__(self):
        try:
            # HTTPX decompresses after this raw stream. Negotiate identity and
            # refuse a peer that ignores it before allocating decoded bytes.
            if self._encoding != "identity":
                raise MCPResponseLimitError("MCP response content encoding must be identity")
            if not self._is_sse and self._length is not None:
                try:
                    length = int(self._length)
                except ValueError as error:
                    raise MCPResponseLimitError("MCP response Content-Length is invalid") from error
                if length < 0 or length > self._max_bytes:
                    raise MCPResponseLimitError("MCP response byte limit exceeded")
            total = 0
            async for chunk in self._stream:
                if not self._is_sse:
                    total += len(chunk)
                    if total > self._max_bytes:
                        raise MCPResponseLimitError("MCP response byte limit exceeded")
                yield chunk
        finally:
            await self.aclose()

    async def aclose(self):
        if not self._closed:
            self._closed = True
            await self._stream.aclose()


class MCPResponseBudget:
    """Public HTTPX response hook; SSE events use the native SDK's event cap."""

    def __init__(self, max_bytes):
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("MCP response byte limit must be a positive integer")
        self.max_bytes = max_bytes

    async def __call__(self, response):
        response.stream = _ResponseStream(response, self.max_bytes)
