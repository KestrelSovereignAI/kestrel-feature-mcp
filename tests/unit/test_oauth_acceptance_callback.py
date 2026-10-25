"""Actual loopback HTTP checks for the manual vendor-consent receiver."""

import asyncio
import os
import socket
from urllib.parse import urlencode, urlsplit

import pytest

from tests.oauth_acceptance.callback import CallbackRejected, LoopbackCallback


ISSUER = "https://issuer.example"
STATE = "a-random-attempt-state"
CODE = "test-authorization-code"


@pytest.fixture
def redirect_uri():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}/oauth/callback"


async def request(redirect_uri, *, fields=None, target=None, headers=None):
    url = urlsplit(redirect_uri)
    if target is None:
        values = {"code": CODE, "state": STATE, "iss": ISSUER} if fields is None else fields
        target = url.path + "?" + urlencode(values)
    extra = [f"Host: {url.netloc}"] if headers is None else headers
    reader, writer = await asyncio.open_connection("127.0.0.1", url.port)
    try:
        writer.write((f"GET {target} HTTP/1.1\r\n" + "\r\n".join(extra)
                      + "\r\n\r\n").encode("ascii"))
        await writer.drain()
        async with asyncio.timeout(5):
            return await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()


async def test_listener_must_be_owned_before_arming_and_busy_port_never_moves(redirect_uri):
    callback = LoopbackCallback(redirect_uri, ISSUER, timeout=5)
    with pytest.raises(CallbackRejected, match="owned before"):
        callback.arm(STATE)
    async with callback:
        async with asyncio.timeout(5):
            with pytest.raises(OSError):
                async with LoopbackCallback(redirect_uri, ISSUER, timeout=5):
                    pytest.fail("The occupied published port was replaced")
        callback.arm(STATE)
        with pytest.raises(CallbackRejected, match="once"):
            callback.arm(STATE)
        reply = await request(redirect_uri)
        assert reply.startswith(b"HTTP/1.1 200")
        result = await callback.result()
        assert (result.code, result.state, result.iss) == (CODE, STATE, ISSUER)
        assert CODE.encode() not in reply and STATE.encode() not in reply
        assert b"Cache-Control: no-store" in reply
        assert b"Referrer-Policy: no-referrer" in reply
        assert (await request(redirect_uri)).startswith(b"HTTP/1.1 409")
    assert not callback._server.is_serving()
    assert all(task.done() for task in callback._tasks)


@pytest.mark.skipif(os.name != "posix", reason="POSIX TIME_WAIT and SO_REUSEADDR contract")
async def test_completed_attempt_can_retry_the_published_callback_port(redirect_uri):
    for _ in range(3):
        async with LoopbackCallback(redirect_uri, ISSUER, timeout=5) as callback:
            callback.arm(STATE)
            assert (await request(redirect_uri)).startswith(b"HTTP/1.1 200")
            assert (await callback.result()).code == CODE


@pytest.mark.parametrize("change", [
    "state", "state-unicode", "state-invalid-utf8", "issuer", "missing-issuer", "code", "duplicate-code", "duplicate-state",
    "path", "host", "duplicate-host", "body", "transfer", "absolute", "fragment",
    "malformed-query",
])
async def test_invalid_http_callback_cannot_consume_the_valid_attempt(redirect_uri, change):
    fields = {"code": CODE, "state": STATE, "iss": ISSUER}
    target = None
    headers = None
    if change == "state":
        fields["state"] = "other-attempt"
    elif change == "state-unicode":
        fields["state"] = "caf\u00e9"
    elif change == "state-invalid-utf8":
        target = "/oauth/callback?" + urlencode(fields).replace("state=" + STATE, "state=%FF")
    elif change == "issuer":
        fields["iss"] = "https://other-issuer.example"
    elif change == "missing-issuer":
        del fields["iss"]
    elif change == "code":
        fields["code"] = ""
    elif change in {"duplicate-code", "duplicate-state"}:
        key = change.removeprefix("duplicate-")
        target = "/oauth/callback?" + urlencode(fields) + f"&{key}=another-value"
    elif change == "path":
        target = "/other?" + urlencode(fields)
    elif change == "host":
        headers = ["Host: attacker.example"]
    elif change == "duplicate-host":
        headers = [f"Host: {urlsplit(redirect_uri).netloc}"] * 2
    elif change == "body":
        headers = [f"Host: {urlsplit(redirect_uri).netloc}", "Content-Length: 1"]
    elif change == "transfer":
        headers = [f"Host: {urlsplit(redirect_uri).netloc}", "Transfer-Encoding: chunked"]
    elif change == "absolute":
        target = redirect_uri + "?" + urlencode(fields)
    elif change == "fragment":
        target = "/oauth/callback?" + urlencode(fields) + "#ignored"
    else:
        assert change == "malformed-query"
        target = "/oauth/callback?not-a-pair"
    async with LoopbackCallback(redirect_uri, ISSUER, timeout=5) as callback:
        callback.arm(STATE)
        waiting = asyncio.create_task(callback.result())
        try:
            assert (await request(redirect_uri, fields=fields, target=target,
                                  headers=headers)).startswith(b"HTTP/1.1 400")
            assert not waiting.done()
            assert (await request(redirect_uri)).startswith(b"HTTP/1.1 200")
            result = await waiting
            assert result.code == CODE and result.state == STATE and result.iss == ISSUER
        finally:
            if not waiting.done():
                waiting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiting


async def test_unknown_standard_response_parameters_are_ignored(redirect_uri):
    async with LoopbackCallback(redirect_uri, ISSUER, timeout=5) as callback:
        callback.arm(STATE)
        fields = {"code": CODE, "state": STATE, "iss": ISSUER,
                  "session_state": "opaque-session", "scope": "read"}
        assert (await request(redirect_uri, fields=fields)).startswith(b"HTTP/1.1 200")
        result = await callback.result()
        assert (result.code, result.state, result.iss) == (CODE, STATE, ISSUER)


async def test_vendor_denial_requires_the_same_issuer_and_state(redirect_uri):
    async with LoopbackCallback(redirect_uri, ISSUER, timeout=5) as callback:
        callback.arm(STATE)
        fields = {"error": "access_denied", "state": STATE, "iss": ISSUER,
                  "error_description": "private-vendor-diagnostic"}
        reply = await request(redirect_uri, fields=fields)
        assert reply.startswith(b"HTTP/1.1 200")
        assert b"private-vendor-diagnostic" not in reply
        with pytest.raises(CallbackRejected, match="vendor denied"):
            await callback.result()
        assert (await request(redirect_uri)).startswith(b"HTTP/1.1 409")


async def test_missing_callback_times_out_and_physically_closes_the_listener(redirect_uri):
    async with LoopbackCallback(redirect_uri, ISSUER, timeout=0.01) as callback:
        callback.arm(STATE)
        with pytest.raises(TimeoutError):
            await callback.result()
    with pytest.raises(ConnectionError):
        await asyncio.open_connection("127.0.0.1", urlsplit(redirect_uri).port)


async def test_connection_budget_is_finite_and_fails_the_attempt(redirect_uri):
    async with LoopbackCallback(redirect_uri, ISSUER, timeout=5, max_connections=1) as callback:
        callback.arm(STATE)
        assert (await request(redirect_uri, fields={"state": "invalid"})).startswith(b"HTTP/1.1 400")
        reader, writer = await asyncio.open_connection("127.0.0.1", urlsplit(redirect_uri).port)
        try:
            with pytest.raises(CallbackRejected, match="budget exceeded"):
                await callback.result()
            assert await reader.read() == b""
        finally:
            writer.close()
            await writer.wait_closed()
    assert all(task.done() for task in callback._tasks)


async def test_budget_exhaustion_retires_an_already_admitted_callback(redirect_uri):
    async with LoopbackCallback(redirect_uri, ISSUER, timeout=5, max_connections=1) as callback:
        callback.arm(STATE)
        url = urlsplit(redirect_uri)
        reader, writer = await asyncio.open_connection("127.0.0.1", url.port)
        try:
            # The real first handler owns a partial request while a second
            # connection exhausts this attempt's finite admission budget.
            target = url.path + "?" + urlencode({"code": CODE, "state": STATE, "iss": ISSUER})
            writer.write(f"GET {target} HTTP/1.1\r\n".encode("ascii"))
            await writer.drain()
            rejected_reader, rejected_writer = await asyncio.open_connection("127.0.0.1", url.port)
            try:
                assert await rejected_reader.read() == b""
            finally:
                rejected_writer.close()
                await rejected_writer.wait_closed()
            with pytest.raises(CallbackRejected, match="budget exceeded"):
                await callback.result()
            writer.write(f"Host: {url.netloc}\r\n\r\n".encode("ascii"))
            await writer.drain()
            assert (await reader.read()).startswith(b"HTTP/1.1 409")
        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.parametrize("redirect", [
    "https://127.0.0.1:44721/oauth/callback", "http://localhost:44721/oauth/callback",
    "http://0.0.0.0:44721/oauth/callback", "http://127.0.0.1/oauth/callback",
    "http://user@127.0.0.1:44721/oauth/callback", "http://127.0.0.1:44721/oauth/callback?a=b",
    "http://127.0.0.1:44721/oauth/callback#fragment",
])
def test_only_the_exact_published_native_redirect_is_eligible(redirect):
    with pytest.raises(CallbackRejected, match="exact IPv4 loopback"):
        LoopbackCallback(redirect, ISSUER, timeout=5)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_timeout_fails_before_a_listener_exists(redirect_uri, timeout):
    with pytest.raises(CallbackRejected, match="finite and positive"):
        LoopbackCallback(redirect_uri, ISSUER, timeout=timeout)
