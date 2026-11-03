"""Every lifecycle cleanup is attempted without losing original control."""

import asyncio

import pytest

from kestrel_feature_mcp._lifecycle import run_cleanup_steps


async def test_cleanup_preserves_order_and_all_original_failures():
    visited = []
    first, second = PermissionError("first"), asyncio.CancelledError("second")
    def synchronous():
        visited.append("synchronous")
        raise first
    async def asynchronous():
        visited.append("asynchronous")
        raise second
    async def last():
        visited.append("last")
    with pytest.raises(BaseExceptionGroup) as caught:
        await run_cleanup_steps([(False, synchronous), (True, asynchronous), (True, last)])
    assert visited == ["synchronous", "asynchronous", "last"]
    assert caught.value.exceptions == (first, second)


async def test_setup_failure_is_preserved_after_successful_rollback():
    original = PermissionError("setup")
    visited = []
    async def rollback():
        visited.append("rollback")
    with pytest.raises(PermissionError) as caught:
        await run_cleanup_steps([(True, rollback)], failure=original)
    assert caught.value is original and visited == ["rollback"]
