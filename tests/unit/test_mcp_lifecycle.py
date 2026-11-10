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
    with pytest.raises(asyncio.CancelledError) as caught:
        await run_cleanup_steps([(False, synchronous), (True, asynchronous), (True, last)])
    assert visited == ["synchronous", "asynchronous", "last"]
    assert caught.value is second
    assert caught.value.__cause__.exceptions == (first,)


async def test_setup_failure_is_preserved_after_successful_rollback():
    original = PermissionError("setup")
    visited = []
    async def rollback():
        visited.append("rollback")
    with pytest.raises(PermissionError) as caught:
        await run_cleanup_steps([(True, rollback)], failure=original)
    assert caught.value is original and visited == ["rollback"]


async def test_original_task_cancellation_survives_an_independent_cleanup_failure():
    entered, visited = asyncio.Event(), []
    failure = RuntimeError('independent closer was not acknowledged')
    async def first():
        visited.append('first')
        entered.set()
        await asyncio.Event().wait()
    async def second():
        visited.append('second')
        raise failure
    owner = asyncio.create_task(run_cleanup_steps([(True, first), (True, second)]))
    await entered.wait()
    owner.cancel('owned HTTP request cancellation')
    with pytest.raises(asyncio.CancelledError) as caught:
        await owner
    assert owner.cancelled() and visited == ['first', 'second']
    assert caught.value.__cause__.exceptions == (failure,)


async def test_native_timeout_scope_recognizes_its_cancellation_after_cleanup_failure():
    import anyio
    visited = []
    async def first():
        visited.append('first')
        await anyio.sleep_forever()
    async def second():
        visited.append('second')
        raise RuntimeError('independent closer was not acknowledged')
    with pytest.raises(TimeoutError):
        with anyio.fail_after(0.025) as scope:
            await run_cleanup_steps([(True, first), (True, second)])
    assert scope.cancelled_caught and visited == ['first', 'second']


@pytest.mark.parametrize('control', ['asyncio', 'anyio'])
async def test_cleanup_recovers_control_suppressed_by_an_original_closer(control):
    import anyio
    entered, visited = asyncio.Event(), []
    async def first():
        visited.append('first')
        entered.set()
        try:
            await anyio.sleep_forever()
        except asyncio.CancelledError:
            return
    async def second():
        visited.append('second')
        raise RuntimeError('independent original close failed')
    if control == 'anyio':
        with pytest.raises(TimeoutError):
            with anyio.fail_after(0.025) as scope:
                await run_cleanup_steps([(True, first), (True, second)])
        assert scope.cancelled_caught
    else:
        owner = asyncio.create_task(run_cleanup_steps([(True, first), (True, second)]))
        await entered.wait()
        owner.cancel('owned original request cancellation')
        with pytest.raises(asyncio.CancelledError):
            await owner
        assert owner.cancelled()
    assert visited == ['first', 'second']


async def test_nested_cleanup_control_does_not_leave_itself_in_its_own_cause():
    cancellation, failure = asyncio.CancelledError('original nested cancellation'), ValueError('original failure')
    async def close():
        raise BaseExceptionGroup('nested native close', [cancellation, failure])
    with pytest.raises(asyncio.CancelledError) as caught:
        await run_cleanup_steps([(True, close)])
    assert caught.value is cancellation
    assert caught.value.__cause__.exceptions[0].exceptions == (failure,)


async def test_interrupt_has_native_priority_over_cancellation():
    cancellation, interrupt = asyncio.CancelledError('original cancellation'), SystemExit('owned test interrupt')
    async def first():
        raise cancellation
    async def second():
        raise interrupt
    with pytest.raises(SystemExit) as caught:
        await run_cleanup_steps([(True, first), (True, second)])
    assert caught.value is interrupt
    assert caught.value.__cause__.exceptions == (cancellation,)


@pytest.mark.parametrize('control', ['asyncio', 'anyio'])
async def test_maintenance_join_keeps_original_cancellation_primary_when_retirement_fails(control):
    from kestrel_feature_mcp._lifecycle import join_maintenance
    import anyio

    entered, release = asyncio.Event(), asyncio.Event()
    failure = PermissionError('native retirement inventory was not acknowledged')

    async def retire():
        entered.set()
        await release.wait()
        raise failure

    maintenance = asyncio.create_task(retire())
    await entered.wait()
    if control == 'asyncio':
        caller = asyncio.create_task(join_maintenance(maintenance, 'owned retirement'))
        await asyncio.sleep(0)
        caller.cancel('original caller cancellation')
        await asyncio.sleep(0)
        caller.cancel('later caller withdrawal')
        release.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await caller
        assert caller.cancelled()
        assert str(caught.value) == 'original caller cancellation'
        assert caught.value.__cause__.subgroup(lambda error: error is failure) is not None
    else:
        async def release_after_deadline():
            await asyncio.sleep(0.05)
            release.set()
        releaser = asyncio.create_task(release_after_deadline())
        with pytest.raises(TimeoutError):
            with anyio.fail_after(0.025) as scope:
                await join_maintenance(maintenance, 'owned retirement')
        assert scope.cancelled_caught
        await releaser
    assert maintenance.done() and maintenance.exception() is failure
