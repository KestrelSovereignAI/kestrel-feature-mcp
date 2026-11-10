"""Shared MCP lifecycle failures and exhaustive, ordered cleanup."""

import asyncio
from collections.abc import Callable
from contextlib import AsyncExitStack
from anyio.lowlevel import checkpoint_if_cancelled


class MCPFeatureClosingError(RuntimeError):
    """A connection start belongs to a feature generation that is closing."""


async def run_cleanup_steps(steps: list[tuple[bool, Callable]], *, failure: BaseException | None = None) -> None:
    """Attempt every original cleanup, preserving failures and cancellation."""
    task = asyncio.current_task()
    if task is None:
        raise RuntimeError('MCP cleanup requires its original asyncio task')
    cancelling = task.cancelling()
    failures = [] if failure is None else [failure]

    def retain_failure(_kind, error, _traceback):
        if error is None:
            return False
        if not any(error is previous for previous in failures):
            failures.append(error)
        return True

    async with AsyncExitStack() as cleanup:
        for asynchronous, operation in reversed(steps):
            cleanup.push(retain_failure)
            if asynchronous:
                cleanup.push_async_callback(operation)
            else:
                cleanup.callback(operation)
    def leaves(errors):
        for error in errors:
            if isinstance(error, BaseExceptionGroup):
                yield from leaves(error.exceptions)
            else:
                yield error

    primary = next((error for error in leaves(failures)
        if isinstance(error, (KeyboardInterrupt, SystemExit))), None)
    if primary is None:
        primary = next((error for error in leaves(failures) if isinstance(error, asyncio.CancelledError)), None)
    if primary is None and task.cancelling() > cancelling:
        try:
            await checkpoint_if_cancelled()
        except asyncio.CancelledError as error:
            primary = error
        if primary is None:
            primary = asyncio.CancelledError()
    if primary is not None:
        others = []
        for error in failures:
            if error is primary:
                continue
            if isinstance(error, BaseExceptionGroup):
                _, error = error.split(lambda item: item is primary)
            if error is not None:
                others.append(error)
        if others:
            raise primary from BaseExceptionGroup('Independent MCP cleanup failures', others)
        raise primary
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup("MCP cleanup did not complete normally", failures)


async def join_maintenance(maintenance, label):
    """Observe the original maintenance task without losing caller cancellation."""
    if maintenance is None:
        return
    cancellation = None
    while not maintenance.done():
        try:
            await asyncio.wait({maintenance})
        except asyncio.CancelledError as error:
            if cancellation is None:
                cancellation = error
    failure = None if maintenance.cancelled() else maintenance.exception()
    if failure is not None and cancellation is not None:
        await run_cleanup_steps([], failure=BaseExceptionGroup(label + " retention cleanup failed", [cancellation, failure]))
    if failure is not None:
        raise failure
    if cancellation is not None:
        raise cancellation
