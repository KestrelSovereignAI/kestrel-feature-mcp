"""Shared MCP lifecycle failures and exhaustive, ordered cleanup."""

from collections.abc import Callable
from contextlib import AsyncExitStack


class MCPFeatureClosingError(RuntimeError):
    """A connection start belongs to a feature generation that is closing."""


async def run_cleanup_steps(steps: list[tuple[bool, Callable]], *, failure: BaseException | None = None) -> None:
    """Attempt every original cleanup, preserving failures and cancellation."""
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
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup("MCP cleanup did not complete normally", failures)
