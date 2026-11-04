"""Shared safe refusals and budgets for native OAuth roles."""

DEFAULT_RESPONSE_MAX_BYTES = 65536


class GrantRejected(ValueError):
    """Safe diagnostic; never interpolate a token, callback or response body."""


def response_budget(value: int) -> int:
    if type(value) is not int or value < 1:
        raise GrantRejected("OAuth response budget must be a positive integer")
    return value


