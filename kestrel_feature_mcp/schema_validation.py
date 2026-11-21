"""Validate native MCP schemas without retrieving references over the network."""

import re

from jsonschema import Draft202012Validator
from jsonschema.exceptions import UnknownType
from referencing import Registry


def matches_schema(schema: dict, value) -> bool:
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, registry=Registry(),
            format_checker=Draft202012Validator.FORMAT_CHECKER)
        return validator.is_valid(value)
    except (ArithmeticError, AttributeError, LookupError, RecursionError, TypeError,
            UnknownType, ValueError, re.error):
        # A reference can reach an unchecked schema, and formats can raise
        # when evaluating peer data. None of these outcomes proves conformance.
        return False
