"""Manual Phase 0 client: native initial OAuth, then canonical MCP discovery.

This is not the console authentication service or persistent grant storage.
Run as a module from this checkout; tokens stay in this short-lived process.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--vendor", required=True)
    parser.add_argument("--mode", choices=["discover", "authorize"], default="discover")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # This isolated CLI emits structured results. SDK exception messages can
    # contain response bodies or state; never print them or request URLs.
    logging.disable(logging.CRITICAL)

    safe_errors = ()

    def failure(kind, error, traceback):
        detail = str(error) if isinstance(error, safe_errors) else "Native operation failed; credential and response details withheld"
        json.dump({"stage": "failed", "error_type": kind.__name__, "detail": detail}, sys.stderr)
        sys.stderr.write("\n")

    sys.excepthook = failure
    # Reserve the report before config/network/consent work. A failed attempt
    # records no success, even if the vendor already issued a grant.
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        result = {"stage": "failed", "acceptance_verified": False}
        try:
            from .native_client import load_selection, run
            from .policy import GrantRejected
            from .callback import CallbackRejected

            safe_errors = (GrantRejected, CallbackRejected)
            selected, timeouts = load_selection(json.loads(args.config.read_text()), args.vendor)
            result = asyncio.run(run(selected, mode=args.mode, **timeouts))
        finally:
            json.dump(result, output, indent=2)
            output.write("\n")
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
