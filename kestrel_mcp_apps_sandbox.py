"""Launch the packaged public sandbox without importing the agent feature."""

import os
from pathlib import Path
import shutil
import sys


def main() -> None:
    requested = os.environ.get("KESTREL_MCP_APPS_NODE", "node")
    executable = shutil.which(requested) if requested else None
    if executable is None:
        raise SystemExit("MCP Apps sandbox requires Node.js 22 or newer; set KESTREL_MCP_APPS_NODE to its executable")
    assets = Path(__file__).resolve().parent / "kestrel_feature_mcp" / "apps_sandbox"
    entry = assets / "sandbox-service.mjs"
    if not entry.is_file():
        raise SystemExit("Packaged MCP Apps sandbox assets are missing; install a built feature package")
    # The public service has no host identity or authentication lane. Do not
    # pass host credentials, HOME, NODE_OPTIONS, module paths or cloud config.
    environment = {key: os.environ[key] for key in (
        "SystemRoot", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE",
    ) if key in os.environ}
    os.chdir(assets)
    os.execve(executable, [executable, str(entry), *sys.argv[1:]], environment)


if __name__ == "__main__":
    main()
