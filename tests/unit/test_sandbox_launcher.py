"""The standalone public service fails clearly before a missing executable."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("executable", ["", "missing-owned-node-executable"])
def test_sandbox_launcher_requires_an_explicitly_available_node(tmp_path, executable):
    launcher = Path(__file__).resolve().parents[2] / "kestrel_mcp_apps_sandbox.py"
    result = subprocess.run(
        [sys.executable, "-B", str(launcher), "--config", str(tmp_path / "not-read.json")],
        cwd=tmp_path,
        env={**{key: value for key, value in os.environ.items() if key in {"SystemRoot", "WINDIR"}},
             "HOME": str(tmp_path), "PATH": str(tmp_path), "KESTREL_MCP_APPS_NODE": executable},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 1
    assert "Node.js 22 or newer" in result.stderr
    assert "KESTREL_MCP_APPS_NODE" in result.stderr
    assert "Traceback" not in result.stderr
    assert not result.stdout
