"""Public install contracts for the feature's native HTTPS client."""

from pathlib import Path
import tomllib

from packaging.requirements import Requirement
from packaging.version import Version


ROOT = Path(__file__).parents[2]


def test_remote_mcp_requires_the_shared_sdk_trust_bundle_policy():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    (sdk,) = [Requirement(raw) for raw in project["dependencies"]
              if Requirement(raw).name == "kestrel-sovereign-sdk"]
    assert sdk.extras == {"httpx2"}
    assert not sdk.specifier.contains("0.42.3")
    assert not sdk.specifier.contains("0.42.4")
    assert sdk.specifier.contains("0.43.0")


def test_frozen_mcp_install_uses_public_current_https_dependencies():
    packages = {item["name"]: item for item in tomllib.loads(
        (ROOT / "uv.lock").read_text())["package"]}
    for name, floor in [("kestrel-sovereign-sdk", "0.43.0"), ("certifi", "2026.10.23")]:
        assert Version(packages[name]["version"]) >= Version(floor)
        assert packages[name]["source"] == {"registry": "https://pypi.org/simple"}
