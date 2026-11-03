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
    assert not sdk.specifier.contains("0.43.0")
    assert not sdk.specifier.contains("0.44.0")
    assert not sdk.specifier.contains("0.44.1")
    assert not sdk.specifier.contains("0.45.0")
    assert sdk.specifier.contains("0.46.0")


def test_frozen_mcp_install_uses_public_current_https_dependencies():
    packages = {item["name"]: item for item in tomllib.loads(
        (ROOT / "uv.lock").read_text())["package"]}
    for name, floor in [("kestrel-sovereign-sdk", "0.46.0"), ("certifi", "2026.10.23")]:
        assert Version(packages[name]["version"]) >= Version(floor)
        assert packages[name]["source"] == {"registry": "https://pypi.org/simple"}


def test_app_host_tests_require_authenticated_physical_view_ownership():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    (core,) = [Requirement(raw) for raw in project["optional-dependencies"]["test"]
               if Requirement(raw).name == "kestrel-sovereign"]
    for old in ["0.55.0", "0.55.1", "0.55.2", "0.56.0", "0.57.0", "0.58.0", "0.59.0"]:
        assert not core.specifier.contains(old)
    assert core.specifier.contains("0.60.0")
    assert core.specifier.contains("0.61.0")
    packages = {item["name"]: item for item in tomllib.loads(
        (ROOT / "uv.lock").read_text())["package"]}
    assert Version(packages["kestrel-sovereign"]["version"]) >= Version("0.60.0")
    assert packages["kestrel-sovereign"]["source"] == {"registry": "https://pypi.org/simple"}
