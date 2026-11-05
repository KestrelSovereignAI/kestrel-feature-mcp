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
    assert sdk.extras == {"crypto", "httpx2"}
    assert not sdk.specifier.contains("0.42.3")
    assert not sdk.specifier.contains("0.42.4")
    assert not sdk.specifier.contains("0.43.0")
    assert not sdk.specifier.contains("0.44.0")
    assert not sdk.specifier.contains("0.44.1")
    assert not sdk.specifier.contains("0.45.0")
    assert not sdk.specifier.contains("0.46.0")
    assert not sdk.specifier.contains("0.47.0")
    assert sdk.specifier.contains("0.48.0")


def test_frozen_mcp_install_uses_public_patched_security_dependencies():
    packages = {item["name"]: item for item in tomllib.loads(
        (ROOT / "uv.lock").read_text())["package"]}
    for name, floor in [("kestrel-sovereign-sdk", "0.48.0"), ("certifi", "2026.10.23"),
                        ("pyasn1", "0.6.5")]:
        assert Version(packages[name]["version"]) >= Version(floor)
        assert packages[name]["source"] == {"registry": "https://pypi.org/simple"}


def test_host_tests_require_native_apps_oauth_and_unconfirmed_outcomes():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    (core,) = [Requirement(raw) for raw in project["optional-dependencies"]["test"]
               if Requirement(raw).name == "kestrel-sovereign"]
    floor = Version("0.62.2")
    assert any(spec.operator == ">=" and Version(spec.version) >= floor
               for spec in core.specifier)
    assert not core.specifier.contains("0.61.3")
    assert not core.specifier.contains("0.62.0")
    assert not core.specifier.contains("0.62.1")
    assert core.specifier.contains(str(floor))
    packages = {item["name"]: item for item in tomllib.loads(
        (ROOT / "uv.lock").read_text())["package"]}
    assert Version(packages["kestrel-sovereign"]["version"]) >= floor
    assert packages["kestrel-sovereign"]["source"] == {"registry": "https://pypi.org/simple"}


def test_production_refresh_installs_public_authlib_without_the_test_extra():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    (authlib,) = [Requirement(raw) for raw in project['dependencies']
        if Requirement(raw).name.lower() == 'authlib']
    assert not authlib.specifier.contains('1.9.3')
    assert authlib.specifier.contains('1.9.4')
    assert all(Requirement(raw).name.lower() != 'authlib'
        for raw in project['optional-dependencies']['test'])
    packages = {item['name']: item for item in tomllib.loads((ROOT / 'uv.lock').read_text())['package']}
    assert Version(packages['authlib']['version']) >= Version('1.9.4')
    assert packages['authlib']['source'] == {'registry': 'https://pypi.org/simple'}
