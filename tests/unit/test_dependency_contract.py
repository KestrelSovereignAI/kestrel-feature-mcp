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
    minimum = max(Version(spec.version) for spec in sdk.specifier if spec.operator == '>=')
    assert minimum >= Version('0.52.1')
    assert not sdk.specifier.contains('0.52.0')
    assert sdk.specifier.contains(str(minimum))


def test_frozen_mcp_install_uses_public_patched_security_dependencies():
    packages = {item["name"]: item for item in tomllib.loads(
        (ROOT / "uv.lock").read_text())["package"]}
    for name, floor in [("kestrel-sovereign-sdk", "0.52.1"), ("certifi", "2026.10.23"),
                        ("pyasn1", "0.6.5")]:
        assert Version(packages[name]["version"]) >= Version(floor)
        assert packages[name]["source"] == {"registry": "https://pypi.org/simple"}


def test_host_tests_require_native_apps_oauth_and_unconfirmed_outcomes():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = metadata["project"]
    (core,) = [Requirement(raw) for raw in project["optional-dependencies"]["test"]
               if Requirement(raw).name == "kestrel-sovereign"]
    floor = max(Version(spec.version) for spec in core.specifier if spec.operator == '>=')
    assert floor >= Version('0.64.6')
    assert not core.specifier.contains('0.64.5')
    assert core.specifier.contains(str(floor))
    packages = {item["name"]: item for item in tomllib.loads(
        (ROOT / "uv.lock").read_text())["package"]}
    assert Version(packages["kestrel-sovereign"]["version"]) >= floor
    assert metadata.get("tool", {}).get("uv", {}).get("sources", {}) == {}
    assert all(Requirement(raw).name != core.name for raw in project["dependencies"])
    assert packages["kestrel-sovereign"]["source"] == {"registry": "https://pypi.org/simple"}


def test_ci_uses_the_same_locked_native_host_profile_for_all_test_installs():
    workflow = (ROOT / '.github/workflows/ci.yml').read_text()
    assert "uv pip install -e '.[test]'" not in workflow
    assert "uv pip install '.[test]'" not in workflow
    assert workflow.count('uv sync --locked --extra test --python ${{ env.PYTHON_VERSION }}') == 3
    assert ('UV_PROJECT_ENVIRONMENT=.venv-test uv sync --locked --extra test --no-editable '
            '--python ${{ matrix.python-version }}') in workflow


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


def test_readme_has_one_canonical_supported_core_minimum():
    import re

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    core, = [Requirement(raw) for raw in project["optional-dependencies"]["test"]
             if Requirement(raw).name == "kestrel-sovereign"]
    minimum = max(Version(spec.version) for spec in core.specifier if spec.operator == ">=")
    readme = (ROOT / "README.md").read_text()
    assert re.findall(r"\bCore ([0-9]+\.[0-9]+\.[0-9]+)", readme) == [str(minimum)], (
        "Declare the supported Core minimum once in Runtime requirements; link other sections to it"
    )
    assert "## Runtime requirements\n" in readme
    assert readme.count("(#runtime-requirements)") >= 3
