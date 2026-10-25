"""Manual client configuration checks; real OAuth uses a separate HTTPS lane."""

import copy
import json
from pathlib import Path
import shlex
import subprocess
import sys

import httpx2
import pytest

from tests.oauth_acceptance.client import RefuseUnselectedOrigin, load_selection, open_authorization
from tests.oauth_acceptance.policy import GrantRejected


@pytest.fixture
def config():
    return json.loads((Path(__file__).parents[1] / "oauth_acceptance/vendors.json").read_text())


@pytest.mark.parametrize("vendor", ["notion", "linear", "github"])
def test_vendor_selection_freezes_the_same_published_client(config, vendor):
    selected, timeouts = load_selection(config, vendor)
    assert selected.client_id == "https://agents.kestrelsovereign.com/oauth/kestrel-local-client.json"
    assert selected.redirect_uri == "http://127.0.0.1:44721/oauth/callback"
    assert selected.scopes == frozenset(config["vendors"][vendor]["scopes"])
    assert set(timeouts) == {"browser_timeout", "network_timeout", "connect_timeout",
                            "call_timeout", "close_timeout", "response_max_bytes"}
    assert timeouts["response_max_bytes"] == 65536


@pytest.mark.parametrize("field", ["access_token", "client_secret", "headers", "auth"])
def test_vendor_config_cannot_smuggle_credentials_or_another_auth_mode(config, field):
    config = copy.deepcopy(config)
    config["vendors"]["notion"][field] = "synthetic-credential"
    with pytest.raises(GrantRejected, match="unsupported grant fields"):
        load_selection(config, "notion")


async def test_no_unselected_origin_has_a_transport():
    async with httpx2.AsyncClient(transport=RefuseUnselectedOrigin(), trust_env=False) as client:
        with pytest.raises(GrantRejected, match="unselected origin"):
            await client.get("https://unselected.example/metadata")


@pytest.mark.parametrize("field", ["access_token", "client_secret", "auth", "headers"])
def test_top_level_config_rejects_unimplemented_credentials(config, field):
    config[field] = "synthetic-secret"
    with pytest.raises(GrantRejected, match="unsupported or missing"):
        load_selection(config, "notion")


def test_unknown_vendor_fails_before_requests(config):
    with pytest.raises(GrantRejected, match="selected vendor is missing"):
        load_selection(config, "unknown-vendor")


@pytest.mark.parametrize("value", [True, "20", None])
def test_config_timeout_types_fail_before_requests(config, value):
    config["network_timeout"] = value
    with pytest.raises(GrantRejected, match="must be numbers"):
        load_selection(config, "notion")


@pytest.mark.parametrize("value", [True, 0, -1, "65536"])
def test_config_response_budget_fails_before_requests(config, value):
    config["response_max_bytes"] = value
    with pytest.raises(GrantRejected, match="response budget"):
        load_selection(config, "notion")


def test_existing_output_is_refused_before_any_attempt(tmp_path):
    output = tmp_path / "existing.json"
    output.write_text("previous-result-sentinel")
    result = subprocess.run([
        sys.executable, "-B", "-m", "tests.oauth_acceptance.client",
        "--config", str(tmp_path / "missing-config.json"), "--vendor", "notion",
        "--output", str(output),
    ], cwd=Path(__file__).parents[2], capture_output=True, text=True, timeout=5)
    assert result.returncode != 0 and result.stdout == ""
    assert json.loads(result.stderr)["error_type"] == "FileExistsError"
    assert output.read_text() == "previous-result-sentinel"


async def test_browser_launcher_ignores_imports_from_the_working_directory(tmp_path, monkeypatch):
    # The owned browser command records a synthetic URL without opening a GUI.
    # A cwd module must not replace the launcher's standard-library module.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "webbrowser.py").write_text(
        "from pathlib import Path\nPath('poison-imported').write_text('bad')\n"
        "def open(url, new): return True\n")
    spy = tmp_path / "owned_browser.py"
    receipt = tmp_path / "browser-receipt"
    spy.write_text("from pathlib import Path\nimport sys\n"
                   "Path(sys.argv[1]).write_text(sys.argv[2])\n")
    monkeypatch.setenv("BROWSER", shlex.join([sys.executable, str(spy), str(receipt), "%s"]))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    url = "https://issuer.example/authorize?state=synthetic-test-state"
    await open_authorization(url)
    assert receipt.read_text() == url
    assert not (tmp_path / "poison-imported").exists()
