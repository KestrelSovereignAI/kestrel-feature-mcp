"""Exercise the normally installed CLI, packaged assets and credential boundary."""

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

import kestrel_mcp_apps_sandbox


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", required=True)
    args = parser.parse_args()
    assert not any(name in sys.modules for name in (
        "kestrel_feature_mcp", "kestrel_sdk", "kestrel_sovereign",
    )), "The public sandbox launcher imported host identity/agent modules"
    launcher = Path(sys.executable).parent / "kestrel-mcp-apps-sandbox"
    assert launcher.is_file()
    assert Path(kestrel_mcp_apps_sandbox.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="owned-installed-mcp-sandbox-") as folder:
        root = Path(folder)
        config = root / "sandbox.json"
        config.write_text(json.dumps({
            "listen": {"host": "127.0.0.1", "port": 0},
            "sandbox": {"hostOrigin": "https://host.example", "policy": {},
                        "maxMessageBytes": 8 * 1024 * 1024, "maxHtmlBytes": 1024 * 1024},
        }))
        (root / "bin").mkdir()
        (root / "bin" / "node").symlink_to(Path(args.node).resolve())
        scenarios = [
            ("absolute", args.node, str(config)),
            ("relative-config", args.node, config.name),
            ("relative-node", os.path.relpath(Path(args.node).resolve(), root.resolve()), config.name),
            ("relative-path", None, config.name),
        ]
        for scenario, requested, config_argument in scenarios:
            environment = {key: value for key, value in os.environ.items()
                           if key in {"SystemRoot", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE"}}
            environment.update(HOME=str(root),
                NODE_OPTIONS="--owned-kestrel-invalid-option-must-not-reach-the-public-service")
            if requested is not None:
                environment["KESTREL_MCP_APPS_NODE"] = requested
            else:
                environment["PATH"] = "bin"
            process = subprocess.Popen([str(launcher), "--config", config_argument], cwd=root,
                env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    assert selector.select(15), "The installed sandbox did not become ready"
                    line = process.stdout.readline()
                assert line, f"Installed sandbox exited before readiness: {process.stderr.read()}"
                ready = json.loads(line)
                assert ready["event"] == "mcp-apps-sandbox-listening"
                origin = "http://127.0.0.1:" + str(ready["address"]["port"])
                for route in ("/proxy", "/sandbox-entry.js", "/THIRD_PARTY_NOTICES.txt", "/health"):
                    with opener.open(origin + route, timeout=5) as response:
                        assert response.status == 200 and response.read()
                        assert response.headers.get("Set-Cookie") is None
                request = urllib.request.Request(origin + "/config", headers={"Authorization": "Bearer owned-fixture"})
                try:
                    opener.open(request, timeout=5)
                except urllib.error.HTTPError as error:
                    assert error.code == 400
                    assert b"owned-fixture" not in error.read()
                    error.close()
                else:
                    raise AssertionError("The installed sandbox accepted an identity credential")
                with opener.open(urllib.request.Request(origin + "/config",
                        headers={"Origin": "https://host.example"}), timeout=5) as response:
                    assert response.headers["Access-Control-Allow-Origin"] == "https://host.example"
                    assert response.headers.get("Access-Control-Allow-Credentials") is None
                    assert json.load(response)["hostOrigin"] == "https://host.example"
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
                stderr = process.stderr.read()
                process.stdout.close()
                process.stderr.close()
            assert code == 0 and not stderr, (code, stderr)
        print(json.dumps({"complete": True, "version": importlib.metadata.version("kestrel-feature-mcp"),
            "installed_launcher": str(launcher), "host_modules_not_imported": True,
            "node_options_not_inherited": True, "public_routes_healthy": True,
            "identity_credentials_refused": True, "graceful_process_exit": code, "path_scenarios": [item[0] for item in scenarios]}))


if __name__ == "__main__":
    main()
