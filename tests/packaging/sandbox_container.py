"""Exercise the actual sandbox image, including Docker's filtered build context."""

from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[2]
ASSETS = ROOT / "kestrel_feature_mcp" / "apps_sandbox"


def docker(*arguments, **kwargs):
    result = subprocess.run(["docker", *arguments], capture_output=True, **kwargs)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout


def owned_container(cleanup, *arguments):
    container = docker("create", *arguments).decode().strip()
    cleanup.callback(docker, "container", "rm", "--force", container)
    return container


def wait_until_ready(opener, origin, require_owner, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        require_owner()
        try:
            with opener.open(origin + "/health", timeout=1) as response:
                assert response.status == 200
            return
        except urllib.error.HTTPError as error:
            error.close()
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionResetError):
            if time.monotonic() >= deadline:
                raise AssertionError("Owned sandbox container did not become ready")
            time.sleep(0.05)


def verify_readiness_errors():
    for status in (200, 503):
        class Peer(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.attempts += 1
                if status == 200 and self.server.attempts == 1:
                    self.close_connection = True
                    self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    self.connection.close()
                    return
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Peer)
        server.attempts = 0
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()

        def require_owner():
            assert worker.is_alive()

        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                wait_until_ready(opener, "http://127.0.0.1:" + str(server.server_port), require_owner, timeout=2)
            except urllib.error.HTTPError as error:
                assert status == 503 and error.code == 503
            else:
                assert status == 200
            assert server.attempts == (2 if status == 200 else 1)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


def main():
    verify_readiness_errors()
    generated = set(json.loads((ASSETS / "manifest.json").read_text())["assets"])
    generated.add("manifest.json")
    assert generated == {"sandbox-entry.js", "sandbox-service.mjs", "parent-entry.js",
                         "oauth-panel.js", "oauth-panel.css", "THIRD_PARTY_NOTICES.txt", "manifest.json"}
    with tempfile.TemporaryDirectory(prefix="mcp-sandbox-container-") as temporary, ExitStack() as cleanup:
        folder = Path(temporary)
        context = folder / "context"
        context.mkdir()
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for name in filter(None, tracked):
            destination = context / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        for name in (".env", ".git/credentials", "kestrel_feature_mcp/apps_sandbox/host.env"):
            path = context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("SYNTHETIC_HOST_CREDENTIAL=must-not-enter-the-build\n")

        suffix = uuid4().hex
        probe_image = "kestrel-mcp-context-owned:" + suffix
        docker("build", "--quiet", "--tag", probe_image, "--file", "-", str(context),
               input=b"FROM scratch\nCOPY . /inventory/\n")
        cleanup.callback(docker, "image", "rm", probe_image)
        probe = owned_container(cleanup, probe_image, "/never-run")
        with tarfile.open(fileobj=io.BytesIO(docker("export", probe))) as archive:
            inventory = {item.name.removeprefix("inventory/") for item in archive
                         if item.isfile() and item.name.startswith("inventory/")}
        expected = {"kestrel_feature_mcp/apps_sandbox/" + name for name in generated}
        expected.update({"docker/Dockerfile.apps-sandbox", "LICENSE"})
        assert inventory == expected, inventory ^ expected

        image = "kestrel-mcp-sandbox-owned:" + suffix
        docker("build", "--quiet", "--tag", image, "--file",
               str(context / "docker/Dockerfile.apps-sandbox"), str(context))
        cleanup.callback(docker, "image", "rm", image)
        image_info = json.loads(docker("image", "inspect", image))[0]
        assert image_info["Config"]["User"] == "node"
        assert image_info["Config"]["Labels"]["org.opencontainers.image.licenses"] == "Apache-2.0"
        assert not any(name.split("=", 1)[0].startswith(("KESTREL_", "GOOGLE_", "OPENAI_", "AWS_"))
                       for name in image_info["Config"]["Env"])
        container = owned_container(cleanup, image)
        with tarfile.open(fileobj=io.BytesIO(docker("export", container))) as archive:
            license_path = "usr/share/licenses/kestrel-mcp-apps/LICENSE"
            assert license_path in archive.getnames(), "Sandbox image is missing its project license"
            assert archive.extractfile(license_path).read() == (ROOT / "LICENSE").read_bytes()
            for path in (license_path, "usr/share/licenses/kestrel-mcp-apps"):
                item = archive.getmember(path)
                assert item.uid == 0 and not item.mode & 0o022, (
                    f"Project license path must stay root-owned and not writable by the runtime user: {path}"
                )
            for item in archive.getmembers():
                if item.name == "app" or item.name.startswith("app/"):
                    assert item.uid == 0 and not item.mode & 0o022, item.name
            files = {item.name.removeprefix("app/"): archive.extractfile(item).read()
                     for item in archive if item.isfile() and item.name.startswith("app/")}
        assert set(files) == generated
        assert all(data == (ASSETS / name).read_bytes() for name, data in files.items())

        config = folder / "sandbox.json"
        configuration = {"listen": {"host": "0.0.0.0", "port": 8080}, "sandbox": {
            "hostOrigin": "https://host.example", "maxMessageBytes": 8388608,
            "maxHtmlBytes": 1048576, "policy": {}}}
        config.write_text(json.dumps(configuration))
        config.chmod(0o644)
        runtime = ["--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                   "--pids-limit=64", "--memory=256m", "--cpus=1",
                   "--mount", f"type=bind,source={config},target=/etc/kestrel-mcp-apps/sandbox.json,readonly"]
        running = owned_container(cleanup, *runtime, "--publish", "127.0.0.1::8080", image)
        docker("start", running)
        info = json.loads(docker("inspect", running))[0]
        binding, = info["NetworkSettings"]["Ports"]["8080/tcp"]
        origin = "http://127.0.0.1:" + binding["HostPort"]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def require_container():
            state = json.loads(docker("inspect", running))[0]["State"]
            assert state["Running"], docker("logs", running)

        wait_until_ready(opener, origin, require_container)
        public_routes = ("/proxy", "/sandbox-entry.js", "/config", "/health", "/THIRD_PARTY_NOTICES.txt")
        for path in public_routes:
            with opener.open(origin + path, timeout=3) as response:
                assert response.status == 200
                assert response.headers.get("Set-Cookie") is None
                assert "frame-ancestors https://host.example" in response.headers["Content-Security-Policy"]
            for headers in ({"Cookie": "operator=synthetic-secret"},
                            {"Authorization": "Bearer synthetic-secret"}, {"X-API-Key": "synthetic-secret"}):
                request = urllib.request.Request(origin + path, headers=headers)
                try:
                    opener.open(request, timeout=3)
                except urllib.error.HTTPError as error:
                    assert error.code == 400
                    assert b"synthetic-secret" not in error.read()
                else:
                    raise AssertionError("Sandbox accepted host credentials")
        # The shared manifest verifies Core's host UI files too. They are not
        # public sandbox routes; Core serves them through its feature UI mount.
        for host_asset in ("/oauth-panel.js", "/oauth-panel.css"):
            try:
                opener.open(origin + host_asset, timeout=3)
            except urllib.error.HTTPError as error:
                assert error.code == 404
                error.close()
            else:
                raise AssertionError("Sandbox exposed a host-only UI route")
        with opener.open(origin + "/config", timeout=3) as response:
            assert json.load(response) == configuration["sandbox"]

        unstartable = owned_container(cleanup, *runtime, "--entrypoint", "/missing-owned-sandbox-node", image)
        failed_start = subprocess.run(["docker", "start", unstartable], capture_output=True, timeout=10)
        assert failed_start.returncode != 0
        assert b"/missing-owned-sandbox-node" in failed_start.stderr
        assert not json.loads(docker("inspect", unstartable))[0]["State"]["Running"]

        tampered = folder / "sandbox-entry.js"
        tampered.write_bytes((ASSETS / "sandbox-entry.js").read_bytes() + b"\n// corrupted\n")
        tampered.chmod(0o644)
        corrupted = owned_container(cleanup, *runtime, "--mount",
            f"type=bind,source={tampered},target=/app/sandbox-entry.js,readonly", image)
        failure = subprocess.run(["docker", "start", "--attach", corrupted], capture_output=True, timeout=10)
        state = json.loads(docker("inspect", corrupted))[0]["State"]
        assert not state["Running"] and state["ExitCode"] != 0
        assert b"Sandbox packaged asset failed integrity verification: sandbox-entry.js" in failure.stderr + failure.stdout
        print(json.dumps({"image": image_info["Id"], "user": "node", "context_files": len(inventory),
                          "verified_assets": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()},
                          "public_routes": len(public_routes), "credential_refusals": 3 * len(public_routes), "tamper_refused": True,
                          "unstartable_container_owned": True, "project_license_preserved": True,
                          "startup_reset_retried": True, "http_failure_not_retried": True,
                          "assets_root_owned": True, "host_ui_routes_unavailable": True}))


if __name__ == "__main__":
    main()
