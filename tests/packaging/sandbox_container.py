"""Exercise the actual sandbox image, including Docker's filtered build context."""

from contextlib import ExitStack
import hashlib
from http.client import RemoteDisconnected
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
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


def main():
    generated = set(json.loads((ASSETS / "manifest.json").read_text())["assets"])
    generated.add("manifest.json")
    assert generated == {"sandbox-entry.js", "sandbox-service.mjs", "parent-entry.js",
                         "THIRD_PARTY_NOTICES.txt", "manifest.json"}
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
        probe = docker("create", probe_image, "/never-run").decode().strip()
        cleanup.callback(docker, "container", "rm", "--force", probe)
        with tarfile.open(fileobj=io.BytesIO(docker("export", probe))) as archive:
            inventory = {item.name.removeprefix("inventory/") for item in archive
                         if item.isfile() and item.name.startswith("inventory/")}
        expected = {"kestrel_feature_mcp/apps_sandbox/" + name for name in generated}
        expected.add("docker/Dockerfile.apps-sandbox")
        assert inventory == expected, inventory ^ expected

        image = "kestrel-mcp-sandbox-owned:" + suffix
        docker("build", "--quiet", "--tag", image, "--file",
               "docker/Dockerfile.apps-sandbox", str(context))
        cleanup.callback(docker, "image", "rm", image)
        image_info = json.loads(docker("image", "inspect", image))[0]
        assert image_info["Config"]["User"] == "node"
        assert not any(name.split("=", 1)[0].startswith(("KESTREL_", "GOOGLE_", "OPENAI_", "AWS_"))
                       for name in image_info["Config"]["Env"])
        container = docker("create", image).decode().strip()
        cleanup.callback(docker, "container", "rm", "--force", container)
        with tarfile.open(fileobj=io.BytesIO(docker("export", container))) as archive:
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
        running = docker("run", "--detach", *runtime, "--publish", "127.0.0.1::8080", image).decode().strip()
        cleanup.callback(docker, "container", "rm", "--force", running)
        info = json.loads(docker("inspect", running))[0]
        binding, = info["NetworkSettings"]["Ports"]["8080/tcp"]
        origin = "http://127.0.0.1:" + binding["HostPort"]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 30
        while True:
            state = json.loads(docker("inspect", running))[0]["State"]
            assert state["Running"], docker("logs", running)
            try:
                with opener.open(origin + "/health", timeout=1) as response:
                    assert response.status == 200
                break
            except urllib.error.HTTPError:
                raise
            except (urllib.error.URLError, TimeoutError, RemoteDisconnected):
                if time.monotonic() >= deadline:
                    raise AssertionError("Owned sandbox container did not become ready")
                time.sleep(0.05)
        for path in ("/proxy", "/sandbox-entry.js", "/config", "/health", "/THIRD_PARTY_NOTICES.txt"):
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
        with opener.open(origin + "/config", timeout=3) as response:
            assert json.load(response) == configuration["sandbox"]

        tampered = folder / "sandbox-entry.js"
        tampered.write_bytes((ASSETS / "sandbox-entry.js").read_bytes() + b"\n// corrupted\n")
        tampered.chmod(0o644)
        corrupted = docker("create", *runtime, "--mount",
            f"type=bind,source={tampered},target=/app/sandbox-entry.js,readonly", image).decode().strip()
        cleanup.callback(docker, "container", "rm", "--force", corrupted)
        failure = subprocess.run(["docker", "start", "--attach", corrupted], capture_output=True, timeout=10)
        state = json.loads(docker("inspect", corrupted))[0]["State"]
        assert not state["Running"] and state["ExitCode"] != 0
        assert b"Sandbox packaged asset failed integrity verification: sandbox-entry.js" in failure.stderr + failure.stdout
        print(json.dumps({"image": image_info["Id"], "user": "node", "context_files": len(inventory),
                          "verified_assets": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()},
                          "public_routes": 5, "credential_refusals": 15, "tamper_refused": True}))


if __name__ == "__main__":
    main()
