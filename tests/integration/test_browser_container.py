"""Native Docker ownership, including descendants born during shutdown."""

from contextlib import closing
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import time
from uuid import uuid4

import docker
from docker.errors import NotFound
import pytest

from tests.browser.run_native import build_image, container_file, original_container, retire_container


pytestmark = pytest.mark.docker


@pytest.fixture
def native_docker():
    with closing(docker.from_env(timeout=30)) as client:
        yield client


@pytest.fixture(autouse=True)
def independent_container_cleanup(native_docker, tmp_path):
    # Acceptance assertions run before this independent daemon cleanup. It also
    # retires a deliberately broken owner during the negative-control campaign.
    yield
    for path in (tmp_path / 'receipt.json', tmp_path / 'output/container.json'):
        if path.exists():
            container_id = json.loads(path.read_text())['container_id']
            try:
                native_docker.api.remove_container(container_id, force=True)
            except NotFound:
                pass


@pytest.fixture
def browser_image(request):
    configured = request.config.getoption("--browser-build-receipt")
    assert configured, "Supply --browser-build-receipt from the original native browser build"
    path = Path(configured)
    return json.loads(path.read_text())['image_id']


@pytest.fixture
def synthetic_proxy_docker(tmp_path, monkeypatch):
    config = tmp_path / 'synthetic-docker-config'
    config.mkdir()
    marker = 'synthetic-proxy-user:synthetic-proxy-password'
    (config / 'config.json').write_text(json.dumps({'proxies': {'default': {
        'httpProxy': 'http://' + marker + '@proxy.invalid:3128',
        'httpsProxy': 'http://' + marker + '@proxy.invalid:3128',
    }}}))
    monkeypatch.setenv('DOCKER_CONFIG', str(config))
    with closing(docker.from_env(timeout=30)) as client:
        yield client, marker


def require_birth(witness):
    birth = witness.get('child_birth')
    assert birth and birth['pid'] == witness['child'] and birth['session'] == witness['child'] and birth['term_ignored'] is True, (
        'Original child did not acknowledge detachment and TERM disposition'
    )


def family_command(mode):
    return ['/work/.venv/bin/python', '-c', textwrap.dedent('''
        import json, os, pathlib, signal, sys, time
        mode = sys.argv[1]
        def publish(path, value):
            target = pathlib.Path(path)
            pending = target.with_suffix('.pending')
            pending.write_text(json.dumps(value))
            pending.replace(target)
        def detached():
            reader, writer = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(reader)
                os.setsid()
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                birth = dict(pid=os.getpid(), session=os.getsid(0),
                             term_ignored=signal.getsignal(signal.SIGTERM) == signal.SIG_IGN)
                os.write(writer, json.dumps(birth).encode())
                os.close(writer)
                while True:
                    time.sleep(1)
            os.close(writer)
            with os.fdopen(reader, 'rb') as acknowledgment:
                birth = json.loads(acknowledgment.read())
            assert birth == dict(pid=pid, session=pid, term_ignored=True)
            return birth
        def retire(signum, frame):
            birth = detached()
            publish('/tmp/late.json', dict(parent=os.getpid(), child=birth['pid'], child_birth=birth))
            raise SystemExit(0)
        if mode == 'late':
            signal.signal(signal.SIGTERM, retire)
            birth = None
        else:
            birth = detached()
        publish('/tmp/ready.json', dict(
            parent=os.getpid(), child=birth['pid'] if birth else None, child_birth=birth))
        if mode != 'exit':
            while True:
                time.sleep(1)
        '''), mode]


def ready(client, container_id):
    deadline = time.monotonic() + 5
    while True:
        try:
            return json.loads(container_file(client, container_id, '/tmp/ready.json'))
        except NotFound:
            if not client.api.inspect_container(container_id)['State']['Running']:
                # The file can be committed between the original native 404
                # and process exit. Read the completed original artifact once.
                try:
                    return json.loads(container_file(client, container_id, '/tmp/ready.json'))
                except NotFound:
                    raise AssertionError('Original family exited before readiness') from None
            assert time.monotonic() < deadline, 'Original family never reached readiness'
            time.sleep(0.01)


def require_retired(client, container_id, receipt_path):
    receipt = json.loads(receipt_path.read_text())
    assert receipt.get('container_id') == container_id and receipt.get('container_absent') is True, (
        'Original browser namespace did not retain its terminal removal receipt'
    )
    assert receipt['terminal_state']['Pid'] == 0 and not receipt['terminal_state']['Running']
    assert receipt['host_config']['NetworkMode'] == 'none' and not receipt['host_config']['PidMode']
    with pytest.raises(NotFound):
        client.api.inspect_container(container_id)


@pytest.mark.parametrize('mode', ['exit', 'late'])
def test_original_namespace_retires_detached_and_shutdown_born_children(native_docker, browser_image, tmp_path, mode):
    client, path = native_docker, tmp_path / 'receipt.json'
    with original_container(client, browser_image, path, command=family_command(mode)) as (container_id, receipt):
        client.api.start(container_id)
        witness = ready(client, container_id)
        if mode == 'late':
            client.api.kill(container_id, signal='TERM')
        assert client.api.wait(container_id, timeout=5)['StatusCode'] == 0
        if mode == 'late':
            late = json.loads(container_file(client, container_id, '/tmp/late.json'))
            assert late['parent'] == witness['parent'] and late['child'] != late['parent']
            require_birth(late)
        else:
            assert witness['child'] != witness['parent']
            require_birth(witness)
    require_retired(client, container_id, path)
    retire_container(client, container_id, receipt, path)
    require_retired(client, container_id, path)


@pytest.mark.parametrize('failure', [AssertionError, KeyboardInterrupt, RuntimeError])
def test_original_failure_still_retires_the_live_namespace(native_docker, browser_image, tmp_path, failure):
    client, path = native_docker, tmp_path / 'receipt.json'
    with pytest.raises(failure, match='original-caller-failure'):
        with original_container(client, browser_image, path, command=family_command('live')) as (container_id, _):
            client.api.start(container_id)
            witness = ready(client, container_id)
            assert witness['child'] != witness['parent']
            require_birth(witness)
            assert client.api.inspect_container(container_id)['State']['Running']
            raise failure('original-caller-failure')
    require_retired(client, container_id, path)


def test_original_container_is_owned_before_startup(native_docker, browser_image, tmp_path):
    client, path = native_docker, tmp_path / 'receipt.json'
    with pytest.raises(RuntimeError, match='original-startup-failure'):
        with original_container(client, browser_image, path) as (container_id, _):
            assert client.api.inspect_container(container_id)['State']['Status'] == 'created'
            raise RuntimeError('original-startup-failure')
    require_retired(client, container_id, path)


@pytest.mark.parametrize('configured_proxy', [False, True])
def test_browser_build_context_excludes_untracked_host_state(native_docker, synthetic_proxy_docker, tmp_path, configured_proxy):
    repository, output = tmp_path / 'source', tmp_path / 'output'
    (repository / 'tests/browser').mkdir(parents=True)
    output.mkdir()
    (repository / '.dockerignore').write_text('**\n')
    (repository / 'tests/browser/runtime.json').write_text(json.dumps({'image': 'unused', 'uv_image': 'unused'}))
    (repository / 'tests/browser/Dockerfile').write_text('FROM scratch\nCOPY . /\n' + (
        'ARG HTTP_PROXY\nLABEL test.proxy=$HTTP_PROXY\n' if configured_proxy else ''
    ))
    sentinel = uuid4().hex
    (repository / 'tracked.txt').write_text(sentinel)
    subprocess.run(['git', 'init', '--quiet'], cwd=repository, check=True)
    subprocess.run(['git', 'add', '.dockerignore', 'tests', 'tracked.txt'], cwd=repository, check=True)
    (repository / 'untracked.env').write_text('SYNTHETIC_OPERATOR_SECRET=must-stay-out\n')
    client, marker = synthetic_proxy_docker if configured_proxy else (native_docker, None)
    image_id = build_image(client, repository, output)
    try:
        if configured_proxy:
            assert marker not in json.dumps(client.api.inspect_image(image_id)['Config'].get('Labels')), (
                'Docker build copied operator proxy configuration'
            )
        with original_container(client, image_id, output / 'container.json', command=['/never-start']) as (container_id, _):
            assert container_file(client, container_id, '/tracked.txt').decode() == sentinel
            for path in ['/untracked.env', '/.git/config']:
                with pytest.raises(NotFound):
                    container_file(client, container_id, path)
        assert set(json.loads((output / 'build.json').read_text())['source_sha256']) == {
            '.dockerignore', 'tests/browser/runtime.json', 'tests/browser/Dockerfile', 'tracked.txt',
        }
    finally:
        client.api.remove_image(image_id)


def test_browser_container_excludes_operator_proxy_configuration(synthetic_proxy_docker, browser_image, tmp_path):
    client, marker = synthetic_proxy_docker
    with original_container(client, browser_image, tmp_path / 'receipt.json') as (container_id, _):
        assert not any(marker in item for item in client.api.inspect_container(container_id)['Config']['Env']), (
            'Docker container copied operator proxy configuration'
        )


def test_readiness_reconciles_the_original_namespace_after_normal_exit(native_docker, browser_image, tmp_path, monkeypatch):
    client, path = native_docker, tmp_path / 'receipt.json'
    command = ['/work/.venv/bin/python', '-c', textwrap.dedent("""
        import json, pathlib, time
        while not pathlib.Path('/tmp/release').exists():
            time.sleep(0.01)
        pathlib.Path('/tmp/ready.json').write_text(json.dumps({'completed': True}))
    """)]
    with original_container(client, browser_image, path, command=command) as (container_id, _):
        client.api.start(container_id)
        original_file = container_file
        def complete_between_native_observations(original_id, native_path):
            try:
                return original_file(client, original_id, native_path)
            except NotFound:
                execution = client.api.exec_create(original_id, ['/work/.venv/bin/python', '-c',
                    "from pathlib import Path; Path('/tmp/release').touch()"])['Id']
                client.api.exec_start(execution)
                assert client.api.wait(original_id, timeout=5)['StatusCode'] == 0
                raise
        monkeypatch.setattr(sys.modules[__name__], 'container_file',
            lambda actual_client, original_id, native_path: complete_between_native_observations(original_id, native_path))
        assert ready(client, container_id) == {'completed': True}
    require_retired(client, container_id, path)
