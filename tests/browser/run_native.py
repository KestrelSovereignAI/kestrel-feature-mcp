"""Own native browser acceptance by immutable Docker image/container identities."""

import argparse
from contextlib import closing, contextmanager
import hashlib
import io
import json
import logging
from pathlib import Path
import signal
import subprocess
import tarfile
import xml.etree.ElementTree as ET

import docker
from docker.errors import APIError, NotFound


def save_receipt(path, receipt):
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(receipt, indent=2) + '\n')
    temporary.replace(path)


def retire_container(client, container_id, receipt, path):
    """Join this original namespace before removal; never signal a host PID."""
    try:
        state = client.api.inspect_container(container_id)['State']
    except NotFound:
        if not receipt.get('container_absent'):
            raise RuntimeError('Original container disappeared before its terminal receipt') from None
        return
    if state['Running']:
        try:
            client.api.kill(container_id)
        except APIError as error:
            # A natural exit can win the kill. Only fresh native state can
            # establish that outcome; unrelated Docker failures still propagate.
            if error.status_code != 409 or client.api.inspect_container(container_id)['State']['Running']:
                raise
    if state['Status'] != 'created':
        receipt['retirement_wait'] = client.api.wait(container_id, timeout=30)
    state = client.api.inspect_container(container_id)['State']
    if state['Running'] or state['Pid'] != 0:
        raise RuntimeError('Original browser container namespace has not retired')
    receipt['terminal_state'] = state
    save_receipt(path, receipt)
    client.api.remove_container(container_id)
    try:
        client.api.inspect_container(container_id)
    except NotFound:
        receipt['container_absent'] = True
        save_receipt(path, receipt)
    else:
        raise RuntimeError('Original browser container remains after removal')


@contextmanager
def original_container(client, image_id, receipt_path, *, command=None):
    receipt = {'image_id': image_id}
    container_id = None
    try:
        host = client.api.create_host_config(
            init=True, network_mode='none', cap_drop=['ALL'],
            security_opt=['no-new-privileges'], pids_limit=512, mem_limit='4g',
        )
        container_id = client.api.create_container(image_id, command=command, host_config=host, use_config_proxy=False)['Id']
        receipt['container_id'] = container_id
        save_receipt(receipt_path, receipt)
        info = client.api.inspect_container(container_id)
        host = info['HostConfig']
        if host['PidMode'] or host['Privileged'] or host['NetworkMode'] != 'none' or info['Mounts']:
            raise RuntimeError('Native browser container must have a private namespace and no host mounts')
        receipt['host_config'] = host
        save_receipt(receipt_path, receipt)
        yield container_id, receipt
    finally:
        if container_id is not None:
            retire_container(client, container_id, receipt, receipt_path)


def build_image(client, repository, output):
    runtime = json.loads((repository / 'tests/browser/runtime.json').read_text())
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=repository).decode().split('\0')
    inventory = {}
    context = io.BytesIO()
    with tarfile.open(fileobj=context, mode='w') as archive:
        for name in filter(None, names):
            path = repository / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f'Browser build requires a regular tracked file: {name}')
            body = path.read_bytes()
            inventory[name] = hashlib.sha256(body).hexdigest()
            # The production sandbox allowlist is a different image context.
            # This context already contains only tracked source, with no .git,
            # dependency caches, operator state, credentials or host mounts.
            if name == '.dockerignore':
                body = b''
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(body), path.stat().st_mode & 0o777
            archive.addfile(item, io.BytesIO(body))
    context.seek(0)
    image_id = None
    with (output / 'build.jsonl').open('w') as log:
        for row in client.api.build(
            fileobj=context, custom_context=True, dockerfile='tests/browser/Dockerfile',
            buildargs={'PLAYWRIGHT_IMAGE': runtime['image'], 'UV_IMAGE': runtime['uv_image']},
            rm=True, decode=True, use_config_proxy=False,
        ):
            log.write(json.dumps(row) + '\n')
            log.flush()
            if 'error' in row:
                raise RuntimeError(row['error'])
            if row.get('aux', {}).get('ID'):
                image_id = row['aux']['ID']
    if not image_id:
        raise RuntimeError('Docker build did not return an immutable browser image ID')
    client.api.inspect_image(image_id)
    save_receipt(output / 'build.json', {'image_id': image_id, 'runtime': runtime, 'source_sha256': inventory})
    return image_id


def container_file(client, container_id, path):
    stream, _ = client.api.get_archive(container_id, path)
    with tarfile.open(fileobj=io.BytesIO(b''.join(stream))) as archive:
        return archive.extractfile(Path(path).name).read()


def run_acceptance(client, image_id, output):
    with original_container(client, image_id, output / 'container.json') as (container_id, receipt):
        client.api.start(container_id)
        receipt['test_wait'] = client.api.wait(container_id, timeout=300)
        (output / 'browser.log').write_bytes(client.api.logs(container_id))
        xml = container_file(client, container_id, '/work/native-browser.xml')
        (output / 'native-browser.xml').write_bytes(xml)
        cases = list(ET.fromstring(xml).iter('testcase'))
        counts = {kind: sum(case.find(kind) is not None for case in cases)
                  for kind in ('failure', 'error', 'skipped')}
        receipt['tests'], receipt['results'] = len(cases), counts
        save_receipt(output / 'container.json', receipt)
        if receipt['test_wait']['StatusCode'] or not cases or any(counts.values()):
            raise RuntimeError(f'Native browser acceptance failed; see {output / "browser.log"}')
        logging.info('Native browser acceptance passed %s cases', len(cases))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cleanup', action='store_true', help='Reconcile the same original container receipt')
    args = parser.parse_args()
    output = args.output.resolve()
    repository = Path(__file__).resolve().parents[2]
    if output == repository or repository in output.parents:
        parser.error('--output must be outside the source checkout')
    output.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO)

    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'Native browser caller received signal {signum}')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with closing(docker.from_env(timeout=30)) as client:
        if args.cleanup:
            receipt_path = output / 'container.json'
            if receipt_path.exists():
                receipt = json.loads(receipt_path.read_text())
                retire_container(client, receipt['container_id'], receipt, receipt_path)
        else:
            run_acceptance(client, build_image(client, repository, output), output)


if __name__ == '__main__':
    main()
