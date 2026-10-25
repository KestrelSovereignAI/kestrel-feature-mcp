"""Actual HTTP/TLS listeners shared by MCP and OAuth wire tests."""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import uvicorn


@dataclass
class HTTPPeer:
    url: str
    server: uvicorn.Server
    task: asyncio.Task
    certificate_file: str | None
    server_names: list[str]


def tls_files(directory, hostname):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                   .sign(key, hashes.SHA256()))
    certificate_file, key_file = directory / "certificate.pem", directory / "key.pem"
    certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(certificate_file), str(key_file)


@asynccontextmanager
async def serve_http(app, directory, *, certificate_host=None):
    directory.mkdir(parents=True, exist_ok=True)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    certificate_file = None
    options = {}
    if certificate_host is not None:
        certificate_file, key_file = tls_files(directory, certificate_host)
        options = {"ssl_certfile": certificate_file, "ssl_keyfile": key_file}
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", **options))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def ready():
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("Owned HTTP peer exited before startup")
            await asyncio.sleep(0.01)

    try:
        await asyncio.wait_for(ready(), 5)
        names = []
        if certificate_host is not None:
            server.config.ssl.set_servername_callback(
                lambda _socket, name, _context: names.append(name))
        scheme = "https" if certificate_host is not None else "http"
        yield HTTPPeer(f"{scheme}://127.0.0.1:{port}", server, task,
                       certificate_file, names)
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, 5)
        finally:
            sock.close()
