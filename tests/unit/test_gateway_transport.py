"""Unit tests for the gateway transport selection + ephemeral-port logic (#12).

These exercise the pure logic of ``DockerMCPGateway`` without Docker: the move
from the deprecated HTTP+SSE transport to Streamable HTTP, the ephemeral-port
default that kills the fixed-:9000 collision, and readiness detection.
"""

from kestrel_feature_mcp.gateway import DockerMCPGateway


def test_default_transport_is_streaming_not_deprecated_sse():
    gw = DockerMCPGateway()
    assert gw.transport == "streaming"
    assert gw._is_streaming is True
    # Streamable HTTP serves at /mcp, not the deprecated /sse path.
    gw.port = 1234
    assert gw.endpoint_url == "http://localhost:1234/mcp"


def test_legacy_sse_transport_still_selectable():
    gw = DockerMCPGateway(port=9100, transport="sse")
    assert gw._is_streaming is False
    assert gw.endpoint_url == "http://localhost:9100/sse"
    # Back-compat alias still resolves to the active endpoint.
    assert gw.sse_url == gw.endpoint_url


def test_default_port_is_ephemeral():
    # Port 0 means "pick a free one at start()"; nothing is pinned to :9000.
    gw = DockerMCPGateway()
    assert gw._requested_port == 0
    assert gw.port == 0


def test_explicit_port_is_honoured():
    gw = DockerMCPGateway(port=9200)
    assert gw._requested_port == 9200
    assert gw.port == 9200


def test_find_free_port_avoids_a_port_already_in_use():
    import socket

    p1 = DockerMCPGateway._find_free_port()
    assert isinstance(p1, int) and 1024 < p1 < 65536
    # Hold p1 bound, then allocate again: the OS must not hand back a port that
    # is currently in use, so the second allocation is deterministically
    # distinct. (Two *closed* ephemeral ports may legally coincide, so we don't
    # assert that — we assert the helper avoids a live bind.)
    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held.bind(("127.0.0.1", p1))
    held.listen(1)
    try:
        p2 = DockerMCPGateway._find_free_port()
        assert p2 != p1
    finally:
        held.close()


def test_streaming_readiness_line_detection():
    assert DockerMCPGateway._is_ready_line("> Start streaming server on port 9477")
    assert DockerMCPGateway._is_ready_line("starting STREAMING SERVER ...")
    assert not DockerMCPGateway._is_ready_line("- Reading configuration...")
    assert not DockerMCPGateway._is_ready_line("Start sse server on :9000")
