"""Original descriptor bytes are stable, immutable and shared with real input runtime."""

from dataclasses import FrozenInstanceError
import hashlib
import json
from types import SimpleNamespace

from mcp import types
import pytest

from kestrel_feature_mcp.connection import MCPConnection, bind_tool_caller
from kestrel_feature_mcp import input_runtime
from kestrel_feature_mcp.tool_contract import (
    MCPToolContractError, MCPToolContractSnapshot, capture_tool_contract,
)


def original():
    return capture_tool_contract(types.Tool(name='echo', description='café', input_schema={'type': 'object'}),
        connection_name='owned', url='https://tools.example/mcp', protocol='2026-07-28')


def test_existing_continuation_fingerprint_format_is_preserved_byte_for_byte():
    snapshot = original()
    expected = (b'{"connection":"owned","protocol":"2026-07-28","tool":'
        b'{"description":"caf\\u00e9","inputSchema":{"type":"object"},"name":"echo"},'
        b'"url":"https://tools.example/mcp"}')
    assert snapshot.canonical_json == expected
    assert snapshot.digest == hashlib.sha256(expected).hexdigest()


def test_descriptor_and_producer_mutation_cannot_change_original_bytes():
    tool = types.Tool(name='echo', input_schema={'type': 'object', 'properties': {'original': {'type': 'string'}}})
    snapshot = capture_tool_contract(tool, connection_name='owned', url=None, protocol=None)
    before = snapshot.canonical_json, snapshot.digest
    tool.input_schema['properties']['original']['type'] = 'integer'
    snapshot.descriptor['inputSchema']['properties']['original']['type'] = 'boolean'
    assert snapshot.descriptor['inputSchema']['properties']['original']['type'] == 'string'
    assert (snapshot.canonical_json, snapshot.digest) == before
    with pytest.raises(FrozenInstanceError):
        snapshot.canonical_json = b'changed'


@pytest.mark.parametrize('field,value', [
    ('connection', 'different'), ('url', 'https://different.example/mcp'),
    ('protocol', '2025-11-25'), ('tool', {'name': 'different', 'inputSchema': {'type': 'object'}}),
])
def test_each_original_contract_field_contributes_to_the_digest(field, value):
    before = original()
    document = json.loads(before.canonical_json)
    document[field] = value
    changed = MCPToolContractSnapshot(json.dumps(document, sort_keys=True, separators=(',', ':')).encode())
    assert before.digest != changed.digest


@pytest.mark.parametrize('kind', ['mutable', 'text', 'none'])
def test_snapshot_requires_immutable_bytes(kind):
    data = original().canonical_json
    value = {'mutable': bytearray(data), 'text': data.decode(), 'none': None}[kind]
    with pytest.raises(TypeError, match='immutable'):
        MCPToolContractSnapshot(value)


@pytest.mark.parametrize('document', [
    [], {}, {'connection': 1, 'url': None, 'protocol': None, 'tool': {}},
    {'connection': 'owned', 'url': [], 'protocol': None, 'tool': {}},
    {'connection': 'owned', 'url': None, 'protocol': [], 'tool': {}},
    {'connection': 'owned', 'url': None, 'protocol': None, 'tool': []},
    {'connection': 'owned', 'url': None, 'protocol': None, 'tool': {}, 'extra': True},
], ids=['array', 'missing', 'connection-type', 'url-type', 'protocol-type', 'tool-type', 'extra'])
def test_snapshot_rejects_malformed_contract_shapes(document):
    with pytest.raises(MCPToolContractError):
        MCPToolContractSnapshot(json.dumps(document, sort_keys=True, separators=(',', ':')).encode())


@pytest.mark.parametrize('value', [b'bad-json', b'\xff', b'{"connection":"owned","protocol":null,"tool":{"x":NaN},"url":null}'],
    ids=['syntax', 'encoding', 'nonfinite'])
def test_snapshot_refuses_invalid_json_without_echoing_it(value):
    with pytest.raises(MCPToolContractError) as caught:
        MCPToolContractSnapshot(value)
    assert 'bad-json' not in str(caught.value) and 'NaN' not in str(caught.value)


def test_snapshot_refuses_a_noncanonical_encoding():
    with pytest.raises(MCPToolContractError, match='canonical'):
        MCPToolContractSnapshot(original().canonical_json + b' ')


@pytest.mark.asyncio
async def test_real_input_runtime_uses_the_shared_snapshot_of_the_owned_wire_catalog(mcp_http_server, monkeypatch):
    connection = MCPConnection(mcp_http_server.url)
    captured = []
    real_capture = capture_tool_contract
    def observe(*args, **kwargs):
        snapshot = real_capture(*args, **kwargs)
        captured.append(snapshot)
        return snapshot
    monkeypatch.setattr(input_runtime, 'capture_tool_contract', observe)
    try:
        tools = await connection.connect()
        caller = bind_tool_caller(connection, lambda: connection.is_connected, 'owned-contract')
        registered = SimpleNamespace(tool=SimpleNamespace(bound_caller=caller, native_tool=tools[0]))
        runtime = input_runtime.MCPInputRuntime(None, None)
        digest = runtime._contract(registered)
        assert len(captured) == 1, 'The actual continuation producer must use the one canonical snapshot implementation'
        assert digest == captured[0].digest
        assert captured[0].descriptor == tools[0].model_dump(mode='json', by_alias=True, exclude_none=True)
        assert mcp_http_server.requests and not mcp_http_server.witness
    finally:
        await connection.close()
