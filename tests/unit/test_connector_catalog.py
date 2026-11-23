"""Public Registry records can only prepare URLs for the native consent flow."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest
from pydantic import ValidationError as ModelValidationError

from kestrel_feature_mcp.connector_catalog import MAX_ENDPOINT_CHOICES, _registry_choices
from kestrel_feature_mcp.host_configuration import MCPHostFeatureMixin
from kestrel_feature_mcp.official_registry import OfficialRegistryClient, RegistryPage
from kestrel_feature_mcp.oauth_runtime import OAuthSettings


@pytest.mark.parametrize('change', [
    {'url': 'https://resource.example/mcp?token=anything'},
    {'url': 'https://resource.example/mcp/{tenant}'},
    {'url': 'https://Resource.example:443/mcp'},
    {'url': 'https://127.0.0.1/mcp'},
    {'url': 'https://[::1]/mcp'},
    {'url': 'https://localhost./mcp'},
    {'url': 'https://192.88.99.2/mcp'},
    {'url': 'https://invalid_host.example/mcp'},
    {'url': 'https://00.10.20.30/mcp'},
    {'url': 'https://127.1/mcp'},
    {'url': 'https://0x7f.0x01/mcp'},
    {'url': 'https://resource.example:0/mcp'},
    {'name': 'example.com/untrimmed '},
    {'name': 'example.com/untrimmed\n'},
    {'url': 'https://:@resource.example/mcp'},
    {'scopes': ['read', 'read']},
    {'scopes': ['read write']},
    {'scopes': ['read\\write']},
])
def test_connector_preset_rejects_ambiguous_endpoints_or_scopes(change):
    preset = {'name': 'example.com/owned', 'title': 'Owned connector',
              'url': 'https://resource.example/mcp', 'scopes': ['read']}
    assert OAuthSettings.model_validate({'connector_presets': [preset]}).connector_presets[0].url == preset['url']
    with pytest.raises(ModelValidationError):
        OAuthSettings.model_validate({'connector_presets': [preset | change]})


def test_connector_presets_have_resolvable_refs_in_the_host_config_schema():
    model = MCPHostFeatureMixin()
    schema = model.config_schema
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    configuration = {'oauth': {'connector_presets': [{
        'name': 'example.com/owned', 'title': 'Owned connector',
        'url': 'https://resource.example/mcp?login', 'scopes': ['read'],
    }]}}
    validator.validate(configuration)
    preset = configuration['oauth']['connector_presets'][0]
    assert OAuthSettings.model_validate({'connector_presets': [preset]}).connector_presets[0].url == preset['url']
    del configuration['oauth']['connector_presets'][0]['scopes']
    assert not validator.is_valid(configuration)


def test_connector_search_projects_only_selectable_schema_validated_remotes():
    path = Path(__file__).parents[1] / 'fixtures' / 'official_registry_v0_1.json'
    payload = json.loads(path.read_text())
    first = payload['servers'][0]
    server = first['server']
    url = 'https://resource.example/mcp'
    endpoint = {'type': 'streamable-http', 'url': url}
    bearer_endpoint = endpoint | {'headers': [
        {'name': 'Authorization', 'isRequired': True, 'value': 'Bearer {token}'},
        {'name': 'Accept-Encoding', 'isRequired': True, 'value': 'identity'},
    ]}
    server['remotes'] = [
        bearer_endpoint, bearer_endpoint,
        {'type': 'streamable-http', 'url': url + '?login'},
        {'type': 'streamable-http', 'url': url + '?api_key=private'},
        {'type': 'sse', 'url': url + '/sse'},
        {'type': 'streamable-http', 'url': 'http://resource.example/mcp'},
        {'type': 'streamable-http', 'url': url + '/{region}'},
        {'type': 'streamable-http', 'url': url + '?region=us'},
        {'type': 'streamable-http', 'url': 'https://user@example.com/mcp'},
        {'type': 'streamable-http', 'url': 'https://10.0.0.1/mcp'},
        {'type': 'streamable-http', 'url': url + '/\ud800'},
        {'type': 'streamable-http', 'url': url + '/header', 'headers': [{'name': 'X-Account', 'isRequired': True}]},
        {'type': 'streamable-http', 'url': url + '/fixed',
         'headers': [{'name': 'Authorization', 'isRequired': True, 'value': 'Bearer fixed-token'}]},
        {'type': 'streamable-http', 'url': url + '/compressed',
         'headers': [{'name': 'Accept-Encoding', 'isRequired': True, 'choices': ['gzip', 'br']}]},
        {'type': 'streamable-http', 'url': url + '/empty-choices',
         'headers': [{'name': 'Accept-Encoding', 'isRequired': True, 'choices': []}]},
    ]
    untrusted = {
        'server': server | {'name': 'com.example/other',
                            'remotes': [endpoint | {'headers': [{'name': 'X-Trace'},
                                {'name': 'Accept-Encoding', 'isRequired': True, 'choices': ['br', 'identity']},
                                {'name': 'Authorization', 'isRequired': True}]}]},
        '_meta': first['_meta'],
    }
    rejected = {'server': {'name': 'com.example/broken'}}
    metadata_key = 'io.modelcontextprotocol.registry/official'
    deprecated = untrusted | {
        'server': untrusted['server'] | {'name': 'com.example/older', 'title': 'Older\ud800'},
        '_meta': {metadata_key: {'status': 'deprecated', 'statusMessage': 'Choose the new server.'}},
    }
    deleted = untrusted | {
        'server': untrusted['server'] | {'name': 'com.example/deleted'},
        '_meta': {metadata_key: {'status': 'deleted'}},
    }
    payload['servers'] = [first, untrusted, deprecated, deleted, rejected]
    page = RegistryPage('https://registry.example', payload,
                        OfficialRegistryClient()._validate(payload, 'ServerList'))
    assert len(page.servers) == 4 and len(page.rejected_records) == 1
    assert page.next_cursor == payload['metadata']['nextCursor']
    preset = {'name': server['name'], 'title': 'Recommended', 'url': url, 'scopes': ['read']}
    choices, truncated = _registry_choices(page, {(server['name'], url): preset})
    assert not truncated
    assert choices == [
        preset,
        {'name': server['name'], 'title': server.get('title') or server['name'],
         'description': server['description'], 'url': url + '?login', 'scopes': []},
        {'name': 'com.example/other', 'title': server.get('title') or 'com.example/other',
         'description': server['description'], 'url': url, 'scopes': []},
        {'name': 'com.example/older', 'title': 'Older?',
         'description': server['description'], 'url': url, 'scopes': [],
         'deprecated': True, 'status_message': 'Choose the new server.'},
    ]


def test_connector_search_bounds_the_number_of_endpoints_from_one_server():
    path = Path(__file__).parents[1] / 'fixtures' / 'official_registry_v0_1.json'
    payload = json.loads(path.read_text())
    payload['servers'][0]['server']['remotes'] = [
        {'type': 'streamable-http', 'url': f'https://resource.example/mcp/{index}'}
        for index in range(MAX_ENDPOINT_CHOICES + 1)
    ]
    page = RegistryPage('https://registry.example', payload,
                        OfficialRegistryClient()._validate(payload, 'ServerList'))
    choices, truncated = _registry_choices(page, {})
    assert truncated and len(choices) == MAX_ENDPOINT_CHOICES
