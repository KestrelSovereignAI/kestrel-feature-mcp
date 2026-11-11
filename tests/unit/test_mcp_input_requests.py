"""Native MRTR checkpoint classification, with no network or fabricated SDK."""

import pytest
from mcp import types

from kestrel_feature_mcp.input_requests import MCPInputResume, plan_mcp_inputs, validate_form_responses


def checkpoint(requests=None):
    return types.InputRequiredResult.model_validate({
        'resultType': 'input_required', 'requestState': '  opaque\u0000signed-state\n',
        'inputRequests': requests or {}, '_meta': {'private': 'native-secret'},
    })


def form():
    return {'method': 'elicitation/create', 'params': {'mode': 'form', 'message': 'Private city?',
        'requestedSchema': {'type': 'object', 'properties': {'city': {'type': 'string'}}, 'required': ['city']}}}


def url():
    return {'method': 'elicitation/create', 'params': {'mode': 'url', 'message': 'Private consent?',
        'elicitationId': 'original-consent', 'url': 'https://issuer.example/consent'}}


@pytest.mark.parametrize('format_name,valid,invalid', [
    ('email', 'user@example.test', 'invalid-email'),
    ('uri', 'https://example.test/path', 'not a URI'),
    ('date', '2026-11-11', '2026-02-30'),
    ('date-time', '2026-11-11T12:00:00Z', 'not-a-timestamp'),
])
def test_standard_form_formats_are_validated(format_name, valid, invalid):
    request = form()
    request['params']['requestedSchema']['properties']['city']['format'] = format_name
    plan = plan_mcp_inputs(checkpoint({'form': request}), allow_blocking=True)
    assert validate_form_responses(plan, {'form': {'action': 'accept', 'content': {'city': valid}}})
    with pytest.raises(ValueError, match='original schema'):
        validate_form_responses(plan, {'form': {'action': 'accept', 'content': {'city': invalid}}})


@pytest.mark.parametrize('allow_blocking', [True, False])
def test_empty_native_inputs_remain_machine_state_only(allow_blocking):
    native = checkpoint()
    plan = plan_mcp_inputs(native, allow_blocking=allow_blocking)
    assert plan.request_state == native.request_state
    assert plan.operator_requests == plan.declines == plan.unsupported_requests == {}
    assert plan.decisions == ()


def test_interactive_native_forms_need_the_host_and_urls_are_explicitly_declined():
    native = checkpoint({'form': form(), 'url': url()})
    plan = plan_mcp_inputs(native, allow_blocking=True)
    assert set(plan.operator_requests) == {'form'}
    assert plan.operator_requests['form'] == native.input_requests['form']
    assert plan.declines == {'url': types.ElicitResult(action='decline')}
    assert [(d.request_id, d.reason) for d in plan.decisions] == [('url', 'url_mode_declined')]
    assert plan.request_state == native.request_state


def test_unattended_forms_require_no_approver_audit_and_standard_declines():
    plan = plan_mcp_inputs(checkpoint({'first': form(), 'second': form(), 'url': url()}), allow_blocking=False)
    assert plan.operator_requests == {}
    assert set(plan.declines) == {'first', 'second', 'url'}
    assert all(reply == types.ElicitResult(action='decline') for reply in plan.declines.values())
    assert {(d.request_id, d.reason) for d in plan.decisions} == {
        ('first', 'no_approver'), ('second', 'no_approver'), ('url', 'url_mode_declined'),
    }


def test_roots_and_sampling_do_not_become_operator_requests_or_fake_responses():
    native = checkpoint({'roots': {'method': 'roots/list'},
        'sampling': {'method': 'sampling/createMessage', 'params': {'messages': [], 'maxTokens': 1}}})
    plan = plan_mcp_inputs(native, allow_blocking=True)
    assert plan.unsupported_requests == native.input_requests
    assert plan.operator_requests == plan.declines == {}
    assert plan.decisions == ()


def test_native_checkpoint_cannot_be_changed_through_the_input_or_returned_objects():
    native = checkpoint({'form': form(), 'url': url()})
    plan = plan_mcp_inputs(native, allow_blocking=True)
    expected = plan.checkpoint
    native.request_state = 'substituted-state'
    native.input_requests.clear()
    plan.operator_requests['form'].params.message = 'substituted-message'
    plan.checkpoint.meta['private'] = 'substituted-secret'
    plan.declines['url'].action = 'accept'
    assert plan.checkpoint == expected
    assert plan.request_state == '  opaque\u0000signed-state\n'
    assert plan.declines['url'].action == 'decline'
    assert 'native-secret' not in repr(plan)
    assert 'Private city?' not in repr(plan)
    assert 'signed-state' not in repr(plan)


@pytest.mark.parametrize('value', [None, {}, types.CallToolResult(content=[])])
def test_only_the_official_native_intermediate_type_can_be_planned(value):
    with pytest.raises(TypeError, match='native InputRequiredResult'):
        plan_mcp_inputs(value, allow_blocking=True)


@pytest.mark.parametrize('value', [None, 0, 1, 'true'])
def test_missing_or_coerced_interactive_policy_does_not_grant_operator_access(value):
    with pytest.raises(TypeError, match='explicit boolean'):
        plan_mcp_inputs(checkpoint({'form': form()}), allow_blocking=value)


@pytest.mark.parametrize('action', ['accept', 'decline', 'cancel'])
def test_operator_answers_use_the_original_native_form_schema(action):
    plan = plan_mcp_inputs(checkpoint({'form': form(), 'url': url()}), allow_blocking=True)
    answer = {'action': action}
    if action == 'accept':
        answer['content'] = {'city': 'private answer'}
    result = validate_form_responses(plan, {'form': answer})
    assert result['form'].action == action
    resume = MCPInputResume.seal(plan.checkpoint, {**result, **plan.declines})
    answer['action'] = 'cancel'
    assert resume.responses['form'].action == action
    assert resume.request_state == plan.request_state
    assert 'private answer' not in repr(resume) and 'signed-state' not in repr(resume)


@pytest.mark.parametrize('answer', [
    {}, {'other': {'action': 'decline'}}, {'form': {'action': 'invalid'}},
    {'form': {'action': 'accept', 'content': {}}},
    {'form': {'action': 'accept', 'content': {'city': 42}}},
    {'form': {'action': 'accept', 'content': {'city': 'private answer'}, '_meta': {}}},
    {'form': {'action': 'decline', 'content': {'city': 'private answer'}}},
    {'form': {'action': 'accept', 'content': {'city': 'private answer'}}, 'url': {'action': 'accept'}},
])
def test_wrong_missing_or_schema_invalid_responses_are_not_wire_inputs(answer):
    plan = plan_mcp_inputs(checkpoint({'form': form(), 'url': url()}), allow_blocking=True)
    with pytest.raises(ValueError) as caught:
        validate_form_responses(plan, answer)
    assert 'private answer' not in str(caught.value)


def test_resume_requires_every_outstanding_key_even_for_machine_declines():
    native = checkpoint({'form': form(), 'url': url()})
    with pytest.raises(ValueError, match='every outstanding'):
        MCPInputResume.seal(native, {'form': types.ElicitResult(action='decline')})


@pytest.mark.parametrize('schema', [
    {'type': 'object', 'properties': {'city': {'$ref': 'http://127.0.0.1:11434/private-schema'}}},
    {'type': 'object', 'properties': {'city': {'type': 'invented-private-type'}}},
])
def test_peer_schema_cannot_trigger_network_resolution_or_echo_private_content(schema):
    request = form()
    request['params']['requestedSchema'] = schema
    plan = plan_mcp_inputs(checkpoint({'form': request}), allow_blocking=True)
    with pytest.raises(ValueError, match='schema is invalid or requires an unavailable reference') as caught:
        validate_form_responses(plan, {'form': {'action': 'accept', 'content': {'city': 'private answer'}}})
    assert '11434' not in str(caught.value) and 'private answer' not in str(caught.value)
