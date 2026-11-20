"""Real native ACK handoffs distinguish local retirement from uncertain sends."""
import os
from uuid import uuid4
import pytest
from mcp import types
from mcp.shared.exceptions import MCPError
from kestrel_sdk.resources import ResourceOutcomeUnknown
from kestrel_sovereign.execution_custody import execution_evidence_carriers
from kestrel_sovereign.mcp_tasks import MCPTaskRound
from kestrel_feature_mcp.connection import MCPCallOutcomeUnknownError
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_task_runtime import start, pytestmark


async def waiting(b, peer):
    peer.require_input = True
    host = await start(b)
    assert (await b.client.post('/api/owned-credential-call')).status_code == 200
    pending = await b.client.get('/api/mcp/inputs', params={'session_id': 'credential-chat'})
    row, = pending.json()['inputs']
    return host, row


async def respond(b, row):
    return await b.client.post('/api/mcp/inputs/' + row['request_id'] + '/responses',
        params={'session_id': 'credential-chat'}, json={'revision': row['revision'],
            'operation_id': uuid4().hex,
            'responses': {'form': {'action': 'accept', 'content': {'label': 'native input'}}}})


async def retained(host, row):
    task, = await host.store.list_retained()
    original_input = await host.input_host.store.read_for(task.binding.origin.principal_digest,
        'credential-chat', row['request_id'])
    return task, original_input


def fail_owned_read(originals):
    descriptor = os.open(os.devnull, os.O_WRONLY)
    try:
        os.read(descriptor, 1)
    except OSError as error:
        originals.append(error)
        raise
    finally:
        os.close(descriptor)


async def test_registration_retirement_after_reservation_ack_closes_the_unsent_issuer(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    host = await start(b)
    registration = b.agent._explored_features['mcp:credential']
    reserve = host.store.reserve
    async def retire_after_real_commit(*args, **kwargs):
        result = await reserve(*args, **kwargs)
        b.feature._unmount_tools('mcp:credential')
        return result
    monkeypatch.setattr(host.store, 'reserve', retire_after_real_commit)
    result = await b.client.post('/api/owned-credential-call')
    actual, = await host.store.list_retained()
    peer = mcp_http_server.settings['extensions'][0]
    assert not peer.tool_requests and not b.peer.resource.witness
    assert result.status_code == 200, result.text
    assert actual.phase == 'NOT_SENT'
    assert actual.envelope == {'version': 1, 'refusal': {'reason': 'dispatch_not_started'}}
    assert not registration.task_holds
    assert await host.store.database.fetchone("SELECT COUNT(*) FROM mcp_task_records WHERE phase='ISSUING'") == (0,)


@pytest.mark.parametrize('retire_at', ['joint-ack', 'host-claim-return'])
async def test_acknowledged_unsent_continuation_retires_both_original_claims(
        credential_boundary, mcp_http_server, monkeypatch, retire_at):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    registration = b.agent._explored_features['mcp:credential']
    owner, method = (host.joint, 'resume') if retire_at == 'joint-ack' else (
        host.input_host, 'claim_response')
    original = getattr(owner, method)
    async def retire_after_real_ack(*args, **kwargs):
        result = await original(*args, **kwargs)
        b.feature._unmount_tools('mcp:credential')
        return result
    monkeypatch.setattr(owner, method, retire_after_real_ack)
    response = await respond(b, row)
    task, original_input = await retained(host, row)
    assert response.status_code == 200 and response.json()['state'] == 'NON_RESUMABLE', response.text
    assert not {'continuation', 'app_result'}.intersection(response.json())
    assert len(peer.tool_requests) == 1 and not peer.calls and not b.peer.resource.witness
    assert task.phase == 'NOT_SENT' and original_input.state == 'NON_RESUMABLE'
    assert original_input.revision == row['revision'] + 2
    assert not registration.task_holds
    assert await host.store.database.fetchone("SELECT COUNT(*) FROM mcp_inputs WHERE state IN ('WAITING','RESPONDING')") == (0,)


async def test_wire_marker_prevents_retirement_even_when_the_owned_failure_precedes_bytes(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    start_wire = MCPTaskRound.start_wire
    originals = []
    def failed_after_marker(round):
        start_wire(round)
        fail_owned_read(originals)
    monkeypatch.setattr(MCPTaskRound, 'start_wire', failed_after_marker)
    response = await respond(b, row)
    task, original_input = await retained(host, row)
    assert len(originals) == 1
    assert response.status_code == 503, response.text
    assert task.phase == 'ISSUING' and original_input.state == 'RESPONDING'
    assert len(peer.tool_requests) == 1 and not peer.calls and not b.peer.resource.witness


async def test_unacknowledged_joint_resume_never_becomes_a_known_no_claim_refusal(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    resume, refuse = host.joint.resume, b.feature._task_runtime._refuse
    originals, uncertain = [], []
    async def lose_returned_ack(*args, **kwargs):
        await resume(*args, **kwargs)
        fail_owned_read(originals)
    async def observed_refusal(*args, **kwargs):
        try:
            return await refuse(*args, **kwargs)
        except ResourceOutcomeUnknown as error:
            uncertain.append(error)
            raise
    monkeypatch.setattr(host.joint, 'resume', lose_returned_ack)
    monkeypatch.setattr(b.feature._task_runtime, '_refuse', observed_refusal)
    response = await respond(b, row)
    task, original_input = await retained(host, row)
    assert response.status_code == 503, response.text
    assert task.phase == 'ISSUING' and original_input.state == 'RESPONDING'
    assert len(originals) == len(uncertain) == 1
    assert originals[0] in execution_evidence_carriers(uncertain[0])
    assert len(peer.tool_requests) == 1 and not peer.calls and not b.peer.resource.witness


@pytest.mark.parametrize('code', [
    types.METHOD_NOT_FOUND, types.INVALID_PARAMS, types.HEADER_MISMATCH, types.INVALID_REQUEST])
async def test_real_native_rejection_after_an_input_round_remains_unknown(
        credential_boundary, mcp_http_server, code):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    peer.tool_reject_code = code
    response = await respond(b, row)
    task, original_input = await retained(host, row)
    assert response.status_code == 503, response.text
    assert task.phase == 'ISSUING' and task.envelope is None
    assert original_input.state == 'RESPONDING'
    assert len(peer.tool_requests) == 2
    assert peer.tool_requests[-1]['requestState'] == 'native-mrtr-state'
    assert not peer.calls and not b.peer.resource.witness


async def test_core_rejects_a_producer_attempt_to_retire_real_post_resume_wire_errors(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    peer.tool_reject_code = types.INVALID_PARAMS
    call = b.connection.call_tool
    guards = []
    async def attempted_retirement(*args, **kwargs):
        try:
            return await call(*args, **kwargs)
        except MCPCallOutcomeUnknownError as error:
            assert isinstance(error.__cause__, MCPError)
            actual_native = error.__cause__.error.model_dump(mode='json',
                by_alias=True, exclude_unset=True)
            try:
                await host.current_round().refuse(native_errors=[actual_native])
            except ResourceOutcomeUnknown as refusal:
                guards.append(refusal)
                raise refusal from error
            raise
    monkeypatch.setattr(b.connection, 'call_tool', attempted_retirement)
    response = await respond(b, row)
    task, original_input = await retained(host, row)
    assert len(guards) == 1, 'Core accepted a post-wire retirement based on a producer error claim'
    assert response.status_code == 503 and task.phase == 'ISSUING', response.text
    assert original_input.state == 'RESPONDING' and len(peer.tool_requests) == 2


async def test_local_retirement_cannot_hide_a_received_native_result(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    peer.return_ordinary = True
    settle = host.input_host.settle_response
    async def competing_actual_settlement(claim, **kwargs):
        await host.input_host.store.settle(claim, state='NON_RESUMABLE')
        return await settle(claim, **kwargs)
    monkeypatch.setattr(host.input_host, 'settle_response', competing_actual_settlement)
    response = await respond(b, row)
    task, original_input = await retained(host, row)
    assert response.status_code == 503, response.text
    assert task.phase == 'SETTLED' and task.envelope['native']['resultType'] == 'complete'
    assert original_input.state == 'NON_RESUMABLE'
    assert b.peer.resource.witness == ['owned-effect'] and len(peer.tool_requests) == 2


async def test_local_retirement_requires_the_exact_acknowledged_input_revision(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    claim_response = host.input_host.claim_response
    retire = host.joint.retire_unsent
    async def retire_registration_after_claim(*args, **kwargs):
        result = await claim_response(*args, **kwargs)
        b.feature._unmount_tools('mcp:credential')
        return result
    async def alter_caller_receipt_after_actual_commit(issuance, claim, **kwargs):
        result = await retire(issuance, claim, **kwargs)
        object.__setattr__(claim.record, 'revision', 0)
        return result
    monkeypatch.setattr(host.input_host, 'claim_response', retire_registration_after_claim)
    monkeypatch.setattr(host.joint, 'retire_unsent', alter_caller_receipt_after_actual_commit)
    response = await respond(b, row)
    task, original_input = await retained(host, row)
    assert response.status_code == 503, response.text
    assert task.phase == 'NOT_SENT' and original_input.state == 'NON_RESUMABLE'
    assert original_input.revision == row['revision'] + 2
    assert len(peer.tool_requests) == 1 and not peer.calls and not b.peer.resource.witness


async def test_failed_local_state_read_keeps_the_original_unconfirmed_classification(
        credential_boundary, mcp_http_server, monkeypatch):
    b = credential_boundary
    peer = mcp_http_server.settings['extensions'][0]
    host, row = await waiting(b, peer)
    claim = host.input_host.claim_response
    current = host.input_host.current_record
    resume = b.feature._input_runtime.respond
    failures, reader_failures = [], []
    async def retire_registration_after_claim(*args, **kwargs):
        result = await claim(*args, **kwargs)
        b.feature._unmount_tools('mcp:credential')
        return result
    async def ended_original_reader(*args, **kwargs):
        host.input_host._reader.get().active = False
        try:
            return await current(*args, **kwargs)
        except OSError as error:
            reader_failures.append(error)
            raise
    async def observed_resume(*args, **kwargs):
        try:
            return await resume(*args, **kwargs)
        except ResourceOutcomeUnknown as error:
            failures.append(error)
            raise
    monkeypatch.setattr(host.input_host, 'claim_response', retire_registration_after_claim)
    monkeypatch.setattr(host.input_host, 'current_record', ended_original_reader)
    monkeypatch.setattr(b.feature._input_runtime, 'respond', observed_resume)
    result = await respond(b, row)
    task, closed = await retained(host, row)
    assert task.phase == 'NOT_SENT' and closed.state == 'NON_RESUMABLE'
    assert len(peer.tool_requests) == 1 and not peer.calls
    assert result.status_code == 503, result.text
    assert len(failures) == len(reader_failures) == 1
    evidence = execution_evidence_carriers(failures[0])
    assert reader_failures[0] in evidence
    assert any(isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 2 for error in evidence)
