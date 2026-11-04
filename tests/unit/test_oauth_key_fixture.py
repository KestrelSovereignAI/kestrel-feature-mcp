"""Grant tests select their owned key even when another key source is set."""
import base64
from kestrel_sdk.security.encryption import get_master_key_bytes
from tests.unit.conftest import owned_oauth_key


def test_fixture_overrides_a_simulated_foreign_key_source(tmp_path, monkeypatch):
    foreign = tmp_path / 'simulated-foreign-key'
    foreign.write_text(base64.urlsafe_b64encode(b'f' * 32).decode())
    monkeypatch.setenv('KESTREL_DATA_KEY_FILE', str(foreign))
    monkeypatch.setenv('KESTREL_DATA_KEY', base64.urlsafe_b64encode(b'r' * 32).decode())
    selected = owned_oauth_key.__wrapped__(tmp_path, monkeypatch)
    assert selected != foreign
    assert get_master_key_bytes() == base64.urlsafe_b64encode(b'q' * 32)
