"""Strict host configuration before native owner acquisition."""

import pytest
from pydantic import ValidationError
from kestrel_feature_mcp.oauth_runtime import OAuthSettings


@pytest.mark.parametrize('configuration', [{'enabled': 'true'}, {'close_seconds': 0},
    {'maintenance_seconds': float('inf')}, {'max_connections': 1, 'max_connections_per_principal': 2}])
def test_invalid_oauth_configuration_refuses_before_native_owners(configuration):
    with pytest.raises(ValidationError):
        OAuthSettings.model_validate(configuration)

