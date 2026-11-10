"""Unit tests for the gateway --long-lived flag (#12 follow-up).

Constructor contracts remain pure unit checks. Actual command wiring and
session ownership are exercised through the native Docker CLI by the Core
Gateway permission and cancellation campaign, with physical effect witnesses.
"""

from kestrel_feature_mcp.gateway import DockerMCPGateway
from kestrel_feature_mcp.manager import MCPGatewayManager


def test_long_lived_defaults_on():
    assert DockerMCPGateway().long_lived is True
    assert MCPGatewayManager().gateway.long_lived is True


def test_long_lived_can_be_disabled():
    gw = DockerMCPGateway(long_lived=False)
    assert gw.long_lived is False
    assert MCPGatewayManager(long_lived=False).gateway.long_lived is False
