"""
Timeout constants for MCP operations.

These are local copies of values from kestrel_sovereign.kestrel_config.constants
so the MCP package doesn't need a runtime dependency on sovereign's config module.
"""

# Subprocess command timeouts (seconds)
SSH_COMMAND_TIMEOUT_SHORT = 10
SSH_COMMAND_TIMEOUT_DEFAULT = 30

# HTTP/SSE connection timeouts (seconds)
HTTP_TIMEOUT_SHORT = 5
SESSION_CONNECT_TIMEOUT_SHORT = 10
SESSION_CONNECT_TIMEOUT_DEFAULT = 15

# Container management
MCP_MAX_CONNECTION_ATTEMPTS = 10
MCP_CONNECTION_RETRY_DELAY = 0.5
