"""
Timeout constants for MCP operations.

These are local copies of values from kestrel_sovereign.kestrel_config.constants
so the MCP package doesn't need a runtime dependency on sovereign's config module.
"""

import os

# Subprocess command timeouts (seconds)
SSH_COMMAND_TIMEOUT_SHORT = 10
SSH_COMMAND_TIMEOUT_DEFAULT = 30

# MCP connection timeouts (seconds)
HTTP_TIMEOUT_SHORT = 5
SESSION_CONNECT_TIMEOUT_SHORT = 10
SESSION_CONNECT_TIMEOUT_DEFAULT = 15
SESSION_CLOSE_TIMEOUT_DEFAULT = float(os.environ.get("KESTREL_MCP_CLOSE_TIMEOUT", "15"))

# Upper bound on a single MCP tool invocation (seconds). Without this a wedged
# downstream MCP server makes ``session.call_tool`` await forever, hanging the
# whole agent turn (F402). Overridable via ``KESTREL_MCP_CALL_TIMEOUT``.
CALL_TOOL_TIMEOUT = int(os.environ.get("KESTREL_MCP_CALL_TIMEOUT", "120"))

# Container management
MCP_CONTAINER_BIND_HOST = "127.0.0.1"
MCP_REMOVAL_ATTEMPTS = 10
MCP_REMOVAL_RETRY_DELAY = 0.5

# Bound finite wire responses and each native SSE event independently. A
# long-lived SSE channel is not subject to a cumulative stream byte cap.
RESPONSE_MAX_BYTES_DEFAULT = int(os.environ.get("KESTREL_MCP_RESPONSE_MAX_BYTES", str(8 * 1024 * 1024)))
