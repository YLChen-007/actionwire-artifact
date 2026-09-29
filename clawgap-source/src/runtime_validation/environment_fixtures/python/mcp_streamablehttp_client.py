"""Compatibility alias for AgentScope's historical MCP import path."""

from .streamable_http import (
    StreamableHTTPError,
    StreamableHTTPTransport,
    streamable_http_client,
    streamablehttp_client,
)

__all__ = [
    "StreamableHTTPError",
    "StreamableHTTPTransport",
    "streamable_http_client",
    "streamablehttp_client",
]
