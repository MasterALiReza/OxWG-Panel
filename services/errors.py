"""
OxWg Panel - Service Exceptions
===============================
Standard exception hierarchy for OxWg Panel services.
"""


class WGPanelError(Exception):
    """Base exception for all WG Panel errors."""
    pass


class AddressAllocationError(WGPanelError):
    """Raised when no free IP address is available on an interface."""
    pass


class WireGuardError(WGPanelError):
    """Raised when a WireGuard operation or subprocess call fails."""
    pass


class SchemaMigrationError(WGPanelError):
    """Raised when a database schema migration fails."""
    pass


class ShortLinkError(WGPanelError):
    """Raised when a short link operation fails."""
    pass


class ClientConfigIncomplete(WGPanelError):
    """Raised when client WireGuard configuration cannot be completed (e.g. missing server pubkey)."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class NodeClientError(WGPanelError):
    """Raised when communication with a remote node agent fails."""
    pass
