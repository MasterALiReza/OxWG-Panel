"""
OxWg Panel - Application Constants
==================================
Global numeric and string constants for OxWg Panel.
"""

ACTIVE_WITHIN_SECONDS = 180    # Peer considered "online" within this window (3 min)
PANEL_UPDATE_TTL = 1800        # Version check cache TTL (30 min)
GEO_CACHE_TTL = 86400          # Geo lookup cache TTL (24h)
LOG_TAIL_MAX_BYTES = 50_000    # Max bytes to read from log tail
MAX_ADMIN_LOGS = 2000          # Max admin log lines to return
PUBLIC_IP_CACHE_TTL = 3600     # Public IPv4 cache TTL (1 hour)
PUBLIC_IPV6_CACHE_TTL = 600    # Public IPv6 cache TTL (10 min)
MAX_ENUMERATED_HOSTS = 8192    # Max host IPs enumerated per subnet

PANEL_BRAND_NAME = "OxWg Panel"
PANEL_SHORT_NAME = "OxWg"

