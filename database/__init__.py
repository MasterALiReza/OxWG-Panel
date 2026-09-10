"""
OxWg Panel - Database Package
=============================
Schema migrations, bootstrapping, and database integrity maintenance.
"""
from .migrations import (
    SchemaMigrationError,
    _migrate_schema,
    _admin_columns,
    _peer_schema,
    _interface_schema,
    _shortlink_schema,
    _repair_legacy_timer_rows,
    _backfill_peer_address_hosts,
    _migrate_shortlinks_json_to_db,
    bootstrap,
)

__all__ = [
    'SchemaMigrationError',
    '_migrate_schema',
    '_admin_columns',
    '_peer_schema',
    '_interface_schema',
    '_shortlink_schema',
    '_repair_legacy_timer_rows',
    '_backfill_peer_address_hosts',
    '_migrate_shortlinks_json_to_db',
    'bootstrap',
]
