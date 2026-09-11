"""
OxWg Panel - Database Migrations and Schema Synchronization
===========================================================
Safe forward schema migrations, legacy table alterations, index creation,
and timer row reconstructions for OxWg Panel.
"""
import os
import json
import shutil
import logging
from sqlalchemy import inspect, text, func, or_
from models import (
    db,
    Peer,
    InterfaceConfig,
    ShortLink,
    AdminAccount,
    Subscription,
    PeerEvent,
)
from core.paths import INSTANCE_DIR, DB_PATH, _TIME_REPAIR_BACKUP
from core.ip_utils import peer_address_host
from core.time_utils import now_ts, from_ts, to_ts, isoz, add_days_ts

logger = logging.getLogger(__name__)


class SchemaMigrationError(RuntimeError):
    """The database could not be brought up to the schema this build requires."""


def _admin_columns(db_session=None):
    """Bring admin_account table up to current schema (2FA and recovery codes)."""
    insp = inspect(db.engine)
    if not insp.has_table('admin_account'):
        db.create_all()
        return

    cols = {c['name'] for c in insp.get_columns('admin_account')}
    to_add = []
    if 'totp_secret' not in cols:
        to_add.append(("totp_secret", "TEXT"))
    if 'recovery_codes' not in cols:
        to_add.append(("recovery_codes", "TEXT"))
    if 'twofa_enabled' not in cols:
        to_add.append(("twofa_enabled", "INTEGER DEFAULT 0"))
    if 'last_totp_counter' not in cols:
        to_add.append(("last_totp_counter", "INTEGER DEFAULT 0"))

    if to_add:
        with db.engine.begin() as conn:
            for name, typ in to_add:
                conn.execute(text(f'ALTER TABLE admin_account ADD COLUMN {name} {typ}'))


def _migrate_shortlinks_json_to_db(instance_path=None):
    """Move legacy instance/short_links.json into the short_link DB table.

    Fixes Flask context dependency by accepting optional instance_path,
    falling back to core.paths.INSTANCE_DIR.
    """
    target_dir = instance_path or INSTANCE_DIR
    legacy_file = os.path.join(target_dir, "short_links.json")

    if not os.path.isfile(legacy_file):
        return

    try:
        with open(legacy_file, "r", encoding="utf-8") as f:
            old = json.load(f)
    except Exception:
        logger.exception("Could not read legacy short_links.json")
        return

    if not isinstance(old, dict):
        return

    imported = 0
    skipped = 0

    for token, rec in old.items():
        token = (token or "").strip()
        if not token or not isinstance(rec, dict):
            skipped += 1
            continue

        try:
            peer_id = int(rec.get("peer_id") or 0)
        except Exception:
            peer_id = 0

        if peer_id <= 0:
            skipped += 1
            continue

        peer = db.session.get(Peer, peer_id)
        if not peer:
            skipped += 1
            continue

        existing_token = ShortLink.query.filter_by(token=token).first()
        if existing_token:
            skipped += 1
            continue

        existing_peer = ShortLink.query.filter_by(peer_id=peer_id).first()
        if existing_peer:
            skipped += 1
            continue

        db.session.add(ShortLink(token=token, peer_id=peer_id))
        imported += 1

    if imported:
        db.session.commit()

    try:
        migrated_path = legacy_file + ".migrated"
        if not os.path.exists(migrated_path):
            os.replace(legacy_file, migrated_path)
    except Exception:
        logger.warning("Could not rename migrated short_links.json", exc_info=True)

    logger.info(
        "Shortlink migration finished: imported=%s skipped=%s",
        imported,
        skipped,
    )


def _shortlink_schema(instance_path=None):
    """Ensure short_link table exists and migrate old JSON links.

    Loads Peer through the ORM, so it must run after _peer_schema().
    """
    db.create_all()
    _migrate_shortlinks_json_to_db(instance_path=instance_path)


def _backfill_peer_address_hosts(db_session=None):
    """Backfill address_host column and enforce unique index on (iface_id, address_host)."""
    existing_pairs = set(
        db.session.query(Peer.iface_id, Peer.address_host)
        .filter(Peer.address_host.isnot(None), Peer.address_host != '')
        .all()
    )

    pending = (
        db.session.query(Peer)
        .filter(or_(Peer.address_host.is_(None), Peer.address_host == ''))
        .order_by(Peer.id.asc())
        .all()
    )
    for peer in pending:
        host = peer_address_host(peer.address)
        if not host:
            peer.address_host = None
            continue
        pair = (peer.iface_id, host)
        if pair in existing_pairs:
            # Duplicate on same interface: blank out the newer duplicate to preserve uniqueness
            peer.address_host = None
            logger.warning(
                "Blanked duplicate peer address_host '%s' on iface_id=%s for peer_id=%s",
                host,
                peer.iface_id,
                peer.id,
            )
        else:
            peer.address_host = host
            existing_pairs.add(pair)

    if pending:
        db.session.commit()

    duplicates = (
        db.session.query(Peer.iface_id, Peer.address_host, func.count(Peer.id))
        .filter(Peer.address_host.isnot(None))
        .group_by(Peer.iface_id, Peer.address_host)
        .having(func.count(Peer.id) > 1)
        .all()
    )

    if duplicates:
        resolved = 0
        for iface_id, host, _count in duplicates:
            dup_peers = (
                db.session.query(Peer.id)
                .filter(Peer.iface_id == iface_id, Peer.address_host == host)
                .order_by(Peer.id.asc())
                .all()
            )
            loser_ids = [pid for (pid,) in dup_peers[1:]]
            if loser_ids:
                db.session.query(Peer).filter(Peer.id.in_(loser_ids)).update(
                    {Peer.address_host: None}, synchronize_session=False
                )
                resolved += len(loser_ids)
        db.session.commit()
        logger.warning(
            "Resolved %s duplicate peer address_host row(s) by blanking the "
            "newer duplicates (their `address` column is unchanged). "
            "Duplicates were: %s",
            resolved,
            '; '.join(
                f'iface_id={iface_id} address={host} peers={count}'
                for iface_id, host, count in duplicates
            ),
        )


    if 'uq_peer_iface_address_host' in {ix['name'] for ix in inspect(db.engine).get_indexes('peer')}:
        return

    try:
        with db.engine.begin() as conn:
            conn.execute(text(
                'CREATE UNIQUE INDEX uq_peer_iface_address_host '
                'ON peer (iface_id, address_host)'
            ))
    except Exception:
        logger.debug("Peer address uniqueness index not created", exc_info=True)


def _peer_schema(db_session=None):
    """Bring older databases up to the peer/subscription schema.

    Adds peer.address_host, peer.peer_endpoint, peer.timer_started_at,
    subscription.timer_started_at, and subscription_peer.owned.
    """
    insp = inspect(db.engine)

    if not insp.has_table('peer'):
        return

    statements = []

    peer_cols = {c['name'] for c in insp.get_columns('peer')}
    if 'address_host' not in peer_cols:
        statements.append('ALTER TABLE peer ADD COLUMN address_host VARCHAR(64)')
    if 'peer_endpoint' not in peer_cols:
        statements.append('ALTER TABLE peer ADD COLUMN peer_endpoint VARCHAR(128)')
    if 'timer_started_at' not in peer_cols:
        statements.append('ALTER TABLE peer ADD COLUMN timer_started_at DATETIME')

    if insp.has_table('subscription'):
        subscription_cols = {
            c['name'] for c in insp.get_columns('subscription')
        }
        if 'timer_started_at' not in subscription_cols:
            statements.append(
                'ALTER TABLE subscription ADD COLUMN timer_started_at DATETIME'
            )

    if insp.has_table('subscription_peer'):
        link_cols = {c['name'] for c in insp.get_columns('subscription_peer')}
        if 'owned' not in link_cols:
            statements.append(
                'ALTER TABLE subscription_peer '
                'ADD COLUMN owned BOOLEAN NOT NULL DEFAULT 0'
            )

    if statements:
        with db.engine.begin() as conn:
            for sql in statements:
                conn.execute(text(sql))

    _backfill_peer_address_hosts()


def _interface_schema(db_session=None):
    """Ensure interface_config table columns match current schema."""
    insp = inspect(db.engine)

    if not insp.has_table('interface_config'):
        return

    cols = {c['name'] for c in insp.get_columns('interface_config')}
    statements = []

    if 'endpoint_host' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN endpoint_host VARCHAR(255)'
        )
    if 'endpoint_port' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN endpoint_port INTEGER'
        )
    if 'public_key' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN public_key VARCHAR(128)'
        )
    if 'table' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN "table" VARCHAR(64)'
        )
    if 'pre_up' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN pre_up TEXT'
        )
    if 'pre_down' not in cols:
        statements.append(
            'ALTER TABLE interface_config ADD COLUMN pre_down TEXT'
        )

    if statements:
        with db.engine.begin() as conn:
            for sql in statements:
                conn.execute(text(sql))


def _latest_peer_timer_event_ts(peer_id, event_names, *, details_needles=()):
    """Return the newest canonical UTC timestamp for a timer-anchor event."""
    try:
        rows = (
            PeerEvent.query
            .filter(PeerEvent.peer_id == int(peer_id))
            .filter(PeerEvent.event.in_(tuple(event_names)))
            .order_by(PeerEvent.timestamp.desc())
            .limit(20)
            .all()
        )
    except Exception:
        return None

    for row in rows:
        if details_needles:
            details = str(getattr(row, 'details', '') or '').lower()
            if not any(needle in details for needle in details_needles):
                continue
        timestamp = to_ts(getattr(row, 'timestamp', None))
        if timestamp:
            return timestamp
    return None


def _assign_repaired_expiry(record, expected_ts):
    """Safely update expiry column on record if different from expected timestamp."""
    current_ts = to_ts(getattr(record, 'expires_at', None))
    if expected_ts is None:
        if current_ts is None:
            return False
        record.expires_at = None
        return True

    expected_ts = int(expected_ts)
    if current_ts is not None and abs(int(current_ts) - expected_ts) <= 2:
        return False

    record.expires_at = from_ts(expected_ts)
    return True


def _repair_legacy_timer_rows():
    """Repair old peer/subscription expiries without applying a timezone shift.

    Timezones change presentation only. A timer is reconstructed from its
    canonical UTC anchor plus its exact duration. Reset/enable audit events
    are used as the anchor when a timer was intentionally restarted.
    """
    repaired_peers = 0
    repaired_subscriptions = 0

    # Preserve the original database before the first automatic repair
    try:
        if (
            os.path.isfile(DB_PATH)
            and not os.path.exists(_TIME_REPAIR_BACKUP)
        ):
            shutil.copy2(DB_PATH, _TIME_REPAIR_BACKUP)
    except Exception:
        logger.warning(
            'Could not create pre-time-fix database backup',
            exc_info=True,
        )

    for peer in Peer.query.order_by(Peer.id.asc()).all():
        if list(getattr(peer, 'subscription_links', []) or []):
            continue

        try:
            duration_days = float(getattr(peer, 'time_limit_days', 0) or 0)
        except (TypeError, ValueError, OverflowError):
            duration_days = 0.0

        expected_ts = None
        anchor_ts = None
        if not bool(getattr(peer, 'unlimited', False)) and duration_days > 0:
            if bool(getattr(peer, 'start_on_first_use', False)):
                anchor_ts = to_ts(getattr(peer, 'first_used_at', None))
            else:
                anchor_ts = to_ts(getattr(peer, 'created_at', None))

                restarted_ts = _latest_peer_timer_event_ts(
                    peer.id,
                    ('enabled', 'reset_timer'),
                )
                edited_ts = _latest_peer_timer_event_ts(
                    peer.id,
                    ('edited',),
                    details_needles=(
                        'time_limit_days',
                        'start_on_first_use',
                        'unlimited',
                    ),
                )
                anchor_ts = max(
                    [value for value in (anchor_ts, restarted_ts, edited_ts) if value]
                    or [0]
                ) or None

            expected_ts = add_days_ts(anchor_ts, duration_days)

        if to_ts(getattr(peer, 'timer_started_at', None)) != anchor_ts:
            peer.timer_started_at = from_ts(anchor_ts)
            repaired_peers += 1

        if _assign_repaired_expiry(peer, expected_ts):
            repaired_peers += 1

        if (
            expected_ts
            and expected_ts <= now_ts()
            and str(getattr(peer, 'status', '') or '') == 'blocked'
        ):
            latest_expired = (
                PeerEvent.query
                .filter_by(peer_id=peer.id, event='expired')
                .order_by(PeerEvent.timestamp.desc())
                .first()
            )
            if (
                latest_expired
                and (to_ts(getattr(latest_expired, 'timestamp', None)) or 0)
                >= int(anchor_ts or 0)
            ):
                corrected_detail = f'Expired at {isoz(from_ts(expected_ts))}'
                if str(latest_expired.details or '') != corrected_detail:
                    latest_expired.details = corrected_detail
                    repaired_peers += 1

    for sub in Subscription.query.order_by(Subscription.id.asc()).all():
        try:
            duration_days = float(getattr(sub, 'time_limit_days', 0) or 0)
        except (TypeError, ValueError, OverflowError):
            duration_days = 0.0

        expected_ts = None
        anchor_ts = None
        if not bool(getattr(sub, 'unlimited', False)) and duration_days > 0:
            if bool(getattr(sub, 'start_on_first_use', False)):
                anchor_ts = to_ts(getattr(sub, 'first_used_at', None))
            else:
                anchor_ts = to_ts(getattr(sub, 'created_at', None))
                peer_ids = [
                    int(link.peer_id)
                    for link in (getattr(sub, 'links', []) or [])
                    if getattr(link, 'peer_id', None)
                ]
                if peer_ids:
                    reset_event = (
                        PeerEvent.query
                        .filter(PeerEvent.peer_id.in_(peer_ids))
                        .filter(PeerEvent.event == 'subscription_reset_timer')
                        .order_by(PeerEvent.timestamp.desc())
                        .first()
                    )
                    reset_ts = to_ts(
                        getattr(reset_event, 'timestamp', None)
                    ) if reset_event else None
                    if reset_ts:
                        anchor_ts = max(anchor_ts or 0, reset_ts)

            expected_ts = add_days_ts(anchor_ts, duration_days)

        if to_ts(getattr(sub, 'timer_started_at', None)) != anchor_ts:
            sub.timer_started_at = from_ts(anchor_ts)
            repaired_subscriptions += 1

        if _assign_repaired_expiry(sub, expected_ts):
            repaired_subscriptions += 1

        for link in (getattr(sub, 'links', []) or []):
            peer = getattr(link, 'peer', None)
            if not peer:
                continue
            peer_changed = False
            desired_days = duration_days or None
            desired_start = bool(getattr(sub, 'start_on_first_use', False))
            desired_unlimited = bool(getattr(sub, 'unlimited', False))
            desired_first_used = getattr(sub, 'first_used_at', None)
            desired_timer_started = getattr(sub, 'timer_started_at', None)

            if getattr(peer, 'time_limit_days', None) != desired_days:
                peer.time_limit_days = desired_days
                peer_changed = True
            if bool(getattr(peer, 'start_on_first_use', False)) != desired_start:
                peer.start_on_first_use = desired_start
                peer_changed = True
            if bool(getattr(peer, 'unlimited', False)) != desired_unlimited:
                peer.unlimited = desired_unlimited
                peer_changed = True
            if to_ts(getattr(peer, 'first_used_at', None)) != to_ts(desired_first_used):
                peer.first_used_at = desired_first_used
                peer_changed = True
            if to_ts(getattr(peer, 'timer_started_at', None)) != to_ts(desired_timer_started):
                peer.timer_started_at = desired_timer_started
                peer_changed = True
            if _assign_repaired_expiry(peer, expected_ts):
                peer_changed = True

            if peer_changed:
                repaired_peers += 1

    if repaired_peers or repaired_subscriptions:
        db.session.commit()
        logger.warning(
            'Canonical UTC timer repair completed: peers=%s subscriptions=%s',
            repaired_peers,
            repaired_subscriptions,
        )
    else:
        db.session.rollback()

    return {
        'peers': repaired_peers,
        'subscriptions': repaired_subscriptions,
    }


def _migrate_schema(instance_path=None):
    """Bring the database schema up to date with the application requirements."""
    try:
        db.create_all()
        _admin_columns()
        _peer_schema()
        _interface_schema()
        _shortlink_schema(instance_path=instance_path)
        _repair_legacy_timer_rows()
    except Exception as exc:
        raise SchemaMigrationError(str(exc)) from exc

    logger.info("DB initialized / migrated OK")


def bootstrap(app=None):
    """Run schema migrations, optionally wrapping in a Flask application context."""
    if app is not None:
        with app.app_context():
            _migrate_schema(getattr(app, 'instance_path', None))
    else:
        _migrate_schema()
