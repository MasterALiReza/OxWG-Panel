"""
OxWg Panel - Path Constants and Directory Management
=====================================================
Central definition of all filesystem paths used throughout OxWg Panel.
"""
import os
from pathlib import Path

# Base and Instance directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DB_PATH = os.path.join(INSTANCE_DIR, "wg_panel.db")
APP_LOG_FILE = os.path.join(INSTANCE_DIR, "app.log")

# General Settings & State
PANEL_SETTINGS_FILE = os.path.join(INSTANCE_DIR, "panel_settings.json")
RUNTIME_FILE = os.path.join(INSTANCE_DIR, "runtime.json")
TEMPLATE_SETTINGS_FILE = os.path.join(INSTANCE_DIR, "template_settings.json")
ENDPOINT_PRESETS_FILE = os.path.join(INSTANCE_DIR, "endpoint_presets.json")
LAST_PUBLIC_IP_FILE = os.path.join(INSTANCE_DIR, "last_public_ipv4.txt")

# Logging & Retention
ADMIN_LOG_FILE = os.path.join(INSTANCE_DIR, "admin_logs.jsonl")
LOGS_SETTINGS_FILE = Path(INSTANCE_DIR) / "logs_settings.json"
LOGS_SETTINGS_STR = os.path.join(INSTANCE_DIR, "logs_settings.json")
IFACE_LOG_DIR = os.path.join(INSTANCE_DIR, "iface_logs")

# IP Allocation Locks
_ALLOC_LOCK_DIR = os.path.join(INSTANCE_DIR, "locks")

# Telegram Bot Paths
TELEGRAM_ADMINS_FILE = os.path.join(INSTANCE_DIR, "telegram_admins.json")
TELEGRAM_SETTINGS_FILE = os.path.join(INSTANCE_DIR, "telegram_settings.json")
TELEGRAM_LOG_FILE = os.path.join(INSTANCE_DIR, "telegram.log")
TELEGRAM_ADMIN_LOG_FILE = os.path.join(INSTANCE_DIR, "telegram_admin_log.jsonl")
TELEGRAM_HB_FILE = os.path.join(INSTANCE_DIR, "telegram_heartbeat.json")

# Backup System
BACKUP_PREFS_FILE = os.path.join(INSTANCE_DIR, "backup_settings.json")
BACKUP_SCHEDULE_FILE = os.path.join(INSTANCE_DIR, "backup_schedule.json")
BACKUP_LAST_FILE = os.path.join(INSTANCE_DIR, "backup_last.json")
BACKUP_AUTO_DIR = os.path.join(INSTANCE_DIR, "backups")
BACKUP_DIR = BACKUP_AUTO_DIR
_BACKUP_SCHEDULER_STATE_FILE = os.path.join(INSTANCE_DIR, "backup_scheduler_state.json")
_BACKUP_SCHEDULER_LOCK_FILE = os.path.join(INSTANCE_DIR, "backup_scheduler.lock")

# WireGuard configs
WG_CONFIG_DIR = os.environ.get("WIREGUARD_CONF_PATH", "/etc/wireguard")
TG_LOG_FILE = TELEGRAM_LOG_FILE

# HTTP Security & Rate Limiting
_HTTP_4XX_STATE_FILE = os.path.join(INSTANCE_DIR, "suspicious_4xx_state.json")
_HTTP_4XX_LOCK_FILE = os.path.join(INSTANCE_DIR, "suspicious_4xx_state.lock")
_HTTP_SECURITY_SETTINGS_FILE = os.path.join(INSTANCE_DIR, "http_security_settings.json")

# Traffic Policies & GeoIP
TRAFFIC_POLICY_FILE = os.path.join(INSTANCE_DIR, "traffic_policies.json")
TRAFFIC_GEO_DIR = os.path.join(INSTANCE_DIR, "traffic_geo")

# Client & Subscription Profiles
PEER_PROFILE_FILE = os.path.join(INSTANCE_DIR, "peer_profile.json")
PEER_PROFILES_FILE = os.path.join(INSTANCE_DIR, "peer_profiles.json")
SUBSCRIPTION_PROFILES_FILE = os.path.join(INSTANCE_DIR, "subscription_profiles.json")
SUBSCRIPTION_SETTINGS_FILE = os.path.join(INSTANCE_DIR, "subscription_settings.json")
SUBSCRIPTION_PORTAL_OVERRIDES_FILE = os.path.join(INSTANCE_DIR, "subscription_portal_overrides.json")
GEO_CACHE_FILE = os.path.join(INSTANCE_DIR, "subscription_geo_cache.json")

# Node Monitoring
_NODE_NOTIFY_MONITOR_STATE_FILE = os.path.join(INSTANCE_DIR, "node_notification_state.json")
_NODE_NOTIFY_MONITOR_LOCK_FILE = os.path.join(INSTANCE_DIR, "node_notification_monitor.lock")

# Panel Self-Update
UPDATE_STATUS_FILE = Path(INSTANCE_DIR) / "update_status.json"
UPDATE_LOCK_FILE = Path(INSTANCE_DIR) / "update.lock"

# Legacy Database Repair Backup
_TIME_REPAIR_BACKUP = os.path.join(INSTANCE_DIR, "wg_panel.db.pre-time-fix-v5.bak")


def ensure_dirs():
    """Ensure all required runtime directories exist safely."""
    for d in (INSTANCE_DIR, BACKUP_AUTO_DIR, IFACE_LOG_DIR, _ALLOC_LOCK_DIR, TRAFFIC_GEO_DIR):
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass

ensure_dirs()
