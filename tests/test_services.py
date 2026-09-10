"""
OxWg Panel - Phase 3 Services Test Suite
========================================
Comprehensive unmocked tests for the Services Layer:
- node_client
- peer_profiles & subscription_profiles
- panel_settings
- admin_log
- log_retention
- telegram_notifier
- shortlink_service
- update_checker
- wg_parser
- backup_service
- node_monitor
- http_security
- peer_lifecycle
- config_generator
- subscription_service
"""
import os
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from flask import Flask
from core.extensions import db, init_extensions
from models import Peer, InterfaceConfig, ShortLink, Subscription, SubscriptionPeer, Node

import services.errors as errors
import services.node_client as node_client
import services.peer_profiles as peer_profiles
import services.subscription_profiles as subscription_profiles
import services.panel_settings as panel_settings
import services.admin_log as admin_log
import services.log_retention as log_retention
import services.telegram_notifier as telegram_notifier
import services.shortlink_service as shortlink_service
import services.update_checker as update_checker
import services.wg_parser as wg_parser
import services.backup_service as backup_service
import services.node_monitor as node_monitor
import services.http_security as http_security
import services.peer_lifecycle as peer_lifecycle
import services.config_generator as config_generator
import services.subscription_service as subscription_service


class BaseServiceTestCase(unittest.TestCase):
    """Base class providing temporary filesystem directories and SQLite in-memory DB context."""
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.inst_dir = os.path.join(self.temp_dir.name, "instance")
        os.makedirs(self.inst_dir, exist_ok=True)

        self.app = Flask(__name__, instance_path=self.inst_dir)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test-secret-phase3'
        self.app.config['WTF_CSRF_ENABLED'] = False
        init_extensions(self.app)

        self.app_context = self.app.app_context()
        self.app_context.push()
        self.addCleanup(self.app_context.pop)
        db.create_all()


class TestNodeClient(BaseServiceTestCase):
    def test_node_payload_json(self):
        resp = SimpleNamespace(
            headers={'content-type': 'application/json'},
            text='{"ok": true, "code": 123}',
            json=lambda: {"ok": True, "code": 123},
        )
        data = node_client._node_payload(resp)
        self.assertEqual(data, {"ok": True, "code": 123})

    def test_node_payload_text(self):
        resp = SimpleNamespace(
            headers={'content-type': 'text/plain'},
            text='Plain string response',
        )
        data = node_client._node_payload(resp)
        self.assertEqual(data, 'Plain string response')

    def test_node_payload_fallback_json_string(self):
        resp = SimpleNamespace(
            headers={'content-type': 'text/html'},
            text='{"status": "online"}',
        )
        data = node_client._node_payload(resp)
        self.assertEqual(data, {"status": "online"})

    @patch('requests.get')
    def test_node_get(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {'content-type': 'application/json'}
        mock_resp.json.return_value = {'status': 'healthy'}
        mock_get.return_value = mock_resp

        node = SimpleNamespace(base_url='https://node1.example.com', api_key='secret123')
        res = node_client.node_get(node, '/api/health')
        self.assertEqual(res, {'status': 'healthy'})
        mock_get.assert_called_once_with(
            'https://node1.example.com/api/health',
            headers={'Authorization': 'Bearer secret123'},
            timeout=6,
        )

    @patch('requests.post')
    def test_node_post(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.headers = {'content-type': 'application/json'}
        mock_resp.json.return_value = {'ok': True}
        mock_post.return_value = mock_resp

        node = SimpleNamespace(base_url='https://node1.example.com', api_key='secret123')
        res = node_client.node_post(node, '/api/peer', payload={'name': 'test'})
        self.assertEqual(res, {'ok': True})
        mock_post.assert_called_once_with(
            'https://node1.example.com/api/peer',
            headers={'Authorization': 'Bearer secret123', 'Content-Type': 'application/json'},
            json={'name': 'test'},
            timeout=8,
        )

    @patch('requests.delete')
    def test_node_delete(self, mock_delete):
        mock_resp = MagicMock()
        mock_resp.headers = {'content-type': 'text/plain'}
        mock_resp.text = 'deleted'
        mock_delete.return_value = mock_resp

        node = SimpleNamespace(base_url='https://node1.example.com', api_key='secret123')
        res = node_client.node_delete(node, '/api/peer/1')
        self.assertEqual(res, 'deleted')


class TestPeerProfiles(BaseServiceTestCase):
    def test_load_and_save_profiles(self):
        target_file = os.path.join(self.inst_dir, "peer_profiles.json")
        with patch.object(peer_profiles, 'PEER_PROFILES_FILE', target_file):
            d = peer_profiles._load_profiles()
            self.assertIn('Default', d['profiles'])
            self.assertEqual(d['active'], 'Default')

            peer_profiles._set_profile('Gaming', {'dns': '8.8.8.8', 'mtu': 1420})
            prof = peer_profiles._get_profile('Gaming')
            self.assertEqual(prof['dns'], '8.8.8.8')
            self.assertEqual(prof['mtu'], 1420)

            swapped = peer_profiles._set_active_profile('Gaming')
            self.assertTrue(swapped)
            self.assertEqual(peer_profiles._get_profile(None)['dns'], '8.8.8.8')

    def test_panel_default_dns(self):
        target_file = os.path.join(self.inst_dir, "peer_profiles.json")
        with patch.object(peer_profiles, 'PEER_PROFILES_FILE', target_file):
            peer_profiles._set_profile('Default', {'dns': '9.9.9.9, 149.112.112.112'})
            self.assertEqual(peer_profiles._panel_default_dns(), '9.9.9.9, 149.112.112.112')


class TestSubscriptionProfiles(BaseServiceTestCase):
    def test_subscription_profile_crud(self):
        target_file = os.path.join(self.inst_dir, "subscription_profiles.json")
        with patch.object(subscription_profiles, 'SUBSCRIPTION_PROFILES_FILE', target_file):
            empty = subscription_profiles._load_subscription_profiles()
            self.assertEqual(empty['profiles'], {})

            cleaned = subscription_profiles._set_subscription_profile('Pro', {
                'include': {'client': True, 'template': False},
                'client': {'dns': '1.1.1.1'},
            }, activate=True)
            self.assertTrue(cleaned['include']['client'])
            self.assertFalse(cleaned['include']['template'])

            p = subscription_profiles._get_subscription_profile('Pro')
            self.assertIsNotNone(p)
            self.assertEqual(p['client']['dns'], '1.1.1.1')

            rows = subscription_profiles._subscription_profile_rows()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['name'], 'Pro')
            self.assertTrue(rows[0]['active'])

            deleted = subscription_profiles._delete_subscription_profile('Pro')
            self.assertTrue(deleted)
            self.assertIsNone(subscription_profiles._get_subscription_profile('Pro'))


class TestPanelSettings(BaseServiceTestCase):
    def test_load_and_save_panel_settings(self):
        target_file = os.path.join(self.inst_dir, "panel_settings.json")
        with patch.object(panel_settings, 'PANEL_SETTINGS_FILE', target_file):
            settings = panel_settings._load_panel_settings()
            self.assertFalse(settings['tls_enabled'])
            self.assertEqual(settings['https_port'], 443)

            panel_settings._save_panel_settings({
                'tls_enabled': True,
                'domain': 'wg.example.com',
                'https_port': 8443,
                'timezone': 'Europe/Berlin',
            })

            updated = panel_settings._load_panel_settings()
            self.assertTrue(updated['tls_enabled'])
            self.assertEqual(updated['domain'], 'wg.example.com')
            self.assertEqual(updated['https_port'], 8443)
            self.assertEqual(updated['timezone'], 'Europe/Berlin')

    def test_runtime_settings(self):
        target_file = os.path.join(self.inst_dir, "runtime.json")
        with patch.object(panel_settings, 'RUNTIME_FILE', target_file):
            rt = panel_settings._load_runtime()
            self.assertEqual(rt['loglevel'], 'info')

            panel_settings._save_runtime({'port': 9000, 'workers': 4, 'loglevel': 'debug'})
            updated = panel_settings._load_runtime()
            self.assertEqual(updated['port'], 9000)
            self.assertEqual(updated['workers'], 4)
            self.assertEqual(updated['loglevel'], 'debug')

    def test_timezone_validation(self):
        self.assertEqual(panel_settings._valid_timezone_name('UTC'), 'UTC')
        self.assertEqual(panel_settings._valid_timezone_name('Asia/Tehran'), 'Asia/Tehran')
        self.assertIsNone(panel_settings._valid_timezone_name('Invalid/Zone_Name'))

    def test_norm_hostport(self):
        self.assertEqual(panel_settings._norm_hostport('192.168.1.1', 51820), '192.168.1.1:51820')
        self.assertEqual(panel_settings._norm_hostport('2001:db8::1', 51820), '[2001:db8::1]:51820')
        self.assertEqual(panel_settings._norm_hostport('', 51820), '')
        self.assertEqual(panel_settings._norm_hostport('vpn.example.com', None), '')

    def test_is_https(self):
        req = SimpleNamespace(is_secure=True, headers={})
        self.assertTrue(panel_settings._is_https(req))

        req2 = SimpleNamespace(is_secure=False, headers={'X-Forwarded-Proto': 'https'})
        self.assertTrue(panel_settings._is_https(req2))

        req3 = SimpleNamespace(is_secure=False, headers={'CF-Visitor': '{"scheme":"https"}'})
        self.assertTrue(panel_settings._is_https(req3))

        req4 = SimpleNamespace(is_secure=False, headers={'X-Forwarded-Proto': 'http'})
        self.assertFalse(panel_settings._is_https(req4))


class TestAdminLog(BaseServiceTestCase):
    def test_admin_logging_and_retrieval(self):
        target_file = os.path.join(self.inst_dir, "admin_logs.jsonl")
        settings_file = os.path.join(self.inst_dir, "logs_settings.json")
        with patch.object(admin_log, 'ADMIN_LOG_FILE', target_file), \
             patch('core.file_utils.LOGS_SETTINGS_FILE', settings_file):

            entry = admin_log._norm_adminlog({
                'action': 'peer_create',
                'details': 'Created peer client1',
                'admin_id': '1',
                'admin_username': 'admin',
            })
            self.assertEqual(entry['action'], 'peer_create')
            self.assertTrue(entry['ts'].endswith('Z'))
            self.assertEqual(entry['admin_username'], 'admin')

            admin_log.logpanel_action('peer_delete', 'Deleted peer client2')

            logs = admin_log._read_admin_logs()
            self.assertEqual(len(logs), 2)
            self.assertEqual(logs[0]['action'], 'peer_create')
            self.assertEqual(logs[1]['action'], 'peer_delete')


class TestLogRetention(BaseServiceTestCase):
    def test_may_autoclear_size(self):
        log_path = Path(self.inst_dir) / "test.log"
        log_path.write_text("A" * 2000, encoding="utf-8")

        rules = {"max_mb": 1, "max_age_days": 0}
        cleared = log_retention._may_autoclear(log_path, rules)
        self.assertFalse(cleared)
        self.assertTrue(log_path.stat().st_size > 0)

        small_rule = {"max_mb": 0.0001, "max_age_days": 0}
        cleared_trigger = log_retention._may_autoclear(log_path, small_rule)
        self.assertTrue(cleared_trigger)
        self.assertEqual(log_path.stat().st_size, 0)


class TestTelegramNotifier(BaseServiceTestCase):
    def test_tg_human_bytes(self):
        self.assertEqual(telegram_notifier._tg_human_bytes(0), '0 B')
        self.assertEqual(telegram_notifier._tg_human_bytes(500), '500 B')
        self.assertEqual(telegram_notifier._tg_human_bytes(1024), '1.00 KiB')
        self.assertEqual(telegram_notifier._tg_human_bytes(1024 * 1024 * 5), '5.00 MiB')
        self.assertEqual(telegram_notifier._tg_human_bytes(1024 * 1024 * 1024 * 2.5), '2.50 GiB')

    def test_tg_human_duration(self):
        self.assertEqual(telegram_notifier._tg_human_duration(45), '45 seconds')
        self.assertEqual(telegram_notifier._tg_human_duration(120), '2 minutes')
        self.assertEqual(telegram_notifier._tg_human_duration(3665), '1 hour 1 minute')
        self.assertEqual(telegram_notifier._tg_human_duration(86400 * 2 + 3600 * 3), '2 days 3 hours')

    def test_tg_human_datetime(self):
        dt_str = "2026-08-23T12:00:00Z"
        formatted = telegram_notifier._tg_human_datetime(dt_str, relative=False)
        self.assertIn("Aug 2026", formatted)

    def test_tg_event_deduplication(self):
        with patch.object(telegram_notifier, '_TG_EVENT_LAST', {}), \
             patch.object(telegram_notifier, '_load_tg_settings', return_value={'enabled': True, 'bot_token': 'test_token', 'notify': {'app_up': True}}), \
             patch.object(telegram_notifier, '_load_tg_admins', return_value=[{'id': '12345'}]), \
             patch('requests.post') as mock_post:

            mock_post.return_value = SimpleNamespace(status_code=200)

            first = telegram_notifier._send_telegram_event(
                'app_up', 'Server Online', dedupe_key='test_app_up', dedupe_seconds=60
            )
            self.assertTrue(first)

            second = telegram_notifier._send_telegram_event(
                'app_up', 'Server Online', dedupe_key='test_app_up', dedupe_seconds=60
            )
            self.assertFalse(second)


class TestShortlinkService(BaseServiceTestCase):
    def test_shortlink_flow(self):
        iface = InterfaceConfig(name='wg0', path='/etc/wireguard/wg0.conf', address='10.0.0.1/24', listen_port=51820, private_key='test_priv')
        db.session.add(iface)
        db.session.commit()
        peer = Peer(name='alice', private_key='test_peer_priv', address='10.0.0.2/24', public_key='dummy_pubkey_alice_1234567890123456789012=', iface_id=iface.id)
        db.session.add(peer)
        db.session.commit()

        token, url = shortlink_service._shortlink_for_peer(peer)
        self.assertIsNotNone(token)
        self.assertIn(token, url)

        resolved_peer = shortlink_service._peer_from_shortlink_token(token)
        self.assertEqual(resolved_peer.id, peer.id)
        self.assertIsNotNone(ShortLink.query.filter_by(token=token).first().last_used_at)

        tok2, url2 = shortlink_service._shortlink_from_peer_id(peer.id)
        self.assertEqual(tok2, token)

        deleted = shortlink_service._delete_shortlinks_for_peer_ids([peer.id])
        self.assertEqual(deleted, 1)
        self.assertIsNone(shortlink_service._peer_from_shortlink_token(token))


class TestUpdateChecker(BaseServiceTestCase):
    def test_version_tuple_comparison(self):
        self.assertGreater(update_checker._version_tuple("1.2.0"), update_checker._version_tuple("1.1.9"))
        self.assertGreater(update_checker._version_tuple("2.0.0"), update_checker._version_tuple("1.99.99"))
        self.assertEqual(update_checker._version_tuple("v1.5"), (1, 5, 0))
        self.assertEqual(update_checker._version_tuple("invalid"), (0, 0, 0))

    def test_project_version(self):
        v = update_checker._project_version()
        self.assertTrue(bool(v))


class TestWgParser(BaseServiceTestCase):
    def test_valid_wg_key(self):
        valid = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
        self.assertEqual(wg_parser._valid_wg_key(valid), valid)
        self.assertEqual(wg_parser._valid_wg_key("short_key="), "")
        self.assertEqual(wg_parser._valid_wg_key(None), "")

    def test_find_iface(self):
        sample_conf = """
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
MTU = 1420
DNS = 1.1.1.1
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
AllowedIPs = 10.10.0.2/32
"""
        conf_file = Path(self.inst_dir) / "wg0.conf"
        conf_file.write_text(sample_conf, encoding="utf-8")

        parsed = wg_parser.find_iface(str(conf_file))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.name, "wg0")
        self.assertEqual(parsed.address, "10.10.0.1/24")
        self.assertEqual(parsed.listen_port, 51820)
        self.assertEqual(parsed.mtu, 1420)
        self.assertEqual(parsed.dns, "1.1.1.1")
        self.assertIn("iptables -A", parsed.post_up)


class TestBackupService(BaseServiceTestCase):
    def test_backup_settings_and_schedule(self):
        target_prefs = os.path.join(self.inst_dir, "backup_settings.json")
        target_sched = os.path.join(self.inst_dir, "backup_schedule.json")
        with patch.object(backup_service, 'BACKUP_PREFS_FILE', target_prefs), \
             patch.object(backup_service, 'BACKUP_SCHEDULE_FILE', target_sched):

            prefs = backup_service._load_backup_settings()
            self.assertTrue(prefs['include_wg'])

            backup_service._save_backup_settings({'send_to_telegram': True})
            self.assertTrue(backup_service._load_backup_settings()['send_to_telegram'])

            sched = backup_service._load_backup_schedule()
            self.assertFalse(sched['enabled'])
            self.assertEqual(sched['freq'], 'daily')

            backup_service._save_backup_schedule({'enabled': True, 'freq': 'weekly', 'time': '04:00'})
            updated_sched = backup_service._load_backup_schedule()
            self.assertTrue(updated_sched['enabled'])
            self.assertEqual(updated_sched['freq'], 'weekly')


class TestHttpSecurity(BaseServiceTestCase):
    def test_http_security_normalize_networks(self):
        raw = "192.168.1.1, 10.0.0.0/8, ::1"
        cleaned = http_security._http_security_normalize_networks(raw)
        self.assertIn("192.168.1.1/32", cleaned)
        self.assertIn("10.0.0.0/8", cleaned)
        self.assertIn("::1/128", cleaned)

    def test_http_security_trust_and_deny(self):
        settings = {
            "trusted_networks": ["192.168.1.0/24"],
            "deny_networks": ["10.0.0.0/8"],
        }
        self.assertTrue(http_security._http_security_is_trusted("192.168.1.50", settings))
        self.assertFalse(http_security._http_security_is_trusted("192.168.2.50", settings))
        self.assertTrue(http_security._http_security_is_denied("10.5.5.5", settings))
        self.assertFalse(http_security._http_security_is_denied("8.8.8.8", settings))

    def test_http_security_scope_applies(self):
        self.assertTrue(http_security._http_security_scope_applies("/users", "all"))
        self.assertFalse(http_security._http_security_scope_applies("/users", "auth_admin"))
        self.assertTrue(http_security._http_security_scope_applies("/login", "auth_admin"))
        self.assertTrue(http_security._http_security_scope_applies("/api/admin/password", "auth_admin"))


class TestPeerLifecycle(BaseServiceTestCase):
    def test_conv_time_limit(self):
        data = {'time_limit_days': 2, 'time_limit_hours': 12, 'time_limit_minutes': 30}
        days = peer_lifecycle._conv_time_limit(data)
        self.assertAlmostEqual(days, 2.5208333333333335, places=5)

    def test_effective_expiry_calculation(self):
        created_dt = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
        peer = Peer(
            name='bob',
            created_at=created_dt,
            time_limit_days=3.0,
            start_on_first_use=False,
            unlimited=False,
        )
        exp_ts = peer_lifecycle._effective_expiry_ts(peer)
        expected_ts = int(created_dt.timestamp()) + (3 * 86400)
        self.assertEqual(exp_ts, expected_ts)

    def test_accumulate_peer_usage_reboot_offset(self):
        peer = Peer(name='carol', used_bytes_total=1000, bytes_offset=100)
        used, delta, changed = peer_lifecycle._accumulate_peer_usage(peer, live_total=250)
        self.assertEqual(delta, 150)
        self.assertEqual(used, 1150)
        self.assertTrue(changed)

        # Reboot test: live counter drops to 50 (smaller than offset 250)
        used2, delta2, changed2 = peer_lifecycle._accumulate_peer_usage(peer, live_total=50)
        self.assertEqual(delta2, 50)
        self.assertEqual(used2, 1200)
        self.assertTrue(changed2)

    def test_host_port_parsing(self):
        self.assertEqual(peer_lifecycle._host_port("1.2.3.4:51820"), ("1.2.3.4", 51820))
        self.assertEqual(peer_lifecycle._host_port("[2001:db8::1]:51820"), ("2001:db8::1", 51820))
        self.assertEqual(peer_lifecycle._host_port("vpn.example.com"), ("vpn.example.com", None))


class TestConfigGenerator(BaseServiceTestCase):
    def test_endpoint_validation_and_parsing(self):
        self.assertEqual(
            config_generator.parse_endpoint_string("vpn.example.com:51820"),
            "vpn.example.com:51820"
        )
        self.assertEqual(
            config_generator.parse_endpoint_string("[2001:db8::1]:51820"),
            "[2001:db8::1]:51820"
        )
        with self.assertRaises(config_generator.EndpointValidationError):
            config_generator.parse_endpoint_string("http://vpn.example.com:51820")

    def test_client_conf_text_generation(self):
        iface = InterfaceConfig(
            name='wg0',
            public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            dns='1.1.1.1',
        )
        peer = Peer(
            name='alice',
            private_key='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
            address='10.0.0.2/24',
            endpoint='vpn.example.com:51820',
            allowed_ips='0.0.0.0/0',
            persistent_keepalive=25,
            iface=iface,
        )

        conf = config_generator._client_conf_txt(peer)
        self.assertIn("PrivateKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", conf)
        self.assertIn("Address = 10.0.0.2/24", conf)
        self.assertIn("DNS = 1.1.1.1", conf)
        self.assertIn("PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", conf)
        self.assertIn("Endpoint = vpn.example.com:51820", conf)
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_missing_server_pubkey_raises(self):
        iface = InterfaceConfig(name='wg0', public_key='', private_key='')
        peer = Peer(name='alice', private_key='test_key', address='10.0.0.2/24', iface=iface)
        with self.assertRaises(errors.ClientConfigIncomplete):
            config_generator._client_conf_txt(peer)


class TestSubscriptionService(BaseServiceTestCase):
    def test_flag_from_cc(self):
        self.assertEqual(subscription_service._flag_from_cc('US'), '🇺🇸')
        self.assertEqual(subscription_service._flag_from_cc('DE'), '🇩🇪')
        self.assertEqual(subscription_service._flag_from_cc('IR'), '🇮🇷')
        self.assertEqual(subscription_service._flag_from_cc('invalid'), '🌐')

    def test_subscription_access_evaluation(self):
        sub = Subscription(name='vip', enabled=False)
        self.assertFalse(subscription_service.subscription_access(sub)['allowed'])

        sub_ok = Subscription(name='vip', enabled=True, unlimited=True)
        self.assertTrue(subscription_service.subscription_access(sub_ok)['allowed'])

        # Data limit check
        sub_limit = Subscription(
            name='metered',
            enabled=True,
            unlimited=False,
            data_limit_value=1,
            data_limit_unit='Gi',
        )
        access = subscription_service.subscription_access(sub_limit, used_bytes=1024 ** 3 + 100)
        self.assertFalse(access['allowed'])
        self.assertEqual(access['reason'], 'data_exhausted')


class TestServicesBugFixes(BaseServiceTestCase):
    """Deep verification of all bug fixes across the Services layer."""

    def test_peer_profiles_delete_profile(self):
        """Test _delete_profile prevents deleting Default and resets active profile."""
        with patch('services.peer_profiles.PEER_PROFILES_FILE', os.path.join(self.inst_dir, "peer_profiles.json")):
            # Deleting Default is forbidden
            self.assertFalse(peer_profiles._delete_profile("Default"))

            # Create custom profile and set active
            peer_profiles._set_profile("Custom1", {"dns": "8.8.8.8"})
            peer_profiles._set_active_profile("Custom1")
            prof = peer_profiles._load_profiles()
            self.assertEqual(prof["active"], "Custom1")
            self.assertIn("Custom1", prof["profiles"])

            # Delete Custom1 -> should succeed and reset active to Default
            self.assertTrue(peer_profiles._delete_profile("Custom1"))
            prof_after = peer_profiles._load_profiles()
            self.assertEqual(prof_after["active"], "Default")
            self.assertNotIn("Custom1", prof_after["profiles"])

            # Deleting non-existent returns False
            self.assertFalse(peer_profiles._delete_profile("NonExistent"))

    def test_panel_settings_datetime_helpers(self):
        """Test panel timezone conversion and formatting functions."""
        with patch('services.panel_settings._panel_timezone_name', return_value="Asia/Tokyo"):
            utc_dt = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

            # Local datetime Tokyo is UTC+9 -> 21:00
            loc = panel_settings._panel_local_datetime(utc_dt)
            self.assertEqual(loc.hour, 21)

            # Display datetime
            disp = panel_settings._panel_display_datetime(utc_dt, seconds=True)
            self.assertIn("21:00:00", disp)

            # Filename stamp
            stamp = panel_settings._panel_filename_stamp(utc_dt)
            self.assertIn("20260910_210000", stamp)

            # UTC ISO
            iso = panel_settings._utc_timestamp_iso(utc_dt)
            self.assertEqual(iso, "2026-09-10T12:00:00Z")

            # Filter naive UTC
            naive = panel_settings._panel_filter_datetime_utc_naive(utc_dt)
            self.assertIsNone(naive.tzinfo)
            self.assertEqual(naive.hour, 12)

    def test_wg_parser_node_interface_helpers(self):
        """Test node interface identification, device name parsing, and public key persistence."""
        self.assertTrue(wg_parser._iface_is_node("node:1:wg0"))
        self.assertTrue(wg_parser._iface_is_node("n1:wg0"))
        self.assertFalse(wg_parser._iface_is_node("wg0"))

        self.assertEqual(wg_parser.iface_devname("node:2:wg1"), "wg1")
        self.assertEqual(wg_parser.iface_devname("n1:wg0"), "wg0")
        self.assertEqual(wg_parser.iface_devname("wg0"), "wg0")

        self.assertEqual(wg_parser._node_id_from_iface("node:42:wg0"), 42)
        self.assertEqual(wg_parser._node_id_from_iface("n1:wg0"), 1)
        self.assertIsNone(wg_parser._node_id_from_iface("wg0"))
        self.assertIsNone(wg_parser._node_id_from_iface("node:abc:wg0"))

        # Valid 44-char wireguard public key
        key1 = "A" * 43 + "="
        key2 = "B" * 43 + "="

        # Public key extraction from payload
        self.assertEqual(
            wg_parser._public_key_from_node_payload({"public_key": key1}),
            key1
        )
        self.assertEqual(
            wg_parser._public_key_from_node_payload(f'{{"public_key": "{key2}"}}'),
            key2
        )
        self.assertEqual(
            wg_parser._public_key_from_node_payload(key1),
            key1
        )


        # Persist public key
        iface = InterfaceConfig(name="n1:wg0", path="dummy", address="10.0.0.1", listen_port=51820, private_key="(remote)")
        db.session.add(iface)
        db.session.commit()

        self.assertTrue(wg_parser._persist_iface_public_key(iface, key1))
        db.session.refresh(iface)
        self.assertEqual(iface.public_key, key1)

    def test_config_generator_remote_node_pubkey_and_endpoint(self):
        """Test _server_publickey on remote node interfaces with caching."""
        node = Node(name="RemoteNode", base_url="http://node.test:5000", api_key="secret", enabled=True)
        db.session.add(node)
        db.session.flush()

        key = "C" * 43 + "="
        iface = InterfaceConfig(
            name="n1:wg0",
            path="dummy",
            address="10.0.0.1",
            listen_port=51820,
            private_key="(remote)",
            node_id=node.id,
        )
        db.session.add(iface)
        db.session.commit()

        # Mock node public key fetch
        with patch('services.wg_parser._fetch_node_iface_public_key', return_value=key):
            pubkey = config_generator._server_publickey(iface)
            self.assertEqual(pubkey, key)

        # Node endpoint fallback
        with patch('services.node_client.node_get', return_value={'public_ipv4': '203.0.113.10'}):
            ep = config_generator._node_endpoint_fallback(node, "wg0", remote_iface={'listen_port': 51820})
            self.assertEqual(ep, "203.0.113.10:51820")

    def test_peer_lifecycle_disable_peer(self):
        """Test _disable_peer routes to node_post for node interfaces, and wg set for local."""
        # Local interface
        local_iface = InterfaceConfig(name="wg0", path="dummy", address="10.0.0.1", listen_port=51820, private_key="srv_key")
        local_peer = Peer(name="bob", public_key="LOCAL_PUBKEY=", private_key="pk", address="10.0.0.2", iface=local_iface)
        db.session.add_all([local_iface, local_peer])
        db.session.commit()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = SimpleNamespace(returncode=0)
            ok = peer_lifecycle._disable_peer(local_peer, reason="expired")
            self.assertTrue(ok)
            mock_run.assert_called()

        # Remote node interface
        node = Node(name="Node1", base_url="http://node1.test:5000", api_key="secret", enabled=True)
        db.session.add(node)
        db.session.flush()

        node_iface = InterfaceConfig(name="n1:wg0", path="dummy", address="10.0.0.1", listen_port=51820, private_key="(remote)", node_id=node.id)
        node_peer = Peer(name="carol", public_key="REMOTE_PUBKEY=", private_key="pk", address="10.0.0.3", iface=node_iface)
        db.session.add_all([node_iface, node_peer])
        db.session.commit()

        with patch('services.node_client.node_post', return_value={"ok": True}) as mock_post:
            ok = peer_lifecycle._disable_peer(node_peer, reason="quota_exceeded")
            self.assertTrue(ok)
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            self.assertIn("/api/peer/REMOTE_PUBKEY=/disable", args[1])

    def test_subscription_service_inbound_state_offline_peer(self):
        """Test _subscription_inbound_state considers 'offline' peers as usable inbounds."""
        iface = InterfaceConfig(name="wg0", path="dummy", address="10.0.0.1", listen_port=51820, private_key="pk")
        db.session.add(iface)
        db.session.flush()

        peer = Peer(name="dave", public_key="DAVE_PUB=", private_key="pk", address="10.0.0.5", status="offline", iface_id=iface.id)
        db.session.add(peer)
        db.session.flush()

        sub = Subscription(name="mysub", token="SUBTOKEN123", enabled=True)
        db.session.add(sub)
        db.session.flush()

        sp = SubscriptionPeer(subscription_id=sub.id, peer_id=peer.id)
        db.session.add(sp)
        db.session.commit()

        with patch('services.config_generator._server_publickey', return_value="SRV_PUBKEY="), \
             patch('services.config_generator._effective_client_endpoint', return_value="1.2.3.4:51820"):
            state = subscription_service._subscription_inbound_state(sub)
            self.assertEqual(state["inbound_count"], 1)
            self.assertTrue(state["has_inbounds"])

    def test_backup_service_cron_and_timezone_slot(self):
        """Test _cron_field_match and timezone-aware _backup_due_slot."""
        self.assertTrue(backup_service._cron_field_match(5, "*", 0, 59))
        self.assertTrue(backup_service._cron_field_match(15, "*/5", 0, 59))
        self.assertFalse(backup_service._cron_field_match(14, "*/5", 0, 59))
        self.assertTrue(backup_service._cron_field_match(10, "1,10,20", 0, 59))
        self.assertTrue(backup_service._cron_field_match(3, "1-5", 0, 59))
        self.assertFalse(backup_service._cron_field_match(6, "1-5", 0, 59))

        # Timezone-aware slot check
        schedule = {
            "enabled": True,
            "type": "daily",
            "time": "14:30",
            "timezone": "America/New_York",
        }
        # 14:30 in New York (EDT, UTC-4) is 18:30 UTC
        utc_1830 = datetime(2026, 9, 10, 18, 30, 0, tzinfo=timezone.utc)
        slot = backup_service._backup_due_slot(schedule, now_utc=utc_1830)
        self.assertEqual(slot, "2026-09-10")

        # Non-matching time
        utc_1200 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
        self.assertIsNone(backup_service._backup_due_slot(schedule, now_utc=utc_1200))

    def test_telegram_notifier_escaping_and_security(self):
        """Test HTML entity escaping and security notification formatting."""
        # _tg_event_escape
        escaped = telegram_notifier._tg_event_escape('<script>alert("xss") & test</script>')
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&amp;", escaped)
        self.assertIn("&quot;xss&quot;", escaped)

        # _security_notify_enabled
        with patch('services.telegram_notifier._load_tg_settings', return_value={'enabled': True, 'notify': {'login_success': True, 'login_fail': True}}):
            self.assertTrue(telegram_notifier._security_notify_enabled('login_success'))
            self.assertTrue(telegram_notifier._security_notify_enabled('login_failed'))
            self.assertTrue(telegram_notifier._security_notify_enabled('twofa_failed'))
            self.assertFalse(telegram_notifier._security_notify_enabled('unknown_event'))

        # _tg_chatid
        admins = [{'id': '111', 'muted': True}, {'id': '222', 'muted': False}]
        with patch('services.telegram_notifier._load_tg_admins', return_value=admins):
            self.assertEqual(telegram_notifier._tg_chatid(), '222')

    def test_http_security_nftables_and_client_info(self):
        """Test nftables status dictionary and client IP resolution."""
        status = http_security._http_security_nft_status()
        self.assertEqual(status["backend"], "nftables")
        self.assertEqual(status["table"], "wgpanel_security")
        self.assertIn("install_command", status)

        # Client IP resolution with proxy headers
        req_mock = SimpleNamespace(
            headers={'X-Forwarded-For': '203.0.113.195, 10.0.0.1'},
            remote_addr='10.0.0.1',
        )
        client_ip, proxy_chain = http_security._request_client_ip(req_mock)
        self.assertEqual(client_ip, '203.0.113.195')
        self.assertIn('203.0.113.195, 10.0.0.1', proxy_chain)

    def test_shortlink_service_response_for_peer(self):
        """Test _shortlink_response_for_peer outside and inside request context."""
        peer = Peer(id=99, name="eve")
        with patch('services.shortlink_service._shortlink_for_peer', return_value=("token123", "http://panel.test/u/token123")):
            resp = shortlink_service._shortlink_response_for_peer(peer)
            self.assertEqual(resp, {'url': 'http://panel.test/u/token123', 'token': 'token123'})




if __name__ == '__main__':
    unittest.main()

