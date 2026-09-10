"""
OxWg Panel - Phase 1 & Phase 2 Comprehensive Test Suite
======================================================
Tests core infrastructure, cryptographic operations, URL/IP safety,
Flask extensions, URL build fallback handlers, and database migrations.
Uses real Flask app and real SQLite in-memory engine (no shallow mocks).
"""
import os
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from flask import Flask, Blueprint, url_for
from cryptography.fernet import Fernet

import core.constants as constants
import core.paths as paths
import core.time_utils as time_utils
import core.file_utils as file_utils
import core.crypto as crypto
import core.url_utils as url_utils
import core.ip_utils as ip_utils
from core.extensions import db, login_manager, csrf, Admin, load_user, init_extensions
import database.migrations as migrations
from models import Peer, InterfaceConfig, AdminAccount, ShortLink, PeerEvent


class TestCoreConstants(unittest.TestCase):
    def test_constants_values(self):
        self.assertEqual(constants.ACTIVE_WITHIN_SECONDS, 180)
        self.assertEqual(constants.PANEL_UPDATE_TTL, 1800)
        self.assertEqual(constants.GEO_CACHE_TTL, 86400)
        self.assertEqual(constants.LOG_TAIL_MAX_BYTES, 50000)
        self.assertEqual(constants.MAX_ADMIN_LOGS, 2000)
        self.assertEqual(constants.PUBLIC_IP_CACHE_TTL, 3600)
        self.assertEqual(constants.PUBLIC_IPV6_CACHE_TTL, 600)


class TestCorePaths(unittest.TestCase):
    def test_paths_defined_and_absolute(self):
        self.assertTrue(os.path.isabs(paths.BASE_DIR))
        self.assertTrue(os.path.isabs(paths.INSTANCE_DIR))
        self.assertTrue(os.path.isabs(paths.DB_PATH))
        self.assertIn(paths.INSTANCE_DIR, paths.APP_LOG_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths.PANEL_SETTINGS_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths.TELEGRAM_ADMINS_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths.BACKUP_PREFS_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths.TRAFFIC_POLICY_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths.PEER_PROFILE_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths._TIME_REPAIR_BACKUP)
        self.assertIn(paths.INSTANCE_DIR, paths._HTTP_4XX_STATE_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths._HTTP_4XX_LOCK_FILE)
        self.assertIn(paths.INSTANCE_DIR, paths._HTTP_SECURITY_SETTINGS_FILE)

        paths.ensure_dirs()
        self.assertTrue(os.path.isdir(paths.INSTANCE_DIR))
        self.assertTrue(os.path.isdir(paths.BACKUP_AUTO_DIR))
        self.assertTrue(os.path.isdir(paths.IFACE_LOG_DIR))


class TestCoreTimeUtils(unittest.TestCase):
    def test_now_ts_and_conversions(self):
        t = time_utils.now_ts()
        self.assertIsInstance(t, int)
        self.assertGreater(t, 1700000000)

        dt = time_utils.from_ts(t)
        self.assertIsNone(dt.tzinfo)
        self.assertEqual(time_utils.to_ts(dt), t)

        self.assertIsNone(time_utils.to_ts(None))
        self.assertIsNone(time_utils.from_ts(None))

    def test_to_ts_with_string_and_tz(self):
        iso_str = "2026-09-10T01:30:00Z"
        ts = time_utils.to_ts(iso_str)
        self.assertIsNotNone(ts)

        aware_dt = datetime(2026, 9, 10, 1, 30, 0, tzinfo=timezone.utc)
        self.assertEqual(time_utils.to_ts(aware_dt), ts)

    def test_add_days_ts(self):
        self.assertEqual(time_utils.add_days_ts(1000, 1), 1000 + 86400)
        self.assertEqual(time_utils.add_days_ts(1000, 0.5), 1000 + 43200)
        self.assertIsNone(time_utils.add_days_ts(None, 1))
        self.assertIsNone(time_utils.add_days_ts(1000, -1))
        self.assertIsNone(time_utils.add_days_ts(1000, 'bad'))

    def test_isoz_and_tg_parse_datetime(self):
        t = 1757462400
        iso = time_utils.isoz(t)
        self.assertTrue(iso.endswith('Z'))

        parsed = time_utils._tg_parse_datetime(iso)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertIsNone(time_utils._tg_parse_datetime(''))
        self.assertIsNone(time_utils._tg_parse_datetime('—'))
        self.assertIsNone(time_utils.isoz(None))

    def test_panel_filename_stamp(self):
        stamp = time_utils._panel_filename_stamp(1757462400)
        self.assertEqual(len(stamp), 15)
        self.assertIn('_', stamp)

    def test_utc_log_formatter(self):
        fmt = time_utils._utc_log_formatter("%(asctime)s %(message)s")
        self.assertIsNotNone(fmt)


class TestCoreFileUtils(unittest.TestCase):
    def test_json_load_and_save(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, 'test.json')
            file_utils._write_json(p, {'key': 'value', 'num': 100})
            self.assertEqual(file_utils._read_json(p), {'key': 'value', 'num': 100})

            file_utils._json_save(p, {'saved': True})
            self.assertEqual(file_utils._json_load(p), {'saved': True})

            missing = os.path.join(td, 'missing.json')
            self.assertEqual(file_utils._json_load(missing, default='fb'), 'fb')
            self.assertEqual(file_utils._read_json(missing), {})

    def test_extend_file_and_auto_trim(self):
        with tempfile.TemporaryDirectory() as td:
            log_p = os.path.join(td, 'test.log')
            settings_p = os.path.join(td, 'logs_settings.json')
            with patch('core.file_utils.LOGS_SETTINGS_FILE', Path(settings_p)):
                file_utils._save_log_settings({'enabled': True, 'persist': True, 'keep_last_lines': 3})
                file_utils._extend_file(log_p, 'line 1', source='app')
                file_utils._extend_file(log_p, 'line 2', source='app')
                file_utils._extend_file(log_p, 'line 3', source='app')
                file_utils._extend_file(log_p, 'line 4', source='app')

                with open(log_p, 'r', encoding='utf-8') as f:
                    lines = [ln.strip() for ln in f.readlines()]
                self.assertEqual(lines, ['line 2', 'line 3', 'line 4'])

    def test_now_iso(self):
        iso = file_utils._now_iso()
        self.assertTrue(iso.endswith('Z'))
        self.assertIn('T', iso)


class TestCoreCrypto(unittest.TestCase):
    def setUp(self):
        self.key = Fernet.generate_key().decode()
        self.orig_key = os.environ.get('FERNET_KEY')
        os.environ['FERNET_KEY'] = self.key

    def tearDown(self):
        if self.orig_key is not None:
            os.environ['FERNET_KEY'] = self.orig_key
        else:
            os.environ.pop('FERNET_KEY', None)

    def test_gen_and_hash_recovery(self):
        codes = crypto._gen_recovery(n=5, length=8)
        self.assertEqual(len(codes), 5)
        self.assertTrue(all(len(c) == 8 for c in codes))

        secret = 'RECOVER-123'
        hashed = crypto.hash_recovery(secret)
        self.assertTrue(hashed.startswith('sha256$'))
        self.assertTrue(crypto.verify_recovery(secret, hashed))
        self.assertFalse(crypto.verify_recovery('WRONG', hashed))
        self.assertFalse(crypto.verify_recovery('', ''))

    def test_encryption_decryption_and_node_api_key(self):
        secret = 'my-node-api-key-999'
        enc = crypto._probably_encrypt(secret)
        self.assertNotEqual(enc, secret)
        dec = crypto._probably_decrypt(enc)
        self.assertEqual(dec, secret)

        # Node API key extraction
        class DummyNode:
            def __init__(self, key):
                self.api_key = key
                self.id = 1

        # Plain key
        self.assertEqual(crypto._read_api_key(DummyNode('plain-key')), 'plain-key')
        # Encrypted key (must decrypt properly!)
        self.assertEqual(crypto._read_api_key(DummyNode(enc)), secret)
        # Empty key
        self.assertEqual(crypto._read_api_key(DummyNode('')), '')

        # Legacy enc$ prefix
        legacy_enc = f"enc${Fernet(self.key.encode()).encrypt(b'legacy-key').decode()}"
        self.assertEqual(crypto._read_api_key(DummyNode(legacy_enc)), 'legacy-key')


class TestCoreUrlUtils(unittest.TestCase):
    def test_http_url(self):
        self.assertTrue(url_utils._http_url('http://example.com'))
        self.assertTrue(url_utils._http_url('https://example.com:8443/path'))
        self.assertFalse(url_utils._http_url('ftp://example.com'))
        self.assertFalse(url_utils._http_url('javascript:alert(1)'))
        self.assertFalse(url_utils._http_url(''))
        self.assertFalse(url_utils._http_url(None))

    def test_safe_url(self):
        self.assertTrue(url_utils._safe_url('/dashboard', host_url='http://localhost:5000'))
        self.assertTrue(url_utils._safe_url('http://localhost:5000/users', host_url='http://localhost:5000'))
        self.assertFalse(url_utils._safe_url('http://evil.com/phish', host_url='http://localhost:5000'))
        self.assertFalse(url_utils._safe_url('javascript:void(0)', host_url='http://localhost:5000'))

    def test_norm_base_url(self):
        self.assertEqual(url_utils._norm_base_url('https://example.com/'), 'https://example.com')
        self.assertEqual(url_utils._norm_base_url('https://example.com'), 'https://example.com')

    def test_validate_node_base_url_ssrf(self):
        self.assertFalse(url_utils._validate_node_base_url('http://127.0.0.1')[0])
        self.assertFalse(url_utils._validate_node_base_url('http://localhost:8080')[0])
        self.assertFalse(url_utils._validate_node_base_url('http://10.0.0.1')[0])
        self.assertFalse(url_utils._validate_node_base_url('http://192.168.1.1')[0])
        self.assertFalse(url_utils._validate_node_base_url('http://172.16.0.1')[0])
        self.assertFalse(url_utils._validate_node_base_url('http://[::1]')[0])
        self.assertFalse(url_utils._validate_node_base_url('http://169.254.169.254')[0])
        self.assertTrue(url_utils._validate_node_base_url('https://8.8.8.8:443')[0])


class TestCoreIpUtils(unittest.TestCase):
    def test_safe_ip_and_peer_address_host(self):
        self.assertEqual(str(ip_utils._safe_ip('10.0.0.1/24')), '10.0.0.1')
        self.assertEqual(str(ip_utils._safe_ip('fd00::1/64')), 'fd00::1')
        self.assertIsNone(ip_utils._safe_ip('invalid'))

        self.assertEqual(ip_utils.peer_address_host('10.8.0.2/32'), '10.8.0.2')
        self.assertEqual(ip_utils.peer_address_host('fd00::2/128'), 'fd00::2')
        self.assertIsNone(ip_utils.peer_address_host('bad-addr'))

    def test_first_cidr(self):
        self.assertEqual(ip_utils._first_cidr('10.0.0.2/24, fd00::2/64'), '10.0.0.2/24')
        self.assertEqual(ip_utils._first_cidr('fd00::2/64'), 'fd00::2/64')
        self.assertIsNone(ip_utils._first_cidr(''))
        self.assertIsNone(ip_utils._first_cidr(None))


class TestCoreExtensionsAndLegacyUrlHandler(unittest.TestCase):
    def setUp(self):
        self.app = Flask('test_ext_app')
        self.app.config['SERVER_NAME'] = 'panel.oxwg.com'
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SECRET_KEY'] = 'test-secret'
        self.app.config['WTF_CSRF_ENABLED'] = False
        init_extensions(self.app)

        # Register mock blueprints for URL resolution
        auth_bp = Blueprint('auth_bp', __name__)
        @auth_bp.route('/login')
        def login(): return 'login'
        @auth_bp.route('/logout')
        def logout(): return 'logout'
        @auth_bp.route('/register')
        def register(): return 'register'

        peers_bp = Blueprint('peers_bp', __name__)
        @peers_bp.route('/users')
        def users(): return 'users'

        shortlinks_bp = Blueprint('shortlinks_bp', __name__)
        @shortlinks_bp.route('/u/<token>')
        def user_peer_page(token): return f'peer {token}'

        settings_bp = Blueprint('settings_bp', __name__)
        @settings_bp.route('/settings')
        def settings_page(): return 'settings'
        @settings_bp.route('/api/timezone')
        def api_timezone(): return 'tz'

        misc_bp = Blueprint('misc_bp', __name__)
        @misc_bp.route('/')
        def index(): return 'index'

        self.app.register_blueprint(auth_bp)
        self.app.register_blueprint(peers_bp)
        self.app.register_blueprint(shortlinks_bp)
        self.app.register_blueprint(settings_bp)
        self.app.register_blueprint(misc_bp)

    def test_admin_class(self):
        adm = Admin('root_admin')
        self.assertEqual(adm.id, '1')
        self.assertEqual(adm.username, 'root_admin')
        self.assertTrue(adm.is_admin)
        self.assertTrue(adm.is_superuser)
        self.assertTrue(adm.is_authenticated)

    def test_login_manager_and_load_user(self):
        self.assertEqual(login_manager.login_view, 'auth_bp.login')
        with self.app.app_context():
            db.create_all()
            self.assertIsNone(load_user('1'))
            acc = AdminAccount(username='paneladmin', password_hash='hash123')
            db.session.add(acc)
            db.session.commit()

            user = load_user('1')
            self.assertIsNotNone(user)
            self.assertEqual(user.username, 'paneladmin')
            self.assertIsNone(load_user('999'))

    def test_legacy_url_build_handler_fallbacks(self):
        with self.app.app_context(), self.app.test_request_context():
            self.assertEqual(url_for('login'), '/login')
            self.assertEqual(url_for('logout'), '/logout')
            self.assertEqual(url_for('register'), '/register')
            self.assertEqual(url_for('users'), '/users')
            self.assertEqual(url_for('index'), '/')
            self.assertEqual(url_for('settings_page'), '/settings')
            self.assertEqual(url_for('api_timezone'), '/api/timezone')

            # External URL generation
            ext_url = url_for('user_peer_page', token='test_tok', _external=True)
            self.assertEqual(ext_url, 'http://panel.oxwg.com/u/test_tok')

            # Alias compatibility
            self.assertEqual(url_for('auth.login'), '/login')
            self.assertEqual(url_for('peers.users'), '/users')


class TestDatabaseMigrations(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.app = Flask('test_db_app')
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SECRET_KEY'] = 'test-secret'
        self.app.config['WTF_CSRF_ENABLED'] = False
        init_extensions(self.app)

    def tearDown(self):
        self.td.cleanup()

    def test_migrations_and_schema_sync(self):
        with self.app.app_context():
            # Run schema migration on empty DB
            migrations._migrate_schema(instance_path=self.td.name)

            iface = InterfaceConfig(
                name='wg0',
                path='/etc/wireguard/wg0.conf',
                private_key='iface_priv_key',
                address='10.0.0.1/24',
                listen_port=51820,
            )
            db.session.add(iface)
            db.session.commit()

            # Create test peers with edge cases
            p1 = Peer(
                iface_id=iface.id,
                name='p_unlimited',
                public_key='pub1',
                private_key='priv1',
                address='10.0.0.2/32',
                unlimited=True,
            )
            p2 = Peer(
                iface_id=iface.id,
                name='p_negative_days',
                public_key='pub2',
                private_key='priv2',
                address='10.0.0.3/32',
                time_limit_days=-5,
            )
            p3 = Peer(
                iface_id=iface.id,
                name='p_timer_30d',
                public_key='pub3',
                private_key='priv3',
                address='10.0.0.4/32',
                time_limit_days=30,
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            p4 = Peer(
                iface_id=iface.id,
                name='p_first_use',
                public_key='pub4',
                private_key='priv4',
                address='10.0.0.5/32',
                time_limit_days=10,
                start_on_first_use=True,
                first_used_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )
            p5 = Peer(
                iface_id=iface.id,
                name='p_blocked',
                public_key='pub5',
                private_key='priv5',
                address='10.0.0.6/32',
                time_limit_days=1,
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                status='blocked',
            )
            db.session.add_all([p1, p2, p3, p4, p5])
            db.session.commit()

            ev = PeerEvent(
                peer_id=p5.id,
                event='expired',
                timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
                details='old details',
            )
            db.session.add(ev)
            db.session.commit()

            # Test timer repair
            repair_res = migrations._repair_legacy_timer_rows()
            self.assertGreaterEqual(repair_res['peers'], 5)

            self.assertIsNone(p1.expires_at)
            self.assertIsNone(p2.expires_at)
            self.assertEqual(p3.expires_at, datetime(2026, 1, 31, 0, 0, 0))
            self.assertEqual(p4.expires_at, datetime(2026, 2, 11, 0, 0, 0))
            self.assertEqual(p5.expires_at, datetime(2026, 1, 2, 0, 0, 0))
            self.assertEqual(ev.details, 'Expired at 2026-01-02T00:00:00Z')

    def test_backfill_duplicate_address_hosts_resolution(self):
        with self.app.app_context():
            migrations._migrate_schema(instance_path=self.td.name)

            iface = InterfaceConfig(
                name='wg1',
                path='/etc/wireguard/wg1.conf',
                private_key='priv_iface1',
                address='10.1.0.1/24',
                listen_port=51821,
            )
            db.session.add(iface)
            db.session.commit()

            # Insert two peers with identical address on same interface
            p_orig = Peer(
                iface_id=iface.id,
                name='original_peer',
                public_key='orig_pub',
                private_key='orig_priv',
                address='10.1.0.10/32',
            )
            p_dup = Peer(
                iface_id=iface.id,
                name='duplicate_peer',
                public_key='dup_pub',
                private_key='dup_priv',
                address='10.1.0.10/32',
            )
            db.session.add_all([p_orig, p_dup])
            db.session.commit()

            # Reset address_host to simulate unmigrated records
            p_orig.address_host = None
            p_dup.address_host = None
            db.session.commit()

            # Running backfill must resolve duplicates without raising IntegrityError
            migrations._backfill_peer_address_hosts()

            db.session.refresh(p_orig)
            db.session.refresh(p_dup)

            self.assertEqual(p_orig.address_host, '10.1.0.10')
            self.assertIsNone(p_dup.address_host)

    def test_shortlink_json_migration(self):
        with self.app.app_context():
            migrations._migrate_schema(instance_path=self.td.name)

            iface = InterfaceConfig(
                name='wg2',
                path='/etc/wireguard/wg2.conf',
                private_key='priv_iface2',
                address='10.2.0.1/24',
                listen_port=51822,
            )
            db.session.add(iface)
            db.session.commit()

            peer = Peer(
                iface_id=iface.id,
                name='p_short',
                public_key='short_pub',
                private_key='short_priv',
                address='10.2.0.5/32',
            )
            db.session.add(peer)
            db.session.commit()


            json_file = os.path.join(self.td.name, 'short_links.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'tok_valid': {'peer_id': peer.id},
                    'tok_nonexistent': {'peer_id': 99999},
                    '': {'peer_id': peer.id},
                }, f)

            migrations._migrate_shortlinks_json_to_db(instance_path=self.td.name)

            links = ShortLink.query.filter_by(token='tok_valid').all()
            self.assertEqual(len(links), 1)
            self.assertEqual(links[0].peer_id, peer.id)
            self.assertFalse(os.path.exists(json_file))
            self.assertTrue(os.path.exists(json_file + '.migrated'))

    def test_bootstrap_callable(self):
        with self.app.app_context():
            migrations.bootstrap(self.app)


if __name__ == '__main__':
    unittest.main()
