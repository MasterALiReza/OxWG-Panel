"""Test Suite for Phase 4: Blueprints Layer (blueprints/).

Verifies:
1. All 17 modular Blueprints exist and register all 183 non-static rules matching rules_183.json.
2. Rule paths, HTTP methods, and endpoint function names match 100%.
3. Backward compatibility transparent url_for fallback handling.
4. Smoke testing of key routes, authentication gates, and error responses.
5. Verification of sample routes (/api/healthz, /login, /api/panel/version, /api/stats/mini).
6. 2FA branding and QR code generation functionality.
"""

import json
import os
import unittest
from unittest import mock
from io import BytesIO

from flask import Flask, url_for
from werkzeug.routing import BuildError

from core.extensions import db, init_extensions
from models import AdminAccount, InterfaceConfig, Node, Peer, PeerEvent, ShortLink
from blueprints import (
    ALL_BLUEPRINTS,
    admin_bp,
    auth_bp,
    backup_bp,
    interfaces_bp,
    logs_bp,
    misc_bp,
    nodes_bp,
    peers_bp,
    profiles_bp,
    register_blueprints,
    security_bp,
    settings_bp,
    shortlinks_bp,
    stats_bp,
    subscriptions_bp,
    telegram_bp,
    traffic_bp,
    update_bp,
)


class TestBlueprintLayer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        cls.app = Flask(__name__, template_folder=template_dir)
        cls.app.config['TESTING'] = True
        cls.app.config['SECRET_KEY'] = 'test-phase4-blueprints-secret'
        cls.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        cls.app.config['WTF_CSRF_ENABLED'] = False
        cls.app.config['API_KEY'] = 'test-api-key'
        init_extensions(cls.app)
        register_blueprints(cls.app)

        with cls.app.app_context():
            db.create_all()
            if not AdminAccount.query.filter_by(username='admin').first():
                adm = AdminAccount(username='admin', password_hash=AdminAccount.hash_pw('admin123'))
                db.session.add(adm)
                db.session.commit()

        # Load authoritative 183 rules
        rules_path = os.path.join(os.path.dirname(__file__), 'rules_183.json')
        with open(rules_path, 'r', encoding='utf-8') as f:
            cls.expected_rules = json.load(f)

    def setUp(self):
        self.client = self.app.test_client()

    def test_all_17_blueprints_exported(self):
        """Verify that exactly 17 blueprints are defined and in ALL_BLUEPRINTS."""
        self.assertEqual(len(ALL_BLUEPRINTS), 17)
        bp_names = {bp.name for bp in ALL_BLUEPRINTS}
        expected_names = {
            'auth_bp',
            'admin_bp',
            'misc_bp',
            'stats_bp',
            'logs_bp',
            'settings_bp',
            'shortlinks_bp',
            'security_bp',
            'update_bp',
            'profiles_bp',
            'traffic_bp',
            'telegram_bp',
            'backup_bp',
            'interfaces_bp',
            'peers_bp',
            'nodes_bp',
            'subscriptions_bp',
        }
        self.assertEqual(bp_names, expected_names)

    def test_individual_blueprint_rule_counts(self):
        """Verify the exact rule count belonging to each individual blueprint."""
        expected_counts = {
            'auth_bp': 5,
            'admin_bp': 6,
            'misc_bp': 3,
            'stats_bp': 4,
            'logs_bp': 8,
            'settings_bp': 9,
            'shortlinks_bp': 6,
            'security_bp': 8,
            'update_bp': 6,
            'profiles_bp': 12,
            'traffic_bp': 6,
            'telegram_bp': 15,
            'backup_bp': 18,
            'interfaces_bp': 13,
            'peers_bp': 15,
            'nodes_bp': 25,
            'subscriptions_bp': 24,
        }
        self.assertEqual(sum(expected_counts.values()), 183)

        for bp in ALL_BLUEPRINTS:
            temp_app = Flask(__name__)
            temp_app.register_blueprint(bp)
            bp_rules = [r for r in temp_app.url_map.iter_rules() if r.endpoint != 'static']
            self.assertEqual(
                len(bp_rules),
                expected_counts[bp.name],
                f"Blueprint {bp.name} has {len(bp_rules)} rules, expected {expected_counts[bp.name]}",
            )

    def test_full_183_rules_exact_match(self):
        """Verify that all 183 non-static routes registered on the app match rules_183.json 100%."""
        registered = []
        for r in self.app.url_map.iter_rules():
            if r.endpoint == 'static':
                continue
            endpoint_func = r.endpoint.split('.', 1)[1] if '.' in r.endpoint else r.endpoint
            methods = sorted([m for m in r.methods if m not in ('HEAD', 'OPTIONS')])
            registered.append((r.rule, tuple(methods), endpoint_func))

        expected = []
        for r in self.expected_rules:
            methods = sorted(r['methods'])
            expected.append((r['rule'], tuple(methods), r['endpoint']))

        self.assertEqual(len(registered), 183)
        self.assertEqual(len(expected), 183)

        reg_sorted = sorted(registered)
        exp_sorted = sorted(expected)

        missing = set(exp_sorted) - set(reg_sorted)
        extra = set(reg_sorted) - set(exp_sorted)

        self.assertFalse(missing, f"Missing rules from registered app: {missing}")
        self.assertFalse(extra, f"Extra unexpected rules in registered app: {extra}")
        self.assertEqual(reg_sorted, exp_sorted)

    def test_legacy_url_for_handler(self):
        """Verify that legacy un-prefixed url_for calls resolve transparently via url_build_error_handlers."""
        with self.app.test_request_context():
            # Legacy calls without blueprint prefix
            self.assertEqual(url_for('users'), '/users')
            self.assertEqual(url_for('login'), '/login')
            self.assertEqual(url_for('subscriptions_page'), '/subscriptions')
            self.assertEqual(url_for('nodes'), '/nodes')
            self.assertEqual(url_for('backup_page'), '/backup')
            self.assertEqual(url_for('settings_page'), '/settings')
            self.assertEqual(url_for('logs_page'), '/logs')

            # Modern blueprint-prefixed calls
            self.assertEqual(url_for('peers_bp.users'), '/users')
            self.assertEqual(url_for('auth_bp.login'), '/login')
            self.assertEqual(url_for('subscriptions_bp.subscriptions_page'), '/subscriptions')
            self.assertEqual(url_for('nodes_bp.nodes'), '/nodes')
            self.assertEqual(url_for('backup_bp.backup_page'), '/backup')

            # Non-existent route raises BuildError
            with self.assertRaises(BuildError):
                url_for('non_existent_route_12345')

    def test_auth_gates_and_redirects(self):
        """Verify authentication gates redirect anonymous users to login."""
        for ep in ['/users', '/nodes', '/subscriptions', '/settings', '/backup']:
            resp = self.client.get(ep)
            self.assertEqual(resp.status_code, 302)
            self.assertIn('/login', resp.headers.get('Location', ''))

    def test_unauthorized_api_calls_return_401(self):
        """Verify API endpoints require authentication or return 401."""
        unauth_401_endpoints = [
            '/api/peers',
            '/api/nodes',
            '/api/subscriptions',
            '/api/traffic-control',
            '/api/backup/status',
            '/api/healthz',
            '/api/panel/version',
            '/api/stats/mini',
        ]
        for ep in unauth_401_endpoints:
            resp = self.client.get(ep)
            self.assertEqual(
                resp.status_code,
                401,
                f"Expected 401 for unauthorized {ep}, got {resp.status_code}",
            )

        # @login_required routes redirect anonymous browser sessions
        for ep in ['/api/settings', '/api/stats', '/api/app_status', '/api/peer_counts']:
            resp = self.client.get(ep)
            self.assertEqual(resp.status_code, 302)

    def test_public_routes_accessible(self):
        """Verify public endpoints respond without authentication."""
        # /register redirects to /login when admin account exists
        resp = self.client.get('/register')
        self.assertIn(resp.status_code, [200, 302])

        resp = self.client.get('/u/sample_token')
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get('/s/nonexistent_token')
        self.assertEqual(resp.status_code, 404)

    def test_sample_routes_authenticated(self):
        """Verify sample endpoints (/api/healthz, /login, /api/panel/version, /api/stats/mini) work when authenticated."""
        with self.app.app_context():
            if not AdminAccount.query.filter_by(username='admin').first():
                adm = AdminAccount(username='admin', password_hash=AdminAccount.hash_pw('admin123'))
                db.session.add(adm)
                db.session.commit()

        # Login endpoint returns 200 when admin account exists
        resp_login = self.client.get('/login')
        self.assertEqual(resp_login.status_code, 200)

        # Authenticate session
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

        # /api/healthz responds with ok: True and timestamp
        resp_healthz = self.client.get('/api/healthz')
        self.assertEqual(resp_healthz.status_code, 200)
        data_h = resp_healthz.get_json()
        self.assertTrue(data_h.get('ok'))
        self.assertIn('ts', data_h)

        # /api/panel/version responds with valid version structure
        resp_v = self.client.get('/api/panel/version')
        self.assertEqual(resp_v.status_code, 200)
        data_v = resp_v.get_json()
        self.assertTrue(data_v.get('ok'))
        self.assertIn('current', data_v)
        self.assertIn('repo', data_v)

        # /api/panel/update/status responds with idle status
        resp_us = self.client.get('/api/panel/update/status')
        self.assertEqual(resp_us.status_code, 200)
        self.assertIn('status', resp_us.get_json())

        # /api/panel/update/targets responds with nodes list
        resp_ut = self.client.get('/api/panel/update/targets')
        self.assertEqual(resp_ut.status_code, 200)
        self.assertTrue(resp_ut.get_json().get('ok'))
        self.assertIn('nodes', resp_ut.get_json())

        # /api/stats/mini responds with metrics
        resp_mini = self.client.get('/api/stats/mini')
        self.assertEqual(resp_mini.status_code, 200)
        data_m = resp_mini.get_json()
        self.assertIn('cpu', data_m)
        self.assertIn('mem', data_m)
        self.assertIn('counts', data_m)

    def test_shortlinks_and_qr(self):
        """Verify shortlink 404 boundaries and QR code generation using send_file."""
        with self.app.app_context():
            iface = InterfaceConfig.query.filter_by(name='wg_test').first()
            if not iface:
                iface = InterfaceConfig(
                    name='wg_test',
                    path='/etc/wireguard/wg_test.conf',
                    address='10.77.0.1/24',
                    listen_port=51877,
                    private_key='testpriv',
                )
                db.session.add(iface)
                db.session.flush()

            peer = Peer.query.filter_by(public_key='test_pub_qr').first()
            if not peer:
                peer = Peer(
                    iface_id=iface.id,
                    name='qr_peer',
                    public_key='test_pub_qr',
                    private_key='test_priv_qr',
                    address='10.77.0.2/32',
                )
                db.session.add(peer)
                db.session.commit()

        # Nonexistent shortlink returns 404
        resp = self.client.get('/api/u/unknown_token_12345')
        self.assertEqual(resp.status_code, 404)

        resp_cfg = self.client.get('/api/u/unknown_token_12345/config')
        self.assertEqual(resp_cfg.status_code, 404)

        # Authenticate session
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

        # Test config_qr with mock valid conf -> should return image/png (both by public key and by int ID)
        with mock.patch('blueprints.peers_bp._peer_client_conf_or_502', return_value=('[Interface]\nAddress = 10.77.0.2/32', None)):
            resp_qr = self.client.get('/api/peer/test_pub_qr/config_qr')
            self.assertEqual(resp_qr.status_code, 200)
            self.assertEqual(resp_qr.content_type, 'image/png')
            self.assertGreater(len(resp_qr.data), 100)

            # Test by integer peer ID (what users.js sends)
            with self.app.app_context():
                peer_db = Peer.query.filter_by(public_key='test_pub_qr').first()
                pid = peer_db.id

            resp_qr_id = self.client.get(f'/api/peer/{pid}/config_qr')
            self.assertEqual(resp_qr_id.status_code, 200)
            self.assertEqual(resp_qr_id.content_type, 'image/png')

            resp_cfg_id = self.client.get(f'/api/peer/{pid}/config')
            self.assertEqual(resp_cfg_id.status_code, 200)
            self.assertIn('[Interface]', resp_cfg_id.text)

    def test_admin_management_and_branding(self):
        """Verify admin routes and 2FA branding compliance."""
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

        # /api/admin status
        resp = self.client.get('/api/admin')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get('username'), 'admin')
        self.assertIn('twofa_enabled', data)

        # /api/admin/twofa_begin branding checks
        resp_2fa = self.client.post('/api/admin/twofa_begin')
        self.assertEqual(resp_2fa.status_code, 200)
        data_2fa = resp_2fa.get_json()
        self.assertIn('secret', data_2fa)
        self.assertIn('otp_uri', data_2fa)
        otp_uri = data_2fa['otp_uri']
        # Verify issuer="OxWg Panel" and label="OxWg-Panel:admin"
        self.assertTrue('issuer=OxWg+Panel' in otp_uri or 'issuer=OxWg%20Panel' in otp_uri)
        self.assertIn('OxWg-Panel%3Aadmin', otp_uri)

    def test_peer_creation_and_get_interfaces(self):
        """Verify /api/get-interfaces returns available_ips and /users creates peers."""
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

        with self.app.app_context():
            iface = InterfaceConfig.query.filter_by(name='wg0').first()
            if not iface:
                iface = InterfaceConfig(
                    id=10,
                    name='wg0',
                    path='/etc/wireguard/wg0.conf',
                    address='10.88.0.1/24',
                    listen_port=51820,
                    private_key='aW5pdGlhbF9wcml2YXRlX2tleV9mb3JfdGVzdGluZw==',
                    public_key='aW5pdGlhbF9wdWJsaWNfa2V5X2Zvcl90ZXN0aW5nPT0=',
                )
                db.session.add(iface)
                db.session.commit()
            iface_id = iface.id

        # 1. Test /api/get-interfaces
        resp = self.client.get('/api/get-interfaces')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('interfaces', data)
        wg0_row = next((i for i in data['interfaces'] if i['name'] == 'wg0'), None)
        self.assertIsNotNone(wg0_row)
        self.assertIn('available_ips', wg0_row)
        self.assertTrue(len(wg0_row['available_ips']) > 0)
        first_ip = wg0_row['available_ips'][0]
        self.assertTrue(first_ip.endswith('/24'))

        # 2. Test POST /users with automatic IP allocation (empty address)
        with mock.patch('blueprints.peers_bp.install_local_peer'):
            resp_post = self.client.post('/users', data={
                'iface': str(iface_id),
                'name': 'auto-peer',
                'address': '',
                'allowed_ips': '0.0.0.0/0, ::/0',
            }, follow_redirects=False)

            self.assertEqual(resp_post.status_code, 302)
            self.assertIn('/users', resp_post.headers['Location'])

        with self.app.app_context():
            p = Peer.query.filter_by(name='auto-peer').first()
            self.assertIsNotNone(p)
            self.assertEqual(p.address, first_ip)
            self.assertEqual(p.status, 'online')

        # 3. Test POST /users with explicit IP without CIDR mask
        explicit_ip = first_ip.split('/')[0]
        # Use next host
        octets = explicit_ip.split('.')
        octets[-1] = '25'
        custom_ip = '.'.join(octets)

        with mock.patch('blueprints.peers_bp.install_local_peer'):
            resp_post2 = self.client.post('/users', data={
                'iface': str(iface_id),
                'name': 'explicit-peer',
                'address': custom_ip,
                'allowed_ips': '0.0.0.0/0, ::/0',
            }, follow_redirects=False)

            self.assertEqual(resp_post2.status_code, 302)

        with self.app.app_context():
            p2 = Peer.query.filter_by(name='explicit-peer').first()
            self.assertIsNotNone(p2)
            self.assertEqual(p2.address, f"{custom_ip}/24")

    def test_app_log_line_parsing(self):
        """Verify _app_log_line correctly parses ISO, Bracket, Access, and continuation lines."""
        from blueprints.logs_bp import _app_log_line

        # 1. ISO UTC log
        line1 = "2026-09-11T22:51:12Z INFO sqlalchemy.engine.Engine: ROLLBACK"
        r1 = _app_log_line(line1)
        self.assertEqual(r1['ts'], '2026-09-11T22:51:12Z')
        self.assertEqual(r1['level'], 'INFO')
        self.assertEqual(r1['logger'], 'sqlalchemy.engine.Engine')
        self.assertEqual(r1['msg'], 'ROLLBACK')

        # 2. Date with space
        line2 = "2026-09-12 02:08:55 WARNING app: Cache expired"
        r2 = _app_log_line(line2)
        self.assertEqual(r2['ts'], '2026-09-12 02:08:55')
        self.assertEqual(r2['level'], 'WARNING')
        self.assertEqual(r2['logger'], 'app')
        self.assertEqual(r2['msg'], 'Cache expired')

        # 3. Gunicorn bracketed log
        line3 = "[2026-09-11 22:38:42 +0000] [3829999] [INFO] Starting gunicorn 23.0.0"
        r3 = _app_log_line(line3)
        self.assertEqual(r3['ts'], '2026-09-11 22:38:42 +0000')
        self.assertEqual(r3['level'], 'INFO')
        self.assertEqual(r3['msg'], 'Starting gunicorn 23.0.0')

        # 4. Access log
        line4 = '94.183.56.238 - - [11/Sep/2026:22:38:42 +0000] "GET /api/peers HTTP/1.1" 200 1234'
        r4 = _app_log_line(line4)
        self.assertEqual(r4['ts'], '2026-09-11T22:38:42Z')
        self.assertEqual(r4['level'], 'INFO')
        self.assertIn('HTTP GET /api/peers 200', r4['msg'])

        # 5. Continuation line
        line5 = "FROM peer"
        r5 = _app_log_line(line5, default_ts='2026-09-11T22:51:12Z', default_level='INFO', default_logger='sqlalchemy')
        self.assertEqual(r5['ts'], '2026-09-11T22:51:12Z')
        self.assertEqual(r5['level'], 'INFO')
        self.assertEqual(r5['msg'], 'FROM peer')

    def test_app_logs_api_endpoint(self):
        """Verify /api/app_logs returns parsed logs with time_display populated."""
        import tempfile
        from blueprints.logs_bp import APP_LOG_FILE

        sample_content = (
            "2026-09-11T22:51:12Z INFO sqlalchemy.engine.Engine: BEGIN (implicit)\n"
            "2026-09-11T22:51:12Z INFO sqlalchemy.engine.Engine: SELECT peer.id FROM peer\n"
            "2026-09-11T22:51:12Z INFO sqlalchemy.engine.Engine: ROLLBACK\n"
        )
        with mock.patch('blueprints.logs_bp.APP_LOG_FILE', tempfile.mktemp()):
            with mock.patch('blueprints.logs_bp._read_tail', return_value=sample_content):
                # Login as admin
                with self.client.session_transaction() as sess:
                    sess['_user_id'] = '1'

                resp = self.client.get('/api/app_logs')
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertIn('logs', data)
                self.assertEqual(len(data['logs']), 3)

                for item in data['logs']:
                    self.assertIsNotNone(item.get('ts'))
                    self.assertIsNotNone(item.get('time_display'))
                    self.assertIn(item['level'], ['INFO', 'WARN', 'ERROR', 'DEBUG'])

    def test_audit_fixes_lifecycle_and_security(self):
        """Verify the deep audit fixes:
        1. Blocked peers unblock to 'online' on reset_data & reset_timer.
        2. PeerEvent is created cleanly without TypeError.
        3. Public shortlink config route blocks inactive/blocked/expired peers with 403.
        4. delete_iface cascades and removes PeerEvents cleanly.
        """
        with self.app.app_context():
            iface = InterfaceConfig(
                name='wgtestaudit',
                path='/etc/wireguard/wgtestaudit.conf',
                address='10.88.0.1/24',
                listen_port=51899,
                private_key='testprivkeyaudit',
            )
            db.session.add(iface)
            db.session.commit()

            peer = Peer(
                iface_id=iface.id,
                name='audit_peer',
                public_key='testpubaudit123',
                private_key='testprivaudit123',
                address='10.88.0.2/32',
                status='blocked',
                data_limit_value=100,
                data_limit_unit='Mi',
                used_bytes_total=105 * 1024 * 1024,
            )
            db.session.add(peer)
            db.session.commit()
            pid = peer.id

            slink = ShortLink(token='audit_token_test_123', peer_id=pid)
            db.session.add(slink)
            db.session.commit()

        # 1. Blocked peer downloading config via public shortlink should return 403
        resp_blocked = self.client.get('/api/u/audit_token_test_123/config')
        self.assertEqual(resp_blocked.status_code, 403)
        self.assertEqual(resp_blocked.get_json().get('error'), 'peer_inactive')

        # 2. Reset data should restore status to 'online'
        headers = {'X-API-Key': 'test-api-key'}
        with mock.patch('blueprints.peers_bp._wg_enable') as mock_enable:
            resp_reset_data = self.client.post(f'/api/peer/{pid}/reset_data', headers=headers)
            self.assertEqual(resp_reset_data.status_code, 200)
            data = resp_reset_data.get_json()
            self.assertEqual(data.get('status'), 'online')
            mock_enable.assert_called_once()

        # Verify PeerEvent was recorded
        with self.app.app_context():
            evs = PeerEvent.query.filter_by(peer_id=pid).all()
            self.assertGreater(len(evs), 0)
            self.assertEqual(evs[-1].event, 'reset_data')

        # 3. Block peer again, reset timer should restore to 'online'
        with self.app.app_context():
            p = db.session.get(Peer, pid)
            p.status = 'blocked'
            p.time_limit_days = 30
            db.session.commit()

        with mock.patch('blueprints.peers_bp._wg_enable') as mock_enable:
            resp_reset_timer = self.client.post(f'/api/peer/{pid}/reset_timer', headers=headers)
            self.assertEqual(resp_reset_timer.status_code, 200)
            data = resp_reset_timer.get_json()
            self.assertEqual(data.get('status'), 'online')
            mock_enable.assert_called_once()

        # 4. Now that peer is online, /api/u/<token>/config serves config
        with mock.patch('blueprints.shortlinks_bp._peer_client_conf_or_502', return_value=('[Interface]\nAddress = 10.88.0.2/32', None)):
            resp_online = self.client.get('/api/u/audit_token_test_123/config')
            self.assertEqual(resp_online.status_code, 200)

        # 5. Delete interface should cascade cleanly and remove PeerEvents without IntegrityError
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'

        with self.app.app_context():
            iface_obj = InterfaceConfig.query.filter_by(name='wgtestaudit').first()
            iface_id = iface_obj.id

        resp_del = self.client.delete(f'/api/iface/{iface_id}', query_string={'delete_peers': '1'})
        self.assertEqual(resp_del.status_code, 200)
        with self.app.app_context():
            self.assertIsNone(InterfaceConfig.query.filter_by(name='wgtestaudit').first())
            self.assertIsNone(db.session.get(Peer, pid))
            self.assertEqual(PeerEvent.query.filter_by(peer_id=pid).count(), 0)


if __name__ == '__main__':
    unittest.main()

