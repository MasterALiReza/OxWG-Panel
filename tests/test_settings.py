"""
test_settings.py - Comprehensive test suite for Settings Subsystem & Submenus.
Covers:
1. Settings page and subtabs layout
2. Panel settings API (TLS, Domain, HTTPS Port, Cert/Key Paths, Timezone)
3. Regional / Timezone API
4. Runtime worker settings API
5. Template settings and Socials API
6. Admin account management & 2FA API
7. Security / HTTP Protection API
8. Traffic Control policies API
9. Telegram settings & Admins API
"""
import json
import os
import unittest
from datetime import datetime, timezone

from app import app
from core.extensions import db
from models import AdminAccount, InterfaceConfig
from core.paths import (
    RUNTIME_FILE,
    PANEL_SETTINGS_FILE,
    TEMPLATE_SETTINGS_FILE,
    TRAFFIC_POLICY_FILE,
    TELEGRAM_SETTINGS_FILE,
    HTTP_SECURITY_SETTINGS_FILE,
)
from services.panel_settings import _load_panel_settings, _save_panel_settings


class TestSettingsSubsystem(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        self._files_to_restore = {}
        for path in [
            RUNTIME_FILE,
            PANEL_SETTINGS_FILE,
            TEMPLATE_SETTINGS_FILE,
            TRAFFIC_POLICY_FILE,
            TELEGRAM_SETTINGS_FILE,
            HTTP_SECURITY_SETTINGS_FILE,
        ]:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        self._files_to_restore[path] = f.read()
                except OSError:
                    pass
            else:
                self._files_to_restore[path] = None

    def tearDown(self):
        for path, content in getattr(self, '_files_to_restore', {}).items():
            if content is not None:
                try:
                    with open(path, 'wb') as f:
                        f.write(content)
                except OSError:
                    pass
            elif os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        self.app_context.pop()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

    def test_settings_page_and_tabs(self):
        """Verify the settings page renders 200 OK and contains all expected tabs and subtabs."""
        self._login(self.client)
        resp = self.client.get('/settings')
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)

        # Verify main tabs
        self.assertIn('data-tab="panel"', body)
        self.assertIn('data-tab="security"', body)
        self.assertIn('data-tab="iface"', body)
        self.assertIn('data-tab="traffic"', body)
        self.assertIn('data-tab="telegram"', body)
        self.assertIn('data-tab="template"', body)
        self.assertIn('data-tab="admin"', body)

        # Verify Panel subtabs
        self.assertIn('data-sub="tls"', body)
        self.assertIn('data-sub="runtime"', body)
        self.assertIn('data-sub="regional"', body)

        # Verify subpanels
        self.assertIn('id="subpanel-tls"', body)
        self.assertIn('id="subpanel-runtime"', body)
        self.assertIn('id="subpanel-regional"', body)

    def test_panel_settings_tls_and_timezone(self):
        """Test GET and POST /api/settings, including cert/key paths and timezone validation."""
        self._login(self.client)
        r = self.client.get('/api/settings')
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn('tls_enabled', data)
        self.assertIn('timezone', data)

        # Update settings with custom TLS cert/key paths and timezone
        update_payload = {
            "tls_enabled": True,
            "domain": "vpn.example.com",
            "https_port": 8443,
            "force_https_redirect": True,
            "hsts": True,
            "tls_cert_path": "/etc/ssl/certs/fullchain.pem",
            "tls_key_path": "/etc/ssl/private/privkey.pem",
            "timezone": "Asia/Tehran",
        }
        r2 = self.client.post('/api/settings', json=update_payload)
        self.assertEqual(r2.status_code, 200)
        data2 = r2.get_json()
        self.assertTrue(data2.get('ok'))
        saved = data2.get('settings', {})
        self.assertEqual(saved.get('tls_cert_path'), "/etc/ssl/certs/fullchain.pem")
        self.assertEqual(saved.get('tls_key_path'), "/etc/ssl/private/privkey.pem")
        self.assertEqual(saved.get('timezone'), "Asia/Tehran")
        self.assertEqual(saved.get('https_port'), 8443)

        # Verify invalid timezone returns 400
        r_bad = self.client.post('/api/settings', json={"timezone": "Invalid/Nowhere_City"})
        self.assertEqual(r_bad.status_code, 400)
        self.assertEqual(r_bad.get_json().get('error'), 'invalid_timezone')

    def test_timezone_api(self):
        """Verify /api/timezone returns authoritative server epoch and local time."""
        self._login(self.client)
        resp = self.client.get('/api/timezone')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get('ok'))
        self.assertIn('timezone', data)
        self.assertIn('server_epoch', data)
        self.assertIn('utc_now', data)
        self.assertIn('local_now', data)

    def test_runtime_api(self):
        """Verify GET and POST /api/runtime."""
        self._login(self.client)
        r = self.client.get('/api/runtime')
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn('saved', d)
        self.assertIn('effective', d)

        # Update runtime parameters
        post_data = {
            "bind": "0.0.0.0:8000",
            "port": 8000,
            "workers": 2,
            "threads": 4,
            "timeout": 60,
            "graceful_timeout": 30,
            "loglevel": "info"
        }
        r2 = self.client.post('/api/runtime', json=post_data)
        self.assertEqual(r2.status_code, 200)
        d2 = r2.get_json()
        self.assertTrue(d2.get('ok'))
        self.assertEqual(d2['saved']['port'], 8000)
        self.assertEqual(d2['saved']['workers'], 2)

    def test_template_settings_and_socials(self):
        """Verify GET and POST /api/template_settings."""
        self._login(self.client)
        r = self.client.get('/api/template_settings')
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn('selected', d)
        self.assertIn('socials', d)

        # Update template and social links
        payload = {
            "selected": "pro",
            "socials": {
                "telegram": "@OxWgChannel",
                "whatsapp": "+1234567890",
                "instagram": "oxwg_panel",
                "phone": "+1234567890",
                "website": "https://oxwg.example.com",
                "email": "support@oxwg.example.com"
            }
        }
        r2 = self.client.post('/api/template_settings', json=payload)
        self.assertEqual(r2.status_code, 200)
        d2 = r2.get_json()
        self.assertTrue(d2.get('ok'))
        self.assertEqual(d2['settings']['selected'], 'pro')
        self.assertEqual(d2['settings']['socials']['telegram'], '@OxWgChannel')

        # Invalid template returns 400
        r_bad = self.client.post('/api/template_settings', json={"selected": "nonexistent"})
        self.assertEqual(r_bad.status_code, 400)

    def test_admin_api_and_twofa_flow(self):
        """Verify admin account status, rename, and 2FA begin/setup."""
        self._login(self.client)
        r = self.client.get('/api/admin')
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn('username', d)
        self.assertIn('twofa_enabled', d)

        # Test rename
        current_username = d['username']
        new_username = "oxwg_admin_test"
        r_ren = self.client.post('/api/admin/rename', json={"username": new_username})
        self.assertEqual(r_ren.status_code, 200)

        # Verify renamed
        r_check = self.client.get('/api/admin')
        self.assertEqual(r_check.get_json()['username'], new_username)

        # Restore original username
        self.client.post('/api/admin/rename', json={"username": current_username})

        # Test 2FA begin
        r_2fa = self.client.post('/api/admin/twofa_begin')
        self.assertEqual(r_2fa.status_code, 200)
        d_2fa = r_2fa.get_json()
        self.assertIn('secret', d_2fa)
        self.assertIn('otp_uri', d_2fa)
        self.assertIn('OxWg%20Panel', d_2fa['otp_uri'])

    def test_security_http_protection(self):
        """Verify Security Center settings and capabilities APIs."""
        self._login(self.client)
        r_cap = self.client.get('/api/security/http-protection/capabilities')
        self.assertEqual(r_cap.status_code, 200)
        d_cap = r_cap.get_json()
        self.assertTrue(d_cap.get('ok'))

        r_sec = self.client.get('/api/security/http-protection')
        self.assertEqual(r_sec.status_code, 200)
        d_sec = r_sec.get_json()
        self.assertTrue(d_sec.get('ok'))
        self.assertIn('settings', d_sec)
        self.assertIn('active_blocks', d_sec)

        # Test updating security settings
        r_save = self.client.post('/api/security/http-protection', json={
            "enabled": True,
            "response_mode": "monitor",
            "threshold": 100,
            "block_seconds": 900
        })
        self.assertEqual(r_save.status_code, 200)
        self.assertEqual(r_save.get_json()['settings']['threshold'], 100)

    def test_traffic_control_api(self):
        """Verify Traffic Control get and policy save."""
        self._login(self.client)
        r = self.client.get('/api/traffic-control')
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d.get('ok'))
        self.assertIn('policies', d)

        # Test adding a policy
        new_policies = [{
            "id": "test_pol_1",
            "name": "Block Test",
            "enabled": True,
            "location": "local",
            "interface": "wg0",
            "source_mode": "interface",
            "domains": ["ads.example.com"],
            "cidrs": ["198.51.100.0/24"],
            "countries": ["IR"]
        }]
        r2 = self.client.post('/api/traffic-control', json={"policies": new_policies})
        self.assertEqual(r2.status_code, 200)
        d2 = r2.get_json()
        self.assertTrue(d2.get('ok'))
        self.assertEqual(len(d2['policies']), 1)
        self.assertEqual(d2['policies'][0]['name'], "Block Test")

        # Test destination check
        r_test = self.client.post('/api/traffic-control/test-destination', json={
            "policy_id": "test_pol_1",
            "target": "ads.example.com"
        })
        self.assertEqual(r_test.status_code, 200)
        self.assertTrue(r_test.get_json().get('ok'))

    def test_telegram_settings_and_admins(self):
        """Verify Telegram settings, admins CRUD, and status."""
        self._login(self.client)
        r = self.client.get('/api/telegram/settings')
        self.assertEqual(r.status_code, 200)

        # Update notification preferences
        r_save = self.client.post('/api/telegram/settings', json={
            "enabled": False,
            "notify": {
                "app_down": True,
                "app_up": True,
                "node_down": True,
                "node_up": True,
                "backup_success": True,
                "backup_failed": True
            }
        })
        self.assertEqual(r_save.status_code, 200)
        self.assertTrue(r_save.get_json().get('ok'))

        # Add admin
        r_adm = self.client.post('/api/telegram/admins', json={
            "id": "999888777",
            "username": "test_bot_admin",
            "note": "Unit Test Admin",
            "muted": False
        })
        self.assertEqual(r_adm.status_code, 200)
        self.assertTrue(r_adm.get_json().get('ok'))

        # Delete admin
        r_del = self.client.delete('/api/telegram/admins/999888777')
        self.assertEqual(r_del.status_code, 200)
        self.assertTrue(r_del.get_json().get('ok'))

    def test_interface_optional_settings(self):
        """Verify GET /api/iface/<id> and POST /api/iface/<id> handle optional routing settings (table, pre_up, pre_down, post_up, post_down)."""
        self._login(self.client)
        with self.app.app_context():
            iface = InterfaceConfig.query.filter_by(name='wg_opt_test').first()
            if not iface:
                iface = InterfaceConfig(
                    name='wg_opt_test',
                    path='instance/wg_opt_test.conf',
                    address='10.77.0.1/24',
                    listen_port=51829,
                    private_key='dGVzdF9wcml2YXRlX2tleV8xMjM0NTY3ODkwMTI=',
                    public_key='dGVzdF9wdWJsaWNfa2V5XzEyMzQ1Njc4OTAxMjM=',
                    table='auto',
                    pre_up='echo pre_up_orig',
                    pre_down='echo pre_down_orig',
                    post_up='iptables -A FORWARD -i wg_opt_test -j ACCEPT',
                    post_down='iptables -D FORWARD -i wg_opt_test -j ACCEPT',
                )
                db.session.add(iface)
                db.session.commit()
            iface_id = iface.id

        try:
            # 1. GET /api/iface/<id>
            resp = self.client.get(f'/api/iface/{iface_id}')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data.get('ok'))
            self.assertEqual(data.get('table'), 'auto')
            self.assertEqual(data.get('pre_up'), 'echo pre_up_orig')
            self.assertEqual(data.get('pre_down'), 'echo pre_down_orig')
            self.assertEqual(data.get('post_up'), 'iptables -A FORWARD -i wg_opt_test -j ACCEPT')
            self.assertEqual(data.get('post_down'), 'iptables -D FORWARD -i wg_opt_test -j ACCEPT')

            # 2. POST /api/iface/<id> with updated optional settings
            new_payload = {
                'dns': '1.1.1.1, 8.8.8.8',
                'mtu': 1420,
                'listen_port': 51829,
                'table': 'off',
                'pre_up': 'ip rule add from 10.77.0.0/24 table 200',
                'pre_down': 'ip rule del from 10.77.0.0/24 table 200',
                'post_up': 'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE',
                'post_down': 'iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE',
            }
            post_resp = self.client.post(f'/api/iface/{iface_id}', json=new_payload)
            self.assertEqual(post_resp.status_code, 200)
            post_data = post_resp.get_json()
            self.assertTrue(post_data.get('ok'))
            self.assertEqual(post_data['interface']['table'], 'off')
            self.assertEqual(post_data['interface']['pre_up'], 'ip rule add from 10.77.0.0/24 table 200')
            self.assertEqual(post_data['interface']['pre_down'], 'ip rule del from 10.77.0.0/24 table 200')
            self.assertEqual(post_data['interface']['post_up'], 'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')
            self.assertEqual(post_data['interface']['post_down'], 'iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE')
        finally:
            with self.app.app_context():
                obj = db.session.get(InterfaceConfig, iface_id)
                if obj:
                    db.session.delete(obj)
                    db.session.commit()
            if os.path.exists('instance/wg_opt_test.conf'):
                try:
                    os.remove('instance/wg_opt_test.conf')
                except OSError:
                    pass


if __name__ == '__main__':
    unittest.main()
