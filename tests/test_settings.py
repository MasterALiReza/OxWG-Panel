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
from models import AdminAccount
from services.panel_settings import _load_panel_settings, _save_panel_settings


class TestSettingsSubsystem(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
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


if __name__ == '__main__':
    unittest.main()
