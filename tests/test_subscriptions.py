"""
test_subscriptions.py - Comprehensive test suite for Subscriptions subsystem.
Tests management API, public portal routes, configuration export, QR codes, and profiles.
"""
import io
import json
import os
import unittest
import zipfile

from app import app
from core.extensions import db
from models import AdminAccount, InterfaceConfig, Node, Peer, Subscription, SubscriptionPeer
from services.wg_parser import generate_wg_keypair


class TestSubscriptionsSubsystem(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Clean up any leftover test data
        SubscriptionPeer.query.delete()
        Subscription.query.delete()
        Peer.query.delete()
        db.session.commit()

        # Ensure wg0 exists
        ifc = InterfaceConfig.query.filter_by(name='wg0').first()
        if not ifc:
            priv, pub = generate_wg_keypair()
            ifc = InterfaceConfig(
                name='wg0',
                path='/etc/wireguard/wg0.conf',
                address='10.77.0.1/24',
                listen_port=51820,
                private_key=priv,
                public_key=pub,
            )
            db.session.add(ifc)
            db.session.commit()
        self.iface = ifc

    def tearDown(self):
        try:
            SubscriptionPeer.query.delete()
            Subscription.query.delete()
            Peer.query.delete()
            db.session.commit()
        except Exception:
            db.session.rollback()
        self.app_context.pop()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

    def test_subscriptions_page_auth_and_render(self):
        self._login(self.client)
        r = self.client.get('/subscriptions')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Subscriptions', r.data)

    def test_subscriptions_settings_and_template_preview(self):
        self._login(self.client)

        # GET settings
        r = self.client.get('/api/subscriptions/settings')
        self.assertEqual(r.status_code, 200)
        settings = r.get_json()
        self.assertIsInstance(settings, dict)

        # POST settings
        r = self.client.post('/api/subscriptions/settings', json={'portal_title': 'Custom OxWg Portal'})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('ok'))

        # POST template-preview with custom CSS colors
        r = self.client.post(
            '/api/subscriptions/template-preview',
            json={
                'settings': {
                    'primary_color': '#e11d48',
                    'secondary_color': '#3b82f6',
                    'online_color': '#10b981',
                }
            },
        )
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn('--custom-accent: #e11d48', html)
        self.assertIn('--custom-accent2: #3b82f6', html)
        self.assertIn('--status-online: #10b981', html)
        self.assertIn('OxWg Panel', html)

    def test_locations_and_inbounds_catalog(self):
        self._login(self.client)

        # GET locations
        r = self.client.get('/api/subscriptions/locations')
        self.assertEqual(r.status_code, 200)
        locs = r.get_json()
        self.assertIn('local', locs)
        self.assertIn('nodes', locs)
        self.assertTrue(any(l.get('iface') == 'wg0' for l in locs['local']))

        # GET catalog
        r = self.client.get('/api/subscriptions/inbounds_catalog')
        self.assertEqual(r.status_code, 200)
        self.assertIn('inbounds', r.get_json())

    def test_subscription_crud_and_lifecycle(self):
        self._login(self.client)

        # 1. Create subscription with local target
        payload = {
            'name': 'premium-user',
            'note': 'VIP client',
            'data_limit_value': 25,
            'data_limit_unit': 'Gi',
            'time_limit_days': 30,
            'targets': [{
                'scope': 'local',
                'iface_id': self.iface.id,
                'iface': 'wg0',
                'location_label': 'Primary Server',
            }],
        }
        r = self.client.post('/api/subscriptions', json=payload)
        self.assertEqual(r.status_code, 201)
        res = r.get_json()
        self.assertTrue(res.get('ok'))
        sub_data = res.get('subscription')
        sid = sub_data['id']
        token = sub_data['token']
        self.assertEqual(sub_data['name'], 'premium-user')
        self.assertEqual(sub_data['data_limit_value'], 25)
        self.assertEqual(len(sub_data['locations']), 1)
        link_id = sub_data['locations'][0]['link_id']

        # 2. GET subscription by ID
        r = self.client.get(f'/api/subscriptions/{sid}')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['subscription']['name'], 'premium-user')

        # 3. GET shortlink
        r = self.client.get(f'/api/subscriptions/{sid}/shortlink')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['token'], token)

        # 4. Public portal page
        r = self.client.get(f'/s/{token}')
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn('OxWg Panel', html)
        self.assertIn('premium-user', html)

        # 5. Public API
        r = self.client.get(f'/s/{token}/api')
        self.assertEqual(r.status_code, 200)
        pub_api = r.get_json()
        self.assertEqual(pub_api['subscription']['name'], 'premium-user')

        # 6. Public config ZIP
        r = self.client.get(f'/s/{token}/config')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('Content-Type'), 'application/zip')
        zf = zipfile.ZipFile(io.BytesIO(r.data))
        file_names = zf.namelist()
        self.assertTrue(len(file_names) > 0)
        conf_content = zf.read(file_names[0]).decode('utf-8')
        self.assertIn('[Interface]', conf_content)
        self.assertIn('[Peer]', conf_content)

        # 7. Public single inbound config & QR
        r = self.client.get(f'/s/{token}/inbound/{link_id}/config')
        self.assertEqual(r.status_code, 200)
        self.assertIn('[Interface]', r.get_data(as_text=True))

        r = self.client.get(f'/s/{token}/inbound/{link_id}/qr')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('Content-Type'), 'image/png')

        # 8. Update (PUT)
        r = self.client.put(f'/api/subscriptions/{sid}', json={'note': 'Updated VIP note'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['subscription']['note'], 'Updated VIP note')

        # 9. Inbound patch (PATCH)
        r = self.client.patch(f'/api/subscriptions/{sid}/inbounds/{link_id}', json={'location_label': 'NL Edge'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['subscription']['locations'][0]['location_label'], 'NL Edge')

        # 10. Disable & Enable
        r = self.client.post(f'/api/subscriptions/{sid}/disable')
        self.assertIn(r.status_code, (200, 207))

        r = self.client.post(f'/api/subscriptions/{sid}/enable')
        self.assertIn(r.status_code, (200, 207))

        # 11. Reset data & timer
        r = self.client.post(f'/api/subscriptions/{sid}/reset_data')
        self.assertEqual(r.status_code, 200)

        r = self.client.post(f'/api/subscriptions/{sid}/reset_timer')
        self.assertEqual(r.status_code, 200)

        # 12. Delete
        r = self.client.delete(f'/api/subscriptions/{sid}')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('ok'))
        self.assertIsNone(db.session.get(Subscription, sid))

    def test_subscription_profiles(self):
        self._login(self.client)

        # List profiles
        r = self.client.get('/api/subscription_profiles')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('ok'))

        # Save profile
        profile_data = {
            'name': 'Test-Profile-VIP',
            'data': {
                'client': {
                    'data_limit_value': 50,
                    'data_limit_unit': 'Gi',
                    'time_limit_days': 60,
                },
                'template': {
                    'primary_color': '#3b82f6',
                },
            },
        }
        r = self.client.post('/api/subscription_profiles', json=profile_data)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('ok'))

        # Get profile
        r = self.client.get('/api/subscription_profiles/Test-Profile-VIP')
        self.assertEqual(r.status_code, 200)
        prof = r.get_json().get('profile')
        self.assertIsNotNone(prof)

        # Activate profile
        r = self.client.post('/api/subscription_profiles/Test-Profile-VIP/activate')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('ok'))

        # Delete profile
        r = self.client.delete('/api/subscription_profiles/Test-Profile-VIP')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('ok'))


if __name__ == '__main__':
    unittest.main()
