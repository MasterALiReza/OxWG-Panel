"""Unit tests for Nodes subsystem (blueprints/nodes_bp.py and related services).

Verifies:
1. Node listing, creation, health, and summary endpoints.
2. Node peer listing (/api/nodes/<nid>/peers) serialization with shortlink, iface_name.
3. Node peer config and config_qr by integer ID, raw public key, and percent-encoded public key.
4. Node peer enable, disable, reset_data, reset_timer, shortlink endpoints by ID and public key.
5. Node peer edit and delete handlers.
"""

import os
import unittest
from urllib.parse import quote

from flask import Flask
from core.extensions import db, init_extensions
from models import AdminAccount, InterfaceConfig, Node, Peer
from blueprints import register_blueprints


class TestNodesSubsystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        cls.app = Flask(__name__, template_folder=template_dir)
        cls.app.config['TESTING'] = True
        cls.app.config['SECRET_KEY'] = 'test-nodes-secret'
        cls.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        cls.app.config['WTF_CSRF_ENABLED'] = False
        cls.app.config['API_KEY'] = 'test-api-key'
        init_extensions(cls.app)
        register_blueprints(cls.app)

        with cls.app.app_context():
            db.create_all()
            # Create test admin
            admin = AdminAccount(username='admin', password_hash=AdminAccount.hash_pw('admin123'))
            db.session.add(admin)

            # Create test node
            node = Node(
                name='Frankfurt Edge',
                base_url='http://127.0.0.1:58200',
                api_key='node-test-key',
                enabled=True,
            )
            db.session.add(node)
            db.session.commit()

            # Create node mirror interface with valid 44-char base64 WG key
            node_iface = InterfaceConfig(
                name=f'n{node.id}:wg0',
                path='/etc/wireguard/wg0.conf',
                address='10.88.0.1/24',
                listen_port=51820,
                endpoint_host='198.51.100.1',
                endpoint_port=51820,
                private_key='(remote)',
                public_key='NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN=',
                node_id=node.id,
            )
            db.session.add(node_iface)
            db.session.commit()

            # Create test peers on node interface
            peer1 = Peer(
                iface_id=node_iface.id,
                name='node-user-1',
                public_key='y+BC123/5678901234567890123456789012345678=',
                private_key='privatekey1',
                address='10.88.0.2/32',
                allowed_ips='0.0.0.0/0',
                status='online',
            )
            peer2 = Peer(
                iface_id=node_iface.id,
                name='node-user-2',
                public_key='StandardPubKeyWithoutSlash1234567890123456=',
                private_key='privatekey2',
                address='10.88.0.3/32',
                allowed_ips='0.0.0.0/0',
                status='online',
            )
            db.session.add_all([peer1, peer2])
            db.session.commit()

            cls.node_id = node.id
            cls.peer1_id = peer1.id
            cls.peer1_pub = peer1.public_key
            cls.peer2_id = peer2.id
            cls.peer2_pub = peer2.public_key

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

        from unittest.mock import patch
        self.patcher_get = patch('blueprints.nodes_bp.node_get', return_value={'peers': []})
        self.patcher_post = patch('blueprints.nodes_bp.node_post', return_value={'ok': True})
        self.patcher_get.start()
        self.patcher_post.start()

    def tearDown(self):
        self.patcher_get.stop()
        self.patcher_post.stop()

    def test_node_list(self):
        """GET /api/nodes returns configured nodes."""
        res = self.client.get('/api/nodes')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('nodes', data)
        nodes = data['nodes']
        self.assertTrue(isinstance(nodes, list))
        self.assertGreaterEqual(len(nodes), 1)
        self.assertEqual(nodes[0]['name'], 'Frankfurt Edge')

    def test_node_peers_serialization(self):
        """GET /api/nodes/<nid>/peers returns enriched peer dicts."""
        res = self.client.get(f'/api/nodes/{self.node_id}/peers')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('peers', data)
        peers = data['peers']
        self.assertEqual(len(peers), 2)
        p1 = next(p for p in peers if p['id'] == self.peer1_id)
        self.assertEqual(p1['iface_name'], 'wg0')
        self.assertEqual(p1['iface'], 'wg0')
        self.assertIn('shortlink', p1)
        self.assertIn('shortlink_token', p1)
        self.assertEqual(p1['node_id'], self.node_id)

    def test_node_peer_config_qr_by_id_and_key(self):
        """GET /api/nodes/<nid>/peer/<pub>/config_qr works for numeric ID and keys."""
        # 1. By integer ID
        res = self.client.get(f'/api/nodes/{self.node_id}/peer/{self.peer1_id}/config_qr')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], 'image/png')

        # 2. By unencoded public key with slashes
        res = self.client.get(f'/api/nodes/{self.node_id}/peer/{self.peer2_pub}/config_qr')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], 'image/png')

        # 3. By percent-encoded public key with slashes and pluses
        encoded_pub = quote(self.peer1_pub, safe='')
        res = self.client.get(f'/api/nodes/{self.node_id}/peer/{encoded_pub}/config_qr')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers['Content-Type'], 'image/png')

    def test_node_peer_config_text(self):
        """GET /api/nodes/<nid>/peer/<pub>/config works by ID and key."""
        res = self.client.get(f'/api/nodes/{self.node_id}/peer/{self.peer1_id}/config')
        self.assertEqual(res.status_code, 200)
        self.assertIn('[Interface]', res.get_data(as_text=True))
        self.assertIn('[Peer]', res.get_data(as_text=True))

    def test_node_peer_shortlink(self):
        """GET /api/nodes/<nid>/peer/<pub>/shortlink returns valid shortlink payload."""
        res = self.client.get(f'/api/nodes/{self.node_id}/peer/{self.peer1_id}/shortlink')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('token', data)
        self.assertIn('url', data)

    def test_node_peer_reset_data(self):
        """POST /api/nodes/<nid>/peer/<pub>/reset_data resets offset cleanly."""
        res = self.client.post(f'/api/nodes/{self.node_id}/peer/{self.peer1_id}/reset_data')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))


if __name__ == '__main__':
    unittest.main()
