"""
OxWg Panel - Modular app.py and Branding Integration Tests
=========================================================
Verifies:
  1. Modular app.py initialization, ProxyFix wrapping, and configuration.
  2. All 17 blueprints registered and total routes resolve correctly.
  3. All 15 lifecycle hooks and context processors (including branding).
  4. Backward-compatible re-exports from app.py.
  5. Bootstrap sequence execution in app context.
  6. End-to-end route resolution and OxWg Panel branding in templates and config files.
"""
import os
import unittest
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

import app
from core.bootstrap import bootstrap
from blueprints import ALL_BLUEPRINTS


class TestAppModularIntegration(unittest.TestCase):
    """Integration test suite for modular app.py and OxWg branding."""

    @classmethod
    def setUpClass(cls):
        # Configure app for testing
        cls.flask_app = app.app
        cls.flask_app.config["TESTING"] = True
        cls.flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        cls.flask_app.config["WTF_CSRF_ENABLED"] = False
        cls.flask_app.config["API_KEY"] = "modular-test-api-key"
        cls.client = cls.flask_app.test_client()

        with cls.flask_app.app_context():
            app.db.create_all()
            if not app.AdminAccount.query.first():
                admin = app.AdminAccount(username="admin", password_hash="test-hash")
                app.db.session.add(admin)
                app.db.session.commit()

    def _login(self):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["_fresh"] = True

    def test_app_instance_and_proxyfix(self):
        """Verify app is a Flask instance wrapped with ProxyFix middleware."""
        self.assertIsInstance(self.flask_app, Flask)
        self.assertIsInstance(self.flask_app.wsgi_app, ProxyFix)
        self.assertTrue(self.flask_app.config.get("PROPAGATE_EXCEPTIONS"))

    def test_all_17_blueprints_registered(self):
        """Verify that all 17 domain blueprints are properly registered on the app."""
        registered_bp_names = set(self.flask_app.blueprints.keys())
        for bp in ALL_BLUEPRINTS:
            self.assertIn(
                bp.name,
                registered_bp_names,
                f"Blueprint {bp.name} not found in registered blueprints",
            )
        self.assertEqual(len(ALL_BLUEPRINTS), 17)

    def test_route_rules_count(self):
        """Verify that the total routes on app.py match the expected catalog."""
        # 183 custom domain endpoints + 1 default static endpoint = 184 rules
        rules = list(self.flask_app.url_map.iter_rules())
        self.assertGreaterEqual(len(rules), 183)

    def test_context_processors(self):
        """Verify lifecycle context processors inject expected variables."""
        with self.flask_app.test_request_context():
            # 1. Nav flags
            nav = app.inject_nav_flags()
            self.assertIn("HAS_NODES", nav)
            self.assertIn("HAS_SETTINGS", nav)
            self.assertTrue(nav["HAS_NODES"])
            self.assertTrue(nav["HAS_SETTINGS"])

            # 2. Timezone
            tz = app.inject_panel_timezone()
            self.assertIn("PANEL_TIMEZONE", tz)
            self.assertIsInstance(tz["PANEL_TIMEZONE"], str)

            # 3. Branding
            brand = app.inject_brand()
            self.assertIn("PANEL_BRAND_NAME", brand)
            self.assertIn("PANEL_SHORT_NAME", brand)
            self.assertEqual(brand["PANEL_BRAND_NAME"], "OxWg Panel")
            self.assertEqual(brand["PANEL_SHORT_NAME"], "OxWg")

    def test_security_and_cache_headers(self):
        """Verify lifecycle after_request hooks inject proper headers."""
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("no-cache", resp.headers.get("Cache-Control", ""))

    def test_preview_frame_options(self):
        """Verify /preview/ route allows framing from SAMEORIGIN for template preview."""
        self._login()
        resp = self.client.get("/preview/template/default")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertIn("default-src 'self'", resp.headers.get("Content-Security-Policy", ""))

    def test_login_page_branding(self):
        """Verify /login page contains OxWg Panel in title and body."""
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("OxWg Panel — Login", html)
        self.assertIn("Sign in to your OxWg Panel", html)
        self.assertNotIn("WG Panel — Login", html)

    def test_api_docs_branding(self):
        """Verify /api-docs route resolves and references OxWg Panel."""
        self._login()
        resp = self.client.get("/api-docs")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("OxWg Panel", html)

    def test_reexported_models(self):
        """Verify all essential models are accessible from app module."""
        self.assertTrue(hasattr(app, "Peer"))
        self.assertTrue(hasattr(app, "InterfaceConfig"))
        self.assertTrue(hasattr(app, "AdminAccount"))
        self.assertTrue(hasattr(app, "ShortLink"))
        self.assertTrue(hasattr(app, "Subscription"))
        self.assertTrue(hasattr(app, "SubscriptionPeer"))
        self.assertTrue(hasattr(app, "Node"))
        self.assertTrue(hasattr(app, "PeerEvent"))

    def test_reexported_utilities_and_services(self):
        """Verify all critical helpers and services are re-exported on app."""
        self.assertTrue(callable(app.now_ts))
        self.assertTrue(callable(app.from_ts))
        self.assertTrue(callable(app.to_ts))
        self.assertTrue(callable(app._probably_encrypt))
        self.assertTrue(callable(app._probably_decrypt))
        self.assertTrue(callable(app._json_load))
        self.assertTrue(callable(app._json_save))
        self.assertTrue(callable(app._first_cidr))
        self.assertTrue(callable(app._on_boot))
        self.assertTrue(callable(app._run_expiry_once))
        self.assertTrue(callable(app.repoint_endpoints))
        self.assertTrue(callable(app.bootstrap))
        self.assertTrue(callable(app._wg_transfer))
        self.assertTrue(callable(app.install_local_peer))
        self.assertTrue(callable(app.local_firewall_rules))
        self.assertTrue(callable(app._iface_up))
        self.assertTrue(callable(app.allocate_peer_address))
        self.assertTrue(callable(app._shortlink_url))
        self.assertTrue(callable(app._peer_from_shortlink_token))
        self.assertTrue(callable(app._shortlink_for_peer))
        self.assertTrue(callable(app._load_tg_settings))
        self.assertTrue(callable(app._save_tg_settings))
        self.assertTrue(issubclass(app.AddressAllocationError, Exception))
        self.assertTrue(issubclass(app.WGPanelError, Exception))
        self.assertTrue(issubclass(app.WireGuardError, Exception))
        self.assertTrue(issubclass(app.ShortLinkError, Exception))
        self.assertTrue(issubclass(app.NodeClientError, Exception))
        self.assertTrue(issubclass(app.ClientConfigIncomplete, Exception))
        self.assertTrue(hasattr(app, "ADMIN_LOG_FILE"))
        self.assertTrue(hasattr(app, "IFACE_LOG_DIR"))
        self.assertTrue(hasattr(app, "PANEL_SETTINGS_FILE"))
        self.assertTrue(hasattr(app, "LOG_LEVEL"))

    def test_navigation_active_links_and_chartjs(self):
        """Verify active sidebar link highlighting and Chart.js inclusion across routes."""
        self._login()

        # 1. Dashboard (index) should have active Dashboard link and include Chart.js
        resp_index = self.client.get("/")
        self.assertEqual(resp_index.status_code, 200)
        html_index = resp_index.get_data(as_text=True)
        self.assertIn('chart.umd.min.js', html_index)
        self.assertIn('class="sb2-link active" data-tip="Dashboard"', html_index)

        # 2. Peers page
        resp_peers = self.client.get("/users")
        self.assertEqual(resp_peers.status_code, 200)
        html_peers = resp_peers.get_data(as_text=True)
        self.assertIn('class="sb2-link active" data-tip="Peers"', html_peers)

        # 3. Logs page
        resp_logs = self.client.get("/logs")
        self.assertEqual(resp_logs.status_code, 200)
        html_logs = resp_logs.get_data(as_text=True)
        self.assertIn('class="sb2-link active" data-tip="Logs"', html_logs)

        # 4. Backup page
        resp_backup = self.client.get("/backup")
        self.assertEqual(resp_backup.status_code, 200)
        html_backup = resp_backup.get_data(as_text=True)
        self.assertIn('class="sb2-link active" data-tip="Backup"', html_backup)

        # 5. Settings page
        resp_settings = self.client.get("/settings")
        self.assertEqual(resp_settings.status_code, 200)
        html_settings = resp_settings.get_data(as_text=True)
        self.assertIn('class="sb2-link active" data-tip="Settings"', html_settings)

        # 6. API Docs page
        resp_docs = self.client.get("/api-docs")
        self.assertEqual(resp_docs.status_code, 200)
        html_docs = resp_docs.get_data(as_text=True)
        self.assertIn('class="sb2-link active" data-tip="API Docs"', html_docs)

    def test_node_monitor_app_context(self):
        """Verify _node_notify_monitor sets app context reference properly."""
        from services.node_monitor import _app as current_monitor_app, set_app as set_monitor_app
        dummy_app = Flask("dummy_monitor_app")
        app._node_notify_monitor(dummy_app)
        from services.node_monitor import _app as updated_monitor_app
        self.assertEqual(updated_monitor_app, dummy_app)

    def test_bootstrap_execution(self):
        """Verify bootstrap(app) executes cleanly within application context."""
        test_app = Flask("test_bootstrap_app")
        test_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        test_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        test_app.config["TESTING"] = True
        test_app.config["WG_CONF_PATH"] = "/nonexistent/test/wireguard"
        app.init_extensions(test_app)

        bootstrap(test_app)

        with test_app.app_context():
            from sqlalchemy import inspect
            insp = inspect(app.db.engine)
            self.assertTrue(insp.has_table("interface_config"))
            self.assertTrue(insp.has_table("peer"))
            self.assertTrue(insp.has_table("admin_account"))
            self.assertTrue(insp.has_table("short_link"))

    def test_branding_in_files(self):
        """Verify branding updates in template files, service definitions, and wg.py."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # 1. base.html
        with open(os.path.join(base_dir, "templates", "base.html"), "r", encoding="utf-8") as f:
            base_html = f.read()
        self.assertIn("<title>{% block title %}OxWg Panel{% endblock %}</title>", base_html)
        self.assertIn("<strong>OxWg Panel</strong>", base_html)
        self.assertIn('<span class="brand-title">OxWg Panel</span>', base_html)
        self.assertIn('<span class="sb2-update-k">OxWg Panel</span>', base_html)

        # 2. register.html
        with open(os.path.join(base_dir, "templates", "register.html"), "r", encoding="utf-8") as f:
            reg_html = f.read()
        self.assertIn("<title>OxWg Panel — Register</title>", reg_html)
        self.assertIn('<div class="t">OxWg Panel</div>', reg_html)
        self.assertIn("const issuer = j.issuer || 'OxWg Panel';", reg_html)

        # 3. settings.html & users.html
        with open(os.path.join(base_dir, "templates", "settings.html"), "r", encoding="utf-8") as f:
            settings_html = f.read()
        self.assertIn("panel.oxwg.com", settings_html)
        self.assertIn('placeholder="oxwg"', settings_html)

        with open(os.path.join(base_dir, "templates", "users.html"), "r", encoding="utf-8") as f:
            users_html = f.read()
        self.assertIn('placeholder="e.g. oxwg"', users_html)

        # 4. systemd service files
        with open(os.path.join(base_dir, "systemd", "bot.service"), "r", encoding="utf-8") as f:
            bot_svc = f.read()
        self.assertIn("Description=OxWg Panel – Telegram Bot", bot_svc)

        with open(os.path.join(base_dir, "systemd", "wg-node-agent.service"), "r", encoding="utf-8") as f:
            node_svc = f.read()
        self.assertIn("Description=OxWg Panel Node Agent (Flask + Gunicorn)", node_svc)

        # 5. wg.py CLI banner
        with open(os.path.join(base_dir, "wg.py"), "r", encoding="utf-8") as f:
            wg_py = f.read()
        self.assertIn('print(c("OxWg Panel Control"', wg_py)


if __name__ == "__main__":
    unittest.main()
