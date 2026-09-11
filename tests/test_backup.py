"""
test_backup.py - Comprehensive test suite for Backup and Restore subsystem.
Tests manual backups (db, settings, full), inspect API, restore API, auto-backup lifecycle,
preferences, schedules, and background worker execution.
"""
import io
import json
import os
import unittest
import zipfile
from pathlib import Path

from app import app
from core.extensions import db
from core.paths import (
    BACKUP_PREFS_FILE,
    BACKUP_SCHEDULE_FILE,
    BACKUP_LAST_FILE,
    BACKUP_AUTO_DIR,
)
from services.backup_service import (
    _load_backup_settings,
    _save_backup_settings,
    _load_backup_schedule,
    _save_backup_schedule,
    _save_autobackup,
    execute_auto_backup,
    build_full_backup_archive,
)


class TestBackupSubsystem(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        self.auto_dir = Path(BACKUP_AUTO_DIR)
        self.auto_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.app_context.pop()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True

    def test_backup_page_and_status(self):
        self._login(self.client)
        resp = self.client.get('/backup')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Backup', resp.data)

        # Status endpoint
        resp = self.client.get('/api/backup/status')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsInstance(data, dict)

        # Prefs get & post
        resp = self.client.get('/api/backup/prefs')
        self.assertEqual(resp.status_code, 200)
        prefs = resp.get_json()
        self.assertIn('include_wg', prefs)

        resp = self.client.post('/api/backup/prefs', json={'include_wg': False, 'send_to_telegram': True})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json().get('ok'))
        self.assertFalse(resp.get_json()['prefs']['include_wg'])
        self.assertTrue(resp.get_json()['prefs']['send_to_telegram'])

    def test_backup_db_and_settings_downloads(self):
        self._login(self.client)
        # Database backup
        resp = self.client.get('/api/backup/db')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get('Content-Type'), 'application/zip')
        self.assertEqual(resp.headers.get('X-Backup-Kind'), 'db')

        with zipfile.ZipFile(io.BytesIO(resp.data), 'r') as z:
            names = z.namelist()
            self.assertTrue(any(n.startswith('db/') and n.endswith('.db') for n in names))
            self.assertIn('meta/created.txt', names)

        # Settings backup
        resp = self.client.get('/api/backup/settings')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get('X-Backup-Kind'), 'settings')

        with zipfile.ZipFile(io.BytesIO(resp.data), 'r') as z:
            names = z.namelist()
            self.assertTrue(any(n.startswith('instance/') for n in names))
            self.assertIn('meta/created.txt', names)

    def test_backup_full_and_auto_flag(self):
        self._login(self.client)
        # Full backup download with auto=1
        resp = self.client.get('/api/backup/full?wg=0&auto=1')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get('X-Backup-Kind'), 'full')

        with zipfile.ZipFile(io.BytesIO(resp.data), 'r') as z:
            names = z.namelist()
            self.assertTrue(any(n.startswith('db/') for n in names))
            self.assertTrue(any(n.startswith('instance/') for n in names))
            self.assertIn('meta/manifest.json', names)
            manifest = json.loads(z.read('meta/manifest.json').decode('utf-8'))
            self.assertEqual(manifest.get('kind'), 'full')

        # Check that auto backup was saved to disk
        resp = self.client.get('/api/backups/auto')
        self.assertEqual(resp.status_code, 200)
        files = resp.get_json().get('files', [])
        self.assertGreater(len(files), 0)
        latest_file = files[0]['name']

        # Inspect saved auto backup
        resp = self.client.get(f'/api/backups/inspect/{latest_file}')
        self.assertEqual(resp.status_code, 200)
        inspect_data = resp.get_json()
        self.assertTrue(inspect_data.get('ok'))
        self.assertEqual(inspect_data.get('kind'), 'full')
        self.assertTrue(inspect_data.get('has_db'))

        # Delete saved auto backup
        resp = self.client.delete(f'/api/backups/file/{latest_file}')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json().get('ok'))

    def test_backup_inspect_and_restore(self):
        self._login(self.client)
        # Create a sample settings backup in memory
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('instance/test_sample.json', json.dumps({'sample': 'value'}))
            z.writestr('meta/created.txt', '2026-09-11T12:00:00Z')
            z.writestr('meta/manifest.json', json.dumps({'kind': 'settings'}))
        mem.seek(0)

        # Inspect uploaded backup
        data = {'file': (io.BytesIO(mem.getvalue()), 'backup_sample.zip')}
        resp = self.client.post('/api/backup/inspect', data=data, content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 200)
        res = resp.get_json()
        self.assertTrue(res.get('ok'))
        self.assertEqual(res.get('kind'), 'settings')
        self.assertTrue(res.get('has_settings'))

        # Restore uploaded backup
        mem.seek(0)
        data = {
            'file': (io.BytesIO(mem.getvalue()), 'backup_sample.zip'),
            'kind': 'settings',
            'server_settings_mode': 'keep',
        }
        resp = self.client.post('/api/backup/restore', data=data, content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 200)
        restore_res = resp.get_json()
        self.assertTrue(restore_res.get('ok'))
        self.assertTrue(restore_res['restored']['settings'])

    def test_backup_schedule_and_auto_executor(self):
        self._login(self.client)
        # Test schedule get
        resp = self.client.get('/api/backup/schedule')
        self.assertEqual(resp.status_code, 200)
        s = resp.get_json()
        self.assertIn('freq', s)
        self.assertIn('keep', s)

        # Test schedule post with telegram_chat_id
        schedule_payload = {
            'enabled': True,
            'freq': 'daily',
            'time': '03:00',
            'timezone': 'UTC',
            'keep': 5,
            'include_wg': False,
            'send_to_telegram': False,
            'telegram_chat_id': '123456789',
        }
        resp = self.client.post('/api/backup/schedule', json=schedule_payload)
        self.assertEqual(resp.status_code, 200)
        updated_s = resp.get_json()
        self.assertTrue(updated_s.get('ok'))
        self.assertEqual(updated_s.get('telegram_chat_id'), '123456789')
        self.assertEqual(updated_s.get('keep'), 5)

        # Verify persistence on subsequent GET
        resp = self.client.get('/api/backup/schedule')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json().get('telegram_chat_id'), '123456789')

        # Test execute_auto_backup directly
        result = execute_auto_backup()
        self.assertTrue(result.get('ok'))
        self.assertIn('auto_full_', result.get('filename'))
        self.assertGreater(result.get('size'), 0)

        # Cleanup created backup
        fname = result.get('filename')
        resp = self.client.delete(f'/api/backups/file/{fname}')
        self.assertEqual(resp.status_code, 200)
