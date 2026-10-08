"""Execute the actual entrypoint Python preflight without starting services."""
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


class StartupPasswordTests(unittest.TestCase):
    def check(self, password, secret='s' * 40, token='t' * 40):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'start.sh').read_text(encoding='utf-8')
        command = re.search(r'^\s+python -c "([^"]+)"', source, re.MULTILINE).group(1)
        env = {key: value for key, value in os.environ.items()
               if key not in {'ADMIN_PASSWORD_FILE', 'SECRET_KEY_FILE', 'SERVICE_TOKEN_FILE'}}
        env.update(ADMIN_PASSWORD=password, SECRET_KEY=secret, SERVICE_TOKEN=token)
        return subprocess.run([sys.executable, '-X', 'utf8', '-B', '-c', command],
                              cwd=root, env=env, text=True, capture_output=True, timeout=15)

    def test_single_character_bootstrap_has_no_length_gate(self):
        result = self.check('x')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_bootstrap_supports_password_free_dashboard(self):
        result = self.check('')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unicode_bootstrap_has_no_character_gate(self):
        result = self.check('mật khẩu')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ipc_and_session_keys_still_validated(self):
        for secret, token in [('short', 't' * 40), ('s' * 40, 'short')]:
            with self.subTest(secret=secret, token=token):
                result = self.check('', secret=secret, token=token)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('ADMIN_PASSWORD', result.stderr)
