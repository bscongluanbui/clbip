"""Real deployment command contracts: module packaging and LAN health probes."""
import ast
import fnmatch
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


ROOT = Path(os.environ.get('CLBIP_TEST_CONTRACT_ROOT', Path(__file__).resolve().parents[1]))


def packaged_modules():
    sources = []
    for line in (ROOT / 'Dockerfile').read_text(encoding='utf-8').splitlines():
        if line.startswith('COPY ') and line.endswith(' /app/') and '--from=' not in line:
            sources.extend(line.split()[1:-1])
    return {path.stem for path in ROOT.glob('*.py')
            if any(fnmatch.fnmatch(path.name, pattern) for pattern in sources)}


def health_command():
    lines = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8').splitlines()
    line = next(line.strip() for line in lines if '"import urllib.request,os;' in line)
    return ast.literal_eval(line.split('-c, ', 1)[1].rsplit(']', 1)[0])


class InstallPackagingTests(unittest.TestCase):
    def test_all_local_imports_are_available_in_runtime(self):
        available = packaged_modules()
        self.assertIn('worker', available)
        missing = set()
        for name in available:
            for node in ast.walk(ast.parse((ROOT / (name + '.py')).read_text(encoding='utf-8'))):
                names = ([node.module] if isinstance(node, ast.ImportFrom) else
                         [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
                for imported in names:
                    local = (imported or '').split('.')[0]
                    if (ROOT / (local + '.py')).is_file() and local not in available:
                        missing.add(name + ' -> ' + local)
        self.assertEqual(missing, set(), 'Dockerfile omits local module imports')

    def test_dashboard_healthcheck_obeys_effective_bind_and_port(self):
        for bind, connect in [('127.0.0.1', '127.0.0.1'), ('192.168.1.3', '192.168.1.3'),
                              ('0.0.0.0', '127.0.0.1'), ('::', '[::1]'), ('::1', '[::1]')]:
            opener = Mock()
            response = Mock()
            opener.open.return_value = response
            with self.subTest(bind=bind), patch.dict(os.environ, {'GUI_BIND': bind, 'GUI_PORT': '7070'}), \
                    patch('urllib.request.build_opener', return_value=opener) as build, \
                    patch('urllib.request.urlopen', return_value=response) as direct:
                exec(health_command(), {})
                build.assert_called_once()
                direct.assert_not_called()
                opener.open.assert_called_once_with('http://' + connect + ':7070/readyz', timeout=3)
                response.close.assert_called_once()

    def test_cached_image_also_disables_gunicorn_control_socket(self):
        compose = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
        self.assertIn('GUNICORN_CMD_ARGS: "--no-control-socket"', compose)


if __name__ == '__main__':
    unittest.main()
