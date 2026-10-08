"""Offline contracts for target-platform dependency builds and role acceptance."""
import importlib.util
import ast
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('integration_roles_contract', ROOT / 'tests' / 'integration_roles.py')
roles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(roles)
emulated_spec = importlib.util.spec_from_file_location('integration_emulated_contract', ROOT / 'tests' / 'integration_emulated.py')
emulated = importlib.util.module_from_spec(emulated_spec)
emulated_spec.loader.exec_module(emulated)


class MultiplatformRuntimeTests(unittest.TestCase):
    def test_dependencies_build_on_target_architecture_without_runtime_compiler(self):
        source = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        dependency_stage = source.split('FROM ${BASE_IMAGE} AS python-builder', 1)[1].split('FROM ${BASE_IMAGE} AS runtime', 1)[0]
        runtime = source.split('FROM ${BASE_IMAGE} AS runtime', 1)[1]
        self.assertIn('build-essential', dependency_stage)
        self.assertIn('pip install --no-cache-dir --require-hashes --prefix=/install', dependency_stage)
        self.assertIn('COPY requirements.txt /build/requirements.txt', dependency_stage)
        self.assertNotIn('--platform=$BUILDPLATFORM', source)
        self.assertNotIn('build-essential', runtime)
        self.assertNotIn('pip install', runtime)
        self.assertIn('COPY --from=python-builder /install/lib/python3.12/site-packages/', runtime)
        self.assertIn('COPY --from=python-builder /install/bin/gunicorn /usr/local/bin/gunicorn', runtime)
        self.assertIn('python -m pip check', runtime)

    def test_platform_is_optional_and_same_isolated_role_defaults_remain(self):
        with patch.dict(os.environ, {'TEST_IMAGE': 'ipv6-proxy-manager:local', 'TEST_PLATFORM': ''}):
            common = roles.container_defaults()
        self.assertNotIn('platform', common)
        self.assertEqual(common['network_mode'], 'none')
        self.assertTrue(common['read_only'])
        self.assertEqual(common['cap_drop'], ['ALL'])
        self.assertEqual(common['security_opt'], ['no-new-privileges:true'])

    def test_each_supported_platform_is_explicit_in_role_compose(self):
        for platform in ('linux/amd64', 'linux/arm64', 'linux/arm/v7'):
            with self.subTest(platform=platform), patch.dict(os.environ, {'TEST_IMAGE': 'fixture:tested', 'TEST_PLATFORM': platform}):
                common = roles.container_defaults()
                self.assertEqual(common['platform'], platform)
                self.assertEqual(common['image'], 'fixture:tested')

    def test_unknown_platform_rejected_without_docker_call(self):
        with patch.dict(os.environ, {'TEST_PLATFORM': 'linux/unknown'}):
            with self.assertRaisesRegex(ValueError, 'Unsupported integration platform'):
                roles.container_defaults()

    def test_lock_keeps_wheels_and_sdists_for_arm_targets(self):
        provenance = json.loads((ROOT / 'docs' / 'dependency-provenance.json').read_text(encoding='utf-8'))
        lock = (ROOT / 'requirements.txt').read_text(encoding='utf-8')
        for package in provenance['packages']:
            with self.subTest(package=package['name']):
                artifacts = package['artifacts']
                filenames = [artifact['filename'] for artifact in artifacts]
                self.assertTrue(any(name.endswith(('.tar.gz', '.zip')) for name in filenames))
                for architecture in ('aarch64', 'armv7l'):
                    self.assertTrue(any(name.endswith('none-any.whl') or
                                        (architecture in name and 'cp312-' in name)
                                        for name in filenames), (package['name'], architecture))
                for artifact in artifacts:
                    self.assertIn('--hash=sha256:' + artifact['sha256'], lock)


class EmulatedEngineContractTests(unittest.TestCase):
    def test_explicit_opt_in_and_network_none_are_both_required(self):
        emulated.require_isolated_namespace('linux', '1', [{'ifname': 'lo'}])
        for platform, opt_in, links in [('win32', '1', [{'ifname': 'lo'}]),
                                        ('linux', None, [{'ifname': 'lo'}]),
                                        ('linux', '0', [{'ifname': 'lo'}]),
                                        ('linux', '1', [{'ifname': 'lo'}, {'ifname': 'eth0'}]),
                                        ('linux', '1', []), ('linux', '1', {})]:
            with self.subTest(platform=platform, opt_in=opt_in, links=links), self.assertRaises(ValueError):
                emulated.require_isolated_namespace(platform, opt_in, links)

    def test_no_production_ownership_or_lifecycle_calls(self):
        source = (ROOT / 'tests' / 'integration_emulated.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        calls = [node.func.attr for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == 'engine']
        self.assertEqual(calls, ['_generate_single_config'])
        self.assertIn('PRODUCTION_OWNERSHIP=NOT_VALIDATED', source)
        self.assertNotIn('killpg(', source)

    def test_curl_uses_only_loopback_proxy_and_stdin_credentials(self):
        for protocol in ('http', 'socks5h'):
            args = emulated.curl_arguments(protocol, 19001, 'http://[fd00:2::1]:19009/')
            self.assertIn(protocol + '://127.0.0.1:19001', args)
            self.assertEqual(args[args.index('--config') + 1], '-')
            self.assertFalse(any('Integration_Only' in argument for argument in args))
        with self.assertRaises(ValueError):
            emulated.curl_arguments('ftp', 19001, 'http://[fd00:2::1]/')

    def test_tracked_child_is_terminated_and_waited(self):
        from unittest.mock import Mock
        process = Mock()
        process.poll.return_value = None
        emulated.stop_tracked_child(process)
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=15)
        process.kill.assert_not_called()

    def test_already_stopped_child_is_not_signalled(self):
        from unittest.mock import Mock
        process = Mock()
        process.poll.return_value = 0
        emulated.stop_tracked_child(process)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        process.wait.assert_not_called()

    def test_only_tracked_child_is_killed_on_stop_timeout(self):
        import subprocess
        from unittest.mock import Mock
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture-child', 15), 0]
        emulated.stop_tracked_child(process)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)


if __name__ == '__main__':
    unittest.main()
