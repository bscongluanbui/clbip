"""Offline release contract: pull-only production and tested-image publishing."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ContainerReleaseContractTests(unittest.TestCase):
    def test_production_is_pull_only_with_stable_project_and_volumes(self):
        compose = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
        self.assertIn('name: ipv6-proxy-manager', compose)
        self.assertIn('image: "${IPV6_MANAGER_IMAGE:-ghcr.io/bscongluanbui/clbip:latest}"', compose)
        self.assertNotIn('build:', compose)
        for volume in ('proxy-data', 'worker-runtime', 'dashboard-credentials'):
            self.assertIn('  ' + volume + ':', compose)

    def test_local_build_is_explicit_and_keeps_the_integration_image(self):
        override = (ROOT / 'docker-compose.build.yml').read_text(encoding='utf-8')
        self.assertEqual(override.count('image: ipv6-proxy-manager:local'), 2)
        self.assertEqual(override.count('build: .'), 2)
        self.assertEqual(override.count('pull_policy: never'), 2)
        self.assertFalse((ROOT / 'compose.override.yml').exists())

    def test_workflow_publishes_same_local_image_only_after_acceptance_and_scan(self):
        workflow = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
        self.assertIn('docker compose -f docker-compose.yml -f docker-compose.build.yml build', workflow)
        publish = workflow.index('- name: Publish the exact tested image to GHCR')
        for name in ('Python unit tests', 'Real 3proxy in isolated Linux network namespace',
                     'Isolated worker/dashboard roles and authenticated IPC', 'Scan full image SBOM for vulnerabilities'):
            self.assertLess(workflow.index('- name: ' + name), publish)
        release = workflow[publish:]
        self.assertIn("github.event_name != 'pull_request'", release)
        self.assertIn('docker tag ipv6-proxy-manager:local "$IMAGE:sha-$GITHUB_SHA"', release)
        self.assertIn('docker push "$IMAGE:latest"', release)
        self.assertIn('docker pull "$DIGEST"', release)
        self.assertIn('packages: write', workflow)
        self.assertIn("'platform': 'linux/amd64'", release)

    def test_image_and_checkout_have_provenance_and_linux_entrypoint(self):
        dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        self.assertIn('org.opencontainers.image.source="https://github.com/bscongluanbui/clbip"', dockerfile)
        self.assertIn('org.opencontainers.image.revision="${VCS_REF}"', dockerfile)
        attrs = (ROOT / '.gitattributes').read_text(encoding='utf-8')
        self.assertIn('*.sh text eol=lf', attrs)
        self.assertNotIn(b'\r\n', (ROOT / 'start.sh').read_bytes())

    def test_publication_excludes_host_secrets_data_and_other_fork(self):
        ignored = set((ROOT / '.gitignore').read_text(encoding='utf-8').splitlines())
        self.assertTrue({'/secrets/', '/data/', '.env', '/audit/', '/macos_fork/', '__pycache__/'}.issubset(ignored))


if __name__ == '__main__':
    unittest.main()
