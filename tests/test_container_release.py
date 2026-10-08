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

    def test_workflow_matrix_builds_and_tests_three_explicit_platforms(self):
        workflow = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
        unit = workflow.split('  unit:\n', 1)[1].split('\n  publish:\n', 1)[0]
        for platform in ('linux/amd64', 'linux/arm64', 'linux/arm/v7'):
            self.assertIn('platform: ' + platform, unit)
        self.assertRegex(unit, r'arch: amd64[\s\S]*?runner: ubuntu-24\.04')
        self.assertRegex(unit, r'arch: arm64[\s\S]*?runner: ubuntu-24\.04-arm')
        self.assertRegex(unit, r'arch: armv7[\s\S]*?runner: ubuntu-24\.04')
        self.assertIn('runs-on: ${{ matrix.runner }}', unit)
        self.assertIn("matrix.arch == 'armv7'", unit)
        self.assertIn('integration_emulated.py', unit)
        self.assertIn('SCRIPT=integration_linux.py', unit)
        self.assertIn('if [[ "$ARCH" == armv7 ]]; then SCRIPT=integration_emulated.py;', unit)
        self.assertRegex(unit, r'docker build(?:x build)? --platform')
        self.assertIn('ipv6-proxy-manager:local', unit)
        self.assertNotIn("'platform': 'linux/amd64'", unit)

    def test_architecture_image_push_follows_acceptance_and_fixable_gate(self):
        workflow = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
        unit = workflow.split('  unit:\n', 1)[1].split('\n  publish:\n', 1)[0]
        publish = unit.index('- name: Publish the exact tested image to GHCR')
        for name in ('Python unit tests', 'Real 3proxy in isolated Linux network namespace',
                     'Isolated worker/dashboard roles and authenticated IPC',
                     'Scan full image SBOM for vulnerabilities', 'Gate fixable High/Critical vulnerabilities'):
            self.assertLess(unit.index('- name: ' + name), publish)
        release = unit[publish:]
        self.assertIn("github.event_name != 'pull_request'", release)
        self.assertIn('docker tag ipv6-proxy-manager:local "$IMAGE:sha-$GITHUB_SHA-$ARCH"', release)
        self.assertIn('docker push "$IMAGE:sha-$GITHUB_SHA-$ARCH"', release)
        self.assertNotIn('docker push "$IMAGE:latest"', unit)
        self.assertIn('docker pull "$DIGEST"', release)
        self.assertIn('packages: write', workflow)
        self.assertIn('image_vulnerability_gate.py', unit)

    def test_full_report_is_retained_without_only_fixed_filtering(self):
        workflow = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
        scan = workflow.split('- name: Scan full image SBOM for vulnerabilities', 1)[1].split('- name:', 1)[0]
        self.assertIn('fail-build: false', scan)
        self.assertIn('only-fixed: false', scan)
        evidence = workflow.split('- name: Preserve reproducible image SBOM and scan evidence', 1)[1].split('- name:', 1)[0]
        self.assertIn('always()', evidence)
        self.assertIn('image-vulnerabilities.json', evidence)
        self.assertIn('matrix.arch', evidence)

    def test_shared_manifest_waits_for_all_architecture_jobs_and_uses_digests(self):
        workflow = (ROOT / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')
        publish = workflow.split('\n  publish:\n', 1)[1]
        self.assertRegex(publish, r'needs:\s*(?:\[unit\]|unit)')
        self.assertIn("github.event_name != 'pull_request'", publish)
        self.assertIn('actions/download-artifact@', publish)
        self.assertIn('merge_container_release.py', publish)
        self.assertIn('prepare', publish)
        self.assertIn('verify', publish)
        self.assertIn('docker buildx imagetools create', publish)
        self.assertIn('docker pull --platform', publish)
        self.assertNotIn('docker build --platform', publish)
        self.assertNotIn('docker buildx build', publish)

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
