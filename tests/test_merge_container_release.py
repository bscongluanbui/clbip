"""Offline contract tests for immutable, three-platform image publication."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.merge_container_release import PLATFORMS, main, prepare, read_json, verify


ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'ghcr.io/bscongluanbui/clbip'
COMMIT = 'a' * 40


def releases():
    return [{'image': IMAGE, 'commit': COMMIT, 'platform': platform,
             'digest': IMAGE + '@sha256:' + str(number) * 64,
             'image_id': 'sha256:' + str(number + 3) * 64,
             'tags': ['sha-' + COMMIT + '-' + ('amd64', 'arm64', 'armv7')[number - 1]]}
            for number, platform in enumerate(PLATFORMS, 1)]


def merge_input():
    records = releases()
    return {'image': IMAGE, 'commit': COMMIT,
            'refs': sorted(record['digest'] for record in records),
            'platforms': list(PLATFORMS), 'architectures': records}


def image_index():
    platforms = [{'os': 'linux', 'architecture': 'amd64'},
                 {'os': 'linux', 'architecture': 'arm64'},
                 {'os': 'linux', 'architecture': 'arm', 'variant': 'v7'}]
    return {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
            'manifests': [{'digest': record['digest'].split('@', 1)[1],
                           'platform': platform}
                          for record, platform in zip(releases(), platforms)]}


def descriptor():
    return {'digest': 'sha256:' + 'f' * 64,
            'mediaType': 'application/vnd.oci.image.index.v1+json'}


class MergeContainerReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary_root = ROOT / '.test-tmp'
        temporary_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write_releases(self, records=None):
        artifacts = self.directory / 'artifacts'
        artifacts.mkdir()
        for number, record in enumerate(releases() if records is None else records):
            subdirectory = artifacts / ('artifact-' + str(number))
            subdirectory.mkdir()
            (subdirectory / 'container-release.json').write_text(json.dumps(record), encoding='utf-8')
        return artifacts

    def assert_verify_rejected(self, merge=None, index=None, manifest=None):
        with self.assertRaises(ValueError):
            verify(merge_input() if merge is None else merge,
                   image_index() if index is None else index,
                   descriptor() if manifest is None else manifest)

    def test_prepare_recursive_artifacts_are_deterministic_and_immutable(self):
        records = releases()[::-1]
        before = copy.deepcopy(records)
        result = prepare(self.write_releases(records), IMAGE, COMMIT)
        self.assertEqual(result, merge_input())
        self.assertEqual(records, before)
        self.assertEqual(result['refs'], sorted(result['refs']))

    def test_prepare_requires_exactly_three_release_files(self):
        for count in (0, 1, 2, 4):
            with self.subTest(count=count):
                directory = self.directory / ('artifacts-' + str(count))
                directory.mkdir()
                for number in range(count):
                    child = directory / str(number)
                    child.mkdir()
                    (child / 'container-release.json').write_text(json.dumps(releases()[number % 3]))
                with self.assertRaises(ValueError):
                    prepare(directory, IMAGE, COMMIT)

    def test_prepare_requires_directory_and_full_commit_and_image(self):
        artifacts = self.write_releases()
        for image, commit in ((IMAGE, 'abc123'), (IMAGE, 'a' * 39), (IMAGE, 'G' * 40),
                              (IMAGE + ':latest', COMMIT), (IMAGE + '@sha256:abc', COMMIT),
                              ('', COMMIT), (None, COMMIT), (IMAGE, None)):
            with self.subTest(image=image, commit=commit), self.assertRaises(ValueError):
                prepare(artifacts, image, commit)
        with self.assertRaises(ValueError):
            prepare(self.directory / 'absent', IMAGE, COMMIT)

    def test_cross_commit_and_repository_are_rejected(self):
        for field, value in (('commit', 'b' * 40), ('image', 'ghcr.io/other/image')):
            bad = merge_input()
            bad['architectures'][1][field] = value
            with self.subTest(field=field):
                self.assert_verify_rejected(merge=bad)

    def test_duplicate_and_missing_architectures_are_rejected(self):
        for architecture_records in (releases()[:2], releases() + releases()[:1],
                                     [releases()[0], releases()[0], releases()[2]], [], {}, None):
            bad = merge_input()
            bad['architectures'] = architecture_records
            with self.subTest(records=architecture_records):
                self.assert_verify_rejected(merge=bad)

    def test_unknown_or_incomplete_architecture_labels_are_rejected(self):
        for platform in ('linux/arm', 'linux/arm/v6', 'linux/386', 'windows/amd64', None, [], {}):
            bad = merge_input()
            bad['architectures'][2]['platform'] = platform
            with self.subTest(platform=platform):
                self.assert_verify_rejected(merge=bad)

    def test_missing_wrong_repository_or_nonimmutable_child_digest_is_rejected(self):
        for digest in (None, '', IMAGE + ':latest', IMAGE + '@sha256:' + 'a' * 63,
                       IMAGE + '@sha256:' + 'g' * 64, IMAGE + '@sha256:' + 'A' * 64,
                       'ghcr.io/other/image@sha256:' + 'a' * 64, 123):
            bad = merge_input()
            bad['architectures'][0]['digest'] = digest
            with self.subTest(digest=digest):
                self.assert_verify_rejected(merge=bad)

    def test_duplicate_child_digest_is_rejected_even_with_different_platforms(self):
        bad = merge_input()
        bad['architectures'][1]['digest'] = bad['architectures'][0]['digest']
        bad['refs'] = sorted(record['digest'] for record in bad['architectures'])
        self.assert_verify_rejected(merge=bad)

    def test_optional_image_ids_and_tags_are_preserved_but_validated(self):
        stripped = merge_input()
        for record in stripped['architectures']:
            record.pop('image_id')
            record.pop('tags')
        self.assertNotIn('image_id', verify(stripped, image_index(), descriptor())['architectures'][0])
        for field, value in (('image_id', 'sha256:invalid'), ('tags', 'latest'),
                             ('tags', ['bad tag']), ('tags', ['latest', 'latest']),
                             ('tags', [None]), ('tags', [{}]), ('tags', ['a' * 129])):
            bad = merge_input()
            bad['architectures'][0][field] = value
            with self.subTest(field=field, value=value):
                self.assert_verify_rejected(merge=bad)

    def test_merge_input_platform_and_ref_metadata_cannot_drift(self):
        for field, value in (('platforms', list(PLATFORMS)[::-1]), ('platforms', list(PLATFORMS)[:2]),
                             ('refs', []), ('refs', merge_input()['refs'][::-1])):
            bad = merge_input()
            bad[field] = value
            with self.subTest(field=field):
                self.assert_verify_rejected(merge=bad)

    def test_verify_exact_three_platform_index_and_preserves_records(self):
        input_record, index, manifest = merge_input(), image_index(), descriptor()
        before = copy.deepcopy((input_record, index, manifest))
        output = verify(input_record, index, manifest)
        self.assertEqual(output, {'image': IMAGE, 'commit': COMMIT,
                                  'digest': IMAGE + '@sha256:' + 'f' * 64,
                                  'platforms': list(PLATFORMS), 'architectures': releases(),
                                  'tags': ['latest', 'sha-' + COMMIT]})
        self.assertEqual((input_record, index, manifest), before)

    def test_index_descriptor_order_may_differ(self):
        index = image_index()
        index['manifests'].reverse()
        self.assertEqual(verify(merge_input(), index, descriptor())['platforms'], list(PLATFORMS))

    def test_docker_manifest_list_and_arm64_v8_are_accepted(self):
        index = image_index()
        index['mediaType'] = 'application/vnd.docker.distribution.manifest.list.v2+json'
        index['manifests'][1]['platform']['variant'] = 'v8'
        manifest = descriptor()
        manifest['mediaType'] = index['mediaType']
        self.assertEqual(verify(merge_input(), index, manifest)['commit'], COMMIT)

    def test_index_requires_index_media_type_and_schema(self):
        for field, value in (('schemaVersion', 1), ('schemaVersion', None),
                             ('mediaType', 'application/vnd.oci.image.manifest.v1+json'),
                             ('mediaType', None)):
            index = image_index()
            index[field] = value
            with self.subTest(field=field, value=value):
                self.assert_verify_rejected(index=index)
        with self.assertRaises(ValueError):
            verify(merge_input(), None, descriptor())

    def test_index_requires_exactly_three_manifest_objects(self):
        for manifests in ([], image_index()['manifests'][:2],
                          image_index()['manifests'] + image_index()['manifests'][:1], {}, None,
                          [None, {}, {}]):
            index = image_index()
            index['manifests'] = manifests
            with self.subTest(manifests=manifests):
                self.assert_verify_rejected(index=index)

    def test_arm_v7_variant_is_mandatory(self):
        for variant in (None, '', 'v6', 'v8', 7):
            index = image_index()
            index['manifests'][2]['platform']['variant'] = variant
            with self.subTest(variant=variant):
                self.assert_verify_rejected(index=index)

    def test_unknown_architecture_os_and_missing_platform_are_rejected(self):
        for platform in ({'os': 'windows', 'architecture': 'amd64'},
                         {'os': 'linux', 'architecture': '386'},
                         {'os': 'linux', 'architecture': 'amd64', 'variant': 'v7'},
                         {'os': 'linux', 'architecture': 'arm64', 'variant': 'v9'},
                         {}, None, []):
            index = image_index()
            index['manifests'][0]['platform'] = platform
            with self.subTest(platform=platform):
                self.assert_verify_rejected(index=index)

    def test_duplicate_index_platform_is_rejected(self):
        index = image_index()
        index['manifests'][1]['platform'] = index['manifests'][0]['platform']
        self.assert_verify_rejected(index=index)

    def test_index_child_digest_must_match_tested_architecture(self):
        for digest in ('sha256:' + 'f' * 64, 'sha256:' + '2' * 64, 'sha256:bad', None):
            index = image_index()
            index['manifests'][0]['digest'] = digest
            with self.subTest(digest=digest):
                self.assert_verify_rejected(index=index)

    def test_descriptor_requires_valid_bare_index_digest(self):
        for manifest in ({}, {'digest': IMAGE + '@sha256:' + 'f' * 64},
                         {'digest': 'sha256:' + 'f' * 63}, {'digest': None},
                         {'digest': 'sha256:' + 'f' * 64, 'mediaType': 'application/vnd.oci.image.manifest.v1+json'}):
            with self.subTest(manifest=manifest):
                self.assert_verify_rejected(manifest=manifest)
        with self.assertRaises(ValueError):
            verify(merge_input(), image_index(), None)

    def test_duplicate_json_fields_and_nonfinite_constants_are_rejected(self):
        path = self.directory / 'bad.json'
        for payload in ('{"image":"first","image":"second"}', '{"value":NaN}',
                        '{"value":Infinity}', '{"value":-Infinity}'):
            path.write_text(payload, encoding='utf-8')
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                read_json(path)

    def test_oversized_json_is_rejected(self):
        path = self.directory / 'large.json'
        path.write_text(' ' * (2 * 1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            read_json(path)

    def test_cli_prepare_and_verify_literal_outputs_and_files(self):
        input_dir = self.write_releases()
        merge_path = self.directory / 'merge-input.json'
        index_path = self.directory / 'manifest-index.json'
        descriptor_path = self.directory / 'manifest-descriptor.json'
        output_path = self.directory / 'container-release.json'
        index_path.write_text(json.dumps(image_index()), encoding='utf-8')
        descriptor_path.write_text(json.dumps(descriptor()), encoding='utf-8')
        for args, stage in ((['prepare', str(input_dir), '--image', IMAGE, '--commit', COMMIT,
                             '--output', str(merge_path)], 'prepare'),
                            (['verify', str(merge_path), str(index_path), str(descriptor_path),
                              '--output', str(output_path)], 'verify')):
            stream = io.StringIO()
            with redirect_stdout(stream):
                self.assertEqual(main(args), 0)
            self.assertEqual(stream.getvalue(), 'CONTAINER_MERGE: stage=' + stage + ' platforms=3 result=OK\n')
        self.assertEqual(read_json(merge_path), merge_input())
        self.assertEqual(read_json(output_path)['digest'], IMAGE + '@sha256:' + 'f' * 64)
        self.assertEqual(list(self.directory.glob('*.tmp')), [])

    def test_cli_invalid_input_does_not_overwrite_existing_output(self):
        input_dir = self.write_releases(releases()[:2])
        output_path = self.directory / 'merge-input.json'
        output_path.write_text('existing-evidence', encoding='utf-8')
        stream = io.StringIO()
        with redirect_stdout(stream):
            status = main(['prepare', str(input_dir), '--image', IMAGE, '--commit', COMMIT,
                           '--output', str(output_path)])
        self.assertEqual(status, 2)
        self.assertEqual(stream.getvalue(), 'CONTAINER_MERGE: stage=prepare result=ERROR invalid_release=YES\n')
        self.assertEqual(output_path.read_text(), 'existing-evidence')

    def test_cli_verify_rejects_invalid_index_and_overwriting_input(self):
        merge_path = self.directory / 'merge-input.json'
        index_path = self.directory / 'manifest-index.json'
        descriptor_path = self.directory / 'manifest-descriptor.json'
        merge_path.write_text(json.dumps(merge_input()))
        index_path.write_text('{}')
        descriptor_path.write_text(json.dumps(descriptor()))
        output_path = self.directory / 'container-release.json'
        for target in (output_path, merge_path):
            stream = io.StringIO()
            with redirect_stdout(stream):
                status = main(['verify', str(merge_path), str(index_path), str(descriptor_path),
                               '--output', str(target)])
            self.assertEqual(status, 2)
            self.assertEqual(stream.getvalue(), 'CONTAINER_MERGE: stage=verify result=ERROR invalid_release=YES\n')
        self.assertFalse(output_path.exists())
        self.assertEqual(read_json(merge_path), merge_input())


if __name__ == '__main__':
    unittest.main()
