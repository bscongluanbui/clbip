"""Prepare and verify a three-platform container release without network access.

Architecture jobs supply immutable, tested image digests. The publish job may
merge only one release from each required platform, all from the same commit.
"""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile


PLATFORMS = ('linux/amd64', 'linux/arm64', 'linux/arm/v7')
INDEX_MEDIA_TYPES = {
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
}
SHA256 = re.compile(r'^sha256:[0-9a-f]{64}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
IMAGE = re.compile(r'^[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9][a-z0-9._/-]*$')
MAX_JSON_BYTES = 2 * 1024 * 1024


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError('Invalid JSON constant')


def read_json(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Symlink release input')
    payload = path.read_bytes()
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError('Release input is too large')
    return json.loads(payload.decode('utf-8'), object_pairs_hook=_object,
                      parse_constant=_invalid_constant)


def _identity(image, commit):
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise ValueError('Invalid repository image')
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError('Expected full commit SHA')


def _digest(value, image=None):
    if not isinstance(value, str):
        raise ValueError('Missing image digest')
    if image is not None:
        prefix = image + '@'
        if not value.startswith(prefix):
            raise ValueError('Digest repository mismatch')
        value = value[len(prefix):]
    if not SHA256.fullmatch(value):
        raise ValueError('Invalid SHA-256 digest')
    return value


def _architecture_records(records, image, commit):
    _identity(image, commit)
    if not isinstance(records, list) or len(records) != len(PLATFORMS):
        raise ValueError('Expected exactly three architecture releases')
    by_platform, digests = {}, set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError('Invalid architecture release')
        if record.get('image') != image or record.get('commit') != commit:
            raise ValueError('Architecture release identity mismatch')
        platform = record.get('platform')
        if platform not in PLATFORMS or platform in by_platform:
            raise ValueError('Unexpected or duplicate architecture')
        digest = record.get('digest')
        bare_digest = _digest(digest, image)
        if bare_digest in digests:
            raise ValueError('Duplicate architecture digest')
        digests.add(bare_digest)
        result = {'image': image, 'commit': commit, 'platform': platform,
                  'digest': digest}
        if 'image_id' in record:
            _digest(record['image_id'])
            result['image_id'] = record['image_id']
        if 'tags' in record:
            tags = record['tags']
            if not isinstance(tags, list) or any(
                not isinstance(tag, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', tag)
                for tag in tags
            ) or len(tags) != len(set(tags)):
                raise ValueError('Invalid architecture tags')
            result['tags'] = list(tags)
        by_platform[platform] = result
    return [by_platform[platform] for platform in PLATFORMS]


def prepare(input_dir, image, commit):
    """Validate all architecture artifacts and return immutable merge inputs."""
    _identity(image, commit)
    directory = Path(input_dir)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('Expected architecture artifact directory')
    paths = sorted(directory.rglob('container-release.json'))
    if len(paths) != len(PLATFORMS):
        raise ValueError('Expected exactly three release files')
    if any(parent.is_symlink() for path in paths for parent in path.parents
           if parent != directory.parent):
        raise ValueError('Symlink architecture artifact directory')
    records = _architecture_records([read_json(path) for path in paths], image, commit)
    return {'image': image, 'commit': commit,
            'refs': sorted(record['digest'] for record in records),
            'platforms': list(PLATFORMS), 'architectures': records}


def _index_platform(descriptor):
    if not isinstance(descriptor, dict) or not isinstance(descriptor.get('platform'), dict):
        raise ValueError('Missing index platform')
    platform = descriptor['platform']
    if platform.get('os') != 'linux':
        raise ValueError('Unexpected operating system')
    arch, variant = platform.get('architecture'), platform.get('variant')
    if arch == 'amd64' and variant in (None, ''):
        return 'linux/amd64'
    if arch == 'arm64' and variant in (None, '', 'v8'):
        return 'linux/arm64'
    if arch == 'arm' and variant == 'v7':
        return 'linux/arm/v7'
    raise ValueError('Unexpected architecture or variant')


def verify(merge_input, index, descriptor):
    """Verify that a registry index includes only the tested child manifests."""
    if not isinstance(merge_input, dict):
        raise ValueError('Invalid merge input')
    image, commit = merge_input.get('image'), merge_input.get('commit')
    records = _architecture_records(merge_input.get('architectures'), image, commit)
    expected_refs = sorted(record['digest'] for record in records)
    if merge_input.get('platforms') != list(PLATFORMS) or merge_input.get('refs') != expected_refs:
        raise ValueError('Merge input metadata mismatch')
    if not isinstance(index, dict) or index.get('schemaVersion') != 2:
        raise ValueError('Invalid image index schema')
    if index.get('mediaType') not in INDEX_MEDIA_TYPES:
        raise ValueError('Expected OCI index or Docker manifest list')
    manifests = index.get('manifests')
    if not isinstance(manifests, list) or len(manifests) != len(PLATFORMS):
        raise ValueError('Expected exactly three index manifests')
    expected = {record['platform']: _digest(record['digest'], image) for record in records}
    seen = set()
    for manifest in manifests:
        platform = _index_platform(manifest)
        if platform in seen:
            raise ValueError('Duplicate index platform')
        seen.add(platform)
        if _digest(manifest.get('digest')) != expected[platform]:
            raise ValueError('Untested index child digest')
    if seen != set(PLATFORMS):
        raise ValueError('Missing required index platform')
    if not isinstance(descriptor, dict):
        raise ValueError('Invalid manifest descriptor')
    if 'mediaType' in descriptor and descriptor['mediaType'] not in INDEX_MEDIA_TYPES:
        raise ValueError('Descriptor is not an image index')
    index_digest = _digest(descriptor.get('digest'))
    return {'image': image, 'digest': image + '@' + index_digest,
            'commit': commit, 'platforms': list(PLATFORMS),
            'architectures': records, 'tags': ['latest', 'sha-' + commit]}


def _write_json(path, record):
    """Replace metadata atomically; do not leave a partial publish contract."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Symlink release output')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         dir=path.parent, prefix='.' + path.name + '.',
                                         suffix='.tmp', delete=False) as output:
            temporary = Path(output.name)
            output.write(json.dumps(record, indent=2) + '\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='stage', required=True)
    preparation = commands.add_parser('prepare', help='Validate architecture release artifacts')
    preparation.add_argument('inputdir', type=Path)
    preparation.add_argument('--image', required=True)
    preparation.add_argument('--commit', required=True)
    preparation.add_argument('--output', required=True, type=Path)
    verification = commands.add_parser('verify', help='Validate the merged registry manifest')
    verification.add_argument('merge_input', type=Path)
    verification.add_argument('index_raw', type=Path)
    verification.add_argument('descriptor', type=Path)
    verification.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.stage == 'prepare':
            result = prepare(args.inputdir, args.image, args.commit)
        else:
            if args.output.resolve() in {args.merge_input.resolve(), args.index_raw.resolve(),
                                         args.descriptor.resolve()}:
                raise ValueError('Release output must not overwrite verification inputs')
            result = verify(read_json(args.merge_input), read_json(args.index_raw),
                            read_json(args.descriptor))
        _write_json(args.output, result)
    except (OSError, ValueError, TypeError, KeyError):
        print('CONTAINER_MERGE: stage=' + args.stage + ' result=ERROR invalid_release=YES')
        return 2
    print('CONTAINER_MERGE: stage=' + args.stage + ' platforms=3 result=OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
