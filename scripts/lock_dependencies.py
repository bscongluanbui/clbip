"""Rebuild Python locks from official PyPI metadata for Linux CPython 3.12.

Default: preserve direct versions. --upgrade explicitly adopts latest direct versions.
Run in a development venv with pip (its vendored packaging is sufficient).
"""
import argparse
import json
import urllib.request
from pathlib import Path
try:
    from packaging.requirements import Requirement
    from packaging.version import Version
    from packaging.specifiers import SpecifierSet
    from packaging.markers import default_environment
except ImportError:
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.version import Version
    from pip._vendor.packaging.specifiers import SpecifierSet
    from pip._vendor.packaging.markers import default_environment

DIRECT = {'Flask': '3.1.3', 'requests': '2.34.2', 'pyTelegramBotAPI': '4.37.0', 'gunicorn': '26.2.0'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upgrade', action='store_true')
    args = parser.parse_args()
    env = default_environment()
    env.update(python_version='3.12', python_full_version='3.12.12', sys_platform='linux',
               platform_system='Linux', os_name='posix', extra='')
    def get(name, version=None):
        url = 'https://pypi.org/pypi/' + name + ('/' + version if version else '') + '/json'
        with urllib.request.urlopen(url, timeout=30) as stream: return json.load(stream)
    queue = [Requirement(name if args.upgrade else name + '==' + version) for name, version in DIRECT.items()]
    resolved, constraints = {}, {}
    while queue:
        requirement = queue.pop(0)
        if requirement.marker and not requirement.marker.evaluate(env): continue
        key = requirement.name.lower().replace('_', '-')
        constraints.setdefault(key, []).append(requirement.specifier)
        if key in resolved:
            if not all(resolved[key]['info']['version'] in spec for spec in constraints[key]):
                raise RuntimeError('Dependency conflict: ' + key + '; resolve before writing a new lock')
            continue
        data = get(requirement.name)
        if not all(data['info']['version'] in spec for spec in constraints[key]) or not SpecifierSet(data['info']['requires_python'] or '').contains('3.12.12'):
            options = sorted((Version(version) for version, files in data['releases'].items()
                if files and not Version(version).is_prerelease and all(version in spec for spec in constraints[key])
                and any(SpecifierSet(file['requires_python'] or '').contains('3.12.12') and not file.get('yanked') for file in files)), reverse=True)
            if not options: raise RuntimeError('No compatible version: ' + key)
            data = get(requirement.name, str(options[0]))
        resolved[key] = data
        queue.extend(Requirement(value) for value in data['info']['requires_dist'] or [])
    lines = ['# Generated from official PyPI JSON; Linux CPython 3.12; update with scripts/lock_dependencies.py.',
             '# Every direct and transitive package is version- and SHA256-pinned.']
    provenance = {'target': 'Linux CPython 3.12', 'packages': []}
    for key, data in sorted(resolved.items()):
        info, artifacts = data['info'], data['urls']
        hashes = sorted({artifact['digests']['sha256'] for artifact in artifacts if not artifact.get('yanked')})
        if not hashes: raise RuntimeError('No artifact hashes: ' + key)
        lines.append(info['name'] + '==' + info['version'] + ' \\')
        lines.extend('    --hash=sha256:' + digest + (' \\' if i < len(hashes)-1 else '') for i, digest in enumerate(hashes))
        provenance['packages'].append({'name': info['name'], 'version': info['version'],
            'metadata_url': 'https://pypi.org/pypi/' + info['name'] + '/' + info['version'] + '/json',
            'artifacts': [{'filename': artifact['filename'], 'sha256': artifact['digests']['sha256'], 'url': artifact['url']} for artifact in artifacts]})
    sbom_path = Path('docs/sbom.cdx.json')
    sbom = json.loads(sbom_path.read_text(encoding='utf-8')) if sbom_path.exists() else {'bomFormat':'CycloneDX', 'specVersion':'1.5', 'version':1}
    previous = [component for component in sbom.get('components', []) if not component.get('purl', '').startswith('pkg:pypi/')]
    packages = [{'type':'library', 'name':data['info']['name'], 'version':data['info']['version'], 'purl':'pkg:pypi/'+key+'@'+data['info']['version']} for key, data in sorted(resolved.items())]
    sbom['components'] = packages + previous
    sbom_path.write_text(json.dumps(sbom, indent=2) + '\n', encoding='utf-8')
    Path('requirements.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    Path('docs/dependency-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    print('Locked', len(resolved), 'packages. Verify with pip download --require-hashes before deployment.')


if __name__ == '__main__': main()
