"""Bounded, credential-redacted HTTP/SOCKS5 source-probe count matrix.

Counts select existing listener records; this tool never provisions proxies.
Every sample opens a fresh curl process/connection. It measures source-probe
latency, not bandwidth or a promise of supported production capacity.
"""
import argparse
import collections
import concurrent.futures
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import time
from urllib.parse import urlparse

import requests


DEFAULT_COUNTS = [25, 50, 100, 200]
MAX_TOTAL_SAMPLES = 100000
HEALTH_LIMIT = 1024 * 1024


def _clean_text(value, limit=2048):
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValueError('Invalid text field')
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ValueError('URL fields must contain printable ASCII without spaces')
    return value


def _hostname(host):
    if not host or '%' in host:
        raise ValueError('Invalid host')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('Invalid host') from None
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
            raise ValueError('Invalid host')
        return host.lower()


def validate_probe_url(url):
    parsed = urlparse(_clean_text(url))
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.port not in (None, 443)):
        raise ValueError('Probe must be HTTPS port 443 without credentials or fragment')
    host = _hostname(parsed.hostname)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return url
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError('Probe literal address must be public unicast')
    return url


def validate_proxies(records):
    if not isinstance(records, list) or not 1 <= len(records) <= 1024:
        raise ValueError('Provide 1..1024 configured listener records')
    result, endpoints = [], set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {'url', 'expected_ipv6'}:
            raise ValueError('Each listener needs exactly url and expected_ipv6')
        url = _clean_text(record['url'])
        parsed = urlparse(url)
        if (parsed.scheme not in ('http', 'socks5h') or not parsed.hostname
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.path not in ('', '/') or parsed.params or parsed.query or parsed.fragment):
            raise ValueError('Proxy must be http://host:port or socks5h://host:port')
        if (parsed.username is None) != (parsed.password is None):
            raise ValueError('Proxy credentials require both username and password')
        if parsed.username == '' or parsed.password == '':
            raise ValueError('Proxy credentials must be nonempty')
        host = _hostname(parsed.hostname)
        endpoint = f'[{host}]:{parsed.port}' if ':' in host else f'{host}:{parsed.port}'
        if endpoint in endpoints:
            raise ValueError('Duplicate listener endpoint')
        endpoints.add(endpoint)
        value = _clean_text(record['expected_ipv6'], 45)
        expected = ipaddress.IPv6Address(value)
        if expected.ipv4_mapped or '%' in value:
            raise ValueError('Expected source must be native IPv6 without scope')
        result.append({'url': url, 'expected_ipv6': str(expected),
                       'endpoint': endpoint, 'protocol': parsed.scheme})
    return result


def parse_counts(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+(?:,\d+)*', value):
        raise ValueError('Counts must be a comma-separated increasing integer list')
    counts = [int(item) for item in value.split(',')]
    if not 1 <= len(counts) <= 16 or any(not 1 <= item <= 1024 for item in counts):
        raise ValueError('Use 1..16 counts, each 1..1024')
    if counts != sorted(set(counts)):
        raise ValueError('Counts must be strictly increasing without duplicates')
    return counts


def validate_health_url(url):
    parsed = urlparse(_clean_text(url))
    if (parsed.scheme not in ('http', 'https') or parsed.username is not None
            or parsed.password is not None or parsed.fragment or parsed.query
            or parsed.path != '/api/proxy/health' or parsed.port not in range(1, 65536)):
        raise ValueError('Health URL must be an explicit loopback /api/proxy/health URL and port')
    try:
        address = ipaddress.ip_address(parsed.hostname or '')
    except ValueError:
        raise ValueError('Health URL requires a literal loopback IP, not DNS') from None
    if not address.is_loopback or '%' in (parsed.hostname or ''):
        raise ValueError('Service token is sent only to loopback health')
    return url


def _metric_number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _states(value):
    if not isinstance(value, dict):
        return None
    return {key: _metric_number(count) for key, count in value.items()
            if isinstance(key, str) and re.fullmatch(r'[A-Z_]{1,24}', key)}


def project_health(payload):
    """Whitelist observations; never copy credentials, errors or arbitrary JSON."""
    if not isinstance(payload, dict) or not isinstance(payload.get('metrics'), dict):
        raise ValueError('Health response is missing metrics')
    source = payload['metrics']
    metrics = {}
    for group, fields in [('worker', ('rss_bytes', 'fd_count')),
                          ('proxy_children', ('rss_bytes', 'fd_count', 'process_count'))]:
        observed = source.get(group)
        observed = observed if isinstance(observed, dict) else {}
        metrics[group] = {field: _metric_number(observed.get(field)) for field in fields}
    ndp = source.get('ndp')
    ndp = ndp if isinstance(ndp, dict) else {}
    interfaces = ndp.get('interfaces')
    metrics['ndp'] = {'neighbor_count': _metric_number(ndp.get('neighbor_count')),
                      'states': _states(ndp.get('states')), 'interfaces': {}}
    if isinstance(interfaces, dict):
        for iface, observation in list(interfaces.items())[:1024]:
            if isinstance(iface, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', iface) and isinstance(observation, dict):
                metrics['ndp']['interfaces'][iface] = {
                    'neighbor_count': _metric_number(observation.get('neighbor_count')),
                    'states': _states(observation.get('states'))}
    complete = (all(value is not None for group in ('worker', 'proxy_children') for value in metrics[group].values())
                and metrics['ndp']['neighbor_count'] is not None and metrics['ndp']['states'] is not None)
    return {'ok': True, 'ready': payload.get('ready') is True,
            'desired_state': payload.get('desired_state') if payload.get('desired_state') in ('running', 'stopped') else None,
            'active_proxy_count': _metric_number(payload.get('proxy_count')),
            'active_service_count': _metric_number(payload.get('service_count')),
            'metrics_complete': complete, 'metrics': metrics}


def health_snapshot(url, token):
    session = requests.Session()
    session.trust_env = False
    response = None
    try:
        response = session.get(url, headers={'Authorization': 'Bearer ' + token},
                               timeout=(3, 10), allow_redirects=False, stream=True)
        if not 200 <= response.status_code < 300:
            return {'ok': False, 'error_type': 'HealthHTTP', 'http_status': response.status_code}
        chunks, size = [], 0
        for chunk in response.iter_content(chunk_size=16384):
            size += len(chunk)
            if size > HEALTH_LIMIT:
                return {'ok': False, 'error_type': 'HealthResponseTooLarge'}
            chunks.append(chunk)
        return project_health(json.loads(b''.join(chunks)))
    except Exception as error:
        # Exception text can include request headers or URLs: keep only the type.
        return {'ok': False, 'error_type': type(error).__name__}
    finally:
        if response is not None:
            response.close()
        session.close()


def sample(proxy, url):
    started = time.monotonic()
    config = 'proxy = ' + json.dumps(proxy, ensure_ascii=True) + '\n'
    command = ['curl', '--disable', '--config', '-', '--silent', '--fail', '--globoff',
               '--proto', '=https', '--proto-redir', '=https', '--noproxy', '',
               '--connect-timeout', '5', '--max-time', '15', '--max-redirs', '0',
               '--max-filesize', '4096', '--socks5-basic', '--write-out', '\n%{http_code}', '--url', url]
    environment = {key: value for key, value in os.environ.items()
                   if not key.lower().endswith('_proxy') and key not in ('CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR')}
    try:
        # Curl's output never enters a shell; a private temporary file bounds RAM.
        with tempfile.TemporaryFile(mode='w+b') as output:
            completed = subprocess.run(command, input=config.encode('ascii'), stdout=output,
                                       stderr=subprocess.DEVNULL, timeout=20, env=environment, check=False)
            output.seek(0)
            raw = output.read(4097)
        if completed.returncode != 0:
            result = {'ok': False, 'error_type': 'CurlError', 'curl_exit': completed.returncode}
        elif len(raw) > 4096:
            result = {'ok': False, 'error_type': 'ResponseTooLarge'}
        else:
            body, status = raw.decode('ascii').rsplit('\n', 1)
            if not status.isdigit() or not 200 <= int(status) < 300:
                result = {'ok': False, 'error_type': 'ProbeHTTP'}
            else:
                address = ipaddress.IPv6Address(body.strip())
                if '%' in body or address.ipv4_mapped:
                    raise ValueError('Invalid native source response')
                result = {'ok': True, 'source': str(address)}
    except Exception as error:
        result = {'ok': False, 'error_type': type(error).__name__}
    result['latency_ms'] = round((time.monotonic() - started) * 1000, 2)
    return result


def summarize(samples):
    times = sorted(item['latency_ms'] for item in samples if item['ok'])
    matches = sum(item.get('source_matches') is True for item in samples)
    failures = sum(not item['ok'] for item in samples)
    mismatches = len(samples) - matches - failures
    errors = collections.Counter(item.get('error_type', 'SourceMismatch') for item in samples if not item.get('source_matches'))
    return {'sample_count': len(samples), 'success_count': len(samples) - failures,
            'source_match_count': matches, 'source_mismatch_count': mismatches,
            'request_error_count': failures, 'error_rate': (len(samples) - matches) / len(samples) if samples else None,
            'p50_ms': statistics.median(times) if times else None,
            'p95_ms': times[math.ceil(len(times) * .95) - 1] if times else None,
            'error_types': dict(errors)}


def run_matrix(proxies, url, counts, rounds=5, concurrency=4, health=None, continue_on_error=False):
    if not counts or counts != sorted(set(counts)) or any(not 1 <= count <= len(proxies) for count in counts):
        raise ValueError('Every count must be available, unique and increasing')
    if not 1 <= rounds <= 100 or not 1 <= concurrency <= 32 or sum(counts) * rounds > MAX_TOTAL_SAMPLES:
        raise ValueError('rounds=1..100, total concurrency=1..32, samples<=100000')
    report = {'schema_version': 2, 'probe_url': url, 'count_mode': 'participating_listener_records',
              'available_listener_count': len(proxies), 'counts': counts, 'rounds': rounds,
              'total_concurrency': concurrency, 'connection_reuse': False,
              'metrics_requested': health is not None, 'stages': [], 'unrun_counts': []}
    for index, count in enumerate(counts):
        stage = {'participating_listener_count': count, 'health_before': health() if health else None}
        report['stages'].append(stage)
        if health and (not stage['health_before'].get('ok') or not stage['health_before'].get('ready')
                       or stage['health_before'].get('desired_state') != 'running'):
            stage.update({'ok': False, 'samples': [], 'endpoints': [], 'error_type': 'HealthPreflight'})
            report['unrun_counts'] = counts[index + 1:]
            break
        started = time.monotonic()
        selected = proxies[:count]
        # Round-major order reaches the whole selected set; one global pool caps
        # traffic across all listeners, unlike a separate pool per listener.
        jobs = ((proxy_index, round_index) for round_index in range(rounds) for proxy_index in range(count))
        def perform(job):
            proxy_index, round_index = job
            proxy = selected[proxy_index]
            observation = sample(proxy['url'], url)
            observation['source_matches'] = observation['ok'] and observation.get('source') == proxy['expected_ipv6']
            observation.update({'listener_index': proxy_index, 'round': round_index + 1})
            return observation
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            observations = list(pool.map(perform, jobs))
        stage.update(summarize(observations))
        stage['duration_ms'] = round((time.monotonic() - started) * 1000, 2)
        stage['samples'] = observations
        stage['endpoints'] = []
        for proxy_index, proxy in enumerate(selected):
            entry = {key: proxy[key] for key in ('endpoint', 'protocol', 'expected_ipv6')}
            entry.update(summarize([item for item in observations if item['listener_index'] == proxy_index]))
            stage['endpoints'].append(entry)
        stage['health_after'] = health() if health else None
        stage['ok'] = stage['source_match_count'] == count * rounds
        if health:
            stage['ok'] = (stage['ok'] and stage['health_after'].get('ok') is True
                           and stage['health_after'].get('ready') is True
                           and stage['health_after'].get('desired_state') == 'running')
        if not stage['ok'] and not continue_on_error:
            report['unrun_counts'] = counts[index + 1:]
            break
    report['ok'] = not report['unrun_counts'] and all(stage['ok'] for stage in report['stages'])
    report['metrics_complete'] = bool(health) and all(
        (stage.get(key) or {}).get('metrics_complete') is True for stage in report['stages'] for key in ('health_before', 'health_after'))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proxies', required=True, help='Owner-only JSON list: {url, expected_ipv6}')
    parser.add_argument('--probe-url', default='https://api64.ipify.org')
    parser.add_argument('--counts', default=','.join(map(str, DEFAULT_COUNTS)), help='Increasing counts, e.g. 25,50,100,200 or 1,10')
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--concurrency', type=int, default=4, help='Total concurrent requests across all selected listeners')
    parser.add_argument('--health-url', help='Loopback management /api/proxy/health URL with explicit port')
    parser.add_argument('--token-file', help='Service token file; token never enters command arguments or output')
    parser.add_argument('--continue-on-error', action='store_true', help='Run later bounded stages even after a source mismatch')
    parser.add_argument('--output', default='benchmark-result.json')
    args = parser.parse_args(argv)
    try:
        url = validate_probe_url(args.probe_url)
        proxies = validate_proxies(json.loads(Path(args.proxies).read_text(encoding='utf-8')))
        counts = parse_counts(args.counts)
        if bool(args.health_url) != bool(args.token_file):
            raise ValueError('health-url and token-file must be used together')
        health = None
        if args.health_url:
            health_url = validate_health_url(args.health_url)
            token = Path(args.token_file).read_text(encoding='utf-8').strip()
            if not 32 <= len(token) <= 512 or not re.fullmatch(r'[A-Za-z0-9_-]+', token):
                raise ValueError('Invalid service token file')
            health = lambda: health_snapshot(health_url, token)
        target = Path(args.output)
        if target.resolve() in (Path(args.proxies).resolve(), Path(args.token_file).resolve() if args.token_file else None):
            raise ValueError('Output must not overwrite proxy or token input')
        report = run_matrix(proxies, url, counts, args.rounds, args.concurrency, health, args.continue_on_error)
    except (ValueError, KeyError, TypeError, OSError) as error:
        # JSON/URL parser exceptions may contain input: do not echo credentials.
        parser.error('Invalid benchmark configuration (' + type(error).__name__ + ')')
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Report:', target.resolve())
    print('Stages:', len(report['stages']), 'Source checks:', 'PASS' if report['ok'] else 'FAIL')
    if args.health_url and not report['metrics_complete']:
        print('Metrics: INCOMPLETE')
        return 2
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
