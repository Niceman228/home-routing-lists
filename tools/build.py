"""Build data-only sing-box policy, preserving first-match exceptions."""
import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/'
SERVICES = {'geoblock': 'Categories/geoblock.lst', 'block': 'Categories/block.lst',
            'news': 'Categories/news.lst', **{x: f'Services/{x}.lst' for x in
            ('google_ai', 'discord', 'telegram', 'meta', 'twitter', 'youtube')}}

def domain(value, tld=False):
    value = value.strip().lower().removeprefix('*.').lstrip('.').rstrip('.')
    value = value.encode('idna').decode('ascii')
    labels = value.split('.')
    if (not tld and len(labels) < 2) or len(value) > 253 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels
    ) or re.fullmatch(r'[0-9.]+', value):
        raise ValueError('Invalid domain: ' + value)
    return value

def domains(text, community=False):
    result = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        # Broad upstream TLD entries require an explicit regional rule instead.
        if community and '.' not in line.lstrip('.'):
            continue
        result.add(domain(line))
    return sorted(result)

def negate(rule):
    return {**rule, 'invert': not rule.get('invert', False)}

def combine(mode, rules):
    if len(rules) == 1:
        return rules[0]
    return {'type': 'logical', 'mode': mode, 'rules': rules}

def effective(branches, wanted, default):
    prior, result = [], []
    for action, match in branches:
        if action == wanted:
            result.append(combine('and', [match, *[negate(x) for x in prior]]))
        prior.append(match)
    if default == wanted:
        result.append(combine('and', [negate(x) for x in prior]) if prior else {'ip_cidr': ['0.0.0.0/0']})
    return {'version': 3, 'rules': result}

def compile_policy(policy, manual, service_domains, country):
    assert policy['schema'] == 1
    assert policy['default'] in ('direct', 'proxy')
    assert set(policy) <= {'schema', 'default', 'services', 'regions', 'zapret_ready'}
    branches = []
    # Explicit exceptions precede service categories and general region rules.
    for action in ('direct', 'proxy', 'zapret'):
        if manual[action]:
            branches.append((action, {'domain_suffix': manual[action]}))
    for item in policy['services']:
        assert set(item) == {'name', 'route'} and item['name'] in SERVICES
        assert item['route'] in ('direct', 'proxy', 'zapret')
        values = service_domains[item['name']]
        if values:
            branches.append((item['route'], {'domain_suffix': values}))
    intercept = []
    seen_geoip = False
    for item in policy['regions']:
        assert set(item) == {'match', 'route'}
        assert item['route'] in ('direct', 'proxy', 'zapret')
        match = item['match']
        assert len(match) == 1 and next(iter(match)) in ('domain_suffix', 'geoip')
        if 'domain_suffix' in match:
            assert not seen_geoip, 'Place domain regions before GeoIP regions'
            rule = {'domain_suffix': sorted({domain(x, tld=True) for x in match['domain_suffix']})}
        else:
            seen_geoip = True
            assert item['route'] != 'zapret', 'GeoIP -> zapret is unsupported; use domain rules'
            ips = []
            for code in match['geoip']:
                assert re.fullmatch('[A-Z]{2}', code)
                ips.extend(country(code))
            ips = list(ipaddress.collapse_addresses(ips))
            rule = {'ip_cidr': [str(x) for x in ips]}
            if item['route'] == 'proxy':
                intercept.extend(ips)
        branches.append((item['route'], rule))
    zaps = []
    for action, match in branches:
        if action == 'zapret':
            zaps.extend(match['domain_suffix'])
    assert not zaps or policy.get('zapret_ready') is True, 'zapret has not been verified; keep these services in proxy'
    # Purely redundant tail rules do not change first-match routing.
    while branches and branches[-1][0] == policy['default']:
        branches.pop()
    proxy = effective(branches, 'proxy', policy['default'])
    if policy['default'] == 'proxy':
        intercept = [ipaddress.ip_network('0.0.0.0/0')]
    # FakeIP DNS must use only domain conditions, never destination GeoIP.
    # Domain branches are ordered identically; IP classification happens on real IPs.
    dns_branches = [(a, m) for a, m in branches if 'domain_suffix' in m]
    dns = effective(dns_branches, 'proxy', 'direct')
    proxied_domains = sorted({d for a, m in branches if a == 'proxy' for d in m.get('domain_suffix', [])})
    return {'schema': 2, 'default': policy['default'], 'proxy_rules': proxy,
            'proxy_dns': dns, 'intercept_v4': [str(x) for x in ipaddress.collapse_addresses(intercept)],
            'zapret_domains': sorted(set(zaps)), 'proxy_domains': proxied_domains,
            'direct_domains': manual['direct'], 'zapret_ready': bool(policy.get('zapret_ready'))}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--offline', action='store_true')
    args = ap.parse_args()
    cache = ROOT / '.cache'
    cache.mkdir(exist_ok=True)
    provenance = []
    def fetch(url, name):
        path = cache / name
        if not args.offline:
            req = urllib.request.Request(url, headers={'User-Agent': 'home-routing-lists/1'})
            with urllib.request.urlopen(req, timeout=45) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError('Source too large')
            path.write_bytes(data)
        data = path.read_bytes()
        provenance.append({'url': url, 'sha256': hashlib.sha256(data).hexdigest()})
        return data.decode('utf-8-sig')
    policy = json.loads((ROOT / 'rules.json').read_text(encoding='utf-8'))
    manual = {a: domains((ROOT/'lists'/f'{a}.txt').read_text(encoding='utf-8')) for a in ('direct', 'proxy', 'zapret')}
    services = {x['name']: domains(fetch(BASE + SERVICES[x['name']], x['name'] + '.txt'), True) for x in policy['services']}
    def country(code):
        text = fetch(f'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/{code.lower()}.list', f'geoip-{code}.txt')
        nets = [ipaddress.ip_network(x.strip()) for x in text.splitlines() if x.strip() and not x.startswith('#')]
        nets = [x for x in nets if x.version == 4]
        if not nets:
            raise ValueError('Empty GeoIP country: ' + code)
        return nets
    bundle = compile_policy(policy, manual, services, country)
    dist = ROOT/'dist'
    dist.mkdir(exist_ok=True)
    (dist/'bundle.json').write_text(json.dumps(bundle, ensure_ascii=True, separators=(',', ':')) + '\n', encoding='utf-8')
    (dist/'sources.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    for name in ('proxy_rules', 'proxy_dns'):
        (dist/(name.replace('_', '-')+'.json')).write_text(json.dumps(bundle[name], separators=(',', ':'))+'\n', encoding='utf-8')
    print(f'Built: {len(bundle["proxy_domains"])} proxy suffixes, {len(bundle["intercept_v4"])} IPv4 capture ranges; default={policy["default"]}')

if __name__ == '__main__':
    main()
