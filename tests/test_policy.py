import copy
import ipaddress
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from build import compile_policy, domain

def matches(rule, host, ip):
    if rule.get('type') == 'logical':
        values = [matches(x, host, ip) for x in rule['rules']]
        ok = all(values) if rule['mode'] == 'and' else any(values)
    else:
        ok = any(host == d or host.endswith('.'+d) for d in rule.get('domain_suffix', []))
        ok |= any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in rule.get('ip_cidr', []))
    return not ok if rule.get('invert') else ok

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.p = {'schema': 1, 'default': 'proxy', 'zapret_ready': False,
                  'services': [{'name': 'youtube', 'route': 'proxy'}],
                  'regions': [{'match': {'domain_suffix': ['ru', 'рф']}, 'route': 'direct'},
                              {'match': {'geoip': ['RU']}, 'route': 'direct'}]}
        self.manual = {'direct': ['safe.example'], 'proxy': ['blocked.ru'], 'zapret': []}
        self.geo = lambda code: [ipaddress.ip_network('5.0.0.0/8')]
    def test_exceptions_country_and_foreign_default(self):
        b = compile_policy(self.p, self.manual, {'youtube': ['youtube.com']}, self.geo)
        cases = [('blocked.ru', '5.1.1.1', True), ('bank.ru', '8.8.8.8', False),
                 ('site.example', '5.1.1.1', False), ('foreign.example', '8.8.8.8', True),
                 ('youtube.com', '5.1.1.1', True), ('safe.example', '8.8.8.8', False),
                 ('notru.example', '8.8.8.8', True)]
        for host, ip, expected in cases:
            with self.subTest(host=host):
                self.assertEqual(any(matches(r, host, ip) for r in b['proxy_rules']['rules']), expected)
        self.assertEqual(b['intercept_v4'], ['0.0.0.0/0'])
        # Unknown domains retain real DNS answers for country decisions.
        self.assertFalse(any(matches(r, 'foreign.example', '8.8.8.8') for r in b['proxy_dns']['rules']))
    def test_nested_domain_exception_preserved(self):
        self.manual['direct'] = ['safe.youtube.com']
        b = compile_policy(self.p, self.manual, {'youtube': ['youtube.com']}, self.geo)
        self.assertFalse(any(matches(r, 'safe.youtube.com', '8.8.8.8') for r in b['proxy_rules']['rules']))
        self.assertTrue(any(matches(r, 'www.youtube.com', '8.8.8.8') for r in b['proxy_rules']['rules']))
    def test_geoip_proxy_captures_ips(self):
        self.p['default'] = 'direct'
        self.p['regions'] = [{'match': {'geoip': ['RU']}, 'route': 'proxy'}]
        b = compile_policy(self.p, self.manual, {'youtube': ['youtube.com']}, self.geo)
        self.assertEqual(b['intercept_v4'], ['5.0.0.0/8'])
        self.assertTrue(any(matches(r, 'other.example', '5.1.1.1') for r in b['proxy_rules']['rules']))
    def test_unverified_zapret_rejected(self):
        self.manual['zapret'] = ['blocked.example']
        with self.assertRaises(AssertionError):
            compile_policy(self.p, self.manual, {'youtube': []}, self.geo)
    def test_zapret_wins_service_but_respects_manual_exceptions(self):
        self.p['zapret_ready'] = True
        self.manual = {'direct': ['safe.youtube.com'], 'proxy': ['private.youtube.com'],
                       'zapret': ['youtube.com']}
        b = compile_policy(self.p, self.manual, {'youtube': ['youtube.com']}, self.geo)
        for host, wanted in [('www.youtube.com', True), ('safe.youtube.com', False),
                             ('private.youtube.com', False), ('unknown.example', False)]:
            self.assertEqual(any(matches(r, host, '8.8.8.8') for r in b['zapret_rules']['rules']), wanted)
        self.assertFalse(any(matches(r, 'www.youtube.com', '8.8.8.8') for r in b['proxy_rules']['rules']))
        self.assertTrue(any(matches(r, 'private.youtube.com', '8.8.8.8') for r in b['proxy_rules']['rules']))
        self.assertTrue(any(matches(r, 'www.youtube.com', '8.8.8.8') for r in b['proxy_dns']['rules']))
    def test_domain_normalization(self):
        self.assertEqual(domain('рф', tld=True), 'xn--p1ai')
        for value in ('bad;reboot.ru', '192.168.1.1', 'foo..ru', 'https://foo.ru'):
            with self.assertRaises((ValueError, UnicodeError)):
                domain(value)

if __name__ == '__main__':
    unittest.main()
