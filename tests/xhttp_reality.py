"""Run against a local Subconverter: python3 tests/xhttp_reality.py [--mihomo PATH].

Requires PyYAML. Only synthetic nodes are used; Mihomo's -t does not dial them.
"""

import argparse
import base64
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlencode
from urllib.request import urlopen

import yaml


UUID = '12345678-1234-4234-8234-123456789abc'
PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip('=')
HOST = 'transport.example.com'
SNI = 'tls.example.com'
SOURCE = f'''\
proxies:
  - name: round-trip
    type: vless
    server: server.example.com
    port: 443
    uuid: {UUID}
    tls: true
    client-fingerprint: chrome
    servername: {SNI}
    network: xhttp
    xhttp-opts:
      host: {HOST}
      path: /keep%2Fencoded
      mode: auto
      x-padding-bytes: 100-1000
      no-grpc-header: false
      headers:
        X-Number: "001"
        X-Flag: "true"
      reuse-settings:
        max-connections: "1-2"
        h-keep-alive-period: 30
      future-option: [true, "true", 1, "001"]
    reality-opts:
      public-key: {PUBLIC_KEY}
      short-id: "001234"
      support-x25519mlkem768: true
  - name: no-host
    type: vless
    server: server.example.com
    port: 443
    uuid: {UUID}
    tls: true
    client-fingerprint: chrome
    servername: {SNI}
    network: xhttp
    xhttp-opts: {{path: /, headers: {{X-Example: kept}}}}
    reality-opts: {{public-key: {PUBLIC_KEY}, short-id: "012345", support-x25519mlkem768: false}}
  - name: absent-opts
    type: vless
    server: server.example.com
    port: 443
    uuid: {UUID}
    tls: true
    client-fingerprint: chrome
    servername: {SNI}
    network: xhttp
    reality-opts: {{public-key: {PUBLIC_KEY}}}
  - name: ws-reality
    type: vless
    server: server.example.com
    port: 443
    uuid: {UUID}
    tls: true
    client-fingerprint: chrome
    servername: {SNI}
    network: ws
    ws-opts: {{path: /ws, headers: {{Host: {HOST}}}}}
    reality-opts: {{public-key: {PUBLIC_KEY}, short-id: ""}}
'''


def convert(base_url, source, node_list):
    query = urlencode({'target': 'clash', 'url': source, 'new_name': 'true',
                       'list': str(node_list).lower()})
    with urlopen(f'{base_url.rstrip("/")}/sub?{query}', timeout=15) as response:
        return response.read().decode()


def check_yaml_options(proxies):
    expected = yaml.safe_load(SOURCE)['proxies']
    assert len(proxies) == len(expected)
    for actual, original in zip(proxies, expected):
        assert actual['servername'] == SNI, actual
        assert actual.get('xhttp-opts') == original.get('xhttp-opts'), actual
        reality = original['reality-opts'].copy()
        if not reality.get('short-id'):
            reality.pop('short-id', None)
        assert actual['reality-opts'] == reality, actual
    assert 'xhttp-opts' not in proxies[2], proxies[2]
    assert proxies[0]['reality-opts']['support-x25519mlkem768'] is True
    assert proxies[1]['reality-opts']['support-x25519mlkem768'] is False
    assert proxies[0]['xhttp-opts']['no-grpc-header'] is False
    assert type(proxies[0]['xhttp-opts']['reuse-settings']['h-keep-alive-period']) is int
    assert proxies[3]['ws-opts']['headers']['Host'] == HOST, proxies[3]


def check_link(base_url, node_list, with_host, mlkem, uri_sid):
    uri_sni = 'uri-tls.example.com'
    params = {'type': 'xhttp', 'security': 'reality', 'sni': uri_sni, 'pbk': PUBLIC_KEY,
              'sid': uri_sid, 'fp': 'chrome', 'path': '/xhttp', 'mode': 'auto', 'spx': '/spider',
              'extra': json.dumps({'xPaddingKey': '001', 'noGRPCHeader': False,
                                   'xPaddingBytes': '100-1000'}),
              'x_padding_bytes': '100-1000'}
    if with_host:
        params['host'] = HOST
    if mlkem is not None:
        params['support-x25519mlkem768'] = str(mlkem).lower()
    link = f'vless://{UUID}@server.example.com:443?{urlencode(params)}&x-padding-key=%30%30%31#uri'
    output = convert(base_url, link, node_list)
    assert f'short-id: "{uri_sid}"' in output, output
    assert '!<tag:yaml.org,2002:str>' not in output, output
    proxy, = yaml.safe_load(output)['proxies']
    assert proxy['servername'] == uri_sni, proxy
    options = proxy['xhttp-opts']
    if with_host:
        assert options['host'] == HOST, options
    else:
        assert 'host' not in options, options
    assert options['path'] == '/xhttp' and options['mode'] == 'auto', options
    assert options['x-padding-key'] == '001' and options['no-grpc-header'] is False, options
    assert options['x-padding-bytes'] == '100-1000', options
    reality = {'public-key': PUBLIC_KEY, 'short-id': uri_sid}
    if mlkem is not None:
        reality['support-x25519mlkem768'] = mlkem
        assert proxy['reality-opts']['support-x25519mlkem768'] is mlkem, proxy
    assert proxy['reality-opts'] == reality, proxy
    return output


def check_subscription_ids(base_url, node_list):
    # Same server, UUID and public key; only the names and SIDs differ.
    cases = {
        'sid-72': ('&sid=72', '72'),
        'sid-missing': ('', None),
        'sid-leading-zeros': ('&sid=001234', '001234'),
        'sid-empty': ('&sid=', None),
        'sid-hex': ('&sid=ABcdef', 'ABcdef'),
        'sid-encoded': ('&sid=%30%30%37%32', '0072'),
        'sid-nested-only': ('&spx=/search?sid=72', None),
        'sid-with-nested': ('&sid=0099&spx=/search?sid=72', '0099'),
    }
    params = urlencode({'type': 'xhttp', 'security': 'reality', 'sni': SNI,
                        'pbk': PUBLIC_KEY, 'support-x25519mlkem768': 'true'})
    links = [f'vless://{UUID}@server.example.com:443?{params}{query}#{name}'
             for name, (query, _) in cases.items()]
    payload = base64.b64encode('\n'.join(links).encode()).decode()
    source = 'data:text/plain;base64,' + base64.b64encode(payload.encode()).decode()
    output = convert(base_url, source, node_list)
    proxies = yaml.safe_load(output)['proxies']
    assert len(proxies) == len(cases), proxies
    by_name = {proxy['name']: proxy['reality-opts'] for proxy in proxies}
    for name, (_, sid) in cases.items():
        expected = {'public-key': PUBLIC_KEY, 'support-x25519mlkem768': True}
        if sid is not None:
            expected['short-id'] = sid
        assert by_name[name] == expected, (name, by_name[name], expected)
    return output


def check_subscription_public_keys(base_url, node_list):
    alternate = base64.urlsafe_b64encode(bytes(reversed(range(1, 33)))).decode().rstrip('=')
    encoded = f'%{ord(PUBLIC_KEY[0]):02X}{PUBLIC_KEY[1:]}'
    cases = {
        'first-key': (f'pbk={PUBLIC_KEY}', PUBLIC_KEY),
        'second-key': (f'pbk={alternate}', alternate),
        'encoded-key': (f'pbk={encoded}', PUBLIC_KEY),
        'nested-key': (f'pbk={PUBLIC_KEY}&spx=/search?pbk={alternate}', PUBLIC_KEY),
        'no-key': (f'spx=/search?pbk={alternate}', None),
    }
    links = [f'vless://{UUID}@server.example.com:443?type=tcp&security=reality&sid=001234&{query}#{name}'
             for name, (query, _) in cases.items()]
    payload = base64.b64encode('\n'.join(links).encode())
    source = 'data:text/plain;base64,' + base64.b64encode(payload).decode()
    output = convert(base_url, source, node_list)
    proxies = yaml.safe_load(output)['proxies']
    assert len(proxies) == len(cases), proxies
    by_name = {proxy['name']: proxy['reality-opts'] for proxy in proxies}
    for name, (_, key) in cases.items():
        expected = {'short-id': '001234'}
        if key is not None:
            expected['public-key'] = key
        assert by_name[name] == expected, (name, by_name[name], expected)


def validate_mihomo(executable, output):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'config.yaml'
        path.write_text(output, encoding='utf-8')
        result = subprocess.run([executable, '-t', '-d', directory, '-f', str(path)],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:25500')
    parser.add_argument('--mihomo', help='Path to the Mihomo validator (optional)')
    args = parser.parse_args()
    source = 'data:text/yaml;base64,' + base64.b64encode(SOURCE.encode()).decode()
    for node_list in (False, True):
        output = convert(args.url, source, node_list)
        assert 'short-id: "001234"' in output, output
        assert '!<tag:yaml.org,2002:str>' not in output, output
        check_yaml_options(yaml.safe_load(output)['proxies'])
        link_outputs = [check_link(args.url, node_list, with_host, mlkem, sid)
                        for with_host, mlkem, sid in ((True, True, '72'), (True, False, '003344'),
                                                     (False, None, 'abcd'))]
        subscription_output = check_subscription_ids(args.url, node_list)
        check_subscription_public_keys(args.url, node_list)
        if args.mihomo:
            for config in [output, *link_outputs, subscription_output]:
                validate_mihomo(args.mihomo, config)
    print('XHTTP / Reality regression checks passed (full config and node list).')


if __name__ == '__main__':
    main()
