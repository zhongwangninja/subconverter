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
    reality-opts: {{public-key: {PUBLIC_KEY}, short-id: "001122"}}
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
    reality-opts: {{public-key: {PUBLIC_KEY}, short-id: "001122"}}
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
        assert actual['reality-opts'] == original['reality-opts'], actual
        assert type(actual['reality-opts']['short-id']) is str, actual
    assert 'xhttp-opts' not in proxies[2], proxies[2]
    assert proxies[0]['reality-opts']['support-x25519mlkem768'] is True
    assert proxies[1]['reality-opts']['support-x25519mlkem768'] is False
    assert proxies[0]['xhttp-opts']['no-grpc-header'] is False
    assert type(proxies[0]['xhttp-opts']['reuse-settings']['h-keep-alive-period']) is int
    assert proxies[3]['ws-opts']['headers']['Host'] == HOST, proxies[3]


def check_link(base_url, node_list, with_host, mlkem):
    uri_sni, uri_sid = 'uri-tls.example.com', '003344'
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
        check_yaml_options(yaml.safe_load(output)['proxies'])
        link_outputs = [check_link(args.url, node_list, with_host, mlkem)
                        for with_host, mlkem in ((True, True), (True, False), (False, None))]
        if args.mihomo:
            for config in [output, *link_outputs]:
                validate_mihomo(args.mihomo, config)
    print('XHTTP / Reality regression checks passed (full config and node list).')


if __name__ == '__main__':
    main()
