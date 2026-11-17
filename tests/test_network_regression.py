"""网络基础回归：本地 HTTP 服务和假 DNS，不访问外网。"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shlex
import tempfile
import threading
import unittest

from test_regression import shell, write


@contextmanager
def local_http(body):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class NetworkIsolationTests(unittest.TestCase):
    def test_direct_probe_ignores_environment_proxy(self):
        with local_http(b'direct') as (url, direct), local_http(b'proxy') as (proxy, proxied):
            result = shell(f'http {shlex.quote(url)}', env={
                'http_proxy': proxy, 'HTTP_PROXY': proxy, 'ALL_PROXY': proxy,
                'all_proxy': proxy, 'NO_PROXY': '', 'no_proxy': '',
            })
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'direct')
            self.assertEqual(len(direct), 1)
            self.assertEqual(proxied, [])

    def test_explicit_proxy_is_not_bypassed_by_no_proxy(self):
        with local_http(b'direct') as (url, direct), local_http(b'proxy') as (proxy, proxied):
            result = shell(f'PROXY={shlex.quote(proxy)}; http {shlex.quote(url)}',
                           env={'NO_PROXY': '*', 'no_proxy': '*'})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'proxy')
            self.assertEqual(len(proxied), 1)
            self.assertEqual(direct, [])

    def test_probe_does_not_read_curlrc(self):
        with tempfile.TemporaryDirectory() as folder, local_http(b'ok') as (url, requests):
            write(Path(folder) / '.curlrc', 'header = "X-Exitray-Config: loaded"\n')
            result = shell(f'http {shlex.quote(url)}', env={'CURL_HOME': folder})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'ok')
            self.assertEqual(len(requests), 1)
            self.assertNotIn('X-Exitray-Config', requests[0][1])


class AddressValidationTests(unittest.TestCase):
    def test_ipv4_rejects_out_of_range_and_ambiguous_octets(self):
        values = ['8.8.999.999', '256.1.1.1', '1.256.1.1', '1.1.256.1',
                  '1.1.1.256', '010.0.0.1', '8.008.8.8', '1.1.1.01',
                  '1.2.3', '1.2.3.4.5', '', 'example.com']
        for value in values:
            with self.subTest(value=value):
                result = shell(f'is_ipv4 {shlex.quote(value)}')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, '')
                result = shell(f'is_public_ipv4 {shlex.quote(value)}')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, '')

    def test_ipv4_accepts_all_octet_boundaries(self):
        for value in ['0.0.0.0', '255.255.255.255', '192.168.1.1', '8.8.8.8']:
            with self.subTest(value=value):
                self.assertEqual(shell(f'is_ipv4 {value}').returncode, 0)

    def test_invalid_echo_is_not_an_exit(self):
        for body in ['8.8.999.999', '010.0.0.1', '8.008.8.8']:
            with self.subTest(body=body):
                self.assertEqual(shell('extract plain', body).stdout, '')
        self.assertEqual(shell('extract youtube', '{"remoteHost":"1.2.3.4.5"}').stdout, '')


class DnsFallbackTests(unittest.TestCase):
    def test_doh_uses_fallback_if_google_has_no_valid_addresses(self):
        for answer in ['{"type":5,"data":"alias.example."}',
                       '{"type":1,"data":"8.8.999.999"}',
                       '{"type":1,"data":"1.2.3.4.5"}',
                       '{"type":6,"data":"ns.example. admin.example. 1 2 3 4 5"}']:
            with self.subTest(answer=answer):
                code = '''
                    http() {
                      case "$*" in
                        *dns.google*) printf '%s' "$DNS_JSON" ;;
                        *) printf '%s' '{"Answer":[{"type":1,"data":"9.9.9.9"}]}' ;;
                      esac
                    }
                    doh example.com
                '''
                result = shell(code, env={'DNS_JSON': '{"Answer":[' + answer + ']}'})
                self.assertEqual(result.stdout, '9.9.9.9\n')
                self.assertEqual(result.stderr, '')

    def test_doh_preserves_valid_blocking_addresses_and_deduplicates(self):
        result = shell('''
            http() { printf '%s' '{"Answer":[{"data":"0.0.0.0"},{"data":"198.18.0.1"},{"data":"0.0.0.0"},{"data":"999.2.3.4"}]}'; }
            doh example.com
        ''')
        self.assertEqual(result.stdout, '0.0.0.0\n198.18.0.1\n')

    def test_system_resolver_filters_malformed_addresses(self):
        result = shell('''
            getent() { printf '%s\n' '9.9.9.9 STREAM a.example' '9.9.9.9 DGRAM a.example' '999.2.3.4 STREAM a.example' '0.0.0.0 STREAM a.example'; }
            sys_resolve a.example
        ''')
        self.assertEqual(result.stdout, '9.9.9.9\n0.0.0.0\n')

    def test_encrypted_pass_queries_each_provider_once_on_google_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'queries'
            result = shell('''
                http() {
                  printf '%s\\n' "$*" >> "$QUERY_LOG"
                  case "$*" in
                    *dns.google*) printf '%s' '{"Answer":[]}' ;;
                    *) printf '%s' '{"Answer":[{"type":1,"data":"9.9.9.9"}]}' ;;
                  esac
                }
                probe_ip() { printf '%s\\n' "$5"; }
                probe_target E ai a.example 1
            ''', env={'QUERY_LOG': log.as_posix()})
            self.assertEqual(result.stdout, '9.9.9.9\n')
            self.assertEqual(len(log.read_text().splitlines()), 2)


if __name__ == '__main__':
    unittest.main()
