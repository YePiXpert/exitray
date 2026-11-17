"""Offline report format and route aggregation regressions."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import test_regression as regression


class ReportFormatTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='exitray-format-'))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.org = 'AS64500 ACME "Research" \\ Network | <b>**[link](url)</b>'
        self.category = 'team|<b>**'
        regression.write(self.work / 'env.tsv', regression.AnalyzeTests.ENV + 'verdict\tclean\n')
        regression.write(self.work / 'exits_info.tsv', regression.rows(
            ('A', '8.8.8.8', 2, 1, '-', self.org, 'TW', 'Taipei', '-', '-')))
        regression.write(self.work / 'cats.txt', '')
        regression.write(self.work / 'targets.tsv', regression.rows(
            (self.category, 'a.example', 'A', '8.8.8.8', 'direct', 'cloudflare', 1, 1, '-',
             '-', '-', '-', '-', 'none', 1, '200', 'ok', '1.1.1.1=A:ok:1/1:0:-', 0, 0, 0, 0, 0, 0, '-', 0)))

    def report(self, call):
        result = regression.shell(f"WORK='{regression.posix(self.work)}'\n{call}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout

    def test_json_preserves_quotes_backslashes_and_unicode(self):
        data = json.loads(self.report('report_json'))
        self.assertEqual(data['exits'][0]['org'], self.org)
        self.assertEqual(data['targets'][0]['category'], self.category)

    def test_json_escapes_control_characters(self):
        host = 'host' + ''.join(chr(n) for n in (1, 8, 11, 12, 13, 27, 31)) + '节点'
        with (self.work / 'env.tsv').open('a', encoding='utf-8', newline='\n') as out:
            out.write('host\t' + host + '\n')
        data = json.loads(self.report('report_json'))
        self.assertEqual(data['host'], host)

    def test_markdown_escapes_external_table_content(self):
        report = self.report('report_share markdown')
        self.assertIn(r'ACME "Research" \\ Network \| &lt;b&gt;\*\*\[link\](url)&lt;/b&gt;', report)
        self.assertIn(r'team\|&lt;b&gt;\*\*', report)
        self.assertNotIn('<b>', report)
        self.assertNotIn('[link](url)', report)

    def test_summary_preserves_plain_text(self):
        self.assertIn(self.org, self.report('report_share summary'))

    def test_markdown_mask_stars_are_literal(self):
        self.assertIn('| `8.8.*.*` |', self.report('report_share markdown'))
        self.assertIn('| `8.8.8.8` |', self.report('MASK=0 report_share markdown'))


class RouteAggregationTests(unittest.TestCase):
    def test_repeated_paths_keep_distinct_evidence_and_reachability(self):
        helper = regression.AnalyzeTests(methodName='runTest')
        self.addCleanup(helper.doCleanups)
        route_a = '10.0.0.1 10.0.0.2 5.5.5.5'
        route_b = '10.0.0.1 10.9.0.2 6.6.6.6'
        data = []
        for index, (exit_ip, route) in enumerate((('8.8.8.8', route_a), ('9.9.9.9', route_b))):
            for repeat in range(2):
                data.append(('C', 'E', 'cal', f'cal{index}{repeat}.example', 0, '1.1.1.1',
                             exit_ip, 'plain', '-', '-', route, 'ok'))
        cases = [('a', route_a, 'A', 'inferred'), ('b', route_b, 'B', 'inferred'),
                 ('unknown', '-', '?', 'unknown'), ('ambiguous', '10.0.0.1', '?', 'ambiguous'),
                 ('weak', '10.0.0.1 10.3.0.2 5.5.5.5', 'A', 'weak')]
        targets = []
        expected = []
        for repeat in range(2):
            for label, route, exit_id, evidence in cases:
                name = f'{label}{repeat}.example'
                targets.append(('ai', name))
                data.append(('T', 'P', 'ai', name, 1, '1.1.1.2', '-', '-', '200', '-', route, 'ok'))
                expected.append((name, exit_id, evidence))
        targets.append(('ai', 'dead.example'))
        for round_id in (1, 'r1', 'r2'):
            data.append(('T', 'P', 'ai', 'dead.example', round_id, '1.1.1.3', '-', '-', '000', '-', route_a, 'dead'))
        expected.append(('dead.example', '?', 'noconn'))
        helper.analyze(regression.rows(*data), targets)
        result = helper.json()
        self.assertEqual([(row['name'], row['system_dns']['exit_id'], row['system_dns']['evidence'])
                          for row in result['targets']], expected)
        self.assertEqual(result['targets'][-1]['reach'], 'dead')


if __name__ == '__main__':
    unittest.main()
