"""离线回归测试：加载脚本里真实的函数，网络由假命令代替。

运行：python3 tests/test_regression.py
可选环境变量：TEST_BASH 指定 bash，TEST_AWK 指定 awk（如 mawk、"busybox awk"）。
"""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'splitcheck.sh'
STUBS = ROOT / 'tests' / 'stubs'
BASH = os.environ.get('TEST_BASH', shutil.which('bash') or 'bash')
TEST_AWK = os.environ.get('TEST_AWK', '')

AWK_WRAPPER = f'awk() {{ command {TEST_AWK} "$@"; }}\n' if TEST_AWK else ''
PRELUDE = f'export SPLITCHECK_SOURCE_ONLY=1\nsource "{SCRIPT}"\n' + AWK_WRAPPER


def shell(code, data=None, env=None, timeout=30):
    """在加载了脚本函数的 bash 里跑一段代码。"""
    return subprocess.run([BASH, '-c', PRELUDE + code], input=data, text=True,
                          encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, **(env or {})}, timeout=timeout)


def write(path, text):
    Path(path).write_text(text, encoding='utf-8', newline='\n')


def rows(*items):
    """按 rows.tsv 的 11 列拼行：种类 解析方式 分类 名字 轮次 IP 出口 方法 状态码 候选 路径"""
    return ''.join('\t'.join(str(c) for c in item) + '\n' for item in items)


def cells(text):
    """终端里的显示宽度：汉字和全角标点占 2 格，框线、方块、✓ 这些占 1 格。"""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(ch) in 'WF' else 1 for ch in text)


class HelperTests(unittest.TestCase):
    def test_is_public_ipv4(self):
        for value, ok in [('8.8.8.8', True), ('172.32.0.1', True), ('100.128.0.1', True),
                          ('10.0.0.1', False), ('127.0.0.1', False), ('0.0.0.0', False),
                          ('172.16.0.1', False), ('192.168.1.1', False), ('169.254.1.1', False),
                          ('100.64.0.1', False), ('198.18.0.1', False), ('224.0.0.1', False),
                          ('1.2.3', False), ('example.com', False), ('', False)]:
            self.assertEqual(shell(f"is_public_ipv4 '{value}'").returncode == 0, ok, value)

    def test_extract(self):
        cases = [
            ('plain', ' 8.8.8.8\r\n', '8.8.8.8'),
            ('plain', 'Rate limit exceeded', ''),
            ('plain', '10.0.0.1\n', ''),
            ('trace', 'fl=1\nip=8.8.4.4\nts=1\n', '8.8.4.4'),
            ('fastly', '<td id="clientip">8.8.8.8</td>', '8.8.8.8'),
            ('cloudfront', "<span class='red'>8.8.8.8</span>", '8.8.8.8'),
            ('youtube', 'x"remoteHost":"8.8.8.8"y', '8.8.8.8'),
            ('meta', 'IP address (trusted): 8.8.8.8\n', '8.8.8.8'),
        ]
        for method, body, want in cases:
            self.assertEqual(shell(f'extract {method}', body).stdout, want, (method, body))

    def test_proxy_label_hides_credentials(self):
        for proxy, want in [('socks5h://user:secret@127.0.0.1:1080', 'socks5h://127.0.0.1:1080'),
                            ('http://u:p%40ss@host:8080', 'http://host:8080'),
                            ('socks5h://127.0.0.1:1080', 'socks5h://127.0.0.1:1080'),
                            ('', '')]:
            self.assertEqual(shell(f"PROXY='{proxy}'; proxy_label").stdout, want)

    def test_low_resource_respects_explicit_parallel(self):
        out = shell('nproc() { echo 1; }; low_resource; echo $PARALLEL').stdout.strip()
        self.assertEqual(out, '2')
        out = shell('nproc() { echo 32; }; low_resource; echo $PARALLEL').stdout.strip()
        self.assertEqual(out, '4')
        out = shell('PARALLEL=6 PARALLEL_SET=1; low_resource; echo $PARALLEL').stdout.strip()
        self.assertEqual(out, '6')

    def test_one_off_reading_in_the_trigger_test_is_not_a_trigger(self):
        # 9.9.9.9 复测后不算数了，触发测试里“查询后变成 9.9.9.9”的那一条也不能再算触发
        code = textwrap.dedent("""\
            WORK=$(mktemp -d)
            printf '9.9.9.9\\ta.example\\t5.5.5.5\\t8.8.8.8 8.8.8.8\\n' > "$WORK/unstable.tsv"
            {
              printf 'ai\\ta.example\\t5.5.5.5\\t8.8.8.8\\t9.9.9.9\\n'
              printf 'ai\\tb.example\\t5.5.5.6\\t8.8.8.8\\t7.7.7.7\\n'
              printf 'ai\\tc.example\\t-\\t-\\t-\\n'
            } > "$WORK/trigger.tsv"
            settle_triggers
            cat "$WORK/trigger.tsv"
            rm -rf "$WORK"
        """)
        self.assertEqual(shell(code).stdout, 'ai\ta.example\t5.5.5.5\t8.8.8.8\t8.8.8.8\n'
                                             'ai\tb.example\t5.5.5.6\t8.8.8.8\t7.7.7.7\n'
                                             'ai\tc.example\t-\t-\t-\n')


class SpawnTests(unittest.TestCase):
    """并发池：同时在跑的不超过 PARALLEL，有空位就补，不等整批跑完。"""
    CODE = textwrap.dedent("""\
        log=$(mktemp)
        job() { echo "start $1" >> "$log"; sleep "$1"; echo "end $1" >> "$log"; }
        PARALLEL=2
        HAS_WAIT_N=%s
        for d in 1.5 0.1 0.1 0.1 0.1; do spawn job "$d"; done
        wait_all
        awk '$1 == "start" { n++; if (n > max) max = n; if (!long_done) early++ }
             $1 == "end" { n--; finished++; if ($2 == "1.5") long_done = 1 }
             END { print max, finished, early }' "$log"
        rm -f "$log"
    """)

    def pool(self, wait_n):
        result = shell(self.CODE % wait_n)
        self.assertEqual(result.stderr, '')
        return [int(v) for v in result.stdout.split()]

    def check(self, wait_n):
        peak, finished, early = self.pool(wait_n)
        self.assertEqual(finished, 5)
        self.assertEqual(peak, 2)
        # 慢的那个还没跑完，后面几个就已经开始了
        self.assertGreaterEqual(early, 3)

    def test_polling_fallback_for_bash_without_wait_n(self):
        self.check('0')

    def test_wait_n_when_the_shell_has_it(self):
        self.check('$(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) ))')


class ArgsTests(unittest.TestCase):
    def run_script(self, *args):
        # 测试里绝不能真去装软件（CI 的机器有免密 sudo）
        return subprocess.run([BASH, str(SCRIPT), *args], text=True, encoding='utf-8',
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={**os.environ, 'SPLITCHECK_NO_INSTALL': '1'},
                              stdin=subprocess.DEVNULL, timeout=20)

    def test_version_and_help(self):
        self.assertEqual(self.run_script('-V').returncode, 0)
        out = self.run_script('--help').stdout
        for word in ('--low-resource', '--exit-code', 'dev', 'game', 'none'):
            self.assertIn(word, out)

    def test_rejects_bad_values(self):
        for args in (['-c', 'finace'], ['-c', 'AI'], ['-c', 'ai,nope'], ['-n', '0'], ['-p', 'x'],
                     ['-r', 'mars'], ['--tracer', 'ping'], ['--nope'], ['-c']):
            result = self.run_script(*args)
            self.assertEqual(result.returncode, 1, args)
            self.assertIn('splitcheck:', result.stderr, args)
        self.assertIn('finace', self.run_script('-c', 'finace').stderr)

    def test_categories_match_catalog(self):
        result = shell("""
            catalog | awk '{ print ($1 ~ /^@/ ? $2 : $1) }' | sort -u | paste -sd' ' -
            printf '%s\\n' "$CATEGORIES" | tr ' ' '\\n' | sort -u | paste -sd' ' -
            cat_labels | awk '{ print $1 }' | sort -u | paste -sd' ' -
        """)
        catalog, categories, labels = result.stdout.strip().split('\n')
        self.assertEqual(catalog, categories)
        self.assertEqual(catalog, labels)

    def test_common_catalog_has_no_duplicates(self):
        common = shell("catalog | awk '$1 !~ /^@/ { print $2 }' | sort | uniq -d").stdout
        self.assertEqual(common, '')


class TraceParserTests(unittest.TestCase):
    def trace(self, mode, tool, output):
        code = f"""{tool}() {{ printf '%s\\n' "$REPORT"; }}
LIMIT=''
trace_raw {mode} 1.1.1.1
"""
        result = shell(code, env={'REPORT': output})
        self.assertEqual(result.stderr, '')
        return result.stdout.split()

    def test_mtr(self):
        out = ('Start: 2026-11-06\nHOST: x Loss% Snt Last Avg Best Wrst StDev\n'
               '  1.|-- 10.0.0.1 0.0% 2 1.0 1.0 1.0 1.0 0.0\n'
               '  2.|-- ??? 100.0 2 0.0 0.0 0.0 0.0 0.0\n'
               '  3.|-- 8.8.8.8 0.0% 2 1.0 1.0 1.0 1.0 0.0')
        self.assertEqual(self.trace('mtr-icmp', 'mtr', out), ['10.0.0.1', '?', '8.8.8.8'])

    def test_mtr_multipath_continuation_is_ignored(self):
        out = ('  1.|-- 10.0.0.1 0.0% 2 1.0 1.0 1.0 1.0 0.0\n'
               '        10.0.0.2\n'
               '  2.|-- 8.8.8.8 0.0% 2 1.0 1.0 1.0 1.0 0.0')
        self.assertEqual(self.trace('mtr-icmp', 'mtr', out), ['10.0.0.1', '8.8.8.8'])

    def test_traceroute(self):
        out = 'traceroute to 1.1.1.1\n 1  10.0.0.1  1.0 ms\n 2  *\n 3  8.8.8.8  2.0 ms'
        self.assertEqual(self.trace('traceroute', 'traceroute', out), ['10.0.0.1', '?', '8.8.8.8'])

    def test_tracepath(self):
        out = (' 1?: [LOCALHOST] pmtu 1500\n 1:  10.0.0.1  1.0ms\n 1:  10.0.0.1  1.1ms\n'
               ' 2:  no reply\n 3:  8.8.8.8  2.0ms')
        self.assertEqual(self.trace('tracepath', 'tracepath', out), ['10.0.0.1', '?', '8.8.8.8'])


class EmitTests(unittest.TestCase):
    def test_long_rows_stay_intact_under_concurrency(self):
        # 300 个候选 IP 的行有 4.8KB，超过 stdio 的缓冲区。写的时候 PATH 是空的：emit 不能靠
        # dd、cat 这类外部命令，uutils 的 dd 写完会截断文件，并发时把别人的行截掉
        code = textwrap.dedent("""\
            WORK=$(mktemp -d); mkdir "$WORK/rows.d"; touch "$WORK/rows.tsv"
            big=$(printf '100.100.100.100,%.0s' {1..300})
            for w in 1 2 3 4 5 6 7 8; do
              ( PATH=/nonexistent; for i in {1..40}; do emit T "$w" "$i" "$big" END; done ) &
            done
            wait
            rows_merge
            awk -F'\\t' 'NF == 5 && $5 == "END"' "$WORK/rows.tsv" | wc -l
            ls "$WORK/rows.d" | wc -l
            rm -rf "$WORK"
        """)
        result = shell(code, timeout=60)
        self.assertEqual(result.stderr, '')
        self.assertEqual(result.stdout.split(), ['320', '0'])

    def test_merge_without_rows_is_a_no_op(self):
        code = textwrap.dedent("""\
            WORK=$(mktemp -d); mkdir "$WORK/rows.d"; printf 'x\\n' > "$WORK/rows.tsv"
            rows_merge && cat "$WORK/rows.tsv"
            rm -rf "$WORK"
        """)
        result = shell(code)
        self.assertEqual((result.stdout, result.stderr), ('x\n', ''))

    def fake_installer(self):
        """只有假的 apt-get 和 sudo，外加 install_deps 要用的几个命令。"""
        root = Path(tempfile.mkdtemp(prefix='splitcheck-inst-'))
        self.addCleanup(shutil.rmtree, root, True)
        bin_dir = root / 'bin'
        bin_dir.mkdir()
        for tool in ('env', 'mktemp', 'tail', 'rm', 'touch', 'date'):
            os.symlink(shutil.which(tool), bin_dir / tool)
        scripts = {
            # 第一次装会失败（索引太旧），update 之后才装得上
            'apt-get': '#!/bin/sh\necho "$*" >> "$STATE/log"\ncase "$1" in\n'
                       '  update) touch "$STATE/updated" ;;\n'
                       '  install) [ -f "$STATE/updated" ] || { echo "E: Unable to locate package"; exit 100; } ;;\n'
                       'esac\n',
            'sudo': '#!/bin/sh\n[ "$1" = -n ] && shift\n[ "$1" = true ] && exit 0\nexec "$@"\n',
        }
        for name, body in scripts.items():
            write(bin_dir / name, body)
            (bin_dir / name).chmod(0o755)
        return root, {'PATH': str(bin_dir), 'STATE': str(root), 'TMPDIR': str(root)}

    def test_missing_tools_are_installed_in_one_go(self):
        root, env = self.fake_installer()
        result = shell('USE_ROUTE=1; USE_DNS_TEST=1; install_deps', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / 'log').read_text().splitlines(),
                         ['install -y -qq mtr-tiny dnsutils', 'update -qq', 'install -y -qq mtr-tiny dnsutils'])
        self.assertIn('已装好 mtr-tiny dnsutils', result.stderr)

    def test_install_only_what_the_run_needs_and_can_be_turned_off(self):
        root, env = self.fake_installer()
        # 不测 DNS 触发就不装 dig
        shell('USE_ROUTE=1; USE_DNS_TEST=0; install_deps', env=env)
        self.assertEqual((root / 'log').read_text().splitlines()[-1], 'install -y -qq mtr-tiny')
        (root / 'log').unlink()
        for code, extra in (('INSTALL=0; install_deps', {}), ('install_deps', {'SPLITCHECK_NO_INSTALL': '1'}),
                            ('USE_ROUTE=0; USE_DNS_TEST=0; install_deps', {})):
            result = shell(code, env={**env, **extra})
            self.assertEqual((result.returncode, result.stderr), (0, ''), code)
            self.assertFalse((root / 'log').exists(), code)

    def test_pick_one_ip_per_slash_24(self):
        out = shell("printf '1.1.1.1\\n1.1.1.2\\n2.2.2.2\\n3.3.3.3\\n4.4.4.4\\n' | pick_ips 3").stdout
        self.assertEqual(out.split(), ['1.1.1.1', '2.2.2.2', '3.3.3.3'])


class AnalyzeTests(unittest.TestCase):
    """用固定的 rows.tsv 跑真实的 analyze、judge 和三种报告。"""
    GOOD_ORG = 'AS64500 Example Broadband'
    ENV = ('host\thost1\ntime\t2026-11-06 10:00:00\nelapsed\t12\ntracer\tmtr-icmp\nuse_route\t1\n'
           'region\tnone\nproxy\t-\nrounds\t1\ndns_test\t1\nversion\t1.3.0\n')
    # 结论 -> (退出码, 三种文字报告里都该出现、别的结论里不该出现的话)
    VERDICTS = {
        'clean': ('0', r'未发现分流'),
        'inconclusive': ('3', r'不能排除分流'),
        'dns_tampered': ('2', r'DNS 被动了手脚'),
        'blocked': ('2', r'像是被按 IP 拦截'),
        'split': ('2', r'结论(：|  )有分流'),
    }

    def analyze(self, data, targets, env='', orgs=None, sniff=''):
        work = Path(tempfile.mkdtemp(prefix='splitcheck-test-'))
        self.addCleanup(shutil.rmtree, work, True)
        self.work = work
        write(work / 'rows.tsv', data)
        write(work / 'targets.txt', ''.join(f'{c} {n}\n' for c, n in targets))
        write(work / 'env.base', self.ENV + env)
        write(work / 'sniff.tsv', sniff)
        cases = ' '.join(f"{ip}) org='{o}' ;;" for ip, o in (orgs or {}).items())
        self.setup_code = textwrap.dedent(f"""\
            WORK='{work}'; BASE_IP=8.8.8.8
            cat_labels > "$WORK/cats.txt"
            cp "$WORK/env.base" "$WORK/env.tsv"
            touch "$WORK/trigger.tsv" "$WORK/dnsq.tsv"
            analyze || exit 9
            judge || exit 9
            : > "$WORK/exits_info.tsv"
            while IFS=$'\\t' read -r l ip seen def sig; do
              case $ip in
                {cases}
                *) org='{self.GOOD_ORG}' ;;
              esac
              printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\tTW\\tTaipei\\t-\\t-\\n' "$l" "$ip" "$seen" "$def" "$sig" "$org" >> "$WORK/exits_info.tsv"
            done < "$WORK/exits.tsv"
        """)

    def run_report(self, call):
        result = shell(self.setup_code + call + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout

    def text(self):
        return self.run_report('report_text')

    def summary(self):
        return self.run_report('report_share summary')

    def markdown(self):
        return self.run_report('report_share markdown')

    def json(self):
        return json.loads(self.run_report('report_json'))

    def assert_verdict(self, verdict):
        """文字报告、分享摘要、Markdown、JSON 和退出码说的是同一个结论。"""
        self.assertEqual(self.json()['verdict'], verdict)
        self.assertEqual(self.run_report('exit_status').strip(), self.VERDICTS[verdict][0])
        for report in (self.text(), self.summary(), self.markdown()):
            for name, (_, phrase) in self.VERDICTS.items():
                self.assertEqual(bool(re.search(phrase, report)), name == verdict, (name, report[:300]))

    def calibration(self, exit_ip='8.8.8.8', path='10.0.0.1 1.2.3.4'):
        return [('C', 'E', 'cal', 'ipinfo.io', 0, '1.1.1.1', exit_ip, 'plain', '-', '-', path)]

    def direct(self, name='a.example', group='ai', ip='1.1.1.2', path='10.0.0.1 1.2.3.4'):
        return ('T', 'P', group, name, 1, ip, '8.8.8.8', 'cloudflare', '-', '-', path)

    def test_clean_single_exit(self):
        self.analyze(rows(*self.calibration(), self.direct()), [('ai', 'a.example')])
        self.assert_verdict('clean')
        data = self.json()
        self.assertIs(data['split'], False)
        self.assertEqual(data['coverage'], {'direct': 1, 'inferred': 0, 'weak': 0, 'unknown': 0,
                                            'unreachable': 0, 'fake_ip': 0, 'dns_blocked': 0,
                                            'ip_blocked': 0, 'split_by_ip': 0})

    def test_unknown_targets_do_not_read_as_no_split(self):
        self.analyze(rows(*self.calibration(), self.direct(path='-'),
                          ('T', 'P', 'bank', 'b.example', 1, '1.1.1.3', '-', '-', '200', '-', '-')),
                     [('ai', 'a.example'), ('bank', 'b.example')])
        self.assert_verdict('inconclusive')
        self.assertIn('1/2 个目标证据不足', self.text())
        data = self.json()
        self.assertIs(data['split'], False)  # 没发现第二个出口，这一项仍然是 false
        self.assertEqual(data['coverage']['unknown'], 1)

    def test_weak_inference_is_not_confirmation(self):
        # 目标在第 2 跳的内网段就和校准线路分开，只有一个出口时只能算弱推断
        self.analyze(rows(*self.calibration(),
                          ('T', 'P', 'bank', 'b.example', 1, '1.1.1.3', '-', '-', '200', '-', '10.0.0.1 10.9.9.9 5.5.5.5')),
                     [('bank', 'b.example')])
        self.assert_verdict('inconclusive')
        self.assertIn('只有弱推断', self.text())
        self.assertIn('弱推断 1', self.summary())
        self.assertEqual(self.json()['coverage']['weak'], 1)

    def test_unreachable_targets_do_not_change_the_verdict(self):
        # 清单里总会有失效的域名，不能因此永远得不到“未发现分流”
        self.analyze(rows(*self.calibration(), self.direct(),
                          ('T', 'P', 'bank', 'dead.example', 1, '-', '-', 'dns', '-', '-', '-'),
                          ('T', 'P', 'bank', 'closed.example', 1, '1.1.1.5', '-', '-', '000', '-', '-')),
                     [('ai', 'a.example'), ('bank', 'dead.example'), ('bank', 'closed.example')])
        self.assert_verdict('clean')
        self.assertIn('2 个目标解析失败或连不上', self.text())
        self.assertEqual(self.json()['coverage']['unreachable'], 2)
        self.assertIn('未确认 2', self.summary())

    # 第 12 列是这个 IP 连不连得上
    DEAD_E = ('T', 'E', 'meta', 'f.example', 1, '31.13.1.1', '-', '-', '000', '-', '10.0.0.1 1.2.3.4', 'dead')
    LIVE_P = ('T', 'P', 'meta', 'f.example', 1, '57.144.1.1', '8.8.8.8', 'meta', '-', '-', '10.0.0.1 1.2.3.4', 'ok')

    def retests(self, row, *results):
        return [row[:4] + (f'r{k}',) + row[5:] if r is None else row[:4] + (f'r{k}',) + r
                for k, r in enumerate(results, 1)]

    def test_partly_unreachable_target_is_a_block(self):
        # 加密 DNS 解析到的旧网段复测两次都连不上，系统 DNS 给的新网段正常：像是按 IP 拦截
        self.analyze(rows(*self.calibration(), self.DEAD_E, *self.retests(self.DEAD_E, None, None), self.LIVE_P),
                     [('meta', 'f.example')])
        self.assert_verdict('blocked')
        data = self.json()
        target = data['targets'][0]
        self.assertEqual(target['reach'], 'partial')
        self.assertEqual(target['ips'], [{'ip': '31.13.1.1', 'exit_ids': [], 'reachable': False},
                                         {'ip': '57.144.1.1', 'exit_ids': ['A'], 'reachable': True}])
        self.assertEqual(data['coverage']['ip_blocked'], 1)
        text = self.text()
        self.assertIn('1 个目标有部分 IP 连不上', text)
        self.assertIn('部分IP不通', text)
        self.assertIn('连不上的网段：31.13.1.0/24', text)
        self.assertRegex(text, r'31\.13\.1\.0/24 +✗ 连不上 +1 个  f\.example')
        self.assertRegex(text, r'57\.144\.1\.0/24 +✓ A +1 个  f\.example')
        # 每个 IP 的结果只在 -v 时列
        self.assertNotRegex(text, r'31\.13\.1\.1 +.*复测两次都连不上')
        self.assertRegex(self.run_report('VERBOSE=1 report_text'), r'31\.13\.1\.1 +.*复测两次都连不上')
        self.assertIn('1 个目标部分 IP 连不上', self.summary())
        self.assertIn('部分 IP 连不上 |', self.markdown())

    def test_unreachable_reading_that_connects_on_retest_is_not_a_block(self):
        # 系统 DNS 那一次超时，复测连上了：这一次按连得上处理，照常用路由推断，不记成连不上
        dead = ('T', 'P', 'meta', 'f.example', 1, '57.144.1.1', '-', '-', '000', '-', '10.0.0.1 1.2.3.4', 'dead')
        ok = ('57.144.1.1', '-', '-', '200', '-', '10.0.0.1 1.2.3.4', 'ok')
        self.analyze(rows(*self.calibration(), dead, *self.retests(dead, None, ok)), [('meta', 'f.example')])
        self.assert_verdict('clean')
        data = self.json()
        self.assertEqual(data['targets'][0]['reach'], 'ok')
        self.assertEqual(data['targets'][0]['system_dns']['evidence'], 'inferred')
        self.assertEqual(data['coverage']['unreachable'], 0)

    def test_unreachable_reading_is_queued_for_retest(self):
        self.analyze(rows(*self.calibration(), self.DEAD_E, self.LIVE_P), [('meta', 'f.example')])
        self.text()
        self.assertEqual((self.work / 'once.tsv').read_text(), 'T\tE\tmeta\tf.example\t31.13.1.1\n')
        # 没复测过就不算数
        self.assertEqual(self.json()['targets'][0]['reach'], 'ok')

    def test_target_with_every_ip_unreachable_does_not_change_the_verdict(self):
        dead = ('T', 'P', 'social', 'l.example', 1, '147.92.1.1', '-', '-', '000', '-', '-', 'dead')
        self.analyze(rows(*self.calibration(), self.direct(), dead, *self.retests(dead, None, None)),
                     [('ai', 'a.example'), ('social', 'l.example')])
        self.assert_verdict('clean')
        self.assertEqual({t['name']: t['reach'] for t in self.json()['targets']}, {'a.example': 'ok', 'l.example': 'dead'})
        text = self.text()
        self.assertIn('1 个目标的 IP 复测两次全都连不上', text)
        self.assertRegex(text, r'┃ +l\.example')
        # judge 把它也算进“解析失败或连不上”，结论里不再说第二遍
        self.assertNotIn('解析失败或连不上', text)

    def test_ip_ranges_are_summed_up_by_network(self):
        # 像 Seednet 那台：旧网段几个 IP 都不通，新网段两段都通，合成 57.144.x.x 一行；不通的排前面
        rs = [*self.calibration()]
        names = []
        for n, (old, new1, new2) in enumerate([('31.13.87.36', '57.144.92.1', '57.144.64.1'),
                                               ('31.13.87.5', '57.144.92.128', '57.144.64.128'),
                                               ('31.13.87.174', '57.144.92.34', '57.144.64.34')]):
            name = f'm{n}.example'
            names.append(('meta', name))
            dead = ('T', 'E', 'meta', name, 1, old, '-', '-', '000', '-', '10.0.0.1 1.2.3.4', 'dead')
            rs += [dead, *self.retests(dead, None, None)]
            for ip in (new1, new2):
                rs.append(('T', 'E', 'meta', name, 1, ip, '8.8.8.8', 'meta', '-', '-', '10.0.0.1 1.2.3.4', 'ok'))
            rs.append(('T', 'P', 'meta', name, 1, new1, '8.8.8.8', 'meta', '-', '-', '10.0.0.1 1.2.3.4', 'ok'))
        self.analyze(rows(*rs), names)
        self.assert_verdict('blocked')
        lines = self.text().splitlines()
        start = next(i for i, l in enumerate(lines) if l.startswith('── 逐 IP'))
        table = [l.split()[:3] for l in lines[start + 2:start + 4]]
        self.assertEqual(table, [['31.13.87.0/24', '✗', '连不上'], ['57.144.x.x', '✓', 'A']])
        self.assertEqual(lines[start + 4], '')
        self.assertIn('m0.example、m1.example、m2.example', lines[start + 2])

    def test_report_layout(self):
        self.analyze(rows(*self.calibration(), self.DEAD_E, *self.retests(self.DEAD_E, None, None), self.LIVE_P),
                     [('meta', 'f.example')])
        lines = self.text().splitlines()
        # 抬头的框四条边对齐
        box = [l for l in lines if l and l[0] in '╭│╰']
        self.assertEqual(len(box), 4)
        self.assertEqual({cells(l) for l in box}, {cells(box[0])}, box)
        # 分区标题一样长
        rules = [l for l in lines if l.startswith('── ')]
        self.assertEqual(len({cells(l) for l in rules}), 1, rules)
        # 没有目标的分类不列
        self.assertFalse([l for l in lines if l.lstrip().startswith(('AI', 'Telegram'))], lines)
        # 条形图每格一个目标，图例写明每种块是哪个出口
        self.assertIn('  Meta      █          1    ░          1', lines)
        self.assertTrue(any('█ A' in l and '░ 未知' in l for l in lines))

    def test_split_by_ip_is_its_own_class(self):
        # 加密 DNS 下同一个域名两个网段的 IP 各走各的出口
        self.analyze(rows(*self.calibration(),
                          ('T', 'E', 'shop', 's.example', 1, '3.3.3.3', '8.8.8.8', 'cloudflare', '-', '-', '10.0.0.1 1.2.3.4', 'ok'),
                          ('T', 'E', 'shop', 's.example', 1, '4.4.4.4', '9.9.9.9', 'cloudflare', '-', '-', '10.0.0.2 5.6.7.8', 'ok'),
                          ('T', 'P', 'shop', 's.example', 1, '4.4.4.4', '9.9.9.9', 'cloudflare', '-', '-', '10.0.0.2 5.6.7.8', 'ok')),
                     [('shop', 's.example')])
        self.assert_verdict('split')
        data = self.json()
        self.assertEqual(data['targets'][0]['class'], 'byip')
        self.assertEqual(data['coverage']['split_by_ip'], 1)
        self.assertEqual([(i['ip'], i['exit_ids']) for i in data['targets'][0]['ips']],
                         [('3.3.3.3', ['A']), ('4.4.4.4', ['B'])])
        self.assertIs(data['targets'][0]['split_by_ip'], True)
        text = self.text()
        self.assertIn('1 个目标按 IP 分流', text)
        self.assertIn('按IP', text)
        self.assertIn('1 个目标按 IP 分流', self.summary())

    def test_split_by_ip_still_counts_when_system_dns_is_fake_ip(self):
        # 系统 DNS 被透明代理接管时类别写 fakeip，加密 DNS 下看到的按 IP 分流不能因此丢掉
        self.analyze(rows(*self.calibration(),
                          ('T', 'E', 'shop', 's.example', 1, '3.3.3.3', '8.8.8.8', 'cloudflare', '-', '-', '-', 'ok'),
                          ('T', 'E', 'shop', 's.example', 1, '4.4.4.4', '9.9.9.9', 'cloudflare', '-', '-', '-', 'ok'),
                          ('T', 'P', 'shop', 's.example', 1, '198.18.0.9', '-', 'fakeip', '-', '-', '-'),
                          ('T', 'P', 'ai', 'g.example', 1, '5.5.5.5', '9.9.9.9', 'google', '-', '-', '-', 'ok')),
                     [('shop', 's.example'), ('ai', 'g.example')])
        data = self.json()
        target = data['targets'][0]
        self.assertEqual((target['class'], target['split_by_ip']), ('fakeip', True))
        self.assertEqual(data['coverage']['split_by_ip'], 1)
        self.assertIn('按IP', self.text())
        self.assertIn('fake-ip，按 IP', self.markdown())

    def test_same_ip_changing_exit_is_not_split_by_ip(self):
        # 同一个 IP 两轮走了不同出口，是时间上的变化，不能说成按 IP
        self.analyze(rows(*self.calibration(),
                          ('T', 'P', 'shop', 's.example', 1, '3.3.3.3', '8.8.8.8', 'cloudflare', '-', '-', '-', 'ok'),
                          ('T', 'P', 'shop', 's.example', 2, '3.3.3.3', '9.9.9.9', 'cloudflare', '-', '-', '-', 'ok'),
                          ('T', 'P', 'ai', 'g.example', 1, '5.5.5.5', '9.9.9.9', 'google', '-', '-', '-', 'ok')),
                     [('shop', 's.example'), ('ai', 'g.example')])
        self.assertNotEqual(self.json()['targets'][0]['class'], 'byip')

    def split_data(self):
        return rows(*self.calibration(),
                    ('C', 'E', 'cal', 'ident.me', 0, '1.1.1.9', '8.8.8.8', 'plain', '-', '-', '10.0.0.1 1.2.3.4'),
                    ('T', 'E', 'meta', 'f.example', 1, '2.2.2.2', '8.8.8.8', 'meta', '-', '-', '10.0.0.1 1.2.3.4'),
                    ('T', 'P', 'meta', 'f.example', 1, '2.2.2.3', '9.9.9.9', 'meta', '-', '-', '10.0.0.2 5.6.7.8'),
                    ('T', 'E', 'ai', 'g.example', 1, '3.3.3.3', '9.9.9.9', 'google', '-', '-', '10.0.0.2 5.6.7.8'),
                    ('T', 'P', 'ai', 'g.example', 1, '3.3.3.3', '9.9.9.9', 'google', '-', '-', '10.0.0.2 5.6.7.8'),
                    # 不回显，路由和 B 线路相同，应推断到 B
                    ('T', 'P', 'telegram', '149.154.175.50', 1, '149.154.175.50', '-', '-', '-', '-', '10.0.0.2 5.6.7.8'))

    def test_split_classification_and_inference(self):
        self.analyze(self.split_data(),
                     [('meta', 'f.example'), ('ai', 'g.example'), ('telegram', '149.154.175.50')],
                     orgs={'9.9.9.9': 'AS64501 Other Transit'})
        self.assert_verdict('split')
        data = self.json()
        self.assertIs(data['split'], True)
        self.assertEqual(data['default_exit'], '8.8.8.8')
        by_name = {t['name']: t for t in data['targets']}
        self.assertEqual(by_name['f.example']['class'], 'dns')
        self.assertEqual(by_name['g.example']['class'], 'static')
        self.assertEqual(by_name['149.154.175.50']['system_dns']['evidence'], 'inferred')
        self.assertEqual(by_name['149.154.175.50']['system_dns']['exit'], '9.9.9.9')
        text = self.text()
        self.assertIn('其中 1 个不是默认运营商', text)
        self.assertIn('DNS触发', text)
        self.assertIn('名单内', text)

    def test_failed_org_lookup_is_not_same_operator(self):
        # ipinfo 限流时运营商全是 -，不能说“都属于默认运营商”
        self.analyze(self.split_data(), [('meta', 'f.example')],
                     orgs={'8.8.8.8': '-', '9.9.9.9': '-'})
        text = self.text()
        self.assertNotIn('都属于默认运营商', text)
        self.assertIn('运营商信息没查全', text)
        self.assertIn('运营商信息没查全', self.summary())

    def test_one_missing_org_is_not_other_operator(self):
        self.analyze(self.split_data(), [('meta', 'f.example')], orgs={'9.9.9.9': '-'})
        self.assertNotIn('不是默认运营商', self.text())

    def test_same_operator(self):
        self.analyze(self.split_data(), [('meta', 'f.example')])
        self.assertIn('都属于默认运营商', self.text())

    def test_dns_block_and_hijack(self):
        self.analyze(rows(*self.calibration(),
                          ('T', 'E', 'bank', 'b.example', 1, '4.4.4.4', '8.8.8.8', 'cloudflare', '-', '-', '-'),
                          ('T', 'P', 'bank', 'b.example', 1, '0.0.0.0', '-', 'dnsblock', '-', '-', '-')),
                     [('bank', 'b.example')], env='dns_hijack\t1\n')
        self.assert_verdict('dns_tampered')
        text = self.text()
        self.assertIn('53 端口被上游劫持', text)
        self.assertIn('1 个目标被 DNS 屏蔽', text)
        self.assertEqual(self.json()['coverage']['dns_blocked'], 1)

    def test_fake_ip_is_inconclusive_not_blocked(self):
        self.analyze(rows(*self.calibration(),
                          ('T', 'E', 'dev', 'g.example', 1, '4.4.4.4', '8.8.8.8', 'cloudflare', '-', '-', '-'),
                          ('T', 'P', 'dev', 'g.example', 1, '198.18.0.121', '-', 'fakeip', '-', '-', '-')),
                     [('dev', 'g.example')])
        self.assert_verdict('inconclusive')
        text = self.text()
        self.assertIn('fake-ip', text)
        self.assertNotIn('被 DNS 屏蔽', text)
        self.assertIn('fake-ip', self.summary())
        self.assertIn('fake-ip', self.markdown())
        data = self.json()
        self.assertEqual(data['targets'][0]['class'], 'fakeip')
        self.assertEqual(data['targets'][0]['system_dns']['evidence'], 'fakeip')
        self.assertEqual(data['coverage']['fake_ip'], 1)
        self.assertEqual(data['coverage']['unknown'], 0)

    def one_off(self, *retest):
        """a.example 在系统 DNS 轮看到过一次 9.9.9.9，后面是复测的读数（- 表示没拿到回显）。"""
        path = '10.0.0.1 1.2.3.4'
        data = [*self.calibration(), self.direct('b.example', ip='1.1.1.3'),
                ('T', 'E', 'ai', 'a.example', 1, '1.1.1.2', '8.8.8.8', 'cloudflare', '-', '-', path),
                ('T', 'P', 'ai', 'a.example', 1, '1.1.1.2', '9.9.9.9', 'cloudflare', '-', '-', path)]
        for n, seen in enumerate(retest, 1):
            data.append(('T', 'P', 'ai', 'a.example', f'r{n}', '1.1.1.2', seen,
                         '-' if seen == '-' else 'cloudflare', '-', '-', path))
        self.analyze(rows(*data), [('ai', 'a.example'), ('ai', 'b.example')])

    def exits(self):
        return {e['ip']: e['seen'] for e in self.json()['exits']}

    def system_dns(self, name='a.example'):
        found = next(t['system_dns'] for t in self.json()['targets'] if t['name'] == name)
        return found['exit'], found['agree'], found['rounds']

    def test_one_off_exit_is_queued_for_retest(self):
        self.one_off()
        self.assert_verdict('split')  # 还没复测过，先照旧算数
        self.assertEqual((self.work / 'once.tsv').read_text(), 'T\tP\tai\ta.example\t1.1.1.2\n')

    def test_one_off_exit_gone_on_retest_is_not_a_split(self):
        self.one_off('8.8.8.8', '8.8.8.8')
        self.assert_verdict('clean')
        self.assertEqual(self.exits(), {'8.8.8.8': 6})
        self.assertEqual(self.json()['unstable_exits'], [{'ip': '9.9.9.9', 'target': 'a.example',
                                                          'target_ip': '1.1.1.2', 'retest': ['8.8.8.8', '8.8.8.8']}])
        # 那一次的读数按复测看到的算；复测本身不算目标的轮次
        self.assertEqual(self.system_dns(), ('8.8.8.8', 1, 1))
        text = self.text()
        self.assertIn('1 个出口只出现过 1 次', text)
        self.assertIn('9.9.9.9（a.example）', text)
        for report in (self.summary(), self.markdown()):
            self.assertIn('另有 1 个出口只出现过一次', report)
            self.assertNotIn('9.9.9', report)  # 分享用的报告不带这个 IP
        self.assertEqual((self.work / 'once.tsv').read_text(), '')

    def test_one_off_exit_seen_again_on_retest_counts(self):
        for retest in (('9.9.9.9', '9.9.9.9'), ('8.8.8.8', '9.9.9.9')):
            self.one_off(*retest)
            self.assert_verdict('split')
            self.assertEqual(self.json()['unstable_exits'], [])
            self.assertEqual(self.exits()['9.9.9.9'], 1 + retest.count('9.9.9.9'))
            self.assertEqual(self.system_dns(), ('9.9.9.9', 1, 1))

    def test_retest_without_echo_keeps_the_exit(self):
        # 复测没拿到回显，既没证实也没推翻，照旧保留并注明
        self.one_off('-', '-')
        self.assert_verdict('split')
        self.assertEqual(self.json()['unstable_exits'], [])
        self.assertIn('复测没能确认', self.text())
        self.assertEqual((self.work / 'once.tsv').read_text(), '')

    def test_one_echo_exit_backed_by_routes_is_not_doubted(self):
        # 上游把一批 IP 导去另一条线路时，常常只有一个目标拿得到回显，其余目标靠路由推断过去。
        # 至少 2 个目标的路由走那条和默认不同的线路，就不再提示可能是误报
        line = '10.0.0.1 10.66.1.202'
        for extra in (1, 2):
            data = [*self.calibration(), self.direct('b.example', ip='1.1.1.3'),
                    ('T', 'P', 'meta', 'm0.example', 1, '2.2.2.1', '9.9.9.9', 'meta', '-', '-', line + ' 5.5.5.5'),
                    ('T', 'P', 'meta', 'm0.example', 'r1', '2.2.2.1', '-', '-', '-', '-', line + ' 5.5.5.5'),
                    ('T', 'P', 'meta', 'm0.example', 'r2', '2.2.2.1', '-', '-', '-', '-', line + ' 5.5.5.5')]
            names = [('ai', 'b.example'), ('meta', 'm0.example')]
            for k in range(1, extra + 1):
                data.append(('T', 'P', 'meta', f'm{k}.example', 1, f'2.2.3.{k}', '-', '-', '-', '-', f'{line} 5.5.6.{k}'))
                names.append(('meta', f'm{k}.example'))
            self.analyze(rows(*data), names)
            self.assert_verdict('split')
            self.assertEqual(self.system_dns(f'm{extra}.example')[0], '9.9.9.9')
            text = self.text()
            if extra == 1:
                self.assertIn('复测没能确认', text)
                self.assertNotIn('目标的路由走同一条线路', text)
            else:
                self.assertNotIn('复测没能确认', text)
                self.assertIn('回显 1 次，另有 2 个目标的路由走同一条线路', text)

    def test_exit_first_seen_during_retest_does_not_count_either(self):
        self.one_off('8.8.8.8', '7.7.7.7')
        self.assert_verdict('clean')
        self.assertEqual(list(self.exits()), ['8.8.8.8'])
        self.assertEqual(self.json()['unstable_exits'][0]['retest'], ['8.8.8.8', '7.7.7.7'])

    def test_retest_rows_only_speak_for_their_own_target(self):
        path = '10.0.0.1 1.2.3.4'
        self.analyze(rows(*self.calibration(), self.direct('b.example', ip='1.1.1.3'),
                          # a.example 的偶发出口还没复测
                          ('T', 'P', 'ai', 'a.example', 1, '1.1.1.2', '9.9.9.9', 'cloudflare', '-', '-', path),
                          # c.example 的复测过了，没有再出现
                          ('T', 'P', 'ai', 'c.example', 1, '1.1.1.4', '7.7.7.7', 'cloudflare', '-', '-', path),
                          ('T', 'P', 'ai', 'c.example', 'r1', '1.1.1.4', '8.8.8.8', 'cloudflare', '-', '-', path),
                          ('T', 'P', 'ai', 'c.example', 'r2', '1.1.1.4', '8.8.8.8', 'cloudflare', '-', '-', path)),
                     [('ai', 'a.example'), ('ai', 'b.example'), ('ai', 'c.example')])
        self.assertEqual(sorted(self.exits()), ['8.8.8.8', '9.9.9.9'])
        self.assertEqual([u['ip'] for u in self.json()['unstable_exits']], ['7.7.7.7'])
        self.assertEqual((self.work / 'once.tsv').read_text(), 'T\tP\tai\ta.example\t1.1.1.2\n')

    def test_default_exit_is_never_retested(self):
        # 默认出口哪怕只回显过一次，也不拿去复测、不会被丢掉
        self.analyze(rows(*self.calibration(),
                          ('T', 'P', 'bank', 'b.example', 1, '1.1.1.3', '-', '-', '200', '-', '10.0.0.1 1.2.3.4')),
                     [('bank', 'b.example')])
        self.assertEqual(self.exits(), {'8.8.8.8': 1})
        self.assertEqual((self.work / 'once.tsv').read_text(), '')

    def test_retest_can_find_the_stable_exit(self):
        # 第一次看到的是偶发的，复测两次都是另一个出口：那个才是这个目标稳定的出口
        self.one_off('7.7.7.7', '7.7.7.7')
        self.assert_verdict('split')
        self.assertEqual(self.exits(), {'8.8.8.8': 3, '7.7.7.7': 3})
        self.assertEqual(self.system_dns(), ('7.7.7.7', 1, 1))
        self.assertEqual(self.json()['unstable_exits'][0]['ip'], '9.9.9.9')

    def sniff_report(self, sniff):
        self.analyze(rows(*self.calibration(), self.direct()), [('ai', 'a.example')],
                     env='sniff_base\t8.8.8.8\n', sniff=sniff)
        return self.text()

    def test_sni_unchanged(self):
        text = self.sniff_report('a.example\t8.8.8.8\t200\nb.example\t8.8.8.8\t200\n')
        self.assertIn('2 个域名放进 SNI，出口都没变', text)
        self.assertNotIn('没连上', text)

    def test_sni_exit_changed(self):
        text = self.sniff_report('a.example\t9.9.9.9\t200\nb.example\t8.8.8.8\t200\n')
        self.assertIn('1/2 个域名出口变了： a.example=9.9.9.9', text)

    def test_sni_answer_from_somewhere_else_is_a_finding(self):
        # 有应答却不是回显：连接被按 SNI 转去了别的服务器，这正是这项测试要抓的
        text = self.sniff_report('a.example\t-\t404\nb.example\t8.8.8.8\t200\n')
        self.assertIn('1/2 个域名的连接被转去了别处', text)
        self.assertIn('a.example', text)
        self.assertNotIn('出口都没变', text)

    def test_sni_connection_failures_are_not_findings(self):
        text = self.sniff_report('a.example\t-\t000\nb.example\t8.8.8.8\t200\n')
        self.assertIn('1 个域名放进 SNI，出口都没变', text)
        self.assertIn('另有 1 个没连上', text)
        self.assertNotIn('转去了别处', text)
        self.assertIn('都没连上，无法判断', self.sniff_report('a.example\t-\t000\n'))

    def test_sni_rate_limit_is_not_a_finding(self):
        text = self.sniff_report('a.example\t-\t429\nb.example\t8.8.8.8\t200\n')
        self.assertNotIn('转去了别处', text)
        self.assertIn('另有 1 个没连上', text)

    def test_share_reports_mask_ips(self):
        self.analyze(self.split_data(), [('meta', 'f.example')])
        for report in (self.summary(), self.markdown()):
            self.assertNotIn('8.8.8.8', report)
            self.assertIn('8.8.*.*', report)

    def test_detail_order_follows_target_list(self):
        self.analyze(rows(*self.calibration(), self.direct('z.example'), self.direct('a.example', ip='1.1.1.3')),
                     [('ai', 'a.example'), ('ai', 'z.example')])
        self.assertEqual([t['name'] for t in self.json()['targets']], ['a.example', 'z.example'])


class IntegrationTests(unittest.TestCase):
    """用假的 curl、mtr、dig、getent 跑完整流程。"""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='splitcheck-int-'))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bin = self.dir / 'bin'
        self.bin.mkdir()
        self.state = self.dir / 'state'
        self.state.mkdir()
        self.log = self.dir / 'curl.log'
        self.dnslog = self.dir / 'dns.log'
        self.nice_log = self.dir / 'nice.log'
        curl = self.bin / 'curl'
        curl.write_bytes((STUBS / 'curl').read_bytes().replace(b'\r\n', b'\n'))
        curl.chmod(0o755)
        if TEST_AWK:  # 让完整流程也用指定的 awk
            self.stub('awk', f'exec {TEST_AWK} "$@"\n')
        self.stub('mtr', """
            # 路径由目标 IP 决定：$STUB_DIR/routes 里每行“IP 跳 跳 ...”
            ip=${@: -1}
            route=$(awk -v ip="$ip" '$1 == ip { $1 = ""; print; exit }' "$STUB_DIR/routes" 2>/dev/null)
            [[ -n $route ]] || route='10.0.0.1 1.2.3.4'
            echo 'HOST: x Loss% Snt Last Avg Best Wrst StDev'
            n=0
            for h in $route; do n=$((n + 1)); echo "  $n.|-- $h 0.0% 2 1.0 1.0 1.0 1.0 0.0"; done
        """)
        self.stub('getent', """
            echo "getent $2" >> "$STUB_DNSLOG"
            sys=$(awk -v n="$2" '$1 == n { print $2; exit }' "$STUB_DIR/sysdns" 2>/dev/null)
            [[ $sys == fail ]] && exit 2
            echo "${sys:-8.8.4.4} STREAM $2"
        """)
        self.stub('dig', """
            echo "dig $*" >> "$STUB_DNSLOG"
            case "$*" in
              *192.0.2.53*) [[ -e $STUB_DIR/hijack ]] && echo 93.184.216.34 ;;
              *whoami*) echo ';; connection timed out; no servers could be reached' ;;
              *+subnet=*)
                # 触发测试的明文查询：doh_far 里有的域名，给出和 DoH 一样的外地 IP
                for arg in "$@"; do
                  awk -v n="$arg" '$1 == n { print $2 }' "$STUB_DIR/doh_far" 2>/dev/null
                done ;;
            esac
        """)
        self.stub('nice', f"""
            echo "$*" >> '{self.nice_log}'
            shift 2
            exec "$@"
        """)

    def stub(self, name, body):
        path = self.bin / name
        write(path, '#!/usr/bin/env bash\n' + textwrap.dedent(body))
        path.chmod(0o755)

    def state_file(self, name, text):
        write(self.state / name, text)

    def env(self, **extra):
        return {**os.environ, 'PATH': f'{self.bin}{os.pathsep}{os.environ["PATH"]}',
                'STUB_DIR': str(self.state), 'STUB_LOG': str(self.log),
                'STUB_DNSLOG': str(self.dnslog), 'TMPDIR': str(self.dir),
                'SPLITCHECK_NO_INSTALL': '1', **extra}

    def run_script(self, *args, **extra):
        return subprocess.run([BASH, str(SCRIPT), *args], text=True, encoding='utf-8',
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              stdin=subprocess.DEVNULL, env=self.env(**extra), timeout=120)

    def targets(self, text='ai a.example\nai b.example\n'):
        path = self.dir / 'targets.txt'
        path.write_bytes(text.encode('utf-8'))
        return str(path)

    def common(self, targets=None):
        """只测自己的目标，不加载内置清单。"""
        return ('-c', 'none', '-r', 'none', '-n', '1', '-f', targets or self.targets())

    def requests(self, url):
        """假 curl 记下的、发给这个 URL 的请求。"""
        found = []
        for line in self.log.read_text().splitlines():
            fields = line.split('\t')
            if fields[0] == url:
                found.append(dict(f.split('=', 1) for f in fields[1:]))
        return found

    def test_full_run_no_split(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(), '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertIs(data['split'], False)
        self.assertEqual(data['verdict'], 'clean')
        self.assertEqual([t['name'] for t in data['targets']], ['a.example', 'b.example'])
        self.assertEqual(data['exits'][0]['org'], 'AS64500 Example Broadband')
        # 临时目录要清理干净
        self.assertEqual([p.name for p in self.dir.glob('splitcheck.*')], [])

    def test_full_run_with_split_and_exit_code(self):
        self.state_file('sysdns', 'a.example 2.2.2.2\nb.example 8.8.4.4\n')
        self.state_file('exit_for', 'default 8.8.8.8\n2.2.2.2 9.9.9.9\n')
        result = self.run_script(*self.common(), '-j', '--exit-code')
        self.assertEqual(result.returncode, 2, result.stderr)
        data = json.loads(result.stdout)
        self.assertIs(data['split'], True)
        self.assertEqual(data['verdict'], 'split')
        by_name = {t['name']: t for t in data['targets']}
        self.assertEqual(by_name['a.example']['system_dns']['exit'], '9.9.9.9')
        self.assertEqual(by_name['a.example']['encrypted_dns']['exit'], '8.8.8.8')
        self.assertEqual(by_name['a.example']['class'], 'dns')
        # 这个出口只在一次探测里出现过，复测两次都还在，才算数
        self.assertEqual({e['ip']: e['seen'] for e in data['exits']}['9.9.9.9'], 3)
        self.assertEqual(data['unstable_exits'], [])
        self.assertEqual(by_name['a.example']['system_dns']['rounds'], 1)

    def test_one_off_exit_is_retested_and_dropped(self):
        # 头一次回显报了另一个出口，之后恢复正常：像出口池轮换，不是按目标分流
        self.state_file('sysdns', 'a.example 2.2.2.2\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('exit_once', '2.2.2.2 9.9.9.9\n')
        result = self.run_script(*self.common(), '-j', '--exit-code')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['verdict'], 'clean')
        self.assertEqual([e['ip'] for e in data['exits']], ['8.8.8.8'])
        self.assertEqual([(u['ip'], u['target'], u['target_ip'], u['retest']) for u in data['unstable_exits']],
                         [('9.9.9.9', 'a.example', '2.2.2.2', ['8.8.8.8', '8.8.8.8'])])
        by_name = {t['name']: t for t in data['targets']}
        self.assertEqual(by_name['a.example']['system_dns']['exit'], '8.8.8.8')
        self.assertEqual(by_name['a.example']['class'], 'none')
        # 当初那一次，加两次复测
        echoes = [r for r in self.requests('https://a.example/cdn-cgi/trace') if r['pin'] == '2.2.2.2']
        self.assertEqual(len(echoes), 3)

    def test_one_off_reading_in_the_trigger_test_is_retested_too(self):
        # 触发测试里“查询前”那一次回显报了另一个出口，之后恢复正常。不复测的话，这会被说成
        # “明文 DNS 触发了分流”，是最吓人也最容易误报的一条结论
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('doh_far', 'a.example 5.5.5.5\n')
        self.state_file('exit_once', '5.5.5.5 9.9.9.9\n')
        result = self.run_script(*self.common(), '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['verdict'], 'clean')
        self.assertIs(data['dns_triggered'], False)
        trigger = {t['name']: (t['ip'], t['before'], t['after']) for t in data['dns_trigger_test']}
        self.assertEqual(trigger['a.example'], ('5.5.5.5', '8.8.8.8', '8.8.8.8'))
        self.assertEqual([(u['ip'], u['target'], u['target_ip']) for u in data['unstable_exits']],
                         [('9.9.9.9', 'a.example', '5.5.5.5')])
        # 触发测试前后各一次，加两次复测
        echoes = [r for r in self.requests('https://a.example/cdn-cgi/trace') if r['pin'] == '5.5.5.5']
        self.assertEqual(len(echoes), 4)

    def test_exit_code_is_zero_without_flag_even_when_split(self):
        self.state_file('sysdns', 'a.example 2.2.2.2\n')
        self.state_file('exit_for', 'default 8.8.8.8\n2.2.2.2 9.9.9.9\n')
        self.assertEqual(self.run_script(*self.common(), '-j').returncode, 0)

    def test_no_plaintext_dns_before_system_pass(self):
        """到系统 DNS 那一轮之前不能有明文查询，这是 DNS 触发判断成立的前提。"""
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('silent', '8.8.4.4\n')
        self.assertEqual(self.run_script(*self.common(), '--no-sniff', '-j').returncode, 0)
        calls = self.dnslog.read_text().splitlines()
        first_getent = next(i for i, c in enumerate(calls) if c.startswith('getent'))
        before = calls[:first_getent]
        # 触发测试的 dig 是故意的，只查抽样的目标；不能有 getent，也不能查基础设施
        self.assertTrue(all(c.startswith('dig') for c in before), before)
        for host in ('ipinfo.io', 'ip-api.com', 'dns.google'):
            self.assertFalse(any(host in c for c in calls), host)
        # curl 用主机名发请求却没钉 IP，就会走系统解析器。结束时查 IPv6 的那一次除外
        for line in self.log.read_text().splitlines():
            url, pin = line.split('\t')[:2]
            host = url.split('://')[1].split('/')[0]
            if host != 'api64.ipify.org' and not host.replace('.', '').isdigit():
                self.assertNotEqual(pin, 'pin=', line)

    def redirect_scenario(self):
        # 两轮解析到不同的 IP，都不回显，这样两轮都会去翻页面，而且分得清是哪一轮
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('sysdns', 'a.example 9.9.4.4\n')
        self.state_file('silent', '8.8.4.4\n9.9.4.4\n')

    def test_encrypted_pass_pins_redirects_and_system_pass_does_not(self):
        self.redirect_scenario()
        self.assertEqual(self.run_script(*self.common(), '--no-sniff', '-j').returncode, 0)
        pages = {r['pin']: r for r in self.requests('https://a.example/')}
        # 加密 DNS 轮：跳到哪个主机都连这个 IP，curl 没机会自己发明文查询
        self.assertEqual(pages['8.8.4.4']['connect'], '::8.8.4.4:')
        self.assertEqual(pages['8.8.4.4']['follow'], '1')
        # 系统 DNS 轮：和原来一样，跳转交给系统解析器
        self.assertEqual(pages['9.9.4.4']['connect'], '')
        self.assertEqual(pages['9.9.4.4']['follow'], '1')

    def test_old_curl_does_not_follow_redirects_in_encrypted_pass(self):
        self.redirect_scenario()
        result = self.run_script(*self.common(), '--no-sniff', '-j', STUB_NO_CONNECT_TO='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        pages = {r['pin']: r for r in self.requests('https://a.example/')}
        self.assertEqual((pages['8.8.4.4']['connect'], pages['8.8.4.4']['follow']), ('', '0'))
        self.assertEqual((pages['9.9.4.4']['connect'], pages['9.9.4.4']['follow']), ('', '1'))

    def test_ipinfo_rate_limit_falls_back_to_ip_api(self):
        (self.state / 'ipinfo_down').touch()
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script('-c', 'none', '-n', '1', '-f', self.targets(), '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['exits'][0]['org'], 'AS64501 Fallback Telecom')
        self.assertEqual(data['exits'][0]['country'], 'TW')
        self.assertEqual(data['exits'][0]['flag'], 'hosting')
        self.assertEqual(data['region'], 'tw')  # 地区探测也退到备用来源

    def test_dig_timeout_text_does_not_reach_report(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(), '-j')
        self.assertNotIn('timed out', result.stdout)
        self.assertIs(json.loads(result.stdout)['dns_query']['Cloudflare'], None)

    def test_dns_hijack_detected(self):
        (self.state / 'hijack').touch()
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(), '-j', '--exit-code')
        self.assertEqual(result.returncode, 2)
        data = json.loads(result.stdout)
        self.assertIs(data['dns_hijack'], True)
        self.assertEqual(data['verdict'], 'dns_tampered')

    def test_fake_ip_and_blocked_answers_are_told_apart(self):
        self.state_file('sysdns', 'a.example 198.18.0.5\nb.example 0.0.0.0\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(), '-j', '--exit-code')
        self.assertEqual(result.returncode, 2, result.stderr)  # b.example 确实被屏蔽
        by_name = {t['name']: t for t in json.loads(result.stdout)['targets']}
        self.assertEqual(by_name['a.example']['class'], 'fakeip')
        self.assertEqual(by_name['b.example']['class'], 'dnsblock')

    def test_encrypted_pass_probes_each_range_from_both_resolvers(self):
        # Google 给两个同网段的 IP，Cloudflare 给另一个网段的；那个网段走了另一个出口
        self.state_file('doh', 'a.example 2.2.2.2 2.2.2.3\n')
        self.state_file('doh_cf', 'a.example 3.3.3.3\n')
        self.state_file('exit_for', 'default 8.8.8.8\n3.3.3.3 9.9.9.9\n')
        result = self.run_script(*self.common(self.targets('ai a.example\n')), '-j', '--exit-code')
        self.assertEqual(result.returncode, 2, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['verdict'], 'split')
        self.assertEqual(data['targets'][0]['class'], 'byip')
        pins = [r['pin'] for r in self.requests('https://a.example/cdn-cgi/trace')]
        self.assertIn('2.2.2.2', pins)
        self.assertIn('3.3.3.3', pins)
        self.assertNotIn('2.2.2.3', pins)  # 同一个 /24 只测一个

    def test_ip_range_that_cannot_be_reached_is_a_block(self):
        self.state_file('doh', 'a.example 2.2.2.2\n')
        self.state_file('sysdns', 'a.example 4.4.4.4\n')
        self.state_file('dead', '2.2.2.2\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(self.targets('ai a.example\n')), '-j', '--exit-code')
        self.assertEqual(result.returncode, 2, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['verdict'], 'blocked')
        target = data['targets'][0]
        self.assertEqual(target['reach'], 'partial')
        self.assertEqual({i['ip']: i['reachable'] for i in target['ips']}, {'2.2.2.2': False, '4.4.4.4': True})
        # 当初那一次，加两次复测
        self.assertEqual(len([r for r in self.requests('https://a.example/') if r['pin'] == '2.2.2.2']), 3)

    def test_one_off_timeout_is_retested_and_not_a_block(self):
        # 头三个请求（认 CDN、回显、翻页面）都超时，复测时恢复
        self.state_file('doh', 'a.example 2.2.2.2\n')
        self.state_file('sysdns', 'a.example 4.4.4.4\n')
        self.state_file('flaky', '2.2.2.2 3\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(self.targets('ai a.example\n')), '-j', '--exit-code')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['verdict'], 'clean')
        self.assertEqual(data['targets'][0]['reach'], 'ok')

    def test_ip_target_that_cannot_be_reached(self):
        self.state_file('dead', '149.154.175.50\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(self.targets('ai a.example\ntelegram 149.154.175.50\n')), '--exit-code')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('1 个目标的 IP 复测两次全都连不上', result.stdout)
        self.assertRegex(result.stdout, r'149\.154\.175\.0/24 +✗ 连不上 +1 个  149\.154\.175\.50')
        # 两种解析方式各测一次，各复测两次
        self.assertEqual(len(self.requests('http://149.154.175.50:443/')), 6)

    def test_sni_sniff_tells_changed_moved_and_failed_apart(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('sni_moved', 'a.example\n')
        self.state_file('sni_exit', 'b.example 9.9.9.9\n')
        self.state_file('sni_dead', 'c.example\n')
        args = self.common(self.targets('ai a.example\nai b.example\nshop c.example\nshop d.example\n'))
        result = self.run_script(*args, '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        results = {r['sni']: (r['exit'], r['http']) for r in json.loads(result.stdout)['sni_test']['results']}
        self.assertEqual(results, {'a.example': (None, '404'), 'b.example': ('9.9.9.9', '200'),
                                   'c.example': (None, '000'), 'd.example': ('8.8.8.8', '200')})
        # 没拿到回显的重试一次，拿到的不重试
        tries = {name: len(self.requests(f'https://{name}/ip')) for name in results}
        self.assertEqual(tries, {'a.example': 2, 'b.example': 1, 'c.example': 2, 'd.example': 1})
        text = self.run_script(*args).stdout
        self.assertIn('1/4 个域名出口变了： b.example=9.9.9.9', text)
        self.assertIn('1/4 个域名的连接被转去了别处，回来的不是回显服务的应答： a.example', text)
        self.assertIn('另有 1 个没连上', text)

    def test_proxy_credentials_do_not_leak(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(), '-x', 'socks5h://user:secret@127.0.0.1:1080')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('secret', result.stdout + result.stderr)
        self.assertIn('socks5h://127.0.0.1:1080', result.stdout)
        result = self.run_script(*self.common(), '-j', '-x', 'socks5h://user:secret@127.0.0.1:1080')
        self.assertEqual(json.loads(result.stdout)['proxy'], 'socks5h://127.0.0.1:1080')

    def test_target_file_with_bom_crlf_and_comments(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        path = self.targets('\ufeffai a.example\r\n# 注释 行\r\n\r\nai -evil\r\nbroken\r\nai b.example')
        result = self.run_script(*self.common(path), '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        targets = json.loads(result.stdout)['targets']
        self.assertEqual([t['name'] for t in targets], ['a.example', 'b.example'])
        self.assertEqual(targets[0]['category'], 'ai')  # BOM 不能粘在分类名上
        self.assertIn('-evil', result.stderr)
        self.assertIn('broken', result.stderr)
        self.assertNotIn('注释', result.stderr)

    def test_all_output_modes_run(self):
        self.state_file('sysdns', 'a.example 2.2.2.2\n')
        self.state_file('exit_for', 'default 8.8.8.8\n2.2.2.2 9.9.9.9\n')
        for args, needle in ((['-b'], '结论'), (['-v'], '每轮明细'), (['-m'], '# 分流检测报告'),
                             (['--no-mask', '-m'], '8.8.8.8')):
            result = self.run_script(*self.common(), *args)
            self.assertEqual(result.returncode, 0, (args, result.stderr))
            self.assertIn(needle, result.stdout, args)

    def test_low_resource_flag(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.assertEqual(self.run_script(*self.common(), '-j').returncode, 0)
        self.assertFalse(self.nice_log.exists())
        self.assertEqual(self.run_script(*self.common(), '-j', '-L').returncode, 0)
        self.assertTrue(self.nice_log.exists(), '加了 -L，路由探测却没降优先级')

    @unittest.skipUnless(os.name == 'posix', '需要 pty')
    def test_interactive_menu_and_progress_under_a_terminal(self):
        import pty
        import select
        self.state_file('exit_for', 'default 8.8.8.8\n')
        # 校准时有一次回显报了另一个出口，这样带界面的复测步骤也会跑到
        self.state_file('exit_once', '8.8.4.4 9.9.9.9\n')
        pid, fd = pty.fork()
        if pid == 0:  # 子进程：有控制终端，走菜单分支，测的是内置的完整清单
            os.execve(BASH, [BASH, str(SCRIPT)], self.env())
        seen, answered = b'', set()
        deadline = time.time() + 150
        try:
            while time.time() < deadline:
                ready, _, _ = select.select([fd], [], [], 1)
                if ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    seen += chunk
                if '请输入 [默认 1]'.encode() in seen and 'menu' not in answered:
                    os.write(fd, b'7\n')  # 低压力检测
                    answered.add('menu')
                if 'Markdown 报告，方便'.encode() in seen and 'md' not in answered:
                    os.write(fd, b'n\n')
                    answered.add('md')
            _, status = os.waitpid(pid, 0)
        finally:
            os.close(fd)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        text = seen.decode('utf-8', 'replace')
        self.assertIn('低压力检测', text)
        self.assertIn('系统 DNS', text)
        self.assertIn('复测偶发的读数', text)
        self.assertIn('1 个，1 个出口复测看到的是别的出口，按偶发处理', text)
        self.assertIn('未发现分流', text)
        self.assertIn('1 个出口只出现过 1 次', text)
        self.assertIn('\x1b[?25h', text)  # 退出时恢复光标
        self.assertNotIn('command not found', text)
        self.assertNotIn('syntax error', text)
        self.assertTrue(self.nice_log.exists(), '菜单选了低压力检测，路由探测却没降优先级')

    @staticmethod
    def stuck():
        """还在跑的、假装卡住的 mtr。直接读 /proc，不依赖 ps 的写法。"""
        found = []
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                try:
                    with open(f'/proc/{entry}/cmdline', 'rb') as handle:
                        if handle.read() == b'sleep\x0086399\x00':
                            found.append(int(entry))
                except OSError:
                    pass
        return found

    @unittest.skipUnless(os.path.isdir('/proc/self'), '需要 /proc')
    def test_sigterm_stops_children_and_cleans_up(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        # 选路由工具时正常应答，之后每次探测都卡住
        self.stub('mtr', """
            case "$*" in
              *1.1.1.1*) echo '  1.|-- 10.0.0.1 0.0% 2 1 1 1 1 0'; echo '  2.|-- 1.2.3.4 0.0% 2 1 1 1 1 0' ;;
              *) exec sleep 86399 ;;
            esac
        """)
        proc = subprocess.Popen([BASH, str(SCRIPT), *self.common(), '--no-dns-test', '-j'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=self.env())
        try:
            deadline = time.time() + 30
            while time.time() < deadline and not self.stuck():
                time.sleep(0.2)
            self.assertTrue(self.stuck(), '探测没有走到卡住的 mtr')
            proc.send_signal(signal.SIGTERM)
            self.assertEqual(proc.wait(timeout=30), 143)
            deadline = time.time() + 5
            while time.time() < deadline and self.stuck():
                time.sleep(0.2)
            self.assertEqual(self.stuck(), [], '脚本退出后 mtr 还在跑')
            self.assertEqual([p.name for p in self.dir.glob('splitcheck.*')], [])
        finally:
            proc.kill()
            for pid in self.stuck():
                os.kill(pid, signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
