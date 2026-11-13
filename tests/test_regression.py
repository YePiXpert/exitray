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
SCRIPT = ROOT / 'exitray.sh'
STUBS = ROOT / 'tests' / 'stubs'
BASH = os.environ.get('TEST_BASH', shutil.which('bash') or 'bash')
TEST_AWK = os.environ.get('TEST_AWK', '')
# 完整流程一次的时限。Windows 上起进程慢得多，放宽一些
RUN_TIMEOUT = int(os.environ.get('TEST_RUN_TIMEOUT', '120' if os.name == 'posix' else '900'))

AWK_WRAPPER = f'awk() {{ command {TEST_AWK} "$@"; }}\n' if TEST_AWK else ''


def posix(path):
    """交给 bash 和 awk 的路径一律用正斜杠：Windows 上的反斜杠会被 awk -v 当成转义。"""
    return Path(path).as_posix()


PRELUDE = f'export EXITRAY_SOURCE_ONLY=1\nsource "{posix(SCRIPT)}"\n' + AWK_WRAPPER


def shell(code, data=None, env=None, timeout=30):
    """在加载了脚本函数的 bash 里跑一段代码。"""
    return subprocess.run([BASH, '-c', PRELUDE + code], input=data, text=True,
                          encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, **(env or {})}, timeout=timeout)


def write(path, text):
    Path(path).write_text(text, encoding='utf-8', newline='\n')


def rows(*items):
    """按 rows.tsv 的列拼行：种类 解析方式 分类 名字 轮次 IP 出口 方法 状态码 候选 路径 [连通]"""
    return ''.join('\t'.join(str(c) for c in item) + '\n' for item in items)


def cells(text):
    """终端里的显示宽度：汉字和全角标点占 2 格，框线、方块、✓ 这些占 1 格。"""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(ch) in 'WF' else 1 for ch in text)


def plain(text):
    """去掉颜色码。"""
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def squash(text):
    """去掉全部空白。报告里的长句会折行，比对一句完整的话时两边都先压一下。"""
    return re.sub(r'\s+', '', text)


class HelperTests(unittest.TestCase):
    def test_is_public_ipv4(self):
        for value, ok in [('8.8.8.8', True), ('172.32.0.1', True), ('100.128.0.1', True),
                          ('10.0.0.1', False), ('127.0.0.1', False), ('0.0.0.0', False),
                          ('172.16.0.1', False), ('192.168.1.1', False), ('169.254.1.1', False),
                          ('100.64.0.1', False), ('198.18.0.1', False), ('224.0.0.1', False),
                          ('1.2.3', False), ('example.com', False), ('', False)]:
            self.assertEqual(shell(f"is_public_ipv4 '{value}'").returncode == 0, ok, value)

    def test_color_depth(self):
        for setting, env, depth in (('2', {}, '256'), ('0', {}, '0'), ('1', {'TERM': 'xterm-256color'}, '0')):
            # 标准输出是管道：没加 --color 就不上色
            result = shell(f'USE_COLOR={setting}; color_depth 1; echo "$COLOR_DEPTH"', env=env)
            self.assertEqual(result.stdout.strip(), depth, setting)
        # 结果必须写进变量：$(color_depth 1) 里的标准输出是管道，在真终端里也会判成不上色
        self.assertNotRegex(SCRIPT.read_text(encoding='utf-8'), r'\$\(\s*color_depth')

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
                              env={**os.environ, 'EXITRAY_NO_INSTALL': '1'},
                              stdin=subprocess.DEVNULL, timeout=20)

    def test_version_and_help(self):
        version = re.search(r'^VERSION="([^"]+)"', SCRIPT.read_text(encoding='utf-8'), re.M).group(1)
        result = self.run_script('-V')
        self.assertEqual((result.returncode, result.stdout), (0, f'exitray {version}\n'))
        out = self.run_script('--help').stdout
        for word in ('exitray.sh', '--low-resource', '--exit-code', '--color', 'dev', 'game', 'none'):
            self.assertIn(word, out)
        self.assertNotIn('splitcheck', out.lower())

    def test_rejects_bad_values(self):
        for args in (['-c', 'finace'], ['-c', 'AI'], ['-c', 'ai,nope'], ['-n', '0'], ['-p', 'x'],
                     ['-r', 'mars'], ['--tracer', 'ping'], ['--nope'], ['-c']):
            result = self.run_script(*args)
            self.assertEqual(result.returncode, 1, args)
            self.assertIn('exitray:', result.stderr, args)
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
        root = Path(tempfile.mkdtemp(prefix='exitray-inst-'))
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

    @unittest.skipUnless(os.name == 'posix', '需要符号链接')
    def test_missing_tools_are_installed_in_one_go(self):
        root, env = self.fake_installer()
        result = shell('USE_ROUTE=1; USE_DNS_TEST=1; install_deps', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / 'log').read_text().splitlines(),
                         ['install -y -qq mtr-tiny dnsutils', 'update -qq', 'install -y -qq mtr-tiny dnsutils'])
        self.assertIn('已装好 mtr-tiny dnsutils', result.stderr)

    @unittest.skipUnless(os.name == 'posix', '需要符号链接')
    def test_image_tools_are_installed_when_asked_for(self):
        root, env = self.fake_installer()
        result = shell('USE_ROUTE=0; USE_DNS_TEST=0; IMAGE=1; install_deps', env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        line = 'install -y -qq librsvg2-bin fontconfig fonts-wqy-microhei'
        self.assertEqual((root / 'log').read_text().splitlines(), [line, 'update -qq', line])
        self.assertIn('已装好 librsvg2-bin', result.stderr)

    @unittest.skipUnless(os.name == 'posix', '需要符号链接')
    def test_install_only_what_the_run_needs_and_can_be_turned_off(self):
        root, env = self.fake_installer()
        # 不测 DNS 触发就不装 dig
        shell('USE_ROUTE=1; USE_DNS_TEST=0; install_deps', env=env)
        self.assertEqual((root / 'log').read_text().splitlines()[-1], 'install -y -qq mtr-tiny')
        (root / 'log').unlink()
        # 环境变量改名前叫 SPLITCHECK_NO_INSTALL，旧名字也要管用：不能因为改名就开始装软件
        for code, extra in (('INSTALL=0; install_deps', {}), ('install_deps', {'EXITRAY_NO_INSTALL': '1'}),
                            ('install_deps', {'SPLITCHECK_NO_INSTALL': '1'}),
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
        'split': ('2', r'【有分流】|结论：有分流'),
    }
    COVERAGE = {'direct': 0, 'inferred': 0, 'weak': 0, 'unknown': 0, 'unreachable': 0, 'fake_ip': 0,
                'dns_blocked': 0, 'ip_blocked': 0, 'split_by_ip': 0, 'diverted': 0, 'tls_failed': 0}

    def analyze(self, data, targets, env='', orgs=None, sniff=''):
        work = Path(tempfile.mkdtemp(prefix='exitray-test-'))
        self.addCleanup(shutil.rmtree, work, True)
        self.work = work
        write(work / 'rows.tsv', data)
        write(work / 'targets.txt', ''.join(f'{c} {n}\n' for c, n in targets))
        write(work / 'env.base', self.ENV + env)
        write(work / 'sniff.tsv', sniff)
        cases = ' '.join(f"{ip}) org='{o}' ;;" for ip, o in (orgs or {}).items())
        self.setup_code = textwrap.dedent(f"""\
            WORK='{posix(work)}'; BASE_IP=8.8.8.8
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
        self.assertEqual(data['coverage'], {**self.COVERAGE, 'direct': 1})
        self.assertEqual((data['exit_pool'], data['intercepted'], data['system_dns_down']), ([], False, False))

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
        """复测的行。None 是和当初一样的读数，否则给出第 6 列起的内容。"""
        return [row[:4] + (f'r{k}',) + row[5:] if r is None else row[:4] + (f'r{k}',) + r
                for k, r in enumerate(results, 1)]

    @staticmethod
    def ip_entry(ip, exits, state, connected, attempts, diverted=None):
        """JSON 里一个 IP 的结果。"""
        return {'ip': ip, 'exit_ids': exits, 'reachable': None if state == '-' else state != 'dead', 'state': None if state == '-' else state,
                'connected': connected, 'attempts': attempts, 'diverted': diverted}

    def test_partly_unreachable_target_is_a_block(self):
        # 加密 DNS 解析到的旧网段复测两次都连不上，系统 DNS 给的新网段正常：像是按 IP 拦截
        self.analyze(rows(*self.calibration(), self.DEAD_E, *self.retests(self.DEAD_E, None, None), self.LIVE_P),
                     [('meta', 'f.example')])
        self.assert_verdict('blocked')
        data = self.json()
        target = data['targets'][0]
        self.assertEqual(target['reach'], 'partial')
        self.assertEqual(target['ips'], [self.ip_entry('31.13.1.1', [], 'dead', 0, 3),
                                         self.ip_entry('57.144.1.1', ['A'], 'ok', 1, 1)])
        self.assertEqual(data['coverage']['ip_blocked'], 1)
        text = self.text()
        self.assertIn('1 个目标有部分 IP 连不上', text)
        self.assertIn('部分不通', text)
        self.assertIn('连不上的网段：31.13.1.0/24', text)
        # 每个网段连上几次、试了几次。路由和校准线路一样，没有改道
        self.assertRegex(text, r'31\.13\.1\.0/24 +✗ 连不上 +0/3 +- +f\.example')
        self.assertRegex(text, r'57\.144\.1\.0/24 +✓ A +1/1 +- +f\.example')
        # 每个 IP 的结果只在 -v 时列
        self.assertNotRegex(text, r'31\.13\.1\.1 +0/3')
        self.assertRegex(self.run_report('VERBOSE=1 report_text'), r'f\.example +31\.13\.1\.1 +0/3 +✗ 连不上')
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
        # 三次里两次连不上：不算拦截，但逐 IP 的结果里要看得出不稳定
        self.assertEqual(data['targets'][0]['ips'], [self.ip_entry('57.144.1.1', ['A'], 'flaky', 1, 3)])
        text = self.text()
        self.assertRegex(text, r'57\.144\.1\.0/24 +! 时通时断 A +1/3')
        self.assertIn('不稳定', text)

    def test_unreachable_reading_is_queued_for_retest(self):
        self.analyze(rows(*self.calibration(), self.DEAD_E, self.LIVE_P), [('meta', 'f.example')])
        self.text()
        # 连不上的那个 IP 要复测；同一个目标别的 IP 也再连两次，免得把碰巧连上的一次当成正常
        self.assertEqual((self.work / 'once.tsv').read_text(), 'T\tE\tmeta\tf.example\t31.13.1.1\tdead\n'
                                                               'T\tP\tmeta\tf.example\t57.144.1.1\tsib\n')
        # 没复测过就不算数
        target = self.json()['targets'][0]
        self.assertEqual(target['reach'], 'ok')
        self.assertEqual(target['ips'][0], self.ip_entry('31.13.1.1', [], '-', 0, 1))

    def test_target_with_every_ip_unreachable_does_not_change_the_verdict(self):
        dead = ('T', 'P', 'social', 'l.example', 1, '147.92.1.1', '-', '-', '000', '-', '-', 'dead')
        self.analyze(rows(*self.calibration(), self.direct(), dead, *self.retests(dead, None, None)),
                     [('ai', 'a.example'), ('social', 'l.example')])
        self.assert_verdict('clean')
        self.assertEqual({t['name']: t['reach'] for t in self.json()['targets']}, {'a.example': 'ok', 'l.example': 'dead'})
        text = self.text()
        self.assertIn('1 个目标的 IP 复测两次全都连不上', text)
        self.assertIn('换个网络打开就能确认：l.example', text)
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
        start = next(i for i, l in enumerate(lines) if l.startswith('  连通 '))
        table = [l.split() for l in lines[start + 2:start + 4]]
        self.assertEqual(table, [['31.13.87.0/24', '✗', '连不上', '0/9', '-', 'm0.example', '等', '3', '个'],
                                 ['57.144.x.x', '✓', 'A', '9/9', '-', 'm0.example', '等', '3', '个']])
        self.assertIn('每个 IP 的结果加 -v 查看', lines[start + 4])
        self.assertEqual(lines[start + 5], '')

    def check_layout(self, lines):
        # 概览的四张卡片：五行，每行一样宽，不超过 78 格
        tiles = [l for l in lines if l.startswith(('  ╭', '  │', '  ╰'))]
        self.assertEqual(len(tiles), 5, tiles)
        self.assertEqual({cells(l) for l in tiles}, {77}, tiles)
        for title in ('出口', 'DNS', '连通', '证据'):
            self.assertIn(f'╭ {title} ─', tiles[0])
        # 分区标题一样长
        rules = [l for l in lines if re.match(r'  \S.* ─{6,}', l) and not l.startswith('  ╭')]
        self.assertGreaterEqual(len(rules), 4, lines)
        self.assertEqual({cells(l) for l in rules}, {78}, rules)
        # 整份报告不超过 78 格，窄终端不折行
        self.assertEqual([l for l in lines if cells(l) > 78], [])

    def test_report_layout(self):
        self.analyze(rows(*self.calibration(), self.DEAD_E, *self.retests(self.DEAD_E, None, None), self.LIVE_P),
                     [('meta', 'f.example')])
        lines = self.text().splitlines()
        self.check_layout(lines)
        # 字标三行，右边是标题、主机名和概况
        self.assertIn('分流检测报告', lines[1])
        self.assertIn('host1 · 2026-11-06 10:00:00', lines[2])
        self.assertIn('1 个目标 · 用时 12 秒', lines[3])
        # 没有目标的分类不列
        self.assertFalse([l for l in lines if l.lstrip().startswith(('AI', 'Telegram'))], lines)
        # 概览每格一个目标。没有颜色时直接写出口字母：系统 DNS 那一格走 A，加密 DNS 那一格连不上
        self.assertTrue(any(re.fullmatch(r'  Meta +1   A {13}!', l) for l in lines), lines)
        self.assertTrue(any('A 默认' in l and '! 连不上' in l for l in lines))

    def test_colour_report_has_the_same_layout(self):
        self.analyze(self.split_data(), [('meta', 'f.example'), ('ai', 'g.example'), ('telegram', '149.154.175.50')],
                     orgs={'9.9.9.9': 'AS64501 Other Transit'})
        coloured = self.run_report('USE_COLOR=2; report_text')
        self.assertIn('\x1b[38;5;', coloured)
        self.assertIn('\x1b[48;5;', coloured)  # 结论和出口字母是色块
        lines = plain(coloured).splitlines()
        self.check_layout(lines)
        self.assertNotIn('\x1b', self.text())
        # 有颜色时每格是方块，按出口上色；没有颜色时是字母
        self.assertTrue(any(re.fullmatch(r'  Meta +1   ■ {13}■', l) for l in lines), lines)
        # NO_COLOR 和 --no-color 一样不用颜色，--color 可以强制
        self.assertNotIn('\x1b', self.run_report('USE_COLOR=1; NO_COLOR=1 report_text'))

    def test_long_names_and_many_targets_stay_inside_the_width(self):
        # 很长的域名、主机名、运营商名，和一个分类里很多目标，都不能把版式撑破
        names = [('ai', f'a-rather-long-subdomain-number-{k}.some-long-domain-name.example') for k in range(40)]
        rs = [*self.calibration()]
        for k, (_, name) in enumerate(names):
            rs.append(('T', 'P', 'ai', name, 1, f'1.1.{k}.2', '-' if k % 3 else '8.8.8.8', '-' if k % 3 else 'cloudflare',
                       '200' if k % 3 else '-', '-', '10.0.0.1 10.9.9.9 5.5.5.5' if k % 3 else '10.0.0.1 1.2.3.4', 'ok'))
        self.analyze(rows(*rs), names, env='host\ta-very-long-host-name-that-goes-on-and-on.example.com\n',
                     orgs={'8.8.8.8': 'AS64500 An Operator With A Very Long Registered Company Name Limited Liability'})
        for call in ('report_text', 'BRIEF=1 report_text'):
            lines = self.run_report(call).splitlines()
            self.assertEqual([l for l in lines if cells(l) > 78], [], call)
        # -v 最后的每轮明细带着整条路径，本来就宽；它之前的部分照样不能超
        lines = self.run_report('VERBOSE=1 report_text').split('  每轮明细 ')[0].splitlines()
        self.assertEqual([l for l in lines if cells(l) > 78], [])

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
                    ('T', 'P', 'meta', 'f.example', 1, '2.2.2.2', '9.9.9.9', 'meta', '-', '-', '10.0.0.2 5.6.7.8'),
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
        self.assertIs(by_name['f.example']['dns_flip'], True)
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
        self.assertEqual((self.work / 'once.tsv').read_text(), 'T\tP\tai\ta.example\t1.1.1.2\texit\n')

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
        line = '10.0.0.1 10.80.0.1'
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
        self.assertEqual((self.work / 'once.tsv').read_text(), 'T\tP\tai\ta.example\t1.1.1.2\texit\n')

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

    SNI_IP = '34.117.59.81'

    def sni_rows(self, sniff, round_=0, group='ai'):
        """每行“域名 出口 状态码”的嗅探结果，写成 N 行读数。"""
        return [('N', 'E', group, name, round_, self.SNI_IP, ex, 'plain', code, '-', '-')
                for name, ex, code in (line.split('\t') for line in sniff.splitlines())]

    def sniff_report(self, sniff, *more, names=(('ai', 'a.example'),)):
        self.analyze(rows(*self.calibration(), self.direct(), *self.sni_rows(sniff), *more), list(names),
                     env='sniff_base\t8.8.8.8\n', sniff=sniff)
        return self.text()

    def test_sni_unchanged(self):
        text = self.sniff_report('a.example\t8.8.8.8\t200\nb.example\t8.8.8.8\t200\n')
        self.assertIn('2 个域名放进 SNI，出口都没变', text)
        self.assertNotIn('没连上', text)

    def test_sni_exit_changed(self):
        text = self.sniff_report('a.example\t9.9.9.9\t200\nb.example\t8.8.8.8\t200\n')
        self.assertIn(squash('1/2 个域名出口变了：a.example → B'), squash(text))
        # 换了 SNI 才出现的出口同样是出口：进结论，明细里标出来
        self.assert_verdict('split')
        self.assertIn('1/2 个域名换了 SNI 出口就变', text)
        self.assertRegex(text, r'a\.example +A +- +直接·Cloudflare +SNI→B')
        data = self.json()
        self.assertEqual([e['ip'] for e in data['exits']], ['8.8.8.8', '9.9.9.9'])
        self.assertEqual(data['targets'][0]['sni_exit_id'], 'B')
        self.assertEqual((data['sni_test']['changed'], data['sni_test']['moved']), (1, 0))
        self.assertIn('SNI：1/2 个域名换了 SNI 出口就变', self.summary())
        self.assertIn('换 SNI 走 B', self.markdown())
        # 只出现过这一次，先排进复测
        self.assertEqual((self.work / 'once.tsv').read_text(), f'N\tE\tai\ta.example\t{self.SNI_IP}\texit\n')

    def test_one_off_sni_exit_that_is_gone_on_retest_does_not_count(self):
        retest = self.sni_rows('a.example\t8.8.8.8\t200\n', 'r1') + self.sni_rows('a.example\t8.8.8.8\t200\n', 'r2')
        text = self.sniff_report('a.example\t9.9.9.9\t200\nb.example\t8.8.8.8\t200\n', *retest)
        self.assert_verdict('clean')
        self.assertIn('2 个域名放进 SNI，出口都没变', text)
        self.assertNotIn('SNI→', text)
        self.assertEqual([u['ip'] for u in self.json()['unstable_exits']], ['9.9.9.9'])
        self.assertIsNone(self.json()['targets'][0]['sni_exit_id'])

    def test_sni_exit_seen_again_on_retest_counts(self):
        retest = self.sni_rows('a.example\t9.9.9.9\t200\n', 'r1') + self.sni_rows('a.example\t9.9.9.9\t200\n', 'r2')
        self.sniff_report('a.example\t9.9.9.9\t200\nb.example\t8.8.8.8\t200\n', *retest)
        self.assert_verdict('split')
        self.assertEqual({e['ip']: e['seen'] for e in self.json()['exits']}['9.9.9.9'], 3)
        self.assertEqual((self.work / 'once.tsv').read_text(), '')

    def test_target_that_changes_exit_with_its_sni_counts_as_that_exit(self):
        # 钉 IP 借 Akamai 的域名取到的回显是 A；把目标自己的域名放进 SNI，出口却是 B。
        # 真实访问时带的是它自己的 SNI，走的是 B。没有别的证据的目标（m.example）也一样
        path = '10.0.0.1 1.2.3.4'
        self.analyze(rows(*self.calibration(), self.direct(),
                          ('T', 'P', 'stream', 'n.example', 1, '2.2.2.2', '8.8.8.8', 'akamai', '-', '-', path),
                          ('T', 'P', 'stream', 'm.example', 1, '2.2.2.3', '-', '-', '200', '-', '-', 'ok'),
                          *self.sni_rows('n.example\t9.9.9.9\t200\nm.example\t9.9.9.9\t200\n', group='stream'),
                          *self.sni_rows('a.example\t8.8.8.8\t200\n')),
                     [('ai', 'a.example'), ('stream', 'n.example'), ('stream', 'm.example')], env='sniff_base\t8.8.8.8\n')
        self.assert_verdict('split')
        by_name = {t['name']: t for t in self.json()['targets']}
        for name in ('n.example', 'm.example'):
            found = by_name[name]
            self.assertEqual((found['class'], found['sni_exit_id']), ('sni', 'B'), name)
            self.assertEqual((found['system_dns']['exit'], found['system_dns']['evidence'], found['system_dns']['method']),
                             ('9.9.9.9', 'direct', 'sni'), name)
        self.assertEqual((by_name['a.example']['class'], by_name['a.example']['sni_exit_id']), ('none', None))
        text = self.text()
        self.assertRegex(text, r'n\.example +B +- +直接·SNI +按SNI')
        self.assertRegex(text, r'm\.example +B +- +直接·SNI +按SNI')
        # 分类概览里这两个目标算在 B 上
        self.assertTrue(any(re.fullmatch(r'  流媒体 +2   BB', l) for l in text.splitlines()), text)
        self.assertIn('2/3 个域名换了 SNI 出口就变', text)
        self.assertIn('按 SNI', self.markdown())

    def test_evidence_from_the_targets_own_page_wins_over_sni(self):
        # Cloudflare 的回显是在目标自己的域名上取的，本来就带着它的 SNI：两边不一样时以它为准，
        # 换了 SNI 看到的出口只在备注里提一句
        self.analyze(rows(*self.calibration(), self.direct(),
                          *self.sni_rows('a.example\t9.9.9.9\t200\nb.example\t9.9.9.9\t200\n')),
                     [('ai', 'a.example')], env='sniff_base\t8.8.8.8\n')
        target = self.json()['targets'][0]
        self.assertEqual((target['class'], target['system_dns']['exit'], target['sni_exit_id']), ('none', '8.8.8.8', 'B'))
        self.assertRegex(self.text(), r'a\.example +A +- +直接·Cloudflare +SNI→B')

    def test_sni_answer_from_somewhere_else_is_a_finding(self):
        # 有应答却不是回显：连接被按 SNI 转去了别的服务器，这正是这项测试要抓的
        text = self.sniff_report('a.example\t-\t404\nb.example\t8.8.8.8\t200\n')
        self.assertIn(squash('1/2 个域名的连接被转去了别处'), squash(text))
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

    TCP_DEAD = ('-', '-', '-', '-', '-', 'dead')

    def test_dead_ips_whose_route_was_diverted_are_an_upstream_block(self):
        # 目标的 IP 全都连不上，光看这个分不清是谁的问题。但路由在第 2 跳的内网段就离开了已确认的
        # 线路，说明是上游把这个 IP 导去了别处
        dead = ('T', 'P', 'meta', 'f.example', 1, '31.13.1.1', '-', '-', '000', '-', '10.0.0.1 10.80.0.1 ?', 'dead')
        retest = ('31.13.1.1',) + self.TCP_DEAD
        self.analyze(rows(*self.calibration(), self.direct(), dead, *self.retests(dead, retest, retest)),
                     [('ai', 'a.example'), ('meta', 'f.example')])
        self.assert_verdict('blocked')
        data = self.json()
        target = data['targets'][1]
        self.assertEqual(target['reach'], 'dead')
        self.assertEqual(target['ips'], [self.ip_entry('31.13.1.1', [], 'dead', 0, 3, {'hop': 2, 'ip': '10.80.0.1'})])
        self.assertEqual((data['coverage']['ip_blocked'], data['coverage']['diverted']), (1, 1))
        text = self.text()
        self.assertIn('1 个目标全部 IP 连不上，且路由在内网段改了道', text)
        self.assertIn('1 个网段在第 2 跳改道，走 10.80.0.1', text)
        self.assertRegex(text, r'31\.13\.1\.0/24 +✗ 连不上 +0/3 +第 2 跳改道 +f\.example')
        self.assertNotIn('分不清是目标挂了还是被拦', text)
        self.assertIn('1 个目标全部 IP 连不上且路由改道', self.summary())
        self.assertIn('全部 IP 连不上，路由改道 |', self.markdown())

    def test_dead_ips_on_the_usual_route_are_not_blamed_on_the_upstream(self):
        # 路由和已确认的线路一样，只是连不上：可能是目标自己挂了，不下结论
        dead = ('T', 'P', 'meta', 'f.example', 1, '31.13.1.1', '-', '-', '000', '-', '10.0.0.1 1.2.3.4', 'dead')
        retest = ('31.13.1.1',) + self.TCP_DEAD
        self.analyze(rows(*self.calibration(), self.direct(), dead, *self.retests(dead, retest, retest)),
                     [('ai', 'a.example'), ('meta', 'f.example')])
        self.assert_verdict('clean')
        self.assertIsNone(self.json()['targets'][1]['ips'][0]['diverted'])
        self.assertIn('分不清是目标挂了还是被拦', self.text())

    def test_route_diverted_but_reachable_is_weak_evidence(self):
        # 改了道还连得上，但没有回显：出口多半不是默认的那个，只能算弱推断，并且标出改道
        self.analyze(rows(*self.calibration(), self.direct(),
                          ('T', 'P', 'meta', 'f.example', 1, '57.145.1.1', '-', '-', '200', '-', '10.0.0.1 10.80.0.1 5.5.5.5', 'ok')),
                     [('ai', 'a.example'), ('meta', 'f.example')])
        self.assert_verdict('inconclusive')
        data = self.json()
        self.assertEqual(data['targets'][1]['system_dns']['evidence'], 'weak')
        self.assertEqual(data['targets'][1]['ips'], [self.ip_entry('57.145.1.1', ['A'], 'ok', 1, 1, {'hop': 2, 'ip': '10.80.0.1'})])
        text = self.text()
        self.assertIn('还连得上，出口未知', text)
        self.assertRegex(text, r'f\.example +A\? +- +弱推断 +改道')
        # 概览里弱推断的那一格和证据确凿的分开画
        self.assertTrue(any(re.fullmatch(r'  Meta +1   a', l) for l in text.splitlines()), text)
        self.assertIn('小写 弱推断', text)

    def test_private_hop_seen_on_another_confirmed_path_is_not_a_diversion(self):
        # 内网有多路径：目标走的第二跳和相同跳数最多的那条校准路径不一样，但它在别的已确认路径的
        # 同一位置出现过，是这条线路自己的另一条路，不能算改道
        self.analyze(rows(('C', 'E', 'cal', 'ipinfo.io', 0, '1.1.1.1', '8.8.8.8', 'plain', '-', '-', '10.0.0.1 10.1.1.1 5.5.5.5'),
                          ('C', 'E', 'cal', 'ident.me', 0, '1.1.1.9', '8.8.8.8', 'plain', '-', '-', '10.0.0.1 10.1.1.2 6.6.6.6'),
                          ('T', 'P', 'bank', 'b.example', 1, '1.1.1.3', '-', '-', '200', '-', '10.0.0.1 10.1.1.2 5.5.5.5', 'ok')),
                     [('bank', 'b.example')])
        self.assert_verdict('clean')
        self.assertEqual(self.json()['targets'][0]['system_dns']['evidence'], 'inferred')

    def test_private_hop_deep_in_the_path_is_not_a_diversion(self):
        # 第 5 跳才出现的内网地址多半是运营商骨干网自己的，不算改道
        self.analyze(rows(('C', 'E', 'cal', 'ipinfo.io', 0, '1.1.1.1', '8.8.8.8', 'plain', '-', '-', '10.0.0.1 1.2.3.4 1.2.3.5 1.2.3.6 1.2.3.7'),
                          ('T', 'P', 'bank', 'b.example', 1, '1.1.1.3', '-', '-', '200', '-', '10.0.0.1 1.2.3.4 1.2.3.5 1.2.3.6 10.200.1.1', 'ok')),
                     [('bank', 'b.example')])
        self.assertEqual(self.json()['targets'][0]['system_dns']['evidence'], 'inferred')

    def pool_rows(self, *exits):
        """同一个中立回显连问几次看到的出口。"""
        return [('S', 'E', 'stab', '1.1.1.1', f's{k}', '-', ex, 'trace', '-', '-', '-') for k, ex in enumerate(exits, 1)]

    def test_rotating_exit_pool_is_one_default_exit(self):
        # 同一个目标连问几次，出口在两个 IP 之间换：是出口池或多线负载均衡，不是按目标分流。
        # 不合并的话，a.example 会被说成“明文 DNS 触发”
        path = '10.0.0.1 1.2.3.4'
        self.analyze(rows(*self.calibration(), *self.pool_rows('8.8.8.8', '8.8.9.9', '8.8.8.8', '8.8.9.9', '8.8.8.8'),
                          ('T', 'E', 'ai', 'a.example', 1, '1.1.1.2', '8.8.8.8', 'cloudflare', '-', '-', path),
                          ('T', 'P', 'ai', 'a.example', 1, '1.1.1.2', '8.8.9.9', 'cloudflare', '-', '-', path),
                          ('T', 'P', 'ai', 'b.example', 1, '1.1.1.3', '8.8.9.9', 'cloudflare', '-', '-', path)),
                     [('ai', 'a.example'), ('ai', 'b.example')])
        self.assert_verdict('clean')
        data = self.json()
        self.assertIs(data['split'], False)
        self.assertEqual([e['ip'] for e in data['exits']], ['8.8.8.8'])
        self.assertEqual(sorted(e['ip'] for e in data['exit_pool']), ['8.8.8.8', '8.8.9.9'])
        self.assertEqual({t['class'] for t in data['targets']}, {'none'})
        text = self.text()
        self.assertIn('默认出口在 2 个 IP 之间轮换', text)
        self.assertIn('~ 出口池', text)
        self.assertIn('8.8.9.9（', text)
        self.assertIn('默认出口是 2 个 IP 的出口池', self.summary())
        self.assertIn('默认出口是 2 个 IP 的出口池', self.markdown())

    def test_exit_outside_the_pool_is_still_a_split(self):
        path = '10.0.0.1 1.2.3.4'
        self.analyze(rows(*self.calibration(), *self.pool_rows('8.8.8.8', '8.8.9.9', '8.8.8.8', '8.8.9.9'),
                          ('T', 'P', 'ai', 'a.example', 1, '1.1.1.2', '8.8.9.9', 'cloudflare', '-', '-', path),
                          ('T', 'E', 'meta', 'f.example', 1, '2.2.2.2', '9.9.9.9', 'meta', '-', '-', '10.0.0.2 5.6.7.8'),
                          ('T', 'P', 'meta', 'f.example', 1, '2.2.2.2', '9.9.9.9', 'meta', '-', '-', '10.0.0.2 5.6.7.8')),
                     [('ai', 'a.example'), ('meta', 'f.example')])
        self.assert_verdict('split')
        data = self.json()
        self.assertEqual([e['ip'] for e in data['exits']], ['8.8.8.8', '9.9.9.9'])
        self.assertEqual({t['name']: t['class'] for t in data['targets']}, {'a.example': 'none', 'f.example': 'static'})

    def test_single_odd_reading_does_not_make_a_pool(self):
        # 连问几次里只有一次冒出了另一个出口：可能是偶发的读数，而那个出口正是别的目标的分流出口。
        # 不能因此把它并进默认出口，否则真的分流就被吞掉了
        self.analyze(rows(*self.calibration(), *self.pool_rows('8.8.8.8', '9.9.9.9', '8.8.8.8', '8.8.8.8', '8.8.8.8'),
                          self.direct(),
                          ('T', 'E', 'meta', 'f.example', 1, '2.2.2.2', '9.9.9.9', 'meta', '-', '-', '10.0.0.2 5.6.7.8'),
                          ('T', 'P', 'meta', 'f.example', 1, '2.2.2.2', '9.9.9.9', 'meta', '-', '-', '10.0.0.2 5.6.7.8')),
                     [('ai', 'a.example'), ('meta', 'f.example')])
        self.assert_verdict('split')
        data = self.json()
        self.assertEqual(data['exit_pool'], [])
        self.assertEqual([e['ip'] for e in data['exits']], ['8.8.8.8', '9.9.9.9'])
        self.assertEqual(data['targets'][1]['class'], 'static')

    def test_stable_baseline_is_not_a_pool(self):
        self.analyze(rows(*self.calibration(), *self.pool_rows('8.8.8.8', '8.8.8.8', '8.8.8.8'), self.direct()),
                     [('ai', 'a.example')])
        self.assert_verdict('clean')
        self.assertEqual(self.json()['exit_pool'], [])
        self.assertNotIn('出口池', self.text())

    def test_tls_failure_is_not_an_ip_block(self):
        # TCP 连得上、握手不成：不是按 IP 拦截，也不算连不上
        tls = ('T', 'P', 'meta', 'f.example', 1, '57.144.1.1', '-', '-', '000', '-', '10.0.0.1 1.2.3.4', 'tls')
        retest = ('57.144.1.1', '-', '-', '000', '-', '-', 'tls')
        self.analyze(rows(*self.calibration(), self.direct(), tls, *self.retests(tls, retest, retest)),
                     [('ai', 'a.example'), ('meta', 'f.example')])
        self.assert_verdict('clean')
        data = self.json()
        self.assertEqual(data['targets'][1]['reach'], 'ok')
        self.assertEqual(data['targets'][1]['ips'], [self.ip_entry('57.144.1.1', ['A'], 'tls', 3, 3)])
        self.assertEqual((data['coverage']['tls_failed'], data['coverage']['unreachable'], data['coverage']['ip_blocked']), (1, 0, 0))
        text = self.text()
        self.assertIn('1 个目标 TCP 连得上、TLS 握手不成', text)
        self.assertRegex(text, r'57\.144\.1\.0/24 +! TLS 不通 +3/3')
        # 握手不成的读数也要复测
        self.analyze(rows(*self.calibration(), tls), [('meta', 'f.example')])
        self.text()
        self.assertEqual((self.work / 'once.tsv').read_text(), 'T\tP\tmeta\tf.example\t57.144.1.1\ttls\n')

    def test_ips_never_tried_are_not_counted_as_reachable(self):
        # 一个 IP 复测两次都连不上，另一个只有路由、没试过连通：没试过的不能当成连得上，
        # 这个目标不能因此算成“部分 IP 连不上”
        dead = ('T', 'E', 'meta', 'f.example', 1, '31.13.1.1', '-', '-', '000', '-', '10.0.0.1 1.2.3.4', 'dead')
        self.analyze(rows(*self.calibration(), dead, *self.retests(dead, None, None),
                          ('T', 'P', 'meta', 'f.example', 1, '57.144.1.1', '-', '-', '-', '-', '10.0.0.1 1.2.3.4', '-')),
                     [('meta', 'f.example')])
        data = self.json()
        target = data['targets'][0]
        self.assertEqual(target['reach'], 'dead')
        self.assertEqual(target['ips'][1], self.ip_entry('57.144.1.1', ['A'], '-', 0, 0))
        self.assertEqual(data['verdict'], 'clean')
        self.assertRegex(self.text(), r'57\.144\.1\.0/24 +· 没试过 A +0/0')

    def test_system_dns_exit_on_another_ip_is_not_called_dns_triggered(self):
        # 系统 DNS 解析到的 IP 走分流，加密 DNS 解析到的是另一个 IP、走默认出口：可能是明文查询
        # 触发的，也可能那个 IP 本来就在名单里，不能说成“DNS 触发”
        self.analyze(rows(*self.calibration(),
                          ('C', 'E', 'cal', 'ident.me', 0, '1.1.1.9', '8.8.8.8', 'plain', '-', '-', '10.0.0.1 1.2.3.4'),
                          ('T', 'E', 'ai', 'g.example', 1, '3.3.3.3', '8.8.8.8', 'google', '-', '-', '10.0.0.1 1.2.3.4'),
                          ('T', 'P', 'ai', 'g.example', 1, '3.3.3.4', '9.9.9.9', 'google', '-', '-', '10.0.0.2 5.6.7.8'),
                          ('T', 'P', 'ai', 'h.example', 1, '3.3.3.5', '9.9.9.9', 'google', '-', '-', '10.0.0.2 5.6.7.8')),
                     [('ai', 'g.example'), ('ai', 'h.example')])
        self.assert_verdict('split')
        target = self.json()['targets'][0]
        self.assertEqual((target['class'], target['dns_flip']), ('dns', False))
        text = self.text()
        self.assertIn('DNS相关', text)
        self.assertNotIn('DNS触发', text)
        self.assertIn('1 个目标系统 DNS 解析到的 IP 走分流', text)
        self.assertIn('DNS 相关', self.markdown())

    def test_broken_system_resolver_is_not_selective_blocking(self):
        # 系统 DNS 对几乎所有域名都不给地址，是解析器本身用不了，不是有选择的屏蔽
        rs, names = [*self.calibration()], []
        for k in range(1, 8):
            names.append(('bank', f'b{k}.example'))
            rs.append(('T', 'E', 'bank', f'b{k}.example', 1, f'4.4.4.{k}', '8.8.8.8', 'cloudflare', '-', '-', '10.0.0.1 1.2.3.4'))
            rs.append(('T', 'P', 'bank', f'b{k}.example', 1, '-', '-', 'dns', '-', '-', '-'))
        self.analyze(rows(*rs), names)
        self.assert_verdict('inconclusive')
        data = self.json()
        self.assertIs(data['system_dns_down'], True)
        text = self.text()
        self.assertIn('解析器本身用不了', text)
        self.assertNotIn('被 DNS 屏蔽', text)
        self.assertIn('解析器本身用不了', self.summary())
        # 只有少数域名查不到，仍然是屏蔽
        self.analyze(rows(*rs[:3], *[self.direct(f'ok{k}.example', ip=f'1.1.2.{k}') for k in range(6)]),
                     [names[0]] + [('ai', f'ok{k}.example') for k in range(6)])
        self.assert_verdict('dns_tampered')

    def test_trigger_test_says_why_names_could_not_be_tested(self):
        self.analyze(rows(*self.calibration(), self.direct()), [('ai', 'a.example')], env='dns_hijack\t1\n')
        write(self.work / 'trigger.tsv', 'ai\ta.example\t5.5.5.5\t8.8.8.8\t8.8.8.8\tok\n'
                                         'ai\tb.example\t-\t-\t-\tmismatch\n'
                                         'ai\tc.example\t-\t-\t-\tmismatch\n'
                                         'ai\td.example\t-\t-\t-\tnoecho\n')
        text = squash(self.text())
        self.assertIn(squash('触发 0 / 可测 1'), text)
        self.assertIn(squash('另有 3 个测不了：2 个的明文应答里没有外地节点的 IP（53 端口被劫持，应答是劫持方给的），1 个拿不到回显'), text)
        tests = {t['name']: t['untestable'] for t in self.json()['dns_trigger_test']}
        self.assertEqual(tests, {'a.example': None, 'b.example': 'mismatch', 'c.example': 'mismatch', 'd.example': 'noecho'})

    def test_notable_targets_are_listed_and_the_rest_are_folded(self):
        data = [*self.calibration(), self.direct('a.example'), self.direct('b.example', ip='1.1.1.3'),
                self.direct('c.example', group='dev', ip='1.1.1.4'),
                ('T', 'P', 'ai', 'w.example', 1, '1.1.1.5', '-', '-', '200', '-', '10.0.0.1 10.9.9.9 5.5.5.5', 'ok')]
        names = [('ai', 'a.example'), ('ai', 'b.example'), ('ai', 'w.example'), ('dev', 'c.example')]
        self.analyze(rows(*data), names)
        text = self.text()
        self.assertIn('需要留意的 1 个', text)
        self.assertRegex(text, r'    w\.example +A\? ')
        self.assertNotRegex(text, r'    a\.example +A ')
        self.assertIn('其余 2 个正常', text)
        self.assertIn('a.example · b.example', text)
        self.assertIn('其余分类全部正常', text)
        self.assertIn('开发者 1', text)
        # -v 列出全部目标，-b 不列明细
        verbose = self.run_report('VERBOSE=1 report_text')
        self.assertRegex(verbose, r'    a\.example +A ')
        self.assertRegex(verbose, r'    c\.example +A ')
        self.assertNotIn('其余 2 个正常', verbose)
        self.assertNotIn('  明细 ', self.run_report('BRIEF=1 report_text'))

    def test_share_reports_mask_ips(self):
        self.analyze(self.split_data(), [('meta', 'f.example')])
        for report in (self.summary(), self.markdown()):
            self.assertNotIn('8.8.8.8', report)
            self.assertIn('8.8.*.*', report)

    def test_detail_order_follows_target_list(self):
        self.analyze(rows(*self.calibration(), self.direct('z.example'), self.direct('a.example', ip='1.1.1.3')),
                     [('ai', 'a.example'), ('ai', 'z.example')])
        self.assertEqual([t['name'] for t in self.json()['targets']], ['a.example', 'z.example'])

    def test_share_overview_masks_and_stops_after_the_grid(self):
        self.analyze(rows(*self.calibration(path='10.0.0.1 1.2.3.4'), self.direct()), [('ai', 'a.example')])
        full = plain(self.run_report('USE_COLOR=2 report_text'))
        self.assertIn('8.8.8.8', full)
        share = plain(self.run_report('USE_COLOR=2 REPORT_SHARE=1 report_text'))
        self.assertIn('8.8.*.*', share)
        for needle in ('8.8.8.8', 'host1', '1.2.3.4', '线路', '\n  DNS ─', '明细'):
            self.assertNotIn(needle, share, needle)
        self.assertIn('每格一个目标', share)
        self.assertTrue(share.rstrip().endswith('github.com/YePiXpert/exitray'), share[-200:])
        # --no-mask 时不打码
        self.assertIn('8.8.8.8', plain(self.run_report('MASK=0 USE_COLOR=2 REPORT_SHARE=1 report_text')))

    def test_wordmark(self):
        logo = shell('printf "%s\\n" "${LOGO[@]}"').stdout.rstrip('\n').split('\n')
        # 三行一样宽
        self.assertEqual([cells(line) for line in logo], [26, 26, 26])
        self.analyze(rows(*self.calibration(), self.direct()), [('ai', 'a.example')])
        head = [line for line in self.run_report('USE_COLOR=0 report_text').split('\n') if line.strip()][:3]
        for row, line in zip(logo, head):
            self.assertTrue(line.startswith(f'  {row}   '), line)
        self.assertIn('分流检测报告', head[0])

        def codes(line):
            """字标那 26 格各自的色号。"""
            found = re.findall(r'\x1b\[38;5;(\d+)m[^\x1b]', line)[:26]
            self.assertEqual(len(found), 26, line)
            return found

        # 256 色：一格一个色号，从青到紫七个色号都用上，最后一格是最后一个色号
        colour = [line for line in self.run_report('USE_COLOR=2 report_text').split('\n') if line.strip()][:3]
        ramp = shell('printf "%s\\n" "${LOGO_RAMP[@]}"').stdout.split()
        for line in colour:
            got = codes(line)
            self.assertEqual(sorted(set(got), key=got.index), ramp)
            self.assertEqual((got[0], got[-1]), (ramp[0], ramp[-1]))
        # 启动画面的字标是 bash 画的，颜色要和报告里 awk 画的一模一样
        banner = shell('UI_DEPTH=256; ui_colors; ui_logo').stderr.rstrip('\n').split('\n')
        self.assertEqual([plain(line) for line in banner], [f'  {row}' for row in logo])
        self.assertEqual([codes(line) for line in banner], [codes(line) for line in colour])

    def test_render_svg(self):
        import xml.dom.minidom
        self.analyze(rows(*self.calibration(), self.direct()), [('ai', 'a.example')])
        svg = self.run_report('USE_COLOR=2 REPORT_SHARE=1 report_text > "$WORK/x.ansi"\nrender_svg "$WORK/x.ansi" ExitRay')
        doc = xml.dom.minidom.parseString(svg.encode('utf-8'))
        root = doc.documentElement
        self.assertEqual(root.tagName, 'svg')
        self.assertGreaterEqual(int(root.getAttribute('width')), 695)
        texts = [t.firstChild.data for t in doc.getElementsByTagName('text') if t.firstChild]
        # 每个字单独一个 text，汉字也是一个一个的；框线和方块画成了路径，不是文字
        for ch in ('分', '流', '检', '测', 'A', 'I'):
            self.assertIn(ch, texts, ch)
        for ch in ('─', '│', '■', '✓'):
            self.assertNotIn(ch, texts, ch)
        self.assertTrue(doc.getElementsByTagName('path'))
        # 结论的色块（无分流是绿色）画成了背景
        self.assertIn('#5fd787', [r.getAttribute('fill') for r in doc.getElementsByTagName('rect')])


class IntegrationTests(unittest.TestCase):
    """用假的 curl、mtr、dig、getent 跑完整流程。"""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='exitray-int-'))
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
                # 触发测试的明文查询：doh_far 里有的域名，给出和 DoH 一样的外地 IP。
                # 有 dig_local 时应答是按本地给的，像 53 端口被劫持之后那样
                if [[ -e $STUB_DIR/dig_local ]]; then echo 6.6.6.6; exit 0; fi
                for arg in "$@"; do
                  awk -v n="$arg" '$1 == n { print $2 }' "$STUB_DIR/doh_far" 2>/dev/null
                done ;;
            esac
        """)
        self.stub('nice', f"""
            echo "$*" >> '{posix(self.nice_log)}'
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
                'STUB_DIR': posix(self.state), 'STUB_LOG': posix(self.log),
                'STUB_DNSLOG': posix(self.dnslog), 'TMPDIR': posix(self.dir),
                'EXITRAY_NO_INSTALL': '1', **extra}

    def run_script(self, *args, **extra):
        return subprocess.run([BASH, posix(SCRIPT), *args], text=True, encoding='utf-8',
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              stdin=subprocess.DEVNULL, env=self.env(**extra), timeout=RUN_TIMEOUT)

    def targets(self, text='ai a.example\nai b.example\n'):
        path = self.dir / 'targets.txt'
        path.write_bytes(text.encode('utf-8'))
        return posix(path)

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
        self.assertEqual([p.name for p in self.dir.glob('exitray.*')], [])

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
            host = url.split('://')[1].split('/')[0].split(':')[0]
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
        self.assertEqual({i['ip']: (i['reachable'], i['connected'], i['attempts']) for i in target['ips']},
                         {'2.2.2.2': (False, 0, 3), '4.4.4.4': (True, 3, 3)})
        # 当初翻了一次页面；复测只看 TCP，再连两次。同一个目标另一个 IP 也再连两次
        self.assertEqual(len([r for r in self.requests('https://a.example/') if r['pin'] == '2.2.2.2']), 1)
        self.assertEqual(len(self.requests('http://2.2.2.2:443/')), 2)
        self.assertEqual(len(self.requests('http://4.4.4.4:443/')), 2)

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
        self.assertRegex(result.stdout, r'149\.154\.175\.0/24 +✗ 连不上 +0/4 +- +149\.154\.175\.50')
        # 两种解析方式各测一次，同一个 IP 再复测两次
        self.assertEqual(len(self.requests('http://149.154.175.50:443/')), 4)

    def test_untrusted_certificate_is_not_unreachable(self):
        # 自签 CA、证书链不全的站点：校验不过不等于连不上（实测里 chat.signal.org 就是这样被冤枉的）
        self.state_file('doh', 'a.example 2.2.2.2\n')
        self.state_file('sysdns', 'a.example 2.2.2.2\n')
        self.state_file('silent', '2.2.2.2\n')
        self.state_file('badcert', '2.2.2.2\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(self.targets('ai a.example\n')), '-j', '--exit-code')
        self.assertEqual(result.returncode, 0, result.stderr)
        target = json.loads(result.stdout)['targets'][0]
        self.assertEqual(target['reach'], 'ok')
        self.assertEqual([(i['ip'], i['state']) for i in target['ips']], [('2.2.2.2', 'ok')])
        pages = [r for r in self.requests('https://a.example/') if r['pin'] == '2.2.2.2']
        self.assertEqual({r['insecure'] for r in pages}, {'1'})

    def test_handshake_failure_is_told_apart_from_unreachable(self):
        # TCP 连得上、握手总是不成：单独记成 TLS 不通，不算按 IP 拦截
        self.state_file('doh', 'a.example 2.2.2.2\n')
        self.state_file('sysdns', 'a.example 2.2.2.2\n')
        self.state_file('silent', '2.2.2.2\n')
        self.state_file('tlsfail', '2.2.2.2\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script(*self.common(self.targets('ai a.example\nai b.example\n')), '-j', '--exit-code')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        target = data['targets'][0]
        self.assertEqual((target['reach'], target['ips'][0]['state'], target['ips'][0]['reachable']), ('ok', 'tls', True))
        self.assertEqual((data['coverage']['tls_failed'], data['coverage']['ip_blocked']), (1, 0))
        # 两轮各翻一次页面，再复测两次，复测也是翻页面
        self.assertEqual(len([r for r in self.requests('https://a.example/') if r['pin'] == '2.2.2.2']), 4)

    def test_later_rounds_still_check_that_the_ip_connects(self):
        # 第 2 轮不翻页面，但要连一次：没试过的 IP 不能当成连得上
        self.state_file('doh', 'a.example 3.3.3.3\n')
        self.state_file('sysdns', 'a.example 2.2.2.2\n')
        self.state_file('silent', '2.2.2.2\n3.3.3.3\n')
        self.state_file('dead', '2.2.2.2\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = self.run_script('-c', 'none', '-r', 'none', '-n', '2', '-f', self.targets('ai a.example\n'), '-j', '--exit-code')
        self.assertEqual(result.returncode, 2, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['verdict'], 'blocked')
        ips = {i['ip']: (i['state'], i['connected'], i['attempts']) for i in data['targets'][0]['ips']}
        # 2.2.2.2：第 1 轮翻页面、第 2 轮连一次、复测两次，都不通
        self.assertEqual(ips['2.2.2.2'], ('dead', 0, 4))
        self.assertEqual(ips['3.3.3.3'][0], 'ok')
        self.assertEqual(data['targets'][0]['system_dns']['evidence'], 'noconn')
        self.assertEqual(len(self.requests('http://2.2.2.2:443/')), 3)

    def test_rotating_exit_pool_is_not_a_split(self):
        # 每次回显轮流报两个出口：同一个目标连问几次就看得出来，合成一个默认出口
        self.state_file('pool', '8.8.8.8 8.8.9.9\n')
        result = self.run_script(*self.common(), '-j', '--exit-code')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual((data['verdict'], data['split']), ('clean', False))
        self.assertEqual(len(data['exits']), 1)
        self.assertEqual(sorted(e['ip'] for e in data['exit_pool']), ['8.8.8.8', '8.8.9.9'])
        self.assertEqual({t['class'] for t in data['targets']}, {'none'})
        # 发现在轮换就多问几次：开始 16 次，结束时再问
        self.assertGreaterEqual(len(self.requests('https://1.1.1.1/cdn-cgi/trace')), 17)

    def test_stable_exit_is_asked_only_a_few_times(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.assertEqual(self.run_script(*self.common(), '-j').returncode, 0)
        # 基线一次，开始 5 次，结束 3 次
        self.assertEqual(len(self.requests('https://1.1.1.1/cdn-cgi/trace')), 9)

    def test_host_rewriting_proxy_is_detected(self):
        # 有透明代理按 HTTP 的 Host 改写目的地时，靠 Host 认 CDN、取回显都不能信
        self.state_file('hostsniff', '7.7.7.7\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        args = self.common()
        result = self.run_script(*args, '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertIs(data['intercepted'], True)
        # 被转去别处的那个“出口”不能混进结果
        self.assertEqual([e['ip'] for e in data['exits']], ['8.8.8.8'])
        # 只有自检的那一次带着 Akamai 的 Host
        hosts = [line.split('\t')[4] for line in self.log.read_text().splitlines()]
        self.assertEqual(hosts.count('host=whatismyip.akamai.com'), 1)
        text = self.run_script(*args).stdout
        self.assertIn('有透明代理按 HTTP 的 Host 改写目的地', text)

    def test_trigger_test_records_why_a_name_was_not_testable(self):
        # 53 端口被劫持时，明文应答是劫持方按自己的位置给的，里面没有外地节点的 IP
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('doh_far', 'a.example 5.5.5.5\n')
        (self.state / 'dig_local').touch()
        (self.state / 'hijack').touch()
        args = self.common(self.targets('ai a.example\n'))
        result = self.run_script(*args, '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(t['name'], t['untestable']) for t in json.loads(result.stdout)['dns_trigger_test']],
                         [('a.example', 'mismatch')])
        self.assertIn(squash('1 个的明文应答里没有外地节点的 IP'), squash(self.run_script(*args).stdout))

    def test_plaintext_trigger_is_seen_even_when_the_list_is_slow(self):
        # 明文查询之后头一次回显还是老出口，过一会儿才换：要再看一次，不能漏掉
        self.state_file('doh_far', 'a.example 5.5.5.5\n')
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('exit_after', '5.5.5.5 2 9.9.9.9\n')
        result = self.run_script(*self.common(self.targets('ai a.example\n')), '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        trigger = {t['name']: (t['before'], t['after']) for t in data['dns_trigger_test']}
        self.assertEqual(trigger['a.example'], ('8.8.8.8', '9.9.9.9'))
        self.assertIs(data['dns_triggered'], True)

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
        # b.example 换了 SNI 才出现的出口只见过一次，要再问两次；还在，才算数
        self.assertEqual(tries, {'a.example': 2, 'b.example': 3, 'c.example': 2, 'd.example': 1})
        data = json.loads(result.stdout)
        self.assertEqual(data['verdict'], 'split')
        self.assertEqual({e['ip']: e['seen'] for e in data['exits']}['9.9.9.9'], 3)
        self.assertEqual({t['name']: t['sni_exit_id'] for t in data['targets']},
                         {'a.example': None, 'b.example': 'B', 'c.example': None, 'd.example': None})
        text = squash(self.run_script(*args).stdout)
        self.assertIn(squash('1/4 个域名出口变了：b.example → B'), text)
        self.assertIn(squash('1/4 个域名的连接被转去了别处，回来的不是回显服务的应答：a.example'), text)
        self.assertIn(squash('另有 1 个没连上'), text)
        self.assertIn(squash('1/4 个域名换了 SNI 出口就变'), text)

    def test_sni_rule_in_the_sample_makes_every_name_get_asked(self):
        # 每个分类先抽两个域名。抽样里有换了 SNI 出口就变的，说明按域名的规则确实存在，其余的也都问一遍
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('sni_exit', 'b.example 9.9.9.9\nd.example 9.9.9.9\n')
        args = self.common(self.targets('ai a.example\nai b.example\nai c.example\nai d.example\n'))
        result = self.run_script(*args, '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(sorted(r['sni'] for r in data['sni_test']['results']),
                         ['a.example', 'b.example', 'c.example', 'd.example'])
        self.assertEqual({t['name']: t['sni_exit_id'] for t in data['targets']},
                         {'a.example': None, 'b.example': 'B', 'c.example': None, 'd.example': 'B'})
        self.assertEqual(data['verdict'], 'split')
        # 两个域名都看到了这个出口，不用再复测
        self.assertEqual(len(self.requests('https://d.example/ip')), 1)

    def test_names_outside_the_sample_are_not_asked_when_the_sample_is_quiet(self):
        self.state_file('exit_for', 'default 8.8.8.8\n')
        args = self.common(self.targets('ai a.example\nai b.example\nai c.example\n'))
        result = self.run_script(*args, '-j')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(r['sni'] for r in json.loads(result.stdout)['sni_test']['results']), ['a.example', 'b.example'])
        self.assertEqual(self.requests('https://c.example/ip'), [])

    def test_sni_sniff_also_runs_through_a_socks_proxy(self):
        # 经节点测时，节点按域名分流最直接的证据就是 SNI 嗅探
        self.state_file('exit_for', 'default 8.8.8.8\n')
        self.state_file('sni_exit', 'a.example 9.9.9.9\nb.example 9.9.9.9\n')
        result = self.run_script(*self.common(), '-j', '-x', 'socks5h://127.0.0.1:1080')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual({r['sni']: r['exit'] for r in data['sni_test']['results']},
                         {'a.example': '9.9.9.9', 'b.example': '9.9.9.9'})
        self.assertEqual(data['verdict'], 'split')
        self.assertEqual({t['name']: t['sni_exit_id'] for t in data['targets']}, {'a.example': 'B', 'b.example': 'B'})
        # HTTP 代理钉不住 IP，这一项不测
        result = self.run_script(*self.common(), '-j', '-x', 'http://127.0.0.1:8080')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['sni_test']['results'], [])

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
        for args, needle in ((['-b'], '每格一个目标'), (['-v'], '每轮明细'), (['-m'], '# 分流检测报告'),
                             (['--no-mask', '-m'], '8.8.8.8'), (['-s'], '结论：'), (['--summary'], '证据：')):
            result = self.run_script(*self.common(), *args)
            self.assertEqual(result.returncode, 0, (args, result.stderr))
            self.assertIn(needle, result.stdout, args)
        # 默认的文字报告到“说明”就结束，摘要和 Markdown 只在加了 -s、-m 时输出
        result = self.run_script(*self.common())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('说明', result.stdout)
        for needle in ('分享摘要', 'ExitRay 分流检测 ·', 'Markdown', 'report.md'):
            self.assertNotIn(needle, result.stdout + result.stderr)

    def test_image_is_saved(self):
        import xml.dom.minidom
        self.state_file('exit_for', 'default 8.8.8.8\n')
        result = subprocess.run([BASH, posix(SCRIPT), *self.common(), '-i'], text=True, encoding='utf-8',
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                env=self.env(), cwd=self.dir, timeout=RUN_TIMEOUT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('说明', result.stdout)
        self.assertIn('图片已保存', result.stderr)
        images = sorted(self.dir.glob('exitray-report-*'))
        self.assertEqual(len(images), 1, images)
        image = images[0]
        self.assertIn(str(image.name), result.stderr)
        fonts = subprocess.run(['fc-list', ':lang=zh', 'family'], stdout=subprocess.PIPE, text=True).stdout \
            if shutil.which('fc-list') else ''
        if shutil.which('rsvg-convert') and fonts.strip():
            # 有 rsvg-convert 和中文字体（CI 的 linux 任务装了）就必须转出 PNG，不能悄悄退回 SVG
            self.assertEqual(image.suffix, '.png', result.stderr)
            self.assertEqual(image.read_bytes()[:8], b'\x89PNG\r\n\x1a\n')
        else:
            self.assertEqual(image.suffix, '.svg')
            xml.dom.minidom.parse(str(image))
            self.assertNotIn('8.8.8.8', image.read_text(encoding='utf-8'))

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
        env = self.env(TERM='xterm-256color')
        env.pop('NO_COLOR', None)
        pid, fd = pty.fork()
        if pid == 0:  # 子进程：有控制终端，走菜单分支，测的是内置的完整清单
            os.execve(BASH, [BASH, str(SCRIPT)], env)
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
        # 标准输出是终端，报告本身也要上色：结论是色块，不是纯文本的【无分流】
        self.assertIn('\x1b[48;5;78m', text)
        self.assertNotIn('【无分流】', text)
        # 报告到“说明”就结束，不再附分享摘要，也不再问要不要 Markdown
        self.assertIn('说明', text)
        self.assertNotIn('分享摘要', text)
        self.assertNotIn('Markdown', text)
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
            self.assertEqual([p.name for p in self.dir.glob('exitray.*')], [])
        finally:
            proc.kill()
            for pid in self.stuck():
                os.kill(pid, signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
