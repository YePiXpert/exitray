"""重新生成 README 的配图，并核对 README 里的文本样例。

配图都出自脚本自己的输出：用 fixtures.py 造的夹具跑脚本里真实的 analyze、judge 和报告函数，
菜单和进度用真实的界面函数画，再把带颜色的终端输出画成 SVG。夹具里的出口都是文档保留地址。

用法（在仓库根目录）：
  python docs/tools/build.py           重新生成 docs/*.svg，再核对 README
  python docs/tools/build.py --check   不写文件，只检查配图和 README 的文本样例是不是跟脚本的输出一致

和测试一样，TEST_BASH 可以指定 bash（Windows 上指到 Git 自带的 usr\\bin\\bash.exe），TEST_AWK 可以指定 awk。
"""
import difflib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True  # 不在 docs/tools 里留 __pycache__
import diagrams  # noqa: E402
import fixtures  # noqa: E402
import term2svg  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'splitcheck.sh'
DOCS = ROOT / 'docs'
README = ROOT / 'README.md'
BASH = os.environ.get('TEST_BASH', shutil.which('bash') or 'bash')
TEST_AWK = os.environ.get('TEST_AWK', '')


def posix(path):
    return Path(path).as_posix()


def bash(code, work):
    """在加载了脚本函数的 bash 里跑一段代码，WORK 指向 work 目录。"""
    prelude = f'export SPLITCHECK_SOURCE_ONLY=1\nsource "{posix(SCRIPT)}"\nWORK=\'{posix(work)}\'\n'
    if TEST_AWK:
        prelude += f'awk() {{ command {TEST_AWK} "$@"; }}\n'
    # 按字节读：进度那一行靠 \r 回到行首，文本模式会把单独的 \r 当成换行
    result = subprocess.run([BASH, '-c', prelude + code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        sys.exit(f'bash 出错（{result.returncode}）：{result.stderr.decode("utf-8", "replace").strip()}')
    return result.stdout.decode('utf-8').replace('\r', '')


# 跑分析和三种输出：纯文本报告、256 色报告、分享摘要
REPORT = r'''
BASE_IP=$(cat "$WORK/base")
cp "$WORK/env.base" "$WORK/env.tsv"
cat_labels > "$WORK/cats.txt"
analyze && judge || exit 9
: > "$WORK/exits_info.tsv"
while IFS=$'\t' read -r l ip seen def sig; do
  IFS=$'\t' read -r org cc city host kind < <(awk -F'\t' -v ip="$ip" '$1 == ip { print $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 }' "$WORK/info.tsv")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$l" "$ip" "$seen" "$def" "$sig" \
    "${org:--}" "${cc:--}" "${city:--}" "${host:--}" "${kind:--}" >> "$WORK/exits_info.tsv"
done < "$WORK/exits.tsv"
USE_COLOR=0 report_text > "$WORK/plain.txt"
USE_COLOR=2 report_text > "$WORK/color.txt"
report_share summary > "$WORK/summary.txt"
'''

# 菜单和进度：真实的界面函数，数字和 split 那份报告对得上
UI = r'''
# SECONDS 一直在走，跨过整秒时用时会多一秒。unset 之后它就是个普通变量，画出来的用时是固定的
unset SECONDS
SECONDS=1000
UI_DEPTH=256 UI=1
ui_colors
exec 2>&1
menu_draw
printf '\n  %s❯%s 请输入 [默认 1]: 1\n' "$U_C" "$U_R"
UI_ON=1
done_step() { STEP_LABEL=$1; STEP_T0=$((SECONDS - $3)); step_end "$2"; }
install_say '安装依赖 mtr-tiny dnsutils（apt-get，只装这一次；不想装加 --no-install）'
install_say '已装好 mtr-tiny dnsutils'
printf '\n'
done_step '确认出口' '203.0.113.63 · 地区 tw' 1
done_step '准备探测' '142 个目标 · 路由 mtr-icmp · 预计约 5 分钟' 1
done_step '校准出口' '已发现 1 个出口' 12
done_step '加密 DNS' '已发现 3 个出口' 133
done_step '明文 DNS 触发测试' '触发 4 / 可测 23' 49
done_step '系统 DNS 第 1/2 轮' '已发现 3 个出口' 54
# 还在跑的一步：88/142 的进度条
seq 1 88 > "$WORK/progress"
SPIN=2 STEP_LABEL='系统 DNS 第 2/2 轮' STEP_TOTAL=142 STEP_FILE=$WORK/progress STEP_BASE=0
STEP_T0=$((SECONDS - 27)) STEP_DETAIL='www.okx.com'
ui_paint
printf '\n'
'''

# 报告配图：文件名、场景、从哪一节开始（None 是从头）、到哪一节之前停、窗口标题
CROPS = [
    ('report-split.svg', 'split', None, 'DNS', 'splitcheck · 有分流的线路'),
    ('report-detail.svg', 'split', '明细', '其他检查', None),
    ('report-block.svg', 'block', None, 'DNS', 'splitcheck · DNS 被劫持、IP 段被拦的线路'),
    ('report-reach.svg', 'block', '连通', '明细', None),
]


def version():
    return re.search(r'^VERSION="([^"]+)"', SCRIPT.read_text(encoding='utf-8'), re.M).group(1)


def run_scenario(scenario):
    work = Path(tempfile.mkdtemp(prefix='splitcheck-docs-'))
    try:
        listing = bash("REGION=tw CATS='' TARGET_FILE=''\nload_targets\ncat \"$WORK/targets.txt\"\n", work)
        targets = [tuple(line.split()) for line in listing.splitlines() if line.strip()]
        fixtures.make(scenario, targets, work, version())
        bash(REPORT, work)
        read = lambda name: (work / name).read_text(encoding='utf-8').replace('\r', '')
        return {'plain': read('plain.txt'), 'color': read('color.txt'), 'summary': read('summary.txt')}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def section(lines, title, start=0):
    """报告里某一节标题所在的行号：“  标题 ────”。"""
    for i in range(start, len(lines)):
        if term2svg.strip(lines[i]).startswith(f'  {title} ─'):
            return i
    sys.exit(f'报告里找不到“{title}”这一节')


def crop(lines, first, stop):
    a = section(lines, first) if first else 0
    b = section(lines, stop, a + 1)
    return trim(lines[a:b])


def trim(lines):
    while lines and not term2svg.strip(lines[-1]).strip():
        lines = lines[:-1]
    while lines and not term2svg.strip(lines[0]).strip():
        lines = lines[1:]
    return lines


def images(outputs):
    work = Path(tempfile.mkdtemp(prefix='splitcheck-docs-'))
    try:
        ui = bash(UI, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    result = {
        'logo.svg': term2svg.logo(),
        'how.svg': diagrams.how(),
        'flow.svg': diagrams.flow(),
        'run.svg': term2svg.render(trim(ui.split('\n')), 'splitcheck'),
    }
    for name, scenario, first, stop, title in CROPS:
        result[name] = term2svg.render(crop(outputs[scenario]['color'].split('\n'), first, stop), title)
    return result


def readme_problems(outputs):
    """README 里 ```text 代码块的每一行，都要能在脚本的真实输出里找到。"""
    real = set()
    for out in outputs.values():
        for key in ('plain', 'summary'):
            real.update(line.rstrip() for line in out[key].splitlines())
    text = README.read_text(encoding='utf-8').replace('\r\n', '\n')
    missing = []
    for block in re.findall(r'```text\n(.*?)```', text, re.S):
        missing += [line for line in block.splitlines() if line.strip() and line.rstrip() not in real]
    return missing


def main():
    check = '--check' in sys.argv[1:]
    outputs = {scenario: run_scenario(scenario) for scenario in ('split', 'block')}
    problems = []
    for name, svg in images(outputs).items():
        path = DOCS / name
        old = path.read_text(encoding='utf-8').replace('\r\n', '\n') if path.exists() else None
        if old == svg:
            continue
        if check:
            diff = list(difflib.unified_diff((old or '').split('\n'), svg.split('\n'), f'docs/{name}', '重新生成的', n=0, lineterm=''))
            problems.append(f'docs/{name} 和脚本现在的输出不一致，运行 python docs/tools/build.py 重新生成\n'
                            + '\n'.join(line[:200] for line in diff[:24]))
        else:
            path.write_text(svg, encoding='utf-8', newline='\n')
            print(f'更新 docs/{name}')
    missing = readme_problems(outputs)
    if missing:
        problems.append('README 里这些行在脚本的输出里找不到：\n' + '\n'.join('  |' + line for line in missing))
    if problems:
        sys.exit('\n'.join(problems))
    print('配图和 README 的文本样例都跟脚本的输出一致')


if __name__ == '__main__':
    main()
