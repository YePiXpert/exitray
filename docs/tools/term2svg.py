"""把带 ANSI 颜色码的终端输出画成 SVG。

按终端的字符格排版：汉字占 2 格，其余占 1 格。框线、方块、对勾、箭头这些符号画成路径，
不依赖查看者机器上的字体；只有字母、数字和汉字是文字，每一段都写明起点和宽度。

由 build.py 调用：render(行, 标题) 画一段终端输出，logo(三行字标) 画字标。
"""
import html
import re
import unicodedata

CW, LH, FS = 8.4, 19, 14          # 每格宽、行高、字号
FS_WIDE = 15.4                    # 汉字的字号：两格宽 16.8，留一点字距
PAD_X, PAD_Y = 20, 18
BAR = 30                          # 窗口标题栏的高度
BG, FG, FRAME = '#14161b', '#d7dae0', '#262a33'
FONT = ("ui-monospace,'Cascadia Mono','SF Mono',Menlo,Consolas,'DejaVu Sans Mono','Liberation Mono',"
        "'PingFang SC','Hiragino Sans GB','Microsoft YaHei','Noto Sans CJK SC','Source Han Sans SC','WenQuanYi Micro Hei',monospace")
BASE16 = ['#1e1e1e', '#e06c75', '#98c379', '#e5c07b', '#61afef', '#c678dd', '#56b6c2', '#d4d4d4']
ESC = re.compile(r'\x1b\[([0-9;?]*)([A-Za-z])')

# 框线：每个字符从格子中心伸向哪几个方向
BOX = {'─': 'LR', '│': 'UD', '┌': 'RD', '┐': 'LD', '└': 'UR', '┘': 'UL', '├': 'UDR', '┤': 'UDL',
       '┬': 'LRD', '┴': 'LRU', '┼': 'UDLR', '╭': 'RD', '╮': 'LD', '╰': 'UR', '╯': 'UL', '━': 'LR'}
ROUND = set('╭╮╰╯')
BRAILLE = set('⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏')


def strip(line):
    """去掉颜色码和光标控制。"""
    return ESC.sub('', line)


def color256(n):
    if n < 8:
        return BASE16[n]
    if n < 16:
        return BASE16[n - 8]
    if n < 232:
        n -= 16
        conv = lambda v: 0 if v == 0 else 55 + 40 * v
        return '#%02x%02x%02x' % (conv(n // 36), conv(n // 6 % 6), conv(n % 6))
    v = 8 + 10 * (n - 232)
    return '#%02x%02x%02x' % (v, v, v)


def width(ch):
    return 2 if unicodedata.east_asian_width(ch) in 'WF' else 1


def cells(line):
    """一行拆成格子：(字符, 前景, 背景, 粗体, 变暗)。"""
    fg = bg = None
    bold = dim = False
    pos = 0
    out = []
    for m in list(ESC.finditer(line)) + [None]:
        end = m.start() if m else len(line)
        for ch in line[pos:end]:
            out.append((ch, fg, bg, bold, dim))
        if not m:
            break
        pos = m.end()
        if m.group(2) != 'm':
            continue
        codes = [int(c) if c else 0 for c in m.group(1).split(';')]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                fg = bg = None
                bold = dim = False
            elif c == 1:
                bold = True
            elif c == 2:
                dim = True
            elif 30 <= c <= 37:
                fg = BASE16[c - 30]
            elif 40 <= c <= 47:
                bg = BASE16[c - 40]
            elif c in (38, 48) and i + 2 < len(codes) and codes[i + 1] == 5:
                if c == 38:
                    fg = color256(codes[i + 2])
                else:
                    bg = color256(codes[i + 2])
                i += 2
            i += 1
    return out


def box_path(ch, x, y, cw=CW, lh=LH):
    """一个框线字符在自己格子里的路径。"""
    cx, cy = x + cw / 2, y + lh / 2
    x0, x1, y0, y1 = x, x + cw, y, y + lh
    end = {'L': (x0, cy), 'R': (x1, cy), 'U': (cx, y0), 'D': (cx, y1)}
    dirs = BOX[ch]
    f = lambda p: f'{p[0]:.2f},{p[1]:.2f}'
    if len(dirs) == 2 and set(dirs) in ({'L', 'R'}, {'U', 'D'}):
        return f'M{f(end[dirs[0]])}L{f(end[dirs[1]])}'
    if len(dirs) == 2:      # 拐角
        a, b = end[dirs[0]], end[dirs[1]]
        if ch in ROUND:
            r = min(cw, lh) / 2 * 0.9
            pa = (cx + (r if a[0] > cx else -r if a[0] < cx else 0), cy + (r if a[1] > cy else -r if a[1] < cy else 0))
            pb = (cx + (r if b[0] > cx else -r if b[0] < cx else 0), cy + (r if b[1] > cy else -r if b[1] < cy else 0))
            return f'M{f(a)}L{f(pa)}Q{cx:.2f},{cy:.2f} {f(pb)}L{f(b)}'
        return f'M{f(a)}L{cx:.2f},{cy:.2f}L{f(b)}'
    # 丁字和十字：一条直线穿过去，其余的从中心伸出来
    parts = []
    if 'L' in dirs and 'R' in dirs:
        parts.append(f'M{f(end["L"])}L{f(end["R"])}')
        rest = [d for d in dirs if d in 'UD']
    else:
        parts.append(f'M{f(end["U"])}L{f(end["D"])}')
        rest = [d for d in dirs if d in 'LR']
    for d in rest:
        parts.append(f'M{cx:.2f},{cy:.2f}L{f(end[d])}')
    return ''.join(parts)


def glyph(ch, x, y, color, opacity):
    """画成路径的符号。画不了的返回 None，按文字处理。"""
    cx, cy = x + CW / 2, y + LH / 2
    op = f' opacity="{opacity}"' if opacity != 1 else ''
    stroke = f'fill="none" stroke="{color}" stroke-linecap="round" stroke-linejoin="round"{op}'
    if ch in BOX:
        sw = 2.6 if ch == '━' else 1.15
        cap = 'butt' if ch == '━' else 'square'
        return f'<path d="{box_path(ch, x, y)}" fill="none" stroke="{color}" stroke-width="{sw}" stroke-linecap="{cap}" stroke-linejoin="round"{op}/>'
    if ch == '■':
        s = 6.4
        return f'<rect x="{cx - s / 2:.2f}" y="{cy - s / 2 + 0.5:.2f}" width="{s}" height="{s}" rx="1" fill="{color}"{op}/>'
    if ch == '□':
        s = 5.4
        return f'<rect x="{cx - s / 2:.2f}" y="{cy - s / 2 + 0.5:.2f}" width="{s}" height="{s}" rx="1" fill="none" stroke="{color}" stroke-width="1.1"{op}/>'
    if ch == '✓':
        return f'<path d="M{cx - 3.2:.2f},{cy + 0.4:.2f}L{cx - 0.9:.2f},{cy + 3:.2f}L{cx + 3.4:.2f},{cy - 3.2:.2f}" stroke-width="1.6" {stroke}/>'
    if ch == '✗':
        return (f'<path d="M{cx - 2.9:.2f},{cy - 2.9:.2f}L{cx + 2.9:.2f},{cy + 2.9:.2f}M{cx + 2.9:.2f},{cy - 2.9:.2f}L{cx - 2.9:.2f},{cy + 2.9:.2f}" '
                f'stroke-width="1.6" {stroke}/>')
    if ch == '×':
        return (f'<path d="M{cx - 2.3:.2f},{cy - 1.8:.2f}L{cx + 2.3:.2f},{cy + 2.8:.2f}M{cx + 2.3:.2f},{cy - 1.8:.2f}L{cx - 2.3:.2f},{cy + 2.8:.2f}" '
                f'stroke-width="1.4" {stroke}/>')
    if ch in '→←':
        s = 1 if ch == '→' else -1
        return (f'<path d="M{cx - 3.4 * s:.2f},{cy + 0.5:.2f}L{cx + 3.4 * s:.2f},{cy + 0.5:.2f}M{cx + 0.8 * s:.2f},{cy - 2.3:.2f}'
                f'L{cx + 3.4 * s:.2f},{cy + 0.5:.2f}L{cx + 0.8 * s:.2f},{cy + 3.3:.2f}" stroke-width="1.3" {stroke}/>')
    if ch == '↓':
        return (f'<path d="M{cx:.2f},{cy - 3.4:.2f}L{cx:.2f},{cy + 3.6:.2f}M{cx - 2.8:.2f},{cy + 0.9:.2f}L{cx:.2f},{cy + 3.6:.2f}'
                f'L{cx + 2.8:.2f},{cy + 0.9:.2f}" stroke-width="1.3" {stroke}/>')
    if ch in '›❯':
        h = 2.6 if ch == '›' else 3.6
        return f'<path d="M{cx - 1.6:.2f},{cy - h + 0.5:.2f}L{cx + 1.8:.2f},{cy + 0.5:.2f}L{cx - 1.6:.2f},{cy + h + 0.5:.2f}" stroke-width="{1.2 if ch == "›" else 1.7}" {stroke}/>'
    if ch == '·':
        return f'<circle cx="{cx:.2f}" cy="{cy + 0.5:.2f}" r="1.05" fill="{color}"{op}/>'
    if ch == '…':
        return ''.join(f'<circle cx="{cx + d:.2f}" cy="{cy + 4:.2f}" r="0.8" fill="{color}"{op}/>' for d in (-2.6, 0, 2.6))
    if ch in BRAILLE:      # 转圈的那一帧：画成一小段弧
        return f'<path d="M{cx - 2.6:.2f},{cy + 2.4:.2f}A3.6,3.6 0 1 1 {cx + 2.9:.2f},{cy + 1.6:.2f}" stroke-width="1.5" {stroke}/>'
    return None


def render(lines, title=None):
    rows = [cells(l) for l in lines]
    cols = max((sum(width(c[0]) for c in r) for r in rows), default=0)
    cols = max(cols, 78)
    top = BAR if title is not None else 0
    w = PAD_X * 2 + cols * CW
    h = top + PAD_Y * 2 + len(rows) * LH
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="{h:.0f}" viewBox="0 0 {w:.0f} {h:.0f}" '
           f'font-family="{FONT}" font-size="{FS}">',
           f'<rect x="0.5" y="0.5" width="{w - 1:.0f}" height="{h - 1:.0f}" rx="10" fill="{BG}" stroke="{FRAME}"/>']
    if title is not None:
        out.append(f'<path d="M0.5,{BAR}H{w - 0.5:.1f}" stroke="{FRAME}"/>')
        for i, c in enumerate(('#ff5f57', '#febc2e', '#28c840')):
            out.append(f'<circle cx="{20 + i * 18}" cy="{BAR / 2:.1f}" r="5.5" fill="{c}"/>')
        out.append(f'<text x="{w / 2:.0f}" y="{BAR / 2 + 4.5:.1f}" text-anchor="middle" fill="#8b90a0" font-size="12.5">{html.escape(title)}</text>')
    for r, row in enumerate(rows):
        y = top + PAD_Y + r * LH
        col = 0
        # 背景色块：连着的同色格子合成一块
        run_start = run_bg = None
        positions = []
        for ch, fg, bg, bold, dim in row:
            positions.append(col)
            col += width(ch)
        positions.append(col)
        for i, (ch, fg, bg, bold, dim) in enumerate(row + [(None, None, None, False, False)]):
            if bg != run_bg:
                if run_bg:
                    x = PAD_X + positions[run_start] * CW
                    out.append(f'<rect x="{x:.1f}" y="{y + 1.5:.1f}" width="{(positions[i] - positions[run_start]) * CW:.1f}" height="{LH - 3}" rx="3" fill="{run_bg}"/>')
                run_start, run_bg = i, bg
        # 符号画成路径，文字按相同样式、相同宽窄连成段
        i = 0
        while i < len(row):
            ch, fg, bg, bold, dim = row[i]
            x = PAD_X + positions[i] * CW
            color = fg or FG
            opacity = 0.55 if dim and not fg else 1
            if ch == ' ':
                i += 1
                continue
            g = glyph(ch, x, y, color, opacity)
            if g is not None:
                out.append(g)
                i += 1
                continue
            j = i
            wide = width(ch) == 2
            while (j < len(row) and row[j][1:] == row[i][1:] and row[j][0] != ' '
                   and (width(row[j][0]) == 2) == wide and glyph(row[j][0], 0, 0, color, 1) is None):
                j += 1
            seg = ''.join(c[0] for c in row[i:j])
            n = positions[j] - positions[i]
            attrs = f'x="{x:.1f}" y="{y + LH * 0.72:.1f}" textLength="{n * CW:.1f}" lengthAdjust="spacing" fill="{color}"'
            if wide:
                attrs += f' font-size="{FS_WIDE}"'
            if bold:
                attrs += ' font-weight="700"'
            if opacity != 1:
                attrs += f' opacity="{opacity}"'
            out.append(f'<text {attrs}>{html.escape(seg)}</text>')
            i = j
    out.append('</svg>')
    return '\n'.join(out) + '\n'


def logo(lines):
    """单独的字标：透明底，框线画成圆头的粗线，从青到紫渐变。浅色和深色页面上都看得清。lines 是脚本里那三行框线字。"""
    cw, lh, pad = 17, 30, 14
    w, h = pad * 2 + cw * len(lines[0]), pad * 2 + lh * 3
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="ExitRay">',
           f'<defs><linearGradient id="g" gradientUnits="userSpaceOnUse" x1="{pad}" y1="0" x2="{w - pad}" y2="0">'
           '<stop offset="0" stop-color="#00c2c7"/><stop offset="0.5" stop-color="#2f8cff"/><stop offset="1" stop-color="#a070f5"/>'
           '</linearGradient></defs>']
    d = []
    for r, line in enumerate(lines):
        for c, ch in enumerate(line):
            if ch in BOX:
                d.append(box_path(ch, pad + c * cw, pad + r * lh, cw, lh))
    out.append(f'<path d="{"".join(d)}" fill="none" stroke="url(#g)" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>')
    out.append('</svg>')
    return '\n'.join(out) + '\n'

