"""README 里的两张示意图，由 build.py 调用。

how   原理：请求从本机出去，上游把它们分到不同出口，目标回显它看到的访问者 IP
flow  检测流程：八步排成一行，标出哪几步不发明文 DNS

IP 用的是文档保留地址，和 README 里那份示例报告的三个出口一致。
"""

BG, FRAME = '#14161b', '#262a33'
INK, SOFT, DIM, LINE = '#e6e8ee', '#c3c8d2', '#7f8696', '#586172'
SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei','Noto Sans CJK SC',sans-serif"
MONO = "ui-monospace,'Cascadia Mono','SF Mono',Menlo,Consolas,'DejaVu Sans Mono','Liberation Mono',monospace"


def how():
    w, h = 832, 356
    # 出口：字母、颜色、IP、说明、目标
    exits = [
        ('A', '#5fd787', '203.0.113.63', '默认出口', 'chatgpt.com'),
        ('B', '#ffaf5f', '198.51.100.125', '机房 IP · 别的运营商', 'www.facebook.com'),
        ('C', '#d787ff', '192.0.2.36', '同一运营商的另一个出口', 'www.youtube.com'),
    ]
    rows = [104, 176, 248]
    hub = (292, 176)
    exit_x, target_x = 372, 646
    rx, ry0, rw, rh = 232, 40, 338, 262       # 上游那块
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="原理：上游把请求分到不同出口，目标回显它看到的访问者 IP" font-family="{SANS}">',
           '<defs>']
    for letter, color, *_ in exits:
        out.append(f'<linearGradient id="g{letter}" gradientUnits="userSpaceOnUse" x1="{hub[0]}" y1="0" x2="{exit_x}" y2="0">'
                   f'<stop offset="0" stop-color="{LINE}"/><stop offset="1" stop-color="{color}"/></linearGradient>')
    out.append('</defs>')
    out.append(f'<rect x="0.5" y="0.5" width="{w - 1}" height="{h - 1}" rx="12" fill="{BG}" stroke="{FRAME}"/>')

    # 上游
    out.append(f'<rect x="{rx}" y="{ry0}" width="{rw}" height="{rh}" rx="14" fill="#181b22" stroke="#353b49" stroke-dasharray="4 5"/>')
    out.append(f'<text x="{rx + 20}" y="{ry0 + 28}" font-size="15" font-weight="700" fill="{SOFT}">上游</text>')
    out.append(f'<text x="{rx + 62}" y="{ry0 + 28}" font-size="13" fill="{DIM}">在这里分流，从本机看不出来</text>')

    # 本机
    out.append(f'<rect x="36" y="{hub[1] - 44}" width="136" height="88" rx="12" fill="#1c2029" stroke="#3a4150"/>')
    out.append(f'<text x="104" y="{hub[1] - 5}" text-anchor="middle" font-size="15.5" font-weight="700" fill="{INK}">你的机器</text>')
    out.append(f'<text x="104" y="{hub[1] + 18}" text-anchor="middle" font-size="13" fill="{DIM}">VPS / 家宽</text>')
    out.append(f'<path d="M172,{hub[1]}H{hub[0]}" stroke="{LINE}" stroke-width="2.2" fill="none"/>')

    for (letter, color, ip, note, target), ry in zip(exits, rows):
        mid = (hub[0] + exit_x) / 2
        # 从分叉点到出口
        out.append(f'<path d="M{hub[0]},{hub[1]}C{mid:.0f},{hub[1]} {mid:.0f},{ry} {exit_x},{ry}" stroke="url(#g{letter})" '
                   f'stroke-width="2.2" fill="none" stroke-linecap="round"/>')
        # 出口：字母色块、IP、说明
        out.append(f'<rect x="{exit_x}" y="{ry - 13}" width="30" height="26" rx="6" fill="{color}"/>')
        out.append(f'<text x="{exit_x + 15}" y="{ry + 5}" text-anchor="middle" font-family="{MONO}" font-size="14" font-weight="700" '
                   f'fill="#101216">{letter}</text>')
        out.append(f'<text x="{exit_x + 42}" y="{ry - 1}" font-family="{MONO}" font-size="14" font-weight="700" fill="{INK}">{ip}</text>')
        out.append(f'<text x="{exit_x + 42}" y="{ry + 18}" font-size="13" fill="{DIM}">{note}</text>')
        # 出口到目标
        x0, x1 = rx + rw + 12, target_x - 14
        out.append(f'<path d="M{x0},{ry}H{x1 - 2}" stroke="{color}" stroke-width="2" fill="none" stroke-linecap="round"/>')
        out.append(f'<path d="M{x1 - 7},{ry - 5}L{x1},{ry}L{x1 - 7},{ry + 5}" stroke="{color}" stroke-width="2" fill="none" '
                   f'stroke-linecap="round" stroke-linejoin="round"/>')
        # 目标和它的回显
        out.append(f'<text x="{target_x}" y="{ry - 1}" font-family="{MONO}" font-size="14" fill="{INK}">{target}</text>')
        out.append(f'<text x="{target_x}" y="{ry + 18}" font-size="13" fill="{DIM}">回显 '
                   f'<tspan font-family="{MONO}" fill="{color}">{ip}</tspan></text>')

    # 分叉点画在线的上面
    out.append(f'<circle cx="{hub[0]}" cy="{hub[1]}" r="4.6" fill="{BG}" stroke="#9aa2b3" stroke-width="2"/>')
    out.append(f'<text x="{w / 2}" y="{h - 22}" text-anchor="middle" font-size="13.5" fill="{DIM}">'
               f'目标看到的访问者 IP，就是这条连接实际走的出口。把请求钉到目标的 IP 上，让它自己报出来。</text>')
    out.append('</svg>')
    return '\n'.join(out) + '\n'


def flow():
    w, h = 832, 178
    steps = ['确认出口', '校准线路', '加密 DNS', '触发测试', '系统 DNS', 'SNI 嗅探', '复测', '报告']
    cw, ch, gap, top = 84, 38, 14, 34
    x0 = (w - (len(steps) * cw + (len(steps) - 1) * gap)) / 2
    cyan, amber, violet = '#4fd0d6', '#f2c14e', '#a98bf5'
    tone = [cyan, cyan, cyan, amber, amber, violet, violet, INK]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
           f'aria-label="检测流程：确认出口、校准线路、加密 DNS、触发测试、系统 DNS、SNI 嗅探、复测、报告" font-family="{SANS}">',
           f'<rect x="0.5" y="0.5" width="{w - 1}" height="{h - 1}" rx="12" fill="{BG}" stroke="{FRAME}"/>']
    for i, name in enumerate(steps):
        x = x0 + i * (cw + gap)
        last = i == len(steps) - 1
        out.append(f'<rect x="{x:.1f}" y="{top}" width="{cw}" height="{ch}" rx="9" fill="{"#232733" if last else "#1b1f28"}" '
                   f'stroke="{tone[i]}" stroke-opacity="{0.9 if last else 0.55}" stroke-width="1.2"/>')
        if last:
            out.append(f'<text x="{x + cw / 2:.1f}" y="{top + 24}" text-anchor="middle" font-size="13.5" font-weight="700" '
                       f'fill="{INK}">{name}</text>')
            continue
        out.append(f'<text x="{x + 11:.1f}" y="{top + 24}" font-size="13.5" fill="{INK}">'
                   f'<tspan font-family="{MONO}" font-size="12" fill="{tone[i]}">{i + 1}</tspan><tspan dx="7">{name}</tspan></text>')
        ax = x + cw + gap / 2
        out.append(f'<path d="M{ax - 2.5:.1f},{top + ch / 2 - 4}l4,4l-4,4" fill="none" stroke="{LINE}" stroke-width="1.6" '
                   f'stroke-linecap="round" stroke-linejoin="round"/>')

    def bracket(a, b, color, text):
        xa, xb = x0 + a * (cw + gap) + 4, x0 + b * (cw + gap) + cw - 4
        y = top + ch + 14
        out.append(f'<path d="M{xa:.1f},{y - 5}v5h{xb - xa:.1f}v-5" fill="none" stroke="{color}" stroke-opacity="0.7" stroke-width="1.3" '
                   f'stroke-linecap="round" stroke-linejoin="round"/>')
        out.append(f'<text x="{(xa + xb) / 2:.1f}" y="{y + 20}" text-anchor="middle" font-size="13" fill="{color}">{text}</text>')

    bracket(0, 2, cyan, '只用加密 DNS，不发明文查询')
    bracket(3, 4, amber, '开始有明文查询')
    bracket(5, 6, violet, '核实和补充')
    out.append(f'<text x="{w / 2}" y="{h - 20}" text-anchor="middle" font-size="13" fill="{DIM}">'
               f'同一个 IP 在明文查询前后出口不同，就是 DNS 触发的分流；只出现过一次的读数要复测过才算数。</text>')
    out.append('</svg>')
    return '\n'.join(out) + '\n'

