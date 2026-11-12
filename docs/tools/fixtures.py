"""README 配图用的夹具：脚本探测完会得到的那些文件（rows.tsv、env.tsv 等），按两种线路造出来。

  split  三个出口：DNS 触发、名单内、按 IP 分流
  block  一个出口：53 端口被劫持、DNS 屏蔽、部分网段被上游改道后连不上

出口和线路上的地址都是文档保留地址（203.0.113.0/24、198.51.100.0/24、192.0.2.0/24），运营商是
AS64500、AS64501 这类示例号段，主机名是 vps1、vps2。被测目标的 IP 有的照着真实服务的网段写
（Meta、LINE、虾皮），其余按域名算出一个固定的地址，都不对应任何人的线路。
"""
from pathlib import Path

# 校准用的回显服务：方法、域名、IP
CAL = [('trace', 'www.cloudflare.com', '104.16.132.229'), ('trace', 'www.cloudflare.com', '104.16.133.229'),
       ('plain', 'ipinfo.io', '34.117.59.81'), ('plain', 'ifconfig.me', '34.160.111.145'),
       ('plain', 'checkip.amazonaws.com', '52.200.10.5'), ('plain', 'ident.me', '49.12.234.183'),
       ('plain', 'ipinfo.tw', '172.67.1.9'), ('akamai', 'whatismyip.akamai.com', '23.55.1.9'),
       ('fastly', 'www.fastly-debug.com', '151.101.1.57'), ('cloudfront', 'www.expressvpn.com', '18.65.3.9'),
       ('youtube', 'www.youtube.com', '142.250.196.206')]


def ipn(seed):
    """按名字造一个固定的公网 IP。"""
    h = sum(ord(c) * (i + 7) for i, c in enumerate(seed))
    return f'{23 + h % 150}.{h // 7 % 250}.{h // 3 % 250}.{1 + h % 250}'


def is_ip(name):
    return name[0].isdigit() and name.replace('.', '').isdigit()


def make(scenario, targets, out, version):
    """targets 是 [(分类, 名字)]，按脚本内置清单的顺序；文件写进 out 目录。"""
    out = Path(out)
    rows = []

    def row(*cols):
        rows.append('\t'.join(str(c) for c in cols))

    if scenario == 'block':
        env, info, base = _block(targets, row, out, version)
    elif scenario == 'split':
        env, info, base = _split(targets, row, out, version)
    else:
        raise ValueError(f'没有这个场景：{scenario}')

    def write(name, text):
        (out / name).write_text(text, encoding='utf-8', newline='\n')

    write('rows.tsv', '\n'.join(rows) + '\n')
    write('env.base', ''.join(f'{k}\t{v}\n' for k, v in env.items()))
    write('info.tsv', ''.join(f'{ip}\t' + '\t'.join(v) + '\n' for ip, v in info.items()))
    write('base', base)


def _block(targets, row, out, version):
    A = '203.0.113.63'
    LINE = '10.0.1.1 203.0.113.1 203.0.113.9 62.115.1.1'
    DIV = '10.0.1.1 10.80.0.1 ?'      # 在第 2 跳拐去了没见过的内网地址
    for m, h, ip in CAL:
        row('C', 'E', 'cal', h, 0, ip, A, m, '-', '-', LINE)
    for i in range(1, 6):
        row('S', 'E', 'stab', '1.1.1.1', f's{i}', '-', A, 'trace', '-', '-', '-')
    for i in range(1, 4):
        row('S', 'E', 'stab', '1.1.1.1', f'e{i}', '-', A, 'trace', '-', '-', '-')

    direct = {
        'cloudflare': 'chatgpt.com api.openai.com claude.ai api.anthropic.com grok.com www.perplexity.ai copilot.microsoft.com '
                      'openrouter.ai sora.com www.midjourney.com poe.com x.com discord.com www.linkedin.com www.crunchyroll.com '
                      'www.paypal.com wise.com www.visa.com www.revolut.com www.payoneer.com www.okx.com www.coinbase.com '
                      'www.kraken.com www.bitget.com www.kucoin.com metamask.io www.bitfinex.com www.books.com.tw www.temu.com '
                      'gitlab.com registry.npmjs.org stackoverflow.com www.epicgames.com www.dcard.tw ani.gamer.com.tw '
                      'www.104.com.tw',
        'google': 'gemini.google.com generativelanguage.googleapis.com www.google.com www.youtube.com accounts.google.com '
                  'i.ytimg.com play.google.com',
        'cloudfront': 'huggingface.co www.primevideo.com www.dazn.com www.tradingview.com www.binance.com api.binance.com '
                      'app.hyperliquid.xyz www.amazon.com www.kktv.me',
        'akamai': 'www.tiktok.com www.pinterest.com www.disneyplus.com www.hbomax.com www.mastercard.com '
                  'www.interactivebrokers.com www.bybit.com www.gate.com www.mexc.com cf.shopee.tw www.tw.coupang.com '
                  'www.ebay.com www.aliexpress.com www.shein.com www.apple.com apps.apple.com store.steampowered.com '
                  'steamcommunity.com www.playstation.com www.xbox.com www.ea.com udn.com',
        'fastly': 'www.reddit.com www.twitch.tv www.spotify.com tv.apple.com music.apple.com www.paramountplus.com pypi.org '
                  'www.nintendo.com',
        'page': 'www.netflix.com www.moomoo.com',
    }
    method = {n: m for m, names in direct.items() for n in names.split()}
    # 系统 DNS 不给真实地址的域名
    blocked = set('www.jkopay.com polymarket.com www.ctbcbank.com www.cathaybk.com.tw www.fubon.com www.taishinbank.com.tw '
                  'www.megabank.com.tw www.bot.com.tw www.firstbank.com.tw www.sinopac.com www.post.gov.tw www.momoshop.com.tw '
                  'www.ruten.com.tw www.gov.tw'.split())
    # 被上游按 IP 处理的目标：加密 DNS 测到的 IP，和系统 DNS 两轮测到的 IP。
    # 每个 IP 的状态：dead 连不上且改道，down 连不上但路由正常，div 连得上但改道，ok 正常
    special = {
        'www.facebook.com': ([('57.144.20.1', 'dead'), ('57.144.144.1', 'dead'), ('31.13.87.36', 'dead')], [('31.13.87.36', 'dead'), ('57.144.64.1', 'dead')]),
        'graph.facebook.com': ([('57.145.4.1', 'div')], [('57.145.4.1', 'div'), ('57.145.4.1', 'div')]),
        'static.xx.fbcdn.net': ([('31.13.87.5', 'dead'), ('57.144.144.128', 'dead'), ('57.145.10.1', 'div')], [('57.145.10.1', 'div'), ('57.145.10.1', 'div')]),
        'www.instagram.com': ([('31.13.87.174', 'dead')], [('31.13.87.174', 'dead'), ('57.144.64.174', 'dead')]),
        'www.threads.com': ([('157.240.11.63', 'ok'), ('57.144.144.63', 'dead')], [('57.144.92.63', 'ok'), ('57.144.92.63', 'ok')]),
        'www.whatsapp.com': ([('57.144.145.32', 'dead'), ('57.144.93.32', 'ok')], [('57.144.93.32', 'ok'), ('57.144.93.32', 'ok')]),
        'web.whatsapp.com': ([('57.144.65.60', 'dead'), ('57.145.20.60', 'div')], [('57.145.20.60', 'div'), ('57.144.65.60', 'dead')]),
        'www.messenger.com': ([('31.13.87.1', 'dead'), ('57.145.11.1', 'div')], [('57.145.11.1', 'div'), ('31.13.87.1', 'dead')]),
        'www.meta.ai': ([('57.144.64.2', 'dead'), ('57.145.12.2', 'div')], [('57.145.12.2', 'div'), ('57.145.12.2', 'div')]),
        'line.me': ([('147.92.243.206', 'div')], [('147.92.243.206', 'div'), ('147.92.243.206', 'div')]),
        'legy.line-apps.com': ([('147.92.185.2', 'dead'), ('43.223.23.118', 'dead'), ('147.92.146.129', 'dead')], [('147.92.146.129', 'dead'), ('147.92.185.2', 'dead')]),
        'obs.line-apps.com': ([('147.92.185.9', 'dead'), ('147.92.146.10', 'dead')], [('147.92.146.10', 'dead'), ('147.92.185.9', 'dead')]),
        'shopee.tw': ([('147.136.172.131', 'dead'), ('103.117.4.1', 'dead')], [('103.117.4.1', 'dead'), ('147.136.172.131', 'dead')]),
        'seller.shopee.tw': ([('147.136.172.140', 'div')], [('147.136.172.140', 'div'), ('147.136.172.140', 'div')]),
        'hamivideo.hinet.net': ([('203.75.129.96', 'down')], [('203.75.129.96', 'down'), ('203.75.129.96', 'down')]),
    }
    retested = set()

    def probe(pass_, group, name, rnd, ip, state, first):
        """一个没有回显的 IP：state 决定路由和连通。"""
        path = DIV if state in ('dead', 'div') else LINE
        if state in ('dead', 'down'):
            row('T', pass_, group, name, rnd, ip, '-', '-', '000' if first else '-', '-', path, 'dead')
            if (name, ip) not in retested:
                retested.add((name, ip))
                for r in ('r1', 'r2'):
                    row('T', pass_, group, name, r, ip, '-', '-', '-', '-', '-', 'dead')
        else:
            row('T', pass_, group, name, rnd, ip, '-', '-', '200' if first else '-', '-', path, 'ok' if first else 'tcp')
            if state == 'ok' and name in special and (name, ip) not in retested:
                retested.add((name, ip))
                for r in ('r1', 'r2'):
                    row('T', pass_, group, name, r, ip, '-', '-', '-', '-', '-', 'tcp')

    for group, name in targets:
        ip = name if is_ip(name) else ipn(name)
        if name in special:
            enc, sysdns = special[name]
            for eip, st in enc:
                probe('E', group, name, 1, eip, st, True)
            for rnd, (sip, st) in enumerate(sysdns, 1):
                probe('P', group, name, rnd, sip, st, rnd == 1)
            continue
        m = method.get(name)
        # 加密 DNS 轮
        if name == 'www.ruten.com.tw':
            row('T', 'E', group, name, 1, '104.18.10.27', A, 'cloudflare', '-', '-', LINE, 'ok')
            row('T', 'E', group, name, 1, '104.18.11.27', '-', '-', '000', '-', LINE, 'dead')
            for r in ('r1', 'r2'):
                row('T', 'E', group, name, r, '104.18.11.27', '-', '-', '-', '-', '-', 'dead')
                row('T', 'E', group, name, r, '104.18.10.27', '-', '-', '-', '-', '-', 'tcp')
        elif m == 'page':
            row('T', 'E', group, name, 1, ip, '-', '-', '200', f'1.2.3.4,{A}', LINE, 'ok')
        elif m:
            row('T', 'E', group, name, 1, ip, A, m, '-', '-', LINE, 'ok')
        else:
            row('T', 'E', group, name, 1, ip, '-', '-', '-' if is_ip(name) else '200', '-', LINE, 'tcp' if is_ip(name) else 'ok')
        # 系统 DNS 两轮
        for rnd in (1, 2):
            if name in blocked:
                row('T', 'P', group, name, rnd, '0.0.0.0', '-', 'dnsblock', '-', '-', '-')
            elif m == 'page':
                row('T', 'P', group, name, rnd, ip, '-', '-', '200', f'1.2.3.4,{A}', LINE, 'ok')
            elif m:
                row('T', 'P', group, name, rnd, ip, A, m, '-', '-', LINE, 'ok')
            else:
                first = rnd == 1 and not is_ip(name)
                row('T', 'P', group, name, rnd, ip, '-', '-', '200' if first else '-', '-', LINE, 'ok' if first else 'tcp')

    # 触发测试：13 个测得了，出口没变；53 端口被劫持，其余的明文应答里没有外地节点的 IP
    same = 'www.dcard.tw chatgpt.com api.openai.com claude.ai x.com discord.com www.google.com www.youtube.com www.paypal.com ' \
           'wise.com www.okx.com store.steampowered.com www.epicgames.com'.split()
    trig = [f'x\t{n}\t{ipn("far" + n)}\t{A}\t{A}\tok' for n in same]
    others = [n for g, n in targets if n not in same and not is_ip(n)]
    trig += [f'x\t{n}\t-\t-\t-\tmismatch' for n in others[:20]] + [f'x\t{n}\t-\t-\t-\tnoecho' for n in others[20:26]]
    _common_files(out, targets, row, A, trig, 'Cloudflare\t-\nAkamai\t-\nGoogle\t-\n')
    env = dict(host='vps2', time='2026-11-11 15:45:23', elapsed=384, tracer='mtr-icmp', use_route=1, region='tw',
               proxy='-', rounds=2, dns_test=1, version=version, resolver='8.8.8.8 1.1.1.1', ipv6='-', route_defaults=1,
               route_rules=0, route_tunnels='-', sniff_base=A, dns_hijack=1)
    info = {A: ('AS64500 Example Broadband', 'TW', 'Taipei', '-', '-')}
    return env, info, A


def _split(targets, row, out, version):
    A, B, C = '203.0.113.63', '198.51.100.125', '192.0.2.36'
    LA = '10.0.1.1 203.0.113.1 203.0.113.9 62.115.1.1'
    LB = '10.0.2.1 172.18.0.1 198.51.100.1 4.69.1.1'
    LC = '10.0.2.1 10.42.0.1 192.0.2.1 129.250.1.1'
    for m, h, ip in CAL:
        row('C', 'E', 'cal', h, 0, ip, A, m, '-', '-', LA)
    for i in range(1, 6):
        row('S', 'E', 'stab', '1.1.1.1', f's{i}', '-', A, 'trace', '-', '-', '-')
    cdn = {'ai': 'cloudflare', 'meta': 'meta', 'google': 'google', 'crypto': 'cloudflare', 'bank': 'akamai', 'social': 'cloudflare',
           'stream': 'fastly', 'finance': 'cloudflare', 'shop': 'akamai', 'dev': 'cloudflare', 'game': 'akamai', 'local': 'cloudflare'}
    google_ai = {'gemini.google.com', 'generativelanguage.googleapis.com'}
    count = {}
    for group, name in targets:
        count[group] = count.get(group, 0) + 1
        k = count[group]
        isip = is_ip(name)
        ip = name if isip else ipn(name)
        m = 'google' if name in google_ai else cdn.get(group, 'cloudflare')
        if group == 'telegram':
            # 不回显，按路由推断走 B
            for p in ('E', 'P'):
                row('T', p, group, name, 1, ip, '-', '-', '-' if isip else '200', '-', LB, 'tcp' if isip else 'ok')
            row('T', 'P', group, name, 2, ip, '-', '-', '-', '-', LB, 'tcp')
        elif name in google_ai or (group == 'google' and k <= 2):
            row('T', 'E', group, name, 1, ip, C, m, '-', '-', LC, 'ok')
            for r in (1, 2):
                row('T', 'P', group, name, r, ip, C, m, '-', '-', LC, 'ok')
        elif group == 'meta':
            if k == 1:      # 加密 DNS 下也走 B
                row('T', 'E', group, name, 1, ip, B, m, '-', '-', LB, 'ok')
            elif k <= 3:    # 按 IP：一个网段走 A，一个走 B
                row('T', 'E', group, name, 1, ip, A, m, '-', '-', LA, 'ok')
                row('T', 'E', group, name, 1, ipn(name + 'x'), B, m, '-', '-', LB, 'ok')
            else:           # 同一个 IP，明文查询之后才走 B
                row('T', 'E', group, name, 1, ip, A, m, '-', '-', LA, 'ok')
            for r in (1, 2):
                row('T', 'P', group, name, r, ip, B, m, '-', '-', LB, 'ok')
        elif group == 'bank':
            ex, line = (A, LA) if k <= 6 else (B, LB)
            row('T', 'E', group, name, 1, ip, ex if k % 2 else '-', m if k % 2 else '-', '-' if k % 2 else '200', '-', line, 'ok')
            for r in (1, 2):
                row('T', 'P', group, name, r, ip, B if k % 2 else '-', m if k % 2 else '-', '-', '-', LB, 'ok' if k % 2 else 'tcp')
        else:
            echo = k % 4 != 0
            row('T', 'E', group, name, 1, ip, A if echo else '-', m if echo else '-', '-' if echo else '200', '-', LA, 'ok')
            for r in (1, 2):
                row('T', 'P', group, name, r, ip, A if echo else '-', m if echo else '-', '-', '-', LA, 'ok' if echo else 'tcp')
    trig = [f'meta\twww.facebook.com\t57.144.248.1\t{A}\t{B}\tok', f'google\taccounts.google.com\t192.178.226.84\t{A}\t{C}\tok',
            f'meta\twww.instagram.com\t57.144.248.9\t{A}\t{B}\tok', f'meta\tgraph.facebook.com\t57.144.248.3\t{A}\t{B}\tok']
    names = [n for g, n in targets if not is_ip(n)]
    trig += [f'x\t{n}\t{ipn("far" + n)}\t{A}\t{A}\tok' for n in names[10:29]] + [f'x\t{n}\t-\t-\t-\tnoecho' for n in names[30:40]]
    _common_files(out, targets, row, A, trig, f'Cloudflare\t{A}\nAkamai\t{A}\nGoogle\t203.0.113.0/24\n')
    env = dict(host='vps1', time='2026-11-08 21:06:38', elapsed=236, tracer='mtr-icmp', use_route=1, region='tw', proxy='-',
               rounds=2, dns_test=1, version=version, resolver='8.8.8.8', ipv6='-', route_defaults=1, route_rules=0,
               route_tunnels='-', sniff_base=A, dns_hijack=0)
    info = {A: ('AS64500 Example Broadband', 'TW', 'Taipei', '-', '-'), B: ('AS64501 Example Transit', 'TW', 'Taipei', '-', 'hosting'),
            C: ('AS64500 Example Broadband', 'TW', 'Taipei', '-', '-')}
    return env, info, A


def _common_files(out, targets, row, A, trig, dnsq):
    """触发测试、SNI 嗅探（每个分类抽两个域名，出口都没变）和 DNS 查询来源。"""
    (out / 'trigger.tsv').write_text('\n'.join(trig) + '\n', encoding='utf-8', newline='\n')
    seen = {}
    for g, n in targets:
        if is_ip(n) or seen.get(g, 0) >= 2:
            continue
        seen[g] = seen.get(g, 0) + 1
        row('N', 'E', g, n, 0, '34.117.59.81', A, 'plain', '200', '-', '-')
    (out / 'sniff.tsv').write_text('', encoding='utf-8')
    (out / 'dnsq.tsv').write_text(dnsq, encoding='utf-8', newline='\n')
