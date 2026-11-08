# splitcheck

VPS / 家宽出口分流检测。不比路由首跳，直接看每个目标实际从哪个 IP 出去，还能分辨分流是静态名单，还是上游监听明文 DNS 动态触发的，也能发现 53 端口被劫持、域名被 DNS 屏蔽、按 IP 段改道或拦截。

只比路由首跳的脚本遇到内网跳多的线路，常常只能给出“无法判定”，而实际可能已经分流了。这个脚本优先让目标自己报出访问者 IP，拿不到才用路由推断，并标明每条结果的证据。

## 一键运行

在要检测的机器上执行，选好范围后一般约 2 分钟：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/splitcheck/main/splitcheck.sh)
```

跳过菜单，直接指定分类或测全部：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/splitcheck/main/splitcheck.sh) -c ai,meta,telegram
```

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/splitcheck/main/splitcheck.sh) -y
```

运行时显示每一步的进度：

```text
  ✓ 确认出口             203.0.113.63 · 地区 tw  1s
  ✓ 准备探测             90 个目标 · 路由 mtr-icmp · 预计约 2 分钟  2s
  ✓ 校准出口             已发现 1 个出口  6s
  ✓ 加密 DNS             已发现 2 个出口  25s
  ✓ 明文 DNS 触发测试    触发 4 / 可测 23  9s
  ⠹ 系统 DNS 第 1/2 轮   ████████░░░░░░░░░░░░ 36/90 10s  www.okx.com
```

需要 bash 4+、curl、awk。建议装上 mtr 和 dig，缺了会跳过对应检查：

```bash
apt install -y mtr-tiny dnsutils
```

全程只读，不改系统配置，也不安装任何东西。临时文件放在 mktemp 目录，退出时删除。

## 输出长什么样

下面是一台有分流的机器的实测结果，IP、线路和运营商已替换成示例：

```text
结论  有分流，发现 3 个出口，其中 1 个不是默认运营商
      13 个目标由明文 DNS 触发：加密 DNS 下走默认出口，系统 DNS 下走分流
      26 个目标在分流名单内：加密 DNS 下也走分流

── 出口 ──────────────────────────────────────────────────────────
  A 默认  203.0.113.63      AS64500 Example Broadband  TW Taipei
         回显 188 次 · 线路 10.0.1.1 > 203.0.113.1
  B       198.51.100.125    AS64501 Example Transit  TW Taipei
         回显 41 次 · 线路 10.0.2.1 > 172.18.0.1
  C       192.0.2.36        AS64500 Example Broadband  TW Taipei
         回显 23 次 · 线路 10.0.2.1 > 10.42.0.1

── 分类概览（目标数） ────────────────────────────────────────────
             系统 DNS           加密 DNS
               A   B   C   ?      A   B   C   ?
  AI           9   .   2   .      9   .   2   .
  Meta         1   9   .   .      3   7   .   .
  Telegram     .   8   .   .      .   8   .   .
  虚拟币      12   .   .   .     12   .   .   .
  银行         .   8   .   .      6   2   .   .

── 明文 DNS 触发测试（外地节点 IP，明文查询前后的真实出口） ──────
  www.facebook.com                  57.144.248.1     A → B
  accounts.google.com               192.178.226.84   A → C
  触发 4 / 可测 23（另有 10 个拿不到回显）

── 明细 ──────────────────────────────────────────────────────────
  目标                                系统 DNS             轮次  加密  证据
  AI
    chatgpt.com                       A 203.0.113.63       2/2   A     直接·CF
    gemini.google.com                 C 192.0.2.36         2/2   C     直接·Google  名单内
  Meta
    www.facebook.com                  B 198.51.100.125     2/2   B     直接·Meta  名单内
    www.instagram.com                 B 198.51.100.125     2/2   A     推断  DNS触发
  Telegram
    149.154.175.50                    B 198.51.100.125     2/2   B     推断  名单内
```

### 证据

| 标记 | 含义 |
|---|---|
| 直接 | 目标或同一 IP 上的 CDN 回显了访问者 IP |
| 推断 | 目标不回显，但路由和已确认出口的线路相同 |
| 弱推断 | 只有一个出口可比，目标又在内网段就分开了，可信度低 |
| 不确定 | 路由同时对得上几条线路，判断不了 |
| 未知 | 既没有回显，也没有路由信息 |

### 分流方式

| 标记 | 含义 |
|---|---|
| DNS触发 | 用加密 DNS 解析时走默认出口，用系统 DNS 解析时走分流 |
| 名单内 | 加密 DNS 下也走分流，解析到的 IP 已在上游名单里 |
| DNS 屏蔽 | 系统 DNS 解析成 0.0.0.0、内网地址或查不到，加密 DNS 能拿到真实地址 |
| fake-ip | 系统 DNS 返回 198.18.x.x，有 Clash、sing-box 这类透明代理接管了解析。这不是屏蔽，但系统 DNS 这一轮测不到真实出口，算作证据不足。要测线路本身先关掉它，要测它的分流用 `-x` 指向它的本地端口 |
| 按IP | 同一个域名解析出的几个 IP 各自稳定地走了不同出口，规则是按 IP 段写的 |
| 部分IP不通 | 同一个域名有的 IP 连得上，有的复测两次都连不上，像是按 IP 拦截 |

证据不足不等于没有分流。如果只找到一个出口，但有目标是未知、弱推断或 fake-ip，结论会写“没发现第二个出口，但 N/M 个目标证据不足，不能排除分流”。解析失败、所有 IP 都连不上的目标没有流量可分，单独计数，不影响结论：从一个地方分不清是目标挂了还是被拦了，报告会列出这些目标，换个网络打开就能确认。

### 按 IP 的规则

有的线路不按域名，而按目标 IP 段改道或拦截，例如只把 Meta 的旧网段、LINE、虾皮台湾的 IP 转给 WARP，或者直接丢掉。同一个域名换个解析器就可能落在规则外：Google DoH 带上台湾的 ECS，`www.facebook.com` 解析到 31.13.x.x 的旧网段，运营商 DNS 给的却可能是 57.144.x.x 的新网段。只测一个 IP，结论就看运气。

所以加密 DNS 那一轮把 Google（带出口所在网段的 ECS）和 Cloudflare 的应答合起来，每个 /24 测一个 IP，最多 3 个；系统 DNS 每轮测一个网段，几轮下来轮换。每个 IP 都记下走哪个出口、连不连得上，有差别的单独列出来：

```text
── 逐 IP（各个 IP 结果不一样或连不上的目标） ──────────────────────
  www.facebook.com                  31.13.87.36      ×  复测两次都连不上
                                    57.144.110.1     A
  legy.line-apps.com                147.92.150.193   B
                                    43.223.1.40      A
```

同一个域名有的 IP 连不上、有的正常，结论是“出口没有分流，但有目标的部分 IP 连不上，像是被按 IP 拦截”；几个 IP 走了不同出口，算有分流，标成按IP。

名单内可能是静态名单，也可能是这个 IP 已经被别的明文查询写进去了。触发测试能看出上游是否按 DNS 写名单。

有的线路不换出口，而是拦截 53 端口，把银行、购物这类域名解析成 0.0.0.0。这时报告会写“出口没有分流，但 DNS 被动了手脚”。判断方法是向保留地址 `192.0.2.53` 发一个 DNS 查询：这个地址没有 DNS 服务，能收到应答就说明查询被中途拦截了，换公共 DNS 也没用，要用 DoH/DoT。

## 分享结果

报告末尾会附一段可以直接复制的摘要，IP 只保留前两段，不带主机名和路由：

```text
splitcheck 分流检测 · 2026-11-06 · 地区 tw · 90 个目标
结论：有分流，3 个出口，其中 1 个不是默认运营商
A 默认  203.0.*.*  AS64500 Example Broadband  TW
B  198.51.*.*  AS64501 Example Transit  TW
C  192.0.*.*  AS64500 Example Broadband  TW
AI：A 9 · C 2
Meta：A 1 · B 9
Telegram：B 8
虚拟币：A 12
银行：B 8
明文 DNS 触发：是（触发 4 / 可测 23）
证据：直接 60 · 推断 30 · 未确认 0
https://github.com/YePiXpert/splitcheck
```

要贴到论坛的完整表格，在终端里运行时结尾回答 `y`，或者加 `-m` 直接输出 Markdown：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/splitcheck/main/splitcheck.sh) -m > report.md
```

默认打码，要完整 IP 就加 `--no-mask`。摘要上面的完整报告没有打码，分享时只复制摘要。

## 怎么判断的

1. **回显**：把请求钉到目标解析出的 IP 上，让那个 IP 报出访问者 IP。

   | 服务 | 回显方式 |
   |---|---|
   | Cloudflare | `/cdn-cgi/trace` |
   | Akamai | `Host: whatismyip.akamai.com` |
   | Fastly | `Host: www.fastly-debug.com` |
   | CloudFront | 经同一节点请求一个会显示 IP 的页面 |
   | Google | YouTube 页面的 `remoteHost` |
   | Meta | `facebook.com/diagnostics` |
   | 其他 | 页面或响应头里出现已知出口 |

2. **校准线路**：同时探测路由，记下每条线路对应哪个出口。
3. **路由推断**：Telegram、多数银行这类不回显的目标，用路由匹配已校准的线路。
4. **两种解析方式**：先全部用 DoH 解析测一轮，这时不发任何明文 DNS；再用系统 DNS 测几轮。两轮出口不同，就说明分流由 DNS 触发。DoH 这一轮合并 Google 和 Cloudflare 的应答，每个 /24 测一个 IP，见上面的“按 IP 的规则”。
5. **连通**：拿不到回显的目标翻首页，收到响应头就算连上了；IP 目标看 443 端口能不能建立连接。
6. **触发测试**：用 ECS 拿到本机没解析过的外地节点 IP，比较明文查询前后的真实出口。这一步不受之前运行的影响。
7. **SNI 嗅探**：把目标域名放进 SNI 发给中立的回显服务。回显服务不看 SNI，所以出口变了，或者回来的不是它的应答，都说明上游在按 TLS 域名处理流量。没拿到回显的会重试一次，完全连不上的不下结论。
8. **复测**：只回显过一次的非默认出口，可能只是出口池轮换或临时的线路切换；一次连不上，也可能只是超时。把当初那次探测原样再做两遍，同一个目标、同一个 IP。出口再出现就算数；看到的成了别的出口，这一次就按偶发处理，不算进结论，报告里单独提一句；复测拿不到回显的，保留并注明没能确认。连不上的 IP 两次复测都不通才算连不上，有一次连上就按连得上处理。

## 检查节点本身

在 VPS 上跑，测的是上游这一层。xray、sing-box 可能另有路由规则，比如把 Google 转给另一台机器，这一层要经节点测：

```bash
bash splitcheck.sh -x socks5h://127.0.0.1:1080 -c ai,meta
```

经代理时没有路由信息，不回显的目标会显示未知。

## 选项

```text
-c, --category 列表   只测这些分类，逗号分隔：
                      ai,meta,telegram,social,google,stream,finance,crypto,bank,shop,dev,game,local
                      写 none 则不用内置清单，只测 -a、-f 给的目标
-r, --region 地区     本地银行和电商清单：auto（默认，按出口国家）tw jp hk us sg kr vn none
-a, --add 分类:域名   追加目标，可重复，例如 -a shop:www.pchome.com.tw
-f, --file 文件       从文件读目标，每行“分类 域名”
-n, --rounds N        系统 DNS 测几轮，默认 2
-p, --parallel N      并发数，默认 8
-L, --low-resource    低压力模式：按 CPU 核数把并发降到 2-4，路由探测降低优先级
-x, --proxy URL       经代理测，用来检查节点本身的分流
    --tracer 工具     指定路由工具：mtr-icmp mtr-tcp traceroute-tcp traceroute tracepath
    --no-route        不探测路由，只看回显
    --no-dns-test     跳过加密 DNS 轮和明文 DNS 触发测试
    --no-sniff        跳过 SNI 嗅探测试
-b, --brief           只输出结论和分类概览
-v, --verbose         额外输出每一轮的 IP、路径和证据
-j, --json            输出 JSON
-m, --markdown        输出方便分享的 Markdown 报告，IP 默认打码
    --no-mask         分享摘要和 Markdown 里显示完整 IP
    --exit-code       用退出码表示结论，方便 cron 和监控
-y, --yes             不显示启动菜单，直接测全部分类
    --no-color        不用颜色
```

## 定时检查

默认退出码是 0 检测完成、1 运行出错。加 `--exit-code` 后退出码就是结论：

| 退出码 | JSON 的 `verdict` | 含义 |
|---|---|---|
| 0 | `clean` | 未发现分流，能测的目标都有证据 |
| 1 | | 运行出错 |
| 2 | `split`、`dns_tampered`、`blocked` | 有分流、DNS 被动了手脚，或者同一个域名有部分 IP 连不上 |
| 3 | `inconclusive` | 没发现第二个出口，但部分目标证据不足 |

```bash
bash splitcheck.sh -y -j --exit-code > result.json
```

JSON 里 `split` 只表示有没有发现第二个出口，没发现不等于没有，要看 `verdict`。`coverage` 给出直接、推断、弱推断、未知、连不上、fake-ip、DNS 屏蔽、部分 IP 连不上（`ip_blocked`）和按 IP 分流（`split_by_ip`）各有多少个目标。每个目标的 `ips` 是逐 IP 的结果：`exit_ids` 是走的出口，`reachable` 是连不连得上（`null` 是没试过）；`reach` 汇总成 `ok`、`partial`、`dead`，`split_by_ip` 表示几个 IP 走了不同出口。`unstable_exits` 是只出现过一次、复测时没有再出现的出口，它们不算进 `exits`，也不影响 `verdict`。

## 局限

- 明文解析过的 IP 会在上游名单里留一段时间，两次运行建议间隔 15 分钟以上，否则加密 DNS 那一轮可能受上一次影响。
- 复测在系统 DNS 轮之后做，离第一次看到那个出口隔了几十秒到一两分钟。上游名单的保留时间如果比这还短，真实的分流也可能被当成偶发；这种出口会列在报告里，不会悄悄消失。
- 每个 /24 只测一个 IP，一个域名最多测 3 个网段；解析器都没给出的网段测不到。
- 所有 IP 都连不上的目标，从一个地方分不清是目标挂了还是被拦截，只列出来，不影响结论。
- 只测 IPv4。IPv6 只显示有没有，UDP 只看 DNS 查询这一项。
- 回显依赖第三方页面，页面改版后对应目标会退回路由推断。
- Facebook 对部分机房 IP 会把诊断页跳转到登录页，这时 Meta 也只能靠路由推断。
- 地区清单只有 tw、hk、us 在当地实测过，其余只确认过域名能解析。`tracepath` 只用样例输出验证过解析。

## 隐私

运行时会访问被测网站和这些服务，它们能看到本机的出口 IP：

- DNS：`dns.google`、`1.1.1.1`、`8.8.8.8` 和 Akamai 的权威 DNS
- 查询出口信息：`ipinfo.io`、`ip-api.com`（后者只有 HTTP 接口，也是前者限流时的备用来源）
- 回显：`www.cloudflare.com`、`ifconfig.me`、`checkip.amazonaws.com`、`ident.me`、`ipinfo.tw`、`whatismyip.akamai.com`、`www.fastly-debug.com`、`www.expressvpn.com`、`www.youtube.com`、`www.facebook.com`
- IPv6 检查：`api64.ipify.org`

SNI 嗅探会把目标域名放进发给 `ipinfo.io` 的 TLS 握手。脚本不上传结果，也不收集数据。代理地址里的账号密码不会写进报告和 JSON。

## 开发

测试不联网，用假的 curl、mtr、dig 跑真实的脚本函数和完整流程。Python 只用于测试，运行脚本不需要：

```bash
python3 tests/test_regression.py
```

`TEST_AWK=mawk` 或 `TEST_AWK='busybox awk'` 可以换 awk，`TEST_BASH` 可以换 bash。CI 在 gawk、mawk、BusyBox awk、bash 4.2 和 Alpine 上各跑一遍；`ubuntu-latest` 是 Ubuntu 26.04，coreutils 默认是 Rust 写的 uutils。

并发的探测进程各写各的文件（`rows.d/进程号`），每一步结束再合并，不要让几个进程追加同一个文件：一行是不是一次写完、写完还动不动文件，取决于 shell 和 coreutils 的实现。uutils 的 `dd` 在 2026 年 10 月以前写完会把文件截到自己写到的位置，并发追加时会截掉别的进程刚写的行。

## 许可证

[MIT](LICENSE)
