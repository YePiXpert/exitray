# splitcheck

VPS / 家宽出口分流检测。不比路由首跳，直接看每个目标实际从哪个 IP 出去，还能分辨分流是静态名单，还是上游监听明文 DNS 动态触发的。

只比路由首跳的脚本遇到内网跳多的线路，常常只能给出“无法判定”，而实际可能已经分流了。这个脚本优先让目标自己报出访问者 IP，拿不到才用路由推断，并标明每条结果的证据。

## 一键运行

在要检测的机器上执行，一般约 2 分钟：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/splitcheck/main/splitcheck.sh)
```

只测部分分类：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/splitcheck/main/splitcheck.sh) -c ai,meta,telegram
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

出口
  A 默认  203.0.113.63      AS64500 Example Broadband  TW Taipei
         回显 188 次 · 线路 10.0.1.1 > 203.0.113.1
  B       198.51.100.125    AS64501 Example Transit  TW Taipei
         回显 41 次 · 线路 10.0.2.1 > 172.18.0.1
  C       192.0.2.36        AS64500 Example Broadband  TW Taipei
         回显 23 次 · 线路 10.0.2.1 > 10.42.0.1

分类概览（目标数）
             系统 DNS           加密 DNS
               A   B   C   ?      A   B   C   ?
  AI           9   .   2   .      9   .   2   .
  Meta         1   9   .   .      3   7   .   .
  Telegram     .   8   .   .      .   8   .   .
  虚拟币      12   .   .   .     12   .   .   .
  银行         .   8   .   .      6   2   .   .

明文 DNS 触发测试（外地节点 IP，明文查询前后的真实出口）
  www.facebook.com                  57.144.248.1     A → B
  accounts.google.com               192.178.226.84   A → C
  触发 4 / 可测 23（另有 10 个拿不到回显）

明细
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

名单内可能是静态名单，也可能是这个 IP 已经被别的明文查询写进去了。触发测试能看出上游是否按 DNS 写名单。

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
4. **两种解析方式**：先全部用 DoH 解析测一轮，这时不发任何明文 DNS；再用系统 DNS 测几轮。两轮出口不同，就说明分流由 DNS 触发。
5. **触发测试**：用 ECS 拿到本机没解析过的外地节点 IP，比较明文查询前后的真实出口。这一步不受之前运行的影响。
6. **SNI 嗅探**：把目标域名放进 SNI 发给中立的回显服务，看出口变不变。

## 检查节点本身

在 VPS 上跑，测的是上游这一层。xray、sing-box 可能另有路由规则，比如把 Google 转给另一台机器，这一层要经节点测：

```bash
bash splitcheck.sh -x socks5h://127.0.0.1:1080 -c ai,meta
```

经代理时没有路由信息，不回显的目标会显示未知。

## 选项

```text
-c, --category 列表   只测这些分类，逗号分隔：
                      ai,meta,telegram,social,google,stream,finance,crypto,bank,shop,local
-r, --region 地区     本地银行和电商清单：auto（默认，按出口国家）tw jp hk us sg kr vn none
-a, --add 分类:域名   追加目标，可重复，例如 -a shop:www.pchome.com.tw
-f, --file 文件       从文件读目标，每行“分类 域名”
-n, --rounds N        系统 DNS 测几轮，默认 2
-p, --parallel N      并发数，默认 8
-x, --proxy URL       经代理测，用来检查节点本身的分流
    --tracer 工具     指定路由工具：mtr-icmp mtr-tcp traceroute-tcp traceroute tracepath
    --no-route        不探测路由，只看回显
    --no-dns-test     跳过加密 DNS 轮和明文 DNS 触发测试
    --no-sniff        跳过 SNI 嗅探测试
-b, --brief           只输出结论和分类概览
-v, --verbose         额外输出每一轮的 IP、路径和证据
-j, --json            输出 JSON
    --no-color        不用颜色
```

## 局限

- 明文解析过的 IP 会在上游名单里留一段时间，两次运行建议间隔 15 分钟以上，否则加密 DNS 那一轮可能受上一次影响。
- 只测 IPv4。IPv6 只显示有没有，UDP 只看 DNS 查询这一项。
- 回显依赖第三方页面，页面改版后对应目标会退回路由推断。
- Facebook 对部分机房 IP 会把诊断页跳转到登录页，这时 Meta 也只能靠路由推断。
- 地区清单只有 tw、hk、us 在当地实测过，其余只确认过域名能解析。`tracepath` 只用样例输出验证过解析。

## 隐私

运行时会访问被测网站和这些服务，它们能看到本机的出口 IP：

- DNS：`dns.google`、`1.1.1.1`、`8.8.8.8` 和 Akamai 的权威 DNS
- 查询出口信息：`ipinfo.io`、`ip-api.com`
- 回显：`www.cloudflare.com`、`ifconfig.me`、`checkip.amazonaws.com`、`ident.me`、`ipinfo.tw`、`whatismyip.akamai.com`、`www.fastly-debug.com`、`www.expressvpn.com`、`www.youtube.com`、`www.facebook.com`
- IPv6 检查：`api64.ipify.org`

SNI 嗅探会把目标域名放进发给 `ipinfo.io` 的 TLS 握手。脚本不上传结果，也不收集数据。

## 许可证

[MIT](LICENSE)
