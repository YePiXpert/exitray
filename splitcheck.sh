#!/usr/bin/env bash
#
# splitcheck — VPS / 家宽出口分流检测
#
# 只比路由首跳看不出真实出口，这里直接问目标“你看到的访问者 IP 是什么”：
#   直接  目标或同一 IP 上的 CDN 回显访问者 IP
#         （Cloudflare、Akamai、Fastly、CloudFront、Google、Meta，或页面里出现已知出口）
#   推断  目标不回显时，用路由路径匹配已校准出口的线路
#
# 每个目标用两种解析方式测：
#   加密 DNS  经 DoH 解析，上游看不到查询内容
#   系统 DNS  经系统解析器，和节点默认行为一致
# 两者出口不同，说明上游在监听明文 DNS、按域名动态分流。
#
# 全程只读：不改系统配置，临时文件放在 mktemp 目录，退出时删除。
# 用法见 --help，项目地址 https://github.com/YePiXpert/splitcheck

if [ -z "${BASH_VERSINFO+x}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "splitcheck: 需要 bash 4 或更新版本" >&2
  exit 1
fi

set -u
set -f # 路径里的 ? 不能被当成通配符
export LC_ALL=C

VERSION="1.0.0"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'

ROUNDS=2
PARALLEL=8
MAXHOPS=10
REGION=auto
CATS=""
TARGET_FILE=""
EXTRA=()
PROXY=""
USE_ROUTE=1
USE_DNS_TEST=1
USE_SNIFF=1
JSON=0
BRIEF=0
VERBOSE=0
USE_COLOR=1

WORK=""
TRACER=none
FORCE_TRACER=""
FALLBACK=""
BASE_IP=""
EXIT_NET=""
IPINFO_IP=""
RUNNING=0
LIMIT=""
HAS_WAIT_N=0
START_TS=$(date +%s)

# 这些都走外地节点 IP，用来做明文 DNS 触发测试：日本、德国、加拿大、巴西
FAR_SUBNETS="126.0.0.0/24 85.214.0.0/24 24.48.0.0/24 177.0.0.0/24"

usage() {
  cat <<'EOF'
用法: splitcheck.sh [选项]

看每个目标实际从哪个 IP 出去，判断 VPS 或节点有没有分流、是怎么分的流。

  -c, --category 列表   只测这些分类，逗号分隔：
                        ai,meta,telegram,social,google,stream,finance,crypto,bank,shop,local
  -r, --region 地区     本地银行和电商清单：auto（默认，按出口国家）tw jp hk us sg kr vn none
  -a, --add 分类:域名   追加目标，可重复，例如 -a shop:www.pchome.com.tw
  -f, --file 文件       从文件读目标，每行“分类 域名”
  -n, --rounds N        系统 DNS 测几轮，默认 2
  -p, --parallel N      并发数，默认 8
  -x, --proxy URL       经代理测，用来检查节点本身的分流，例如 socks5h://127.0.0.1:1080
      --tracer 工具     指定路由工具：mtr-icmp mtr-tcp traceroute-tcp traceroute tracepath
      --no-route        不探测路由，只看回显（不回显的目标显示未知）
      --no-dns-test     跳过加密 DNS 轮和明文 DNS 触发测试
      --no-sniff        跳过 SNI 嗅探测试
  -b, --brief           只输出结论和分类概览
  -v, --verbose         额外输出每一轮的 IP、路径和证据
  -j, --json            输出 JSON
      --no-color        不用颜色
  -V, --version         显示版本
  -h, --help            显示帮助

依赖：bash 4+、curl、awk。mtr、traceroute 或 tracepath 用于探测路由，dig 用于明文 DNS
触发测试，缺少时跳过对应检查（Debian 可装 mtr-tiny 和 dnsutils）。

明文解析过的 IP 会在上游名单里留一段时间，两次运行建议间隔 15 分钟以上，
否则加密 DNS 那一轮可能受上一次运行影响。

例子:
  bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/splitcheck/main/splitcheck.sh)
  bash splitcheck.sh -c ai,meta,telegram -n 3
  bash splitcheck.sh -x socks5h://127.0.0.1:1080 -c ai,meta
EOF
}

# 目标清单：“分类 域名”；@ 开头的按地区加载
catalog() {
  cat <<'EOF'
ai chatgpt.com
ai api.openai.com
ai claude.ai
ai api.anthropic.com
ai gemini.google.com
ai generativelanguage.googleapis.com
ai grok.com
ai www.perplexity.ai
ai copilot.microsoft.com
ai openrouter.ai
ai huggingface.co
meta www.facebook.com
meta graph.facebook.com
meta static.xx.fbcdn.net
meta www.instagram.com
meta i.instagram.com
meta www.threads.com
meta www.whatsapp.com
meta web.whatsapp.com
meta www.messenger.com
meta www.meta.ai
telegram telegram.org
telegram web.telegram.org
telegram api.telegram.org
telegram 149.154.175.50
telegram 149.154.167.51
telegram 149.154.175.100
telegram 149.154.167.91
telegram 91.108.56.130
social x.com
social www.tiktok.com
social discord.com
social www.reddit.com
social www.linkedin.com
social www.pinterest.com
social www.twitch.tv
social www.snapchat.com
google www.google.com
google www.youtube.com
google accounts.google.com
google i.ytimg.com
stream www.netflix.com
stream www.disneyplus.com
stream www.primevideo.com
stream www.hbomax.com
stream www.spotify.com
stream tv.apple.com
finance www.paypal.com
finance wise.com
finance stripe.com
finance www.visa.com
finance www.mastercard.com
finance www.interactivebrokers.com
finance www.tradingview.com
crypto www.binance.com
crypto api.binance.com
crypto www.okx.com
crypto www.bybit.com
crypto www.coinbase.com
crypto www.kraken.com
crypto www.bitget.com
crypto www.kucoin.com
crypto www.gate.com
crypto www.mexc.com
crypto www.htx.com
crypto metamask.io
shop www.amazon.com
shop www.ebay.com
shop www.aliexpress.com
shop www.temu.com
shop www.taobao.com
@tw bank www.ctbcbank.com
@tw bank www.cathaybk.com.tw
@tw bank www.esunbank.com
@tw bank www.fubon.com
@tw bank www.taishinbank.com.tw
@tw bank www.megabank.com.tw
@tw bank www.bot.com.tw
@tw bank www.post.gov.tw
@tw shop shopee.tw
@tw shop cf.shopee.tw
@tw shop www.momoshop.com.tw
@tw shop 24h.pchome.com.tw
@tw shop www.ruten.com.tw
@tw shop www.books.com.tw
@tw shop www.tw.coupang.com
@tw shop tw.buy.yahoo.com
@tw local www.dcard.tw
@tw local udn.com
@tw local www.gov.tw
@jp bank www.bk.mufg.jp
@jp bank www.smbc.co.jp
@jp bank www.mizuhobank.co.jp
@jp bank www.rakuten-bank.co.jp
@jp bank www.japanpost.jp
@jp shop www.rakuten.co.jp
@jp shop jp.mercari.com
@jp shop www.amazon.co.jp
@jp shop shopping.yahoo.co.jp
@jp local www.yahoo.co.jp
@jp local www.nicovideo.jp
@jp local abema.tv
@jp local www.dmm.com
@hk bank www.hsbc.com.hk
@hk bank www.bochk.com
@hk bank www.hangseng.com
@hk bank www.sc.com
@hk shop www.hktvmall.com
@hk local www.viu.com
@hk local www.gov.hk
@us bank www.chase.com
@us bank www.bankofamerica.com
@us bank www.wellsfargo.com
@us bank www.citi.com
@us bank www.capitalone.com
@us shop www.walmart.com
@us shop www.target.com
@us shop www.bestbuy.com
@us shop www.costco.com
@us local www.hulu.com
@us local www.espn.com
@sg bank www.dbs.com.sg
@sg bank www.ocbc.com
@sg bank www.uob.com.sg
@sg shop shopee.sg
@sg shop www.lazada.sg
@sg local www.gov.sg
@kr bank www.kbstar.com
@kr bank www.shinhan.com
@kr bank www.wooribank.com
@kr shop www.coupang.com
@kr shop www.gmarket.co.kr
@kr local www.naver.com
@kr local www.kakao.com
@vn bank vietcombank.com.vn
@vn bank bidv.com.vn
@vn shop shopee.vn
@vn shop tiki.vn
@vn local vnexpress.net
EOF
}

cat_labels() {
  cat <<'EOF'
ai AI
meta Meta
telegram Telegram
social 社媒
google Google
stream 流媒体
finance 金融支付
crypto 虚拟币
bank 银行
shop 电商购物
local 本地服务
EOF
}

# 校准用的回显地址：“提取方式 主机 URL”。plain 和 trace 是不属于任何业务的中立回显
cal_list() {
  cat <<'EOF'
trace www.cloudflare.com https://www.cloudflare.com/cdn-cgi/trace
plain ipinfo.io https://ipinfo.io/ip
plain ifconfig.me https://ifconfig.me/ip
plain checkip.amazonaws.com https://checkip.amazonaws.com/
plain ident.me https://ident.me/
plain ipinfo.tw https://ipinfo.tw/ip
akamai whatismyip.akamai.com http://whatismyip.akamai.com/
fastly www.fastly-debug.com https://www.fastly-debug.com/
cloudfront www.expressvpn.com https://www.expressvpn.com/what-is-my-ip
youtube www.youtube.com https://www.youtube.com/embed/
meta www.facebook.com https://www.facebook.com/diagnostics
EOF
}

die() {
  printf 'splitcheck: %s\n' "$*" >&2
  exit 1
}

progress() {
  [[ -t 2 ]] && printf '\r\033[K%s' "$*" >&2
  return 0
}

progress_done() {
  [[ -t 2 ]] && printf '\r\033[K' >&2
  return 0
}

need_arg() {
  (( $2 >= 2 )) || die "$1 需要参数"
}

parse_args() {
  while (( $# )); do
    case $1 in
      -c|--category) need_arg "$1" $#; CATS=$2; shift 2 ;;
      -r|--region)   need_arg "$1" $#; REGION=$2; shift 2 ;;
      -a|--add)      need_arg "$1" $#; EXTRA+=("$2"); shift 2 ;;
      -f|--file)     need_arg "$1" $#; TARGET_FILE=$2; shift 2 ;;
      -n|--rounds)   need_arg "$1" $#; ROUNDS=$2; shift 2 ;;
      -p|--parallel) need_arg "$1" $#; PARALLEL=$2; shift 2 ;;
      -x|--proxy)    need_arg "$1" $#; PROXY=$2; shift 2 ;;
      --tracer)      need_arg "$1" $#; FORCE_TRACER=$2; shift 2 ;;
      --no-route)    USE_ROUTE=0; shift ;;
      --no-dns-test) USE_DNS_TEST=0; shift ;;
      --no-sniff)    USE_SNIFF=0; shift ;;
      -b|--brief)    BRIEF=1; shift ;;
      -v|--verbose)  VERBOSE=1; shift ;;
      -j|--json)     JSON=1; shift ;;
      --no-color)    USE_COLOR=0; shift ;;
      -V|--version)  echo "splitcheck $VERSION"; exit 0 ;;
      -h|--help)     usage; exit 0 ;;
      *) die "未知选项 $1，用 --help 查看用法" ;;
    esac
  done
  [[ $ROUNDS =~ ^[1-9][0-9]*$ ]] || die "--rounds 必须是正整数"
  [[ $PARALLEL =~ ^[1-9][0-9]*$ ]] || die "--parallel 必须是正整数"
  [[ -z $TARGET_FILE || -r $TARGET_FILE ]] || die "读不了文件 $TARGET_FILE"
  case $REGION in auto|tw|jp|hk|us|sg|kr|vn|none) ;; *) die "不支持的地区 $REGION" ;; esac
  case $FORCE_TRACER in ''|mtr-tcp|mtr-icmp|traceroute-tcp|traceroute|tracepath) ;; *) die "不支持的路由工具 $FORCE_TRACER" ;; esac
  # 经代理时只能看回显，节点的 DNS 行为也由节点决定
  if [[ -n $PROXY ]]; then
    USE_ROUTE=0
    USE_DNS_TEST=0
    USE_SNIFF=0
  fi
}

check_deps() {
  local c
  for c in curl awk grep sed sort mktemp touch paste; do
    command -v "$c" >/dev/null 2>&1 || die "缺少 $c"
  done
  command -v timeout >/dev/null 2>&1 && LIMIT="timeout 25"
  if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) )); then
    HAS_WAIT_N=1
  fi
}

cleanup() {
  local pids
  pids=$(jobs -p 2>/dev/null)
  [[ -n $pids ]] && kill $pids 2>/dev/null
  [[ -n $WORK && -d $WORK ]] && rm -rf "$WORK"
  return 0
}

# ---------- 网络基础 ----------

http() {
  curl -4 -s --connect-timeout 4 --max-time "${HTTP_TIMEOUT:-8}" -A "$UA" ${PROXY:+-x "$PROXY"} "$@" 2>/dev/null
}

# 把请求钉到指定 IP，这样测到的才是这个 IP 的出口
pinned() {
  local host=$1 ip=$2 url=$3
  shift 3
  local PROXY=$PROXY
  case $PROXY in
    '') ;;
    socks5h://*) PROXY=socks5://${PROXY#socks5h://} ;;
    socks*) ;;
    *) return 1 ;; # HTTP 代理由代理解析主机名，钉不住
  esac
  http --resolve "$host:443:$ip" --resolve "$host:80:$ip" "$@" "$url"
}

# 请求目标自己：代理模式交给节点解析，直连模式钉到 IP
fetch_own() {
  local host=$1 ip=$2 url=$3
  shift 3
  if [[ -n $PROXY ]]; then
    http "$@" "$url"
  else
    pinned "$host" "$ip" "$url" "$@"
  fi
}

is_ipv4() {
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]
}

is_public_ipv4() {
  is_ipv4 "$1" || return 1
  local a b rest
  IFS=. read -r a b rest <<<"$1"
  case $a in
    0|10|127) return 1 ;;
    169) [[ $b != 254 ]] || return 1 ;;
    172) (( b < 16 || b > 31 )) || return 1 ;;
    192) [[ $b != 168 ]] || return 1 ;;
    100) (( b < 64 || b > 127 )) || return 1 ;;
  esac
  (( a < 224 ))
}

# 从响应体里取访问者 IP，stdin 是响应体
extract() {
  local ip=''
  case $1 in
    plain|akamai) ip=$(tr -d ' \r\n\t' | head -c 64) ;;
    trace)        ip=$(sed -n 's/^ip=//p' | tr -d '\r' | head -1) ;;
    fastly)       ip=$(grep -aoE 'id="clientip">[0-9.]+' | sed 's/.*>//' | head -1) ;;
    cloudfront)   ip=$(grep -aoE "class='red'>[0-9.]+" | sed 's/.*>//' | head -1) ;;
    youtube)      ip=$(grep -aoE '"remoteHost":"[0-9.]+"' | grep -oE '[0-9]+(\.[0-9]+){3}' | head -1) ;;
    meta)         ip=$(grep -aoE 'IP address \(trusted\): [0-9.]+' | sed 's/.*: //' | head -1) ;;
  esac
  is_public_ipv4 "$ip" && printf '%s' "$ip"
}

# 经 DoH 解析，上游看不到查询。$2 是 ECS，默认用出口所在 /24
doh() {
  local name=$1 ecs=${2-$EXIT_NET} query out
  query="name=$name&type=A"
  [[ -n $ecs ]] && query+="&edns_client_subnet=$ecs"
  if [[ -n $PROXY ]]; then
    out=$(HTTP_TIMEOUT=6 http "https://dns.google/resolve?$query")
  else
    out=$(HTTP_TIMEOUT=6 http --resolve dns.google:443:8.8.8.8 "https://dns.google/resolve?$query")
  fi
  if [[ $out != *'"data"'* ]]; then
    out=$(HTTP_TIMEOUT=6 http -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$name&type=A")
  fi
  printf '%s' "$out" | grep -oE '"data": *"[0-9.]+"' | grep -oE '[0-9]+(\.[0-9]+){3}' | awk '!s[$0]++'
}

sys_resolve() {
  if [[ -n $PROXY ]]; then
    doh "$1" ''
  elif command -v getent >/dev/null 2>&1; then
    getent ahostsv4 "$1" 2>/dev/null | awk '!s[$1]++ { print $1 }'
  elif command -v dig >/dev/null 2>&1; then
    dig +short +time=2 +tries=1 "$1" A 2>/dev/null | grep -E '^[0-9.]+$'
  else
    doh "$1"
  fi
}

# 查询 ipinfo 时同样不发明文 DNS
ipinfo_get() {
  if [[ -n $IPINFO_IP ]]; then
    HTTP_TIMEOUT=8 pinned ipinfo.io "$IPINFO_IP" "https://ipinfo.io/$1"
  else
    HTTP_TIMEOUT=8 http "https://ipinfo.io/$1"
  fi
}

# ---------- 路由 ----------

hop_count() {
  local h n=0
  for h in $1; do
    [[ $h == '?' ]] || n=$((n + 1))
  done
  printf '%s' "$n"
}

# 输出逐跳 IP，无回应记为 ?
trace_raw() {
  local mode=$1 ip=$2
  case $mode in
    mtr-tcp|mtr-icmp)
      local -a args=(-4 -n -r -w -c 2 -G 1 -m "$MAXHOPS")
      (( EUID == 0 )) && args+=(-i 0.2)
      [[ $mode == mtr-tcp ]] && args+=(-T -P 443)
      $LIMIT mtr "${args[@]}" "$ip" 2>/dev/null |
        awk '/^ *[0-9]+\.\|--/ { printf "%s ", ($2 == "???" ? "?" : $2) }'
      ;;
    traceroute-tcp)
      $LIMIT traceroute -4 -n -q 1 -w 1 -m "$MAXHOPS" -T -p 443 "$ip" 2>/dev/null |
        awk '$1 ~ /^[0-9]+$/ { printf "%s ", ($2 == "*" ? "?" : $2) }'
      ;;
    traceroute)
      $LIMIT traceroute -4 -n -q 1 -w 1 -m "$MAXHOPS" "$ip" 2>/dev/null |
        awk '$1 ~ /^[0-9]+$/ { printf "%s ", ($2 == "*" ? "?" : $2) }'
      ;;
    tracepath)
      $LIMIT tracepath -4 -n -m "$MAXHOPS" "$ip" 2>/dev/null |
        awk '$1 ~ /^[0-9]+\??:$/ && $2 != "[LOCALHOST]" {
               h = $1 + 0
               if (!(h in s)) s[h] = ($2 == "no" ? "?" : $2)
               if (h > mx) mx = h
             }
             END { for (i = 1; i <= mx; i++) printf "%s ", ((i in s) ? s[i] : "?") }'
      ;;
  esac
}

detect_tracer() {
  (( USE_ROUTE )) || return 0
  local t p list=''
  # 优先 ICMP：多个 TCP 模式的 mtr 同时跑会串线，同一条路径上混进别的线路的跳
  command -v mtr >/dev/null 2>&1 && list="mtr-icmp mtr-tcp"
  command -v traceroute >/dev/null 2>&1 && list="$list traceroute-tcp traceroute"
  command -v tracepath >/dev/null 2>&1 && list="$list tracepath"
  [[ -z $FORCE_TRACER ]] || list=$FORCE_TRACER
  for t in $list; do
    p=$(trace_raw "$t" 1.1.1.1)
    if (( $(hop_count "$p") >= 2 )); then
      TRACER=$t
      break
    fi
  done
  # 个别目标可能不回应这种探测，留另一种方式兜底
  case $TRACER in
    mtr-icmp) FALLBACK=mtr-tcp ;;
    mtr-tcp) FALLBACK=mtr-icmp ;;
    traceroute-tcp) FALLBACK=traceroute ;;
  esac
}

# 同一轮同一 IP 只测一次
route_of() {
  (( USE_ROUTE )) || return 0
  [[ $TRACER != none ]] || return 0
  local ip=$1 cache="$WORK/path/$2.$1" p q
  if [[ -s $cache ]]; then
    cat "$cache"
    return 0
  fi
  p=$(trace_raw "$TRACER" "$ip")
  if [[ -n $FALLBACK ]] && (( $(hop_count "$p") < 4 )); then
    q=$(trace_raw "$FALLBACK" "$ip")
    (( $(hop_count "$q") > $(hop_count "$p") )) && p=$q
  fi
  p=${p% }
  printf '%s\n' "$p" > "$cache"
  printf '%s\n' "$p"
}

# ---------- 回显 ----------

# 用一次明文 HTTP 请求判断这个 IP 属于哪家 CDN
fingerprint() {
  local ip=$1 cache="$WORK/fp/$1" tmp body kind=other
  if [[ -s $cache ]]; then
    cat "$cache"
    return 0
  fi
  tmp=$(mktemp "$WORK/h.XXXXXX")
  body=$(HTTP_TIMEOUT=5 http -D "$tmp" -H 'Host: whatismyip.akamai.com' "http://$ip/" | head -c 3000)
  if [[ ! -s $tmp ]]; then
    kind=none
  elif is_public_ipv4 "$(printf '%s' "$body" | tr -d ' \r\n\t')"; then
    kind=akamai
  elif grep -qiE '^(server: *cloudflare|cf-ray:)' "$tmp"; then
    kind=cloudflare
  elif grep -qiE '^(server: *cloudfront|x-amz-cf-)' "$tmp"; then
    kind=cloudfront
  elif grep -qiE '^(server: *varnish|x-served-by: *cache-)' "$tmp" || [[ $body == *'Fastly error'* ]]; then
    kind=fastly
  elif grep -qiE '^server: *proxygen' "$tmp"; then
    kind=meta
  elif [[ $body == *'Error 404 (Not Found)'* ]]; then
    kind=google
  fi
  rm -f "$tmp"
  printf '%s' "$kind" > "$cache"
  printf '%s' "$kind"
}

# 输出“出口 方法”，拿不到就不输出
echo_by_ip() {
  local name=$1 ip=$2 kind ex='' m=''
  # 经代理时用主机名，让节点按自己的 DNS 配置解析
  if [[ -n $PROXY ]]; then
    case $name in
      www.facebook.com|m.facebook.com)
        ex=$(http "https://$name/diagnostics" | extract meta); m=meta ;;
      www.youtube.com)
        ex=$(http https://www.youtube.com/embed/ | extract youtube); m=google ;;
    esac
  fi
  if [[ -z $ex ]]; then
    kind=$(fingerprint "$ip")
    case $kind in
      akamai)
        ex=$(HTTP_TIMEOUT=5 http -H 'Host: whatismyip.akamai.com' "http://$ip/" | extract akamai)
        m=akamai ;;
      fastly)
        ex=$(HTTP_TIMEOUT=6 http -H 'Host: www.fastly-debug.com' "http://$ip/" | extract fastly)
        m=fastly ;;
      cloudfront)
        ex=$(pinned www.expressvpn.com "$ip" https://www.expressvpn.com/what-is-my-ip | extract cloudfront)
        m=cloudfront ;;
      cloudflare)
        is_ipv4 "$name" || ex=$(fetch_own "$name" "$ip" "https://$name/cdn-cgi/trace" | extract trace)
        [[ -n $ex ]] || ex=$(pinned www.cloudflare.com "$ip" https://www.cloudflare.com/cdn-cgi/trace | extract trace)
        m=cloudflare ;;
      google)
        ex=$(pinned www.youtube.com "$ip" https://www.youtube.com/embed/ | extract youtube)
        m=google ;;
      meta)
        ex=$(pinned www.facebook.com "$ip" https://www.facebook.com/diagnostics | extract meta)
        m=meta ;;
      *)
        # 80 端口不通或经 HTTP 代理时认不出 CDN，再试一次 Cloudflare 的回显路径
        is_ipv4 "$name" || ex=$(HTTP_TIMEOUT=5 fetch_own "$name" "$ip" "https://$name/cdn-cgi/trace" | extract trace)
        m=cloudflare ;;
    esac
  fi
  [[ -n $ex ]] && printf '%s %s' "$ex" "$m"
  return 0
}

# ---------- 探测 ----------

emit() {
  local IFS=$'\t'
  printf '%s\n' "$*" >> "$WORK/rows.tsv"
}

spawn() {
  "$@" </dev/null &
  RUNNING=$((RUNNING + 1))
  if (( RUNNING >= PARALLEL )); then
    if (( HAS_WAIT_N )); then
      wait -n 2>/dev/null
      RUNNING=$((RUNNING - 1))
    else
      wait
      RUNNING=0
    fi
  fi
}

wait_all() {
  wait
  RUNNING=0
}

probe_calibration() {
  local method=$1 host=$2 url=$3 ip=$4 ex='' path='' want=''
  if [[ $ip == - ]]; then
    ex=$(http "$url" | head -c 400000 | extract "$method")
  else
    # 回显页的源站在某些地区可能躲在别家 CDN 后面，这时看到的是 CDN 的 IP，不能算数
    case $method in
      akamai|fastly|cloudfront|meta) want=$method ;;
      youtube) want=google ;;
    esac
    if [[ -z $want || $(fingerprint "$ip") == "$want" ]]; then
      ex=$(pinned "$host" "$ip" "$url" | head -c 400000 | extract "$method")
    fi
    path=$(route_of "$ip" cal)
  fi
  emit C E cal "$host" 0 "$ip" "${ex:--}" "$method" - - "${path:--}"
}

run_calibration() {
  local method host url ip
  cal_list > "$WORK/cal.txt"
  # 先把 IP 解析好（只走 DoH），探测时再钉到 IP 上
  while read -r method host url; do
    if [[ -n $PROXY ]]; then
      printf '%s %s %s -\n' "$method" "$host" "$url"
    else
      doh "$host" | head -2 | while read -r ip; do
        printf '%s %s %s %s\n' "$method" "$host" "$url" "$ip"
      done
    fi
  done < "$WORK/cal.txt" > "$WORK/cal_pinned.txt"
  while read -r method host url ip; do
    spawn probe_calibration "$method" "$host" "$url" "$ip"
  done < "$WORK/cal_pinned.txt"
  wait_all
}

probe_target() {
  local pass=$1 group=$2 name=$3 round=$4 ip path out ex='-' method='-' code='-' cands='-' tmp
  local -a ips=()
  if is_ipv4 "$name"; then
    ip=$name
  else
    if [[ $pass == E ]]; then
      mapfile -t ips < <(doh "$name")
    else
      mapfile -t ips < <(sys_resolve "$name")
    fi
    if (( ${#ips[@]} == 0 )); then
      emit T "$pass" "$group" "$name" "$round" - - dns - - -
      return 0
    fi
    ip=${ips[(round - 1) % ${#ips[@]}]}
    # 经代理时先让节点解析一次，节点若用明文 DNS 也能触发上游名单
    [[ -z $PROXY ]] || HTTP_TIMEOUT=6 http -o /dev/null -I "https://$name/" >/dev/null
  fi
  path=$(route_of "$ip" "$pass$round")
  out=$(echo_by_ip "$name" "$ip")
  if [[ -n $out ]]; then
    ex=${out% *}
    method=${out#* }
  elif ! is_ipv4 "$name"; then
    # 没有回显就翻页面。后面几轮只翻第一轮证明有用的目标，省流量
    if (( round == 1 )) || grep -qxF "$name" "$WORK/page_names" 2>/dev/null; then
      tmp=$(mktemp "$WORK/p.XXXXXX")
      code=$(HTTP_TIMEOUT=10 fetch_own "$name" "$ip" "https://$name/" -i -L --max-redirs 3 -o "$tmp" -w '%{http_code}')
      cands=$(grep -aoE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$tmp" 2>/dev/null | sort -u | head -300 | paste -sd, -)
      rm -f "$tmp"
    fi
  fi
  emit T "$pass" "$group" "$name" "$round" "$ip" "$ex" "$method" "${code:-000}" "${cands:--}" "${path:--}"
}

update_page_names() {
  awk -F'\t' '
    $7 != "-" { known[$7] = 1 }
    $10 != "-" { n++; name[n] = $4; cand[n] = $10 }
    END {
      for (i = 1; i <= n; i++) {
        m = split(cand[i], c, ",")
        for (j = 1; j <= m; j++) if (c[j] in known) { print name[i]; break }
      }
    }' "$WORK/rows.tsv" | sort -u > "$WORK/page_names"
}

run_pass() {
  local pass=$1 total=$2 label=$3 r i count group name
  count=$(wc -l < "$WORK/targets.txt")
  for (( r = 1; r <= total; r++ )); do
    i=0
    while read -r group name; do
      i=$((i + 1))
      progress "$label 第 $r/$total 轮  $i/$count"
      spawn probe_target "$pass" "$group" "$name" "$r"
    done < "$WORK/targets.txt"
    wait_all
    (( r == 1 )) && update_page_names
  done
}

# 用外地节点 IP 做对照：查询前后的真实出口。这些 IP 本机没解析过，不受之前的结果影响
trigger_one() {
  local group=$1 name=$2 sub ip out before after m answers
  for sub in $FAR_SUBNETS; do
    ip=$(doh "$name" "$sub" | head -1)
    [[ -n $ip ]] || continue
    out=$(echo_by_ip "$name" "$ip")
    [[ -n $out ]] || continue
    before=${out% *}
    m=${out#* }
    answers=$(dig +short +time=2 +tries=1 +subnet="$sub" "$name" A @8.8.8.8 2>/dev/null)
    grep -qxF "$ip" <<<"$answers" || continue
    sleep 0.3
    out=$(echo_by_ip "$name" "$ip")
    [[ -n $out ]] || continue
    after=${out% *}
    emit X E "$group" "$name" 0 "$ip" "$before" "$m" - - -
    emit X E "$group" "$name" 0 "$ip" "$after" "$m" - - -
    printf '%s\t%s\t%s\t%s\t%s\n' "$group" "$name" "$ip" "$before" "$after" >> "$WORK/trigger.tsv"
    return 0
  done
  printf '%s\t%s\t-\t-\t-\n' "$group" "$name" >> "$WORK/trigger.tsv"
}

run_trigger() {
  if ! command -v dig >/dev/null 2>&1; then
    printf 'trigger\tno-dig\n' >> "$WORK/env.tsv"
    return 0
  fi
  local group name
  awk '$2 !~ /^[0-9.]+$/ && c[$1]++ < 3' "$WORK/targets.txt" > "$WORK/samples.txt"
  while read -r group name; do
    progress "明文 DNS 触发测试  $name"
    spawn trigger_one "$group" "$name"
  done < "$WORK/samples.txt"
  wait_all
}

sniff_one() {
  local sni=$1 r
  r=$(curl -4 -sk --connect-timeout 4 --max-time 8 --resolve "$sni:443:$IPINFO_IP" -H 'Host: ipinfo.io' "https://$sni/ip" 2>/dev/null | extract plain)
  printf '%s\t%s\n' "$sni" "${r:--}" >> "$WORK/sniff.tsv"
}

# 把目标域名放进 SNI 发给中立回显，出口变了就是按 TLS 域名分流
run_sniff() {
  (( USE_SNIFF )) || return 0
  [[ -n $IPINFO_IP ]] || return 0
  local base sni
  base=$(pinned ipinfo.io "$IPINFO_IP" https://ipinfo.io/ip | extract plain)
  [[ -n $base ]] || return 0
  printf 'sniff_base\t%s\n' "$base" >> "$WORK/env.tsv"
  awk '$2 !~ /^[0-9.]+$/ && c[$1]++ < 2 { print $2 }' "$WORK/targets.txt" > "$WORK/sni.txt"
  while read -r sni; do
    progress "SNI 嗅探测试  $sni"
    spawn sniff_one "$sni"
  done < "$WORK/sni.txt"
  wait_all
}

# DNS 权威看到的来源 IP，走 UDP，可以顺带对比 UDP 的出口
dns_query_exits() {
  [[ -z $PROXY ]] || return 0
  command -v dig >/dev/null 2>&1 || return 0
  local a b c
  a=$(dig +short +time=2 +tries=1 TXT whoami.cloudflare CH @1.1.1.1 2>/dev/null | tr -d '"' | head -1)
  b=$(dig +short +time=2 +tries=1 whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null | head -1)
  c=$(dig +short +time=2 +tries=1 TXT o-o.myaddr.l.google.com @8.8.8.8 2>/dev/null | grep -oE 'edns0-client-subnet [0-9./]+' | awk '{ print $2 }' | head -1)
  printf 'Cloudflare\t%s\nAkamai\t%s\nGoogle\t%s\n' "${a:--}" "${b:--}" "${c:--}" > "$WORK/dnsq.tsv"
}

env_info() {
  local v
  v=$(hostname 2>/dev/null)
  printf 'host\t%s\n' "${v:--}" >> "$WORK/env.tsv"
  printf 'time\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$WORK/env.tsv"
  printf 'elapsed\t%s\n' "$(( $(date +%s) - START_TS ))" >> "$WORK/env.tsv"
  printf 'tracer\t%s\n' "$TRACER" >> "$WORK/env.tsv"
  printf 'use_route\t%s\n' "$USE_ROUTE" >> "$WORK/env.tsv"
  printf 'region\t%s\n' "$REGION" >> "$WORK/env.tsv"
  printf 'proxy\t%s\n' "${PROXY:--}" >> "$WORK/env.tsv"
  printf 'rounds\t%s\n' "$ROUNDS" >> "$WORK/env.tsv"
  printf 'dns_test\t%s\n' "$USE_DNS_TEST" >> "$WORK/env.tsv"
  printf 'version\t%s\n' "$VERSION" >> "$WORK/env.tsv"
  [[ -z $PROXY ]] || return 0
  if [[ -r /etc/resolv.conf ]]; then
    v=$(awk '/^nameserver/ { print $2 }' /etc/resolv.conf | head -2 | paste -sd' ' -)
    printf 'resolver\t%s\n' "${v:--}" >> "$WORK/env.tsv"
  fi
  v=$(curl -6 -s --connect-timeout 3 --max-time 5 https://api64.ipify.org 2>/dev/null | tr -d ' \r\n' | head -c 45)
  [[ $v == *:* ]] || v='-'
  printf 'ipv6\t%s\n' "$v" >> "$WORK/env.tsv"
  if command -v ip >/dev/null 2>&1; then
    local defaults rules tunnels
    defaults=$(ip -4 route show default 2>/dev/null | wc -l | tr -d ' ')
    rules=$(ip -4 rule show 2>/dev/null | grep -cvE 'lookup (local|main|default)')
    tunnels=$(ip -o link show 2>/dev/null | awk -F': ' '{ print $2 }' | sed 's/@.*//' |
      grep -E '^(wg|tun|tap|sit|gre|ipip|vti|xfrm|warp|sing|mihomo|clash|nekoray|utun)' | paste -sd' ' -)
    printf 'route_defaults\t%s\nroute_rules\t%s\nroute_tunnels\t%s\n' "$defaults" "$rules" "${tunnels:--}" >> "$WORK/env.tsv"
  fi
}

load_targets() {
  local f="$WORK/targets.txt" e
  {
    catalog | awk -v r="@$REGION" '$1 == r { print $2, $3 }'
    catalog | awk '$1 !~ /^@/ { print $1, $2 }'
  } | awk -v want=",$CATS," 'want == ",," || index(want, "," $1 ",")' > "$f.raw"
  [[ -z $TARGET_FILE ]] || grep -vE '^[[:space:]]*(#|$)' "$TARGET_FILE" >> "$f.raw"
  for e in ${EXTRA[@]+"${EXTRA[@]}"}; do
    [[ $e == *:* ]] || die "-a 的格式是 分类:域名，收到 $e"
    printf '%s %s\n' "${e%%:*}" "${e#*:}" >> "$f.raw"
  done
  awk 'NF >= 2 && $2 ~ /^[A-Za-z0-9._-]+$/ && !seen[$2]++ { print $1, $2 }' "$f.raw" > "$f"
  [[ -s $f ]] || die "没有可测的目标，检查 --category 和 --region"
}

find_baseline() {
  BASE_IP=$(http https://1.1.1.1/cdn-cgi/trace | extract trace)
  [[ -n $BASE_IP ]] || BASE_IP=$(http https://www.cloudflare.com/cdn-cgi/trace | extract trace)
  [[ -n $BASE_IP ]] || BASE_IP=$(http https://ifconfig.me/ip | extract plain)
  [[ -n $BASE_IP ]] || die "拿不到出口 IP，检查网络${PROXY:+或代理 $PROXY}"
  EXIT_NET="${BASE_IP%.*}.0/24"
}

detect_region() {
  [[ $REGION == auto ]] || return 0
  local cc
  cc=$(ipinfo_get "$BASE_IP/country" | tr -d ' \r\n' | tr 'A-Z' 'a-z')
  case $cc in
    tw|jp|hk|us|sg|kr|vn) REGION=$cc ;;
    *) REGION=none ;;
  esac
}

json_str() {
  printf '%s' "$1" | sed -n "s/.*\"$2\": *\"\([^\"]*\)\".*/\1/p" | head -1
}

lookup_exits() {
  local letter ip seen def sig j org cc city host flags kind
  : > "$WORK/exits_info.tsv"
  while IFS=$'\t' read -r letter ip seen def sig; do
    progress "查询出口信息  $ip"
    j=$(ipinfo_get "$ip/json" | tr -d '\n')
    org=$(json_str "$j" org)
    cc=$(json_str "$j" country)
    city=$(json_str "$j" city)
    host=$(json_str "$j" hostname)
    flags=$(HTTP_TIMEOUT=6 http "http://ip-api.com/json/$ip?fields=hosting,mobile,proxy")
    kind=-
    [[ $flags == *'"hosting":true'* ]] && kind=hosting
    [[ $flags == *'"mobile":true'* ]] && kind=mobile
    [[ $flags == *'"proxy":true'* ]] && kind=proxy
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$letter" "$ip" "$seen" "$def" "$sig" \
      "${org:--}" "${cc:--}" "${city:--}" "${host:--}" "$kind" >> "$WORK/exits_info.tsv"
  done < "$WORK/exits.tsv"
}

# ---------- 分析 ----------

analyze() {
  cat > "$WORK/analyze.awk" <<'AWK'
BEGIN { FS = OFS = "\t"; LET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }

function is_private(ip, a) {
  split(ip, a, ".")
  a[1] += 0; a[2] += 0
  return a[1] == 10 || (a[1] == 172 && a[2] >= 16 && a[2] <= 31) || (a[1] == 192 && a[2] == 168) ||
         (a[1] == 100 && a[2] >= 64 && a[2] <= 127) || (a[1] == 169 && a[2] == 254)
}

# 比较两条路径，返回相同位置上相同的实际跳数；CONFLICT 是第一个不同的位置，0 表示没有不同。
# 不要求前缀完全一致：有多路径的线路，个别跳每次看到的路由器可能不一样
function common(x, y, a, b, na, nb, i, m) {
  na = split(x, a, " "); nb = split(y, b, " "); m = 0; CONFLICT = 0
  for (i = 1; i <= na && i <= nb; i++) {
    if (a[i] == "?" || b[i] == "?") continue
    if (a[i] != b[i]) { if (!CONFLICT) CONFLICT = i; continue }
    m++
  }
  return m
}

# 找相同跳数最多的已校准线路。这些线路都指向同一个出口才算推断成立
function infer(path, c, m, best, pos, nl, e, only, h, lab, cand, total, top) {
  INF_X = "-"; INF_E = "unknown"; INF_CAND = "-"
  if (path == "-" || path == "" || nc == 0) return
  best = 0; pos = 0; total = 0; split("", lab)
  for (c = 1; c <= nc; c++) {
    m = common(path, CP[c])
    if (m > best) { best = m; pos = CONFLICT; split("", lab); lab[CX[c]] = 1; total = 1 }
    else if (m == best && m > 0) { lab[CX[c]]++; total++ }
  }
  if (best == 0) return
  nl = 0; top = 0; cand = ""
  for (e in lab) {
    nl++; cand = cand (cand == "" ? "" : "/") LETTER[e]
    if (lab[e] > top) { top = lab[e]; only = e }
  }
  # 个别校准数据可能赶上线路切换：少数派不超过 2 条且不到一成时忽略
  if (nl > 1 && !(total - top <= 2 && (total - top) * 10 <= total)) { INF_E = "ambiguous"; INF_CAND = cand; return }
  INF_X = only; INF_E = "inferred"
  # 只有一个出口时没有分叉点可比。如果目标还在内网段就和校准线路分开，只算弱推断
  if (nx == 1 && pos > 0) {
    split(path, h, " ")
    if (h[pos] != "?" && is_private(h[pos])) INF_E = "weak"
  }
}

function firstk(p, k, a, na, i, s) {
  na = split(p, a, " "); s = ""
  for (i = 1; i <= na && i <= k; i++) s = s (i > 1 ? " " : "") a[i]
  return s
}

function hops(p, f, l, a, na, i, s) {
  na = split(p, a, " "); s = ""
  for (i = f; i <= l && i <= na; i++) s = s (s == "" ? "" : " > ") a[i]
  return s
}

# 汇总一个目标在某种解析方式下的结果，写入 S_*
function summarize(key, p, j, e, c, best, top) {
  S_L = "-"; S_X = "-"; S_E = "-"; S_M = "-"; S_A = 0; S_T = TOT[key, p] + 0; S_O = "-"
  if (S_T == 0) return
  S_L = "?"; best = 0
  for (j = 1; j <= nx; j++) {
    e = ORDER[j]; c = CNT[key, p, e] + 0
    if (c > best) { best = c; top = e; S_L = substr(LET, j, 1) }
  }
  if (best > 0) {
    S_X = top; S_A = best
    if ((key, p, top) in DIR) { S_E = "direct"; S_M = DIR[key, p, top] }
    else if ((key, p, top) in INFD) S_E = "inferred"
    else S_E = "weak"
    for (j = 1; j <= nx; j++) {
      e = ORDER[j]; c = CNT[key, p, e] + 0
      if (e != top && c > 0) S_O = (S_O == "-" ? "" : S_O " ") substr(LET, j, 1) ":" c
    }
    return
  }
  if (DNSFAIL[key, p] + 0 == S_T) S_E = "dns"
  else if ((key, p) in AMB) { S_E = "ambiguous"; S_M = AMB[key, p] }
  else if (CODE[key] == "000") S_E = "noconn"
  else S_E = "unknown"
}

# 先读目标清单，明细按清单顺序输出，不受探测完成先后影响
FILENAME == F_ORDER {
  split($0, ord, " ")
  key = ord[1] SUBSEP ord[2]
  if (!(key in SEEN)) { nt++; SEEN[key] = nt; KEYS[nt] = key; TC[nt] = ord[1]; TN[nt] = ord[2] }
  next
}

{
  n++
  KD[n] = $1; PS[n] = $2; CT[n] = $3; NM[n] = $4; RD[n] = $5; IP[n] = $6
  EX[n] = $7; MT[n] = $8; HC[n] = $9; CD[n] = $10; PT[n] = $11
  if ($7 != "-") known[$7] = 1
}

END {
  # 页面里出现已知出口，也算直接证据
  for (i = 1; i <= n; i++) {
    if (EX[i] != "-" || CD[i] == "-") continue
    m = split(CD[i], c, ",")
    for (j = 1; j <= m; j++) if (c[j] in known) { EX[i] = c[j]; MT[i] = "page"; break }
  }

  # 校准表：所有拿到回显的路径
  for (i = 1; i <= n; i++) {
    EV[i] = "unknown"
    if (EX[i] == "-") continue
    EV[i] = "direct"
    SEENX[EX[i]]++
    if (KD[i] == "C" && (MT[i] == "trace" || MT[i] == "plain")) NEUTRAL[EX[i]]++
    if (PT[i] != "-" && PT[i] != "") { nc++; CP[nc] = PT[i]; CX[nc] = EX[i] }
  }

  # 默认出口：中立回显里最多的那个，并列时取基线
  best = -1; DEF = BASE
  for (e in SEENX) {
    v = NEUTRAL[e] + 0
    if (v > best || (v == best && e == BASE)) { best = v; DEF = e }
  }
  if (!(DEF in SEENX)) SEENX[DEF] = 0
  nx = 1; ORDER[1] = DEF
  for (e in SEENX) if (e != DEF) { nx++; ORDER[nx] = e }
  for (a = 2; a <= nx; a++)
    for (b = a + 1; b <= nx; b++)
      if (SEENX[ORDER[b]] > SEENX[ORDER[a]]) { t = ORDER[a]; ORDER[a] = ORDER[b]; ORDER[b] = t }
  for (j = 1; j <= nx; j++) LETTER[ORDER[j]] = substr(LET, j, 1)

  # 没有回显的行用路由推断
  for (i = 1; i <= n; i++) {
    if (EX[i] != "-" || MT[i] == "dns") continue
    infer(PT[i])
    EV[i] = INF_E; CAND[i] = INF_CAND
    if (INF_X != "-") EX[i] = INF_X
  }

  # 按目标汇总
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T") continue
    key = CT[i] SUBSEP NM[i]
    if (!(key in SEEN)) { nt++; SEEN[key] = nt; KEYS[nt] = key; TC[nt] = CT[i]; TN[nt] = NM[i] }
    p = PS[i]
    TOT[key, p]++
    if (IP[i] != "-" && !((key, IP[i]) in IPSEEN)) { IPSEEN[key, IP[i]] = 1; IPC[key]++ }
    if (HC[i] != "-" && !(key in CODE)) CODE[key] = HC[i]
    if (MT[i] == "dns") DNSFAIL[key, p]++
    if (EX[i] != "-") {
      CNT[key, p, EX[i]]++
      if (EV[i] == "direct") { if (!((key, p, EX[i]) in DIR)) DIR[key, p, EX[i]] = MT[i] }
      else if (EV[i] == "inferred") INFD[key, p, EX[i]] = 1
    } else if (EV[i] == "ambiguous") AMB[key, p] = CAND[i]
  }

  f = OUT "/targets.tsv"
  for (t2 = 1; t2 <= nt; t2++) {
    key = KEYS[t2]
    summarize(key, "P")
    pl = S_L; px = S_X; pe = S_E; pm = S_M; pa = S_A; pt = S_T; po = S_O
    summarize(key, "E")
    el = S_L; ex = S_X; ee = S_E; em = S_M
    if (px == "-") cls = "unknown"
    else if (el == "-") cls = (px == DEF ? "none" : "split")
    else if (ex == "-") cls = (px == DEF ? "none" : "split")
    else if (ex == DEF && px == DEF) cls = "none"
    else if (ex == DEF && px != DEF) cls = "dns"
    else if (ex != DEF && px != DEF) cls = "static"
    else cls = "mixed"
    print TC[t2], TN[t2], pl, px, pe, pm, pa, pt, po, el, ex, ee, em, cls, IPC[key] + 0, (key in CODE ? CODE[key] : "-") > f
  }

  # 每个出口最常见的路径前段，用来显示分叉点
  for (i = 1; i <= n; i++) {
    if (EV[i] != "direct" || PT[i] == "-" || PT[i] == "") continue
    pre = firstk(PT[i], 6)
    PC[EX[i], pre]++
    if (PC[EX[i], pre] > PCM[EX[i]] + 0) { PCM[EX[i]] = PC[EX[i], pre]; REP[EX[i]] = pre }
  }
  F = 99; L2 = 0
  for (a = 1; a <= nx; a++)
    for (b = a + 1; b <= nx; b++) {
      if (!(ORDER[a] in REP) || !(ORDER[b] in REP)) continue
      common(REP[ORDER[a]], REP[ORDER[b]])
      if (CONFLICT > 0) { if (CONFLICT < F) F = CONFLICT; if (CONFLICT > L2) L2 = CONFLICT }
    }
  f = OUT "/exits.tsv"
  for (j = 1; j <= nx; j++) {
    e = ORDER[j]
    sig = (F <= L2 && (e in REP)) ? hops(REP[e], F, L2) : "-"
    if (sig == "") sig = "-"
    print substr(LET, j, 1), e, SEENX[e] + 0, (e == DEF ? 1 : 0), sig > f
  }

  f = OUT "/detail.tsv"
  for (i = 1; i <= n; i++) {
    if (KD[i] == "X") continue
    print KD[i], PS[i], CT[i], NM[i], RD[i], IP[i], (EX[i] in LETTER ? LETTER[EX[i]] : "?"), EX[i], EV[i], MT[i], PT[i] > f
  }
}
AWK
  touch "$WORK/targets.tsv" "$WORK/exits.tsv" "$WORK/detail.tsv"
  awk -v BASE="$BASE_IP" -v OUT="$WORK" -v F_ORDER="$WORK/targets.txt" -f "$WORK/analyze.awk" "$WORK/targets.txt" "$WORK/rows.tsv" ||
    die "分析结果时出错"
  # 分析出错不能当成“没有分流”
  [[ -s $WORK/exits.tsv && -s $WORK/targets.tsv ]] || die "分析结果时出错：没有出口数据"
}

# ---------- 输出 ----------

report_text() {
  local R='' B='' DIM='' GRN='' YEL='' MAG='' CYN='' RED=''
  if (( USE_COLOR )) && [[ -t 1 ]]; then
    R=$'\033[0m'; B=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[32m'
    YEL=$'\033[33m'; MAG=$'\033[35m'; CYN=$'\033[36m'; RED=$'\033[31m'
  fi
  cat_labels > "$WORK/cats.txt"
  cat > "$WORK/report.awk" <<'AWK'
BEGIN { FS = "\t" }

# 按显示宽度补空格：C locale 下 length 数字节，汉字 3 字节占 2 格
function pad(s, w, t, hb, cells) {
  t = s; hb = gsub(/[^\001-\177]/, "", t)
  cells = length(s) - hb + int(hb * 2 / 3)
  return s (w > cells ? sprintf("%" (w - cells) "s", "") : "")
}
function lc(l, s) {
  if (l == "A") return GRN s R
  if (l == "B") return YEL s R
  if (l == "C") return MAG s R
  if (l == "?" || l == "-") return DIM s R
  return CYN s R
}
function mname(m) {
  if (m == "cloudflare") return "CF"
  if (m == "akamai") return "Akamai"
  if (m == "fastly") return "Fastly"
  if (m == "cloudfront") return "CloudFront"
  if (m == "google") return "Google"
  if (m == "meta") return "Meta"
  if (m == "page") return "页面"
  return m
}
function evid(e, m) {
  if (e == "direct") return "直接·" mname(m)
  if (e == "inferred") return "推断"
  if (e == "weak") return "弱推断"
  if (e == "ambiguous") return "不确定 " m
  if (e == "dns") return "解析失败"
  if (e == "noconn") return "连不上"
  return "未知"
}
function letter_of(ip) { return (ip in IDX) ? XL[IDX[ip]] : ip }
function letter_net(net, pre, j, q) {
  pre = net; sub(/\.[0-9]+\/[0-9]+$/, ".", pre)
  for (j = 1; j <= nx; j++) { q = XI[j]; if (index(q, pre) == 1) return XL[j] }
  return net
}
function asn(s, a) { split(s, a, " "); return a[1] }

FILENAME == F_CATS { split($0, a, " "); if (!(a[1] in CL)) { nc++; CO[nc] = a[1]; CL[a[1]] = a[2] } next }
FILENAME == F_EXITS {
  nx++; XL[nx] = $1; XI[nx] = $2; XS[nx] = $3; XDEF[nx] = $4; XSIG[nx] = $5
  XORG[nx] = $6; XCC[nx] = $7; XCITY[nx] = $8; XHOST[nx] = $9; XKIND[nx] = $10
  IDX[$2] = nx; next
}
FILENAME == F_TARGETS {
  nt++; TC[nt] = $1; TN[nt] = $2; PL[nt] = $3; PX[nt] = $4; PE[nt] = $5; PM[nt] = $6; PA[nt] = $7; PT[nt] = $8; PO[nt] = $9
  EL[nt] = $10; EX[nt] = $11; EE[nt] = $12; EM[nt] = $13; KC[nt] = $14; IC[nt] = $15; HC[nt] = $16
  if (!($1 in CL)) { nc++; CO[nc] = $1; CL[$1] = $1 }
  CCOUNT[$1]++
  MP[$1, $3]++
  if ($10 != "-") { HASE = 1; ME[$1, $10]++ }
  if ($14 == "dns") ndns++
  if ($14 == "static") nstatic++
  if ($14 == "split") nsplit++
  if ($14 == "mixed") nmixed++
  if ($3 == "?") nunk++
  next
}
FILENAME == F_TRIGGER { ntr++; GN[ntr] = $2; GI[ntr] = $3; GB[ntr] = $4; GA[ntr] = $5; next }
FILENAME == F_SNIFF { nsn++; SN[nsn] = $1; SR[nsn] = $2; next }
FILENAME == F_DNSQ { nq++; QN[nq] = $1; QV[nq] = $2; next }
FILENAME == F_ENV { ENVV[$1] = $2; next }
FILENAME == F_DETAIL { ndt++; DL[ndt] = $0; next }

END {
  print B "splitcheck " ENVV["version"] R "  " ENVV["host"] "  " ENVV["time"] DIM "  用时 " ENVV["elapsed"] " 秒" R
  line = nt " 个目标"
  if (ENVV["region"] != "none") line = line " · 地区 " ENVV["region"]
  if (ENVV["proxy"] != "-") line = line " · 经代理 " ENVV["proxy"]
  else {
    line = line " · 路由探测 " (ENVV["tracer"] == "none" ? "无" : ENVV["tracer"])
    if ("resolver" in ENVV) line = line " · 系统 DNS " ENVV["resolver"]
  }
  print DIM line R
  print ""

  # 结论
  nother = 0
  for (j = 2; j <= nx; j++) if (asn(XORG[j]) != asn(XORG[1])) nother++
  if (nx >= 2) {
    line = "有分流，发现 " nx " 个出口"
    if (nother > 0) line = line "，其中 " nother " 个不是默认运营商"
    else line = line "，都属于默认运营商"
    print B "结论" R "  " RED line R
  } else {
    print B "结论" R "  " GRN "未发现分流，能确认的目标都从 " XI[1] " 出去" R
  }
  if (nx >= 2) {
    same24 = 1
    pre = XI[1]; sub(/\.[0-9]+$/, ".", pre)
    for (j = 2; j <= nx; j++) if (index(XI[j], pre) != 1) same24 = 0
    if (same24) print "      " DIM "这些出口在同一个 /24，也可能是运营商的出口池轮换，不一定是分流" R
    once = 0
    for (j = 2; j <= nx; j++) if (XS[j] + 0 <= 1) once++
    if (once > 0) print "      " DIM once " 个出口只回显过 1 次，可能是误报，看明细确认" R
  }
  if (ndns > 0) print "      " ndns " 个目标由明文 DNS 触发：加密 DNS 下走默认出口，系统 DNS 下走分流"
  if (nstatic > 0) print "      " nstatic " 个目标在分流名单内：加密 DNS 下也走分流"
  if (nsplit > 0) print "      " nsplit " 个目标走了非默认出口"
  if (nmixed > 0) print "      " nmixed " 个目标系统 DNS 走默认出口、加密 DNS 反而走分流，通常是解析到的 IP 不同"
  if (nunk > 0) print "      " DIM nunk " 个目标无法确认出口" R
  print ""

  # 出口
  print B "出口" R
  for (j = 1; j <= nx; j++) {
    line = "  " lc(XL[j], B XL[j] (XDEF[j] ? " 默认" : "     ") R) "  " pad(XI[j], 16) "  " XORG[j]
    if (XCC[j] != "-") line = line "  " XCC[j]
    if (XCITY[j] != "-") line = line " " XCITY[j]
    if (XKIND[j] == "hosting") line = line "  " YEL "标记为机房" R
    if (XKIND[j] == "mobile") line = line "  标记为移动网络"
    if (XKIND[j] == "proxy") line = line "  " YEL "标记为代理" R
    print line
    line = "回显 " XS[j] " 次"
    if (XSIG[j] != "-") line = line " · 线路 " XSIG[j]
    if (XHOST[j] != "-") line = line " · 反解 " XHOST[j]
    print "         " DIM line R
  }
  print ""

  # 分类概览
  print B "分类概览" R DIM "（目标数）" R
  w = (nx + 1) * 4
  PH = (ENVV["proxy"] != "-") ? "节点 DNS" : "系统 DNS"
  print "  " pad("", 10) pad(" " PH, w) (HASE ? "   " pad(" 加密 DNS", w) : "")
  line = "  " pad("", 10)
  for (j = 1; j <= nx; j++) line = line lc(XL[j], sprintf("%4s", XL[j]))
  line = line DIM sprintf("%4s", "?") R
  if (HASE) {
    line = line "   "
    for (j = 1; j <= nx; j++) line = line lc(XL[j], sprintf("%4s", XL[j]))
    line = line DIM sprintf("%4s", "?") R
  }
  print line
  for (c = 1; c <= nc; c++) {
    k = CO[c]
    if (!(k in CCOUNT)) continue
    line = "  " pad(CL[k], 10)
    for (j = 1; j <= nx; j++) { v = MP[k, XL[j]] + 0; line = line (v ? lc(XL[j], sprintf("%4d", v)) : DIM sprintf("%4s", ".") R) }
    v = MP[k, "?"] + 0; line = line DIM sprintf("%4s", v ? v : ".") R
    if (HASE) {
      line = line "   "
      for (j = 1; j <= nx; j++) { v = ME[k, XL[j]] + 0; line = line (v ? lc(XL[j], sprintf("%4d", v)) : DIM sprintf("%4s", ".") R) }
      v = ME[k, "?"] + 0; line = line DIM sprintf("%4s", v ? v : ".") R
    }
    print line
  }
  print ""

  # 明文 DNS 触发测试
  if (ENVV["trigger"] == "no-dig") {
    print B "明文 DNS 触发测试" R "  " DIM "没有 dig，已跳过（Debian: apt install -y dnsutils）" R
    print ""
  } else if (ntr > 0) {
    tested = 0; fired = 0; same = ""; nsame = 0; before = ""; nbefore = 0
    for (i = 1; i <= ntr; i++) {
      if (GB[i] == "-") continue
      tested++
      if (GB[i] != GA[i]) fired++
      else if (GB[i] == XI[1]) { nsame++; same = same (same == "" ? "" : " ") GN[i] }
      else { nbefore++; before = before (before == "" ? "" : " ") GN[i] "(" letter_of(GB[i]) ")" }
    }
    print B "明文 DNS 触发测试" R DIM "（外地节点 IP，明文查询前后的真实出口）" R
    if (tested == 0) print "  " DIM "抽样的域名都拿不到回显" R
    for (i = 1; i <= ntr; i++) {
      if (GB[i] == "-" || GB[i] == GA[i]) continue
      print "  " pad(GN[i], 34) pad(GI[i], 17) lc(letter_of(GB[i]), letter_of(GB[i])) " → " lc(letter_of(GA[i]), letter_of(GA[i]))
    }
    print "  触发 " (fired ? YEL fired R : "0") " / 可测 " tested DIM "（另有 " (ntr - tested) " 个拿不到回显）" R
    if (nbefore > 0 && !BRIEF) print "  " DIM "查询前就在分流线：" before R
    if (nsame > 0 && !BRIEF) print "  " DIM "不受影响：" same R
    print ""
  }

  # 明细
  if (!BRIEF) {
    head = "  " pad("目标", 36) pad(PH, 21) pad("轮次", 6)
    if (HASE) head = head pad("加密", 6)
    print B "明细" R
    print DIM head "证据" R
    for (c = 1; c <= nc; c++) {
      k = CO[c]
      if (!(k in CCOUNT)) continue
      print "  " B CL[k] R
      for (t = 1; t <= nt; t++) {
        if (TC[t] != k) continue
        v = PL[t] " " (PX[t] == "-" ? "" : PX[t])
        line = "    " pad(TN[t], 34) lc(PL[t], pad(v, 21)) pad(PX[t] == "-" ? "" : PA[t] "/" PT[t], 6)
        if (HASE) line = line lc(EL[t], pad(EL[t], 6))
        line = line evid(PE[t], PM[t])
        if (PO[t] != "-") { o = PO[t]; gsub(/:/, "×", o); line = line DIM "  另 " o R }
        if (KC[t] == "dns") line = line "  " YEL "DNS触发" R
        else if (KC[t] == "static") line = line "  " MAG "名单内" R
        else if (KC[t] == "mixed") line = line "  " DIM "解析不同" R
        print line
      }
    }
    print ""
  }

  # 其他检查
  has_other = nsn > 0 || nq > 0 || ("route_defaults" in ENVV) || ("ipv6" in ENVV) || (ENVV["tracer"] == "none" && ENVV["use_route"] == 1)
  if (has_other) print B "其他检查" R
  if (nsn > 0) {
    changed = ""; nc2 = 0
    for (i = 1; i <= nsn; i++) if (SR[i] != ENVV["sniff_base"]) { nc2++; changed = changed " " SN[i] "=" SR[i] }
    if (nc2 == 0) print "  " pad("SNI 嗅探", 12) nsn " 个域名放进 SNI，出口都没变，没有按 TLS 域名分流"
    else print "  " pad("SNI 嗅探", 12) YEL nc2 "/" nsn " 个域名出口变了：" changed R
  }
  if (nq > 0) {
    line = ""
    for (i = 1; i <= nq; i++) {
      if (QV[i] == "-") continue
      v = (QV[i] ~ /\//) ? letter_net(QV[i]) : letter_of(QV[i])
      line = line (line == "" ? "" : " · ") QN[i] " " v
    }
    if (line != "") print "  " pad("DNS 查询", 12) line DIM "（UDP，上游看到的来源）" R
  }
  if ("route_defaults" in ENVV) {
    line = ENVV["route_defaults"] " 条默认路由"
    if (ENVV["route_rules"] + 0 > 0) line = line "，" ENVV["route_rules"] " 条策略规则"
    if (ENVV["route_tunnels"] != "-") line = line "，隧道 " ENVV["route_tunnels"]
    if (nx >= 2 && ENVV["route_defaults"] + 0 <= 1 && ENVV["route_rules"] + 0 == 0 && ENVV["route_tunnels"] == "-")
      line = line "，分流发生在上游，不在本机"
    print "  " pad("本机路由", 12) line
  }
  if (ENVV["tracer"] == "none" && ENVV["use_route"] == 1)
    print "  " pad("路由探测", 12) YEL "没有可用的路由工具，不回显的目标无法判断（Debian: apt install -y mtr-tiny）" R
  if ("ipv6" in ENVV) {
    if (ENVV["ipv6"] == "-") print "  " pad("IPv6", 12) "没有 IPv6 出口"
    else print "  " pad("IPv6", 12) ENVV["ipv6"] YEL "（支持 IPv6 的目标可能从这里出去，本次只测 IPv4）" R
  }
  if (has_other) print ""

  if (VERBOSE) {
    print B "每轮明细" R DIM "（E=加密 DNS，P=系统 DNS，C=校准）" R
    for (i = 1; i <= ndt; i++) {
      split(DL[i], d, "\t")
      print "  " d[2] d[5] " " pad(d[4], 34) pad(d[6], 17) lc(d[7], d[7]) " " pad(d[8], 16) " " pad(d[9] (d[10] == "-" ? "" : "/" d[10]), 20) DIM d[11] R
    }
    print ""
  }

  print DIM "直接：目标或同一 IP 上的 CDN 回显的访问者 IP。推断：路由和已校准出口的线路相同，没有直接证据。" R
  print DIM "弱推断：只有一个出口可比，目标又在内网段就分开了，可信度低。" R
  if (ndns + nstatic > 0) {
    print DIM "DNS触发：这个目标解析到的 IP 只有经明文查询才会进分流名单。名单内：解析到的 IP 已在名单里，" R
    print DIM "可能是静态名单，也可能是被其他明文查询写进去的；上面的触发测试能看出上游是否按 DNS 写名单。" R
  }
  if (ENVV["proxy"] != "-") print DIM "经代理时只有回显证据，不回显的目标显示未知。" R
  else print DIM "这里测的是上游这一层。节点上的 xray/sing-box 可能另有路由规则，要检查这一层请用 -x 经节点测。" R
}
AWK
  touch "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" "$WORK/env.tsv" "$WORK/detail.tsv"
  awk -v R="$R" -v B="$B" -v DIM="$DIM" -v GRN="$GRN" -v YEL="$YEL" -v MAG="$MAG" -v CYN="$CYN" -v RED="$RED" \
    -v BRIEF="$BRIEF" -v VERBOSE="$VERBOSE" \
    -v F_CATS="$WORK/cats.txt" -v F_EXITS="$WORK/exits_info.tsv" -v F_TARGETS="$WORK/targets.tsv" \
    -v F_TRIGGER="$WORK/trigger.tsv" -v F_SNIFF="$WORK/sniff.tsv" -v F_DNSQ="$WORK/dnsq.tsv" \
    -v F_ENV="$WORK/env.tsv" -v F_DETAIL="$WORK/detail.tsv" \
    -f "$WORK/report.awk" \
    "$WORK/cats.txt" "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" \
    "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" "$WORK/detail.tsv" || die "生成报告时出错"
}

report_json() {
  cat > "$WORK/json.awk" <<'AWK'
BEGIN { FS = "\t" }
function s(v) { gsub(/[\\"]/, "", v); return "\"" v "\"" }
function sn(v) { return (v == "-" || v == "") ? "null" : s(v) }
FILENAME == F_ENV { ENVV[$1] = $2; next }
FILENAME == F_EXITS {
  nx++
  X[nx] = "{\"id\":" s($1) ",\"ip\":" s($2) ",\"default\":" ($4 ? "true" : "false") ",\"seen\":" ($3 + 0) \
    ",\"org\":" sn($6) ",\"country\":" sn($7) ",\"city\":" sn($8) ",\"hostname\":" sn($9) ",\"flag\":" sn($10) ",\"route\":" sn($5) "}"
  if ($4) DEF = $2
  next
}
FILENAME == F_TARGETS {
  nt++
  T[nt] = "{\"category\":" s($1) ",\"name\":" s($2) \
    ",\"system_dns\":{\"exit_id\":" sn($3) ",\"exit\":" sn($4) ",\"evidence\":" sn($5) ",\"method\":" sn($6) ",\"agree\":" ($7 + 0) ",\"rounds\":" ($8 + 0) ",\"others\":" sn($9) "}" \
    ",\"encrypted_dns\":{\"exit_id\":" sn($10) ",\"exit\":" sn($11) ",\"evidence\":" sn($12) ",\"method\":" sn($13) "}" \
    ",\"class\":" s($14) ",\"ip_count\":" ($15 + 0) ",\"http\":" sn($16) "}"
  next
}
FILENAME == F_TRIGGER {
  ng++
  G[ng] = "{\"category\":" s($1) ",\"name\":" s($2) ",\"ip\":" sn($3) ",\"before\":" sn($4) ",\"after\":" sn($5) "}"
  if ($4 != "-" && $4 != $5) fired = 1
  next
}
FILENAME == F_SNIFF { nn++; N[nn] = "{\"sni\":" s($1) ",\"exit\":" sn($2) "}"; next }
FILENAME == F_DNSQ { nq++; Q[nq] = s($1) ":" sn($2); next }
function arr(a, n, i, o) { o = "["; for (i = 1; i <= n; i++) o = o (i > 1 ? "," : "") a[i]; return o "]" }
END {
  printf "{\"version\":%s,\"host\":%s,\"time\":%s,\"elapsed\":%d,\"proxy\":%s,\"region\":%s,\"tracer\":%s,", \
    s(ENVV["version"]), s(ENVV["host"]), s(ENVV["time"]), ENVV["elapsed"], sn(ENVV["proxy"]), s(ENVV["region"]), s(ENVV["tracer"])
  printf "\"split\":%s,\"dns_triggered\":%s,\"default_exit\":%s,", (nx >= 2 ? "true" : "false"), (fired ? "true" : "false"), s(DEF)
  printf "\"exits\":%s,\"targets\":%s,\"dns_trigger_test\":%s,\"sni_test\":{\"baseline\":%s,\"results\":%s},", \
    arr(X, nx), arr(T, nt), arr(G, ng), sn(ENVV["sniff_base"]), arr(N, nn)
  printf "\"dns_query\":{"
  for (i = 1; i <= nq; i++) printf "%s%s", (i > 1 ? "," : ""), Q[i]
  printf "},\"ipv6\":%s}\n", sn(ENVV["ipv6"])
}
AWK
  touch "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" "$WORK/env.tsv"
  awk -v F_ENV="$WORK/env.tsv" -v F_EXITS="$WORK/exits_info.tsv" -v F_TARGETS="$WORK/targets.tsv" \
    -v F_TRIGGER="$WORK/trigger.tsv" -v F_SNIFF="$WORK/sniff.tsv" -v F_DNSQ="$WORK/dnsq.tsv" \
    -f "$WORK/json.awk" \
    "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" || die "生成 JSON 时出错"
}

main() {
  parse_args "$@"
  check_deps
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/splitcheck.XXXXXX") || die "建不了临时目录"
  trap cleanup EXIT
  trap 'exit 130' INT TERM
  mkdir -p "$WORK/fp" "$WORK/path"
  touch "$WORK/rows.tsv" "$WORK/page_names" "$WORK/env.tsv" "$WORK/trigger.tsv"

  # 到系统 DNS 那一轮之前，所有解析都走 DoH，请求都钉到 IP，不发任何明文查询
  progress "确认出口"
  find_baseline
  [[ -n $PROXY ]] || IPINFO_IP=$(doh ipinfo.io | head -1)
  detect_region
  load_targets
  progress "选择路由探测方式"
  detect_tracer
  progress "校准出口"
  run_calibration
  if (( USE_DNS_TEST )); then
    run_pass E 1 "加密 DNS"
    run_trigger
  fi
  run_pass P "$ROUNDS" "系统 DNS"
  run_sniff
  progress "收集环境信息"
  dns_query_exits
  env_info
  analyze
  lookup_exits
  progress_done
  if (( JSON )); then
    report_json
  else
    report_text
  fi
}

# 脚本可能经 bash -s 从 stdin 读入，子命令不能碰 stdin
main "$@" </dev/null
