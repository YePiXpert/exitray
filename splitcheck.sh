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
# 分流和拦截规则常常按 IP 段写，同一个域名换个解析器就可能落在规则外，所以加密 DNS 那一轮把
# Google 和 Cloudflare 的应答合起来，每个 /24 测一个 IP，并记下每个 IP 连不连得上。
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

VERSION="1.4.0"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'
CATEGORIES='ai meta telegram social google stream finance crypto bank shop dev game local'

ROUNDS=2
PARALLEL=8
PARALLEL_SET=0
LOW_RESOURCE=0
EXIT_CODE=0
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
MARKDOWN=0
MASK=1
BRIEF=0
VERBOSE=0
USE_COLOR=1
STDIN_TTY=0

WORK=""
TRACER=none
FORCE_TRACER=""
FALLBACK=""
BASE_IP=""
EXIT_NET=""
IPINFO_IP=""
IPAPI_IP=""
RUNNING=0
PROGRESS=/dev/null
MAX_IPS=3
LIMIT=""
RESOLVE_LIMIT=""
HAS_WAIT_N=0
HAS_CONNECT_TO=0
START_TS=$(date +%s)

# 这些都走外地节点 IP，用来做明文 DNS 触发测试：日本、德国、加拿大、巴西
FAR_SUBNETS="126.0.0.0/24 85.214.0.0/24 24.48.0.0/24 177.0.0.0/24"

usage() {
  cat <<'EOF'
用法: splitcheck.sh [选项]

看每个目标实际从哪个 IP 出去，判断 VPS 或节点有没有分流、是怎么分的流。

  -c, --category 列表   只测这些分类，逗号分隔：
                        ai,meta,telegram,social,google,stream,finance,crypto,bank,shop,dev,game,local
                        写 none 则不用内置清单，只测 -a、-f 给的目标
  -r, --region 地区     本地银行和电商清单：auto（默认，按出口国家）tw jp hk us sg kr vn none
  -a, --add 分类:域名   追加目标，可重复，例如 -a shop:www.pchome.com.tw
  -f, --file 文件       从文件读目标，每行“分类 域名”
  -n, --rounds N        系统 DNS 测几轮，默认 2
  -p, --parallel N      并发数，默认 8
  -L, --low-resource    低压力模式：按 CPU 核数把并发降到 2-4，路由探测降低优先级
  -x, --proxy URL       经代理测，用来检查节点本身的分流，例如 socks5h://127.0.0.1:1080
      --tracer 工具     指定路由工具：mtr-icmp mtr-tcp traceroute-tcp traceroute tracepath
      --no-route        不探测路由，只看回显（不回显的目标显示未知）
      --no-dns-test     跳过加密 DNS 轮和明文 DNS 触发测试
      --no-sniff        跳过 SNI 嗅探测试
  -b, --brief           只输出结论和分类概览
  -v, --verbose         额外输出每一轮的 IP、路径和证据
  -j, --json            输出 JSON
  -m, --markdown        输出方便分享的 Markdown 报告，IP 默认打码，可重定向到文件
      --no-mask         分享摘要和 Markdown 里显示完整 IP
      --exit-code       用退出码表示结论，方便 cron 和监控（见下）
  -y, --yes             不显示启动菜单，直接测全部分类
      --no-color        不用颜色
  -V, --version         显示版本
  -h, --help            显示帮助

退出码：0 检测完成，1 运行出错。加 --exit-code 后，0 未发现分流，
2 有分流、DNS 被动了手脚或有 IP 被拦截，3 没发现分流但部分目标证据不足。

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
social line.me
social legy.line-apps.com
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
dev github.com
dev raw.githubusercontent.com
dev gitlab.com
dev registry.npmjs.org
dev pypi.org
dev registry-1.docker.io
dev stackoverflow.com
game store.steampowered.com
game steamcommunity.com
game www.epicgames.com
game www.playstation.com
game www.xbox.com
game www.nintendo.com
@tw bank www.ctbcbank.com
@tw bank www.cathaybk.com.tw
@tw bank www.esunbank.com
@tw bank www.fubon.com
@tw bank www.taishinbank.com.tw
@tw bank www.megabank.com.tw
@tw bank www.bot.com.tw
@tw bank www.post.gov.tw
@tw finance www.jkopay.com
@tw shop shopee.tw
@tw shop seller.shopee.tw
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
dev 开发者
game 游戏
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
  (( UI_ON )) && printf '\r\033[K' >&2
  printf 'splitcheck: %s\n' "$*" >&2
  exit 1
}

warn() {
  (( UI_ON )) && printf '\r\033[K' >&2
  printf 'splitcheck: %s\n' "$*" >&2
}

# 代理地址可能带账号密码，写进报告前要去掉
proxy_label() {
  printf '%s' "${PROXY/:\/\/*@/://}"
}

is_category() {
  [[ " $CATEGORIES " == *" $1 "* ]]
}

# ---------- 界面：全部写到 stderr，重定向 stdout 时不受影响 ----------

UI=0
UI_ON=0
MENU_SHOWN=0
U_R='' U_B='' U_D='' U_G='' U_C='' U_Y=''
SPIN=0
SPIN_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
STEP_LABEL='' STEP_TOTAL=0 STEP_FILE='' STEP_BASE=0 STEP_T0=0 STEP_DETAIL=''

ui_setup() {
  [[ -t 2 ]] || return 0
  UI=1
  if (( USE_COLOR )); then
    U_R=$'\033[0m'; U_B=$'\033[1m'; U_D=$'\033[2m'
    U_G=$'\033[32m'; U_C=$'\033[36m'; U_Y=$'\033[33m'
  fi
}

ui_title() {
  (( UI )) || return 0
  UI_ON=1
  # 刷新进度时隐藏光标、关闭自动换行，退出时恢复
  printf '\033[?25l\033[?7l' >&2
  # 菜单已经显示过名称，这里只留分隔线
  (( MENU_SHOWN )) || printf '\n  %ssplitcheck %s%s  VPS / 家宽出口分流检测' "$U_B" "$VERSION" "$U_R" >&2
  printf '\n  %s────────────────────────────────────────────%s\n\n' "$U_D" "$U_R" >&2
}

ui_finish() {
  (( UI_ON )) || return 0
  printf '\r\033[K\033[?7h\033[?25h\n' >&2
  UI_ON=0
}

# 按显示宽度补空格：C locale 下汉字 3 字节占 2 格
ui_pad() {
  local s=$1 ascii=${1//[^[:ascii:]]/} hb cells
  hb=$(( ${#s} - ${#ascii} ))
  cells=$(( ${#ascii} + hb * 2 / 3 ))
  printf '%s%*s' "$s" $(( $2 > cells ? $2 - cells : 0 )) ''
}

ui_lines() {
  local n
  n=$(wc -l < "$1" 2>/dev/null)
  printf '%s' $(( ${n:-0} ))
}

ui_paint() {
  (( UI_ON )) || return 0
  local frame=${SPIN_FRAMES[SPIN % 10]} finished filled i bar='' line
  SPIN=$((SPIN + 1))
  line="  ${U_C}${frame}${U_R} $(ui_pad "$STEP_LABEL" 20)"
  if (( STEP_TOTAL > 0 )); then
    finished=$(( $(ui_lines "$STEP_FILE") - STEP_BASE ))
    (( finished > STEP_TOTAL )) && finished=$STEP_TOTAL
    filled=$(( finished * 20 / STEP_TOTAL ))
    for (( i = 0; i < 20; i++ )); do
      if (( i < filled )); then bar+='█'; else bar+='░'; fi
    done
    line+=" ${U_C}${bar}${U_R} $finished/$STEP_TOTAL"
  fi
  line+=" ${U_D}$((SECONDS - STEP_T0))s${STEP_DETAIL:+  $STEP_DETAIL}${U_R}"
  printf '\r\033[K%s' "$line" >&2
}

# 标签 [总数 计数文件]：计数文件每完成一项多一行
step_begin() {
  STEP_LABEL=$1 STEP_TOTAL=${2:-0} STEP_FILE=${3:-} STEP_T0=$SECONDS STEP_DETAIL='' STEP_BASE=0
  [[ -z $STEP_FILE ]] || STEP_BASE=$(ui_lines "$STEP_FILE")
  ui_paint
}

step_end() {
  (( UI_ON )) || return 0
  printf '\r\033[K  %s✓%s %s %s  %s%ss%s\n' "$U_G" "$U_R" "$(ui_pad "$STEP_LABEL" 20)" "$1" "$U_D" "$((SECONDS - STEP_T0))" "$U_R" >&2
}

ui_warn() {
  (( UI_ON )) || return 0
  printf '\r\033[K  %s! %s%s\n' "$U_Y" "$1" "$U_R" >&2
}

# 没带参数、在终端里直接运行时显示
show_menu() {
  local choice cats c
  MENU_SHOWN=1
  printf '\n  %ssplitcheck %s%s  VPS / 家宽出口分流检测\n' "$U_B" "$VERSION" "$U_R" >&2
  cat >&2 <<'EOF'

  请选择检测范围：

    1) 完整检测    全部分类，约 2 分钟
    2) AI 和社媒   AI、Meta、Telegram、社媒、Google
    3) 金融和购物  金融支付、虚拟币、银行、电商购物
    4) 流媒体      流媒体、Google
    5) 自选分类    输入分类名
    6) 快速检测    全部分类，不测 DNS 触发，约 1 分钟
    7) 低压力检测  全部分类，降低并发，适合小内存 VPS，用时更长
    0) 退出
EOF
  while :; do
    printf '\n  请输入 [默认 1]: ' >&2
    IFS= read -r choice </dev/tty || choice=1
    case ${choice:-1} in
      1) return 0 ;;
      2) CATS=ai,meta,telegram,social,google; return 0 ;;
      3) CATS=finance,crypto,bank,shop; return 0 ;;
      4) CATS=stream,google; return 0 ;;
      5)
        printf '  可选：%s\n  用逗号分隔: ' "$CATEGORIES" >&2
        IFS= read -r cats </dev/tty || cats=''
        cats=${cats// /}
        for c in ${cats//,/ }; do
          is_category "$c" || { printf '  没有这个分类: %s\n' "$c" >&2; cats=''; break; }
        done
        [[ -n $cats ]] && { CATS=$cats; return 0; }
        ;;
      6) USE_DNS_TEST=0; USE_SNIFF=0; return 0 ;;
      7) LOW_RESOURCE=1; return 0 ;;
      0|q) exit 0 ;;
      *) printf '  请输入 0 到 7\n' >&2 ;;
    esac
  done
}

need_arg() {
  (( $2 >= 2 )) || die "$1 需要参数"
}

parse_args() {
  local c
  while (( $# )); do
    case $1 in
      -c|--category) need_arg "$1" $#; CATS=$2; shift 2 ;;
      -r|--region)   need_arg "$1" $#; REGION=$2; shift 2 ;;
      -a|--add)      need_arg "$1" $#; EXTRA+=("$2"); shift 2 ;;
      -f|--file)     need_arg "$1" $#; TARGET_FILE=$2; shift 2 ;;
      -n|--rounds)   need_arg "$1" $#; ROUNDS=$2; shift 2 ;;
      -p|--parallel) need_arg "$1" $#; PARALLEL=$2; PARALLEL_SET=1; shift 2 ;;
      -L|--low-resource) LOW_RESOURCE=1; shift ;;
      --exit-code)   EXIT_CODE=1; shift ;;
      -x|--proxy)    need_arg "$1" $#; PROXY=$2; shift 2 ;;
      --tracer)      need_arg "$1" $#; FORCE_TRACER=$2; shift 2 ;;
      --no-route)    USE_ROUTE=0; shift ;;
      --no-dns-test) USE_DNS_TEST=0; shift ;;
      --no-sniff)    USE_SNIFF=0; shift ;;
      -b|--brief)    BRIEF=1; shift ;;
      -v|--verbose)  VERBOSE=1; shift ;;
      -j|--json)     JSON=1; shift ;;
      -m|--markdown) MARKDOWN=1; shift ;;
      --no-mask)     MASK=0; shift ;;
      -y|--yes)      shift ;;
      --no-color)    USE_COLOR=0; shift ;;
      -V|--version)  echo "splitcheck $VERSION"; exit 0 ;;
      -h|--help)     usage; exit 0 ;;
      *) die "未知选项 $1，用 --help 查看用法" ;;
    esac
  done
  [[ $ROUNDS =~ ^[1-9][0-9]*$ ]] || die "--rounds 必须是正整数"
  [[ $PARALLEL =~ ^[1-9][0-9]*$ ]] || die "--parallel 必须是正整数"
  [[ -z $TARGET_FILE || -r $TARGET_FILE ]] || die "读不了文件 $TARGET_FILE"
  CATS=${CATS// /}
  for c in ${CATS//,/ }; do
    [[ $c == none ]] || is_category "$c" || die "没有这个分类: $c，可选：$CATEGORIES none"
  done
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
  for c in curl awk grep sed sort mktemp touch paste dd; do
    command -v "$c" >/dev/null 2>&1 || die "缺少 $c"
  done
  if command -v timeout >/dev/null 2>&1; then
    LIMIT="timeout 25"
    # 系统解析器失灵时 getent 可能卡几十秒，这里只给它几秒
    RESOLVE_LIMIT="timeout 8"
  fi
  if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) )); then
    HAS_WAIT_N=1
  fi
  # curl 7.49 起才能把所有主机都钉到一个 IP 上，加密 DNS 轮翻页面时要用
  if curl --connect-to ::127.0.0.1: -V >/dev/null 2>&1; then
    HAS_CONNECT_TO=1
  fi
}

low_resource() {
  local cores=1
  command -v nproc >/dev/null 2>&1 && cores=$(nproc 2>/dev/null)
  [[ $cores =~ ^[0-9]+$ ]] || cores=1
  (( cores > 3 )) && cores=3
  (( PARALLEL_SET )) || PARALLEL=$(( cores + 1 ))
  command -v nice >/dev/null 2>&1 && LIMIT="nice -n 15 $LIMIT"
  return 0
}

# 连子进程一起结束，退出后不留下继续跑的 curl 和 mtr
stop_tree() {
  local child children
  children=$({ ps -eo pid=,ppid= 2>/dev/null || ps -o pid,ppid 2>/dev/null; } | awk -v p="$1" '$2 == p { print $1 }')
  kill "$1" 2>/dev/null
  for child in $children; do
    stop_tree "$child"
  done
}

cleanup() {
  local pid
  (( UI_ON )) && printf '\r\033[K\033[?7h\033[?25h' >&2
  for pid in $(jobs -p 2>/dev/null); do
    stop_tree "$pid"
  done
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
    198) (( b != 18 && b != 19 )) || return 1 ;;
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
    doh_cf "$name"
    return 0
  fi
  printf '%s' "$out" | grep -oE '"data": *"[0-9.]+"' | grep -oE '[0-9]+(\.[0-9]+){3}' | awk '!s[$0]++'
}

# Cloudflare 的 DoH 不转发 ECS，应答按它自己的节点给，常常和 Google 带出口 ECS 的应答落在不同网段
doh_cf() {
  HTTP_TIMEOUT=6 http -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$1&type=A" |
    grep -oE '"data": *"[0-9.]+"' | grep -oE '[0-9]+(\.[0-9]+){3}' | awk '!s[$0]++'
}

# 每个 /24 取一个 IP，最多 $1 个。分流和拦截规则按网段写，同一个 /24 里的 IP 走法一样
pick_ips() {
  awk -F. -v max="$1" '!s[$1 "." $2 "." $3]++ { print; if (++n >= max) exit }'
}

# 只看 TCP 能不能连上，不管对方说不说 HTTP。IP 目标没有页面可翻，用它判断连不连得通
tcp_open() {
  local t
  t=$(HTTP_TIMEOUT=5 http -o /dev/null -w '%{time_connect}' "http://$1:$2/")
  [[ $t =~ [1-9] ]]
}

sys_resolve() {
  if [[ -n $PROXY ]]; then
    doh "$1" ''
  elif command -v getent >/dev/null 2>&1; then
    $RESOLVE_LIMIT getent ahostsv4 "$1" 2>/dev/null | awk '!s[$1]++ { print $1 }'
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

# ipinfo 限流或连不上时的备用来源，同时提供机房、移动网络、代理标记。只有 HTTP 接口
ipapi_get() {
  local url="http://ip-api.com/json/$1?fields=countryCode,city,as,hosting,mobile,proxy"
  if [[ -n $IPAPI_IP ]]; then
    HTTP_TIMEOUT=6 pinned ip-api.com "$IPAPI_IP" "$url"
  else
    HTTP_TIMEOUT=6 http "$url"
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

# 每个探测进程只写自己的文件，这一步的进程都结束后再由 rows_merge 并进 rows.tsv。多个进程追加
# 同一个文件靠不住：一行是不是一次写完、写完还动不动文件，要看 shell 和 coreutils 的实现。
# Ubuntu 26.04 默认的 uutils dd 写完会把文件截到自己写到的位置，别的进程刚追加的行就丢了
emit() {
  local IFS=$'\t'
  printf '%s\n' "$*" >> "$WORK/rows.d/$BASHPID"
}

# 只在没有探测进程还在跑的时候调用
rows_merge() {
  [[ -n $WORK ]] || return 0
  local -a parts
  local noglob=${-//[!f]/}
  set +f
  parts=("$WORK/rows.d"/*)
  [[ -z $noglob ]] || set -f
  [[ -e ${parts[0]} ]] || return 0
  cat "${parts[@]}" >> "$WORK/rows.tsv" && rm -f "${parts[@]}"
}

# 每个任务结束时在 $PROGRESS 里记一行，进度条按它数。一个任务可能写好几行结果
spawn() {
  { "$@"; echo >> "$PROGRESS"; } </dev/null &
  RUNNING=$((RUNNING + 1))
  if (( RUNNING >= PARALLEL )); then
    if (( HAS_WAIT_N )); then
      wait -n 2>/dev/null
      RUNNING=$((RUNNING - 1))
    else
      # bash 4.2 没有 wait -n。轮询空位，不用等这一批全部跑完
      while RUNNING=$(jobs -rp | wc -l) && (( RUNNING >= PARALLEL )); do
        ui_paint
        sleep 0.2
      done
    fi
  fi
  ui_paint
}

wait_all() {
  if (( UI_ON )); then
    while [[ -n $(jobs -rp) ]]; do
      ui_paint
      sleep 0.2
    done
  fi
  wait
  RUNNING=0
  rows_merge
}

exits_so_far() {
  awk -F'\t' '$7 != "-" && !s[$7]++ { n++ } END { print n + 0 }' "$WORK/rows.tsv"
}

probe_calibration() {
  local method=$1 host=$2 url=$3 ip=$4 round=${5:-0} ex='' path='' want=''
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
  emit C E cal "$host" "$round" "$ip" "${ex:--}" "$method" - - "${path:--}"
}

run_calibration() {
  local method host url ip
  step_begin "校准出口"
  cal_list > "$WORK/cal.txt"
  # 先把 IP 解析好（只走 DoH），探测时再钉到 IP 上
  while read -r method host url; do
    ui_paint
    if [[ -n $PROXY ]]; then
      printf '%s %s %s -\n' "$method" "$host" "$url"
    else
      doh "$host" | head -2 | while read -r ip; do
        printf '%s %s %s %s\n' "$method" "$host" "$url" "$ip"
      done
    fi
  done < "$WORK/cal.txt" > "$WORK/cal_pinned.txt"
  STEP_FILE=$PROGRESS
  STEP_BASE=$(ui_lines "$STEP_FILE")
  STEP_TOTAL=$(ui_lines "$WORK/cal_pinned.txt")
  while read -r method host url ip; do
    STEP_DETAIL=$host
    spawn probe_calibration "$method" "$host" "$url" "$ip"
  done < "$WORK/cal_pinned.txt"
  STEP_DETAIL=''
  wait_all
  step_end "已发现 $(exits_so_far) 个出口"
}

probe_target() {
  local pass=$1 group=$2 name=$3 round=$4 ip a
  local -a ips=() usable=() pick=()
  if is_ipv4 "$name"; then
    probe_ip "$pass" "$group" "$name" "$round" "$name"
    return 0
  fi
  if [[ $pass == E ]]; then
    # 两家 DoH 的应答合起来测：同一个域名换个解析器可能就落在别的网段，分流和拦截又常常按网段写
    mapfile -t ips < <({ doh "$name"; doh_cf "$name"; } | awk '!s[$0]++')
  else
    mapfile -t ips < <(sys_resolve "$name")
  fi
  if (( ${#ips[@]} == 0 )); then
    emit T "$pass" "$group" "$name" "$round" - - dns - - -
    return 0
  fi
  # 解析成 0.0.0.0、内网这类地址，是 DNS 在屏蔽这个域名
  for a in "${ips[@]}"; do
    is_public_ipv4 "$a" && usable+=("$a")
  done
  if (( ${#usable[@]} == 0 )); then
    # 198.18.0.0/15 是 Clash、sing-box 这类透明代理常用的 fake-ip，不是屏蔽
    case ${ips[0]} in
      198.18.*|198.19.*) emit T "$pass" "$group" "$name" "$round" "${ips[0]}" - fakeip - - - ;;
      *) emit T "$pass" "$group" "$name" "$round" "${ips[0]}" - dnsblock - - - ;;
    esac
    return 0
  fi
  mapfile -t pick < <(printf '%s\n' "${usable[@]}" | pick_ips "$MAX_IPS")
  # 经代理时先让节点解析一次，节点若用明文 DNS 也能触发上游名单
  [[ -z $PROXY ]] || HTTP_TIMEOUT=6 http -o /dev/null -I "https://$name/" >/dev/null
  if [[ $pass == E && -z $PROXY ]]; then
    # 只测一个 IP 会漏掉按 IP 段写的规则。经代理时由节点解析，测几个 IP 都一样
    for ip in "${pick[@]}"; do
      probe_ip "$pass" "$group" "$name" "$round" "$ip"
    done
  else
    # 系统 DNS 每轮测一个网段，几轮下来轮到不同的网段
    probe_ip "$pass" "$group" "$name" "$round" "${pick[(round - 1) % ${#pick[@]}]}"
  fi
}

# 对一个定下来的 IP 取证：路由、回显，没有回显再翻页面，顺带记下连不连得上（ok、dead，
# 没试过是 -）。复测也用它，轮次写成 r1、r2
probe_ip() {
  local pass=$1 group=$2 name=$3 round=$4 ip=$5 path out ex='-' method='-' code='-' cands='-' reach='-' tmp
  path=$(route_of "$ip" "$pass$round")
  out=$(echo_by_ip "$name" "$ip")
  if [[ -n $out ]]; then
    ex=${out% *}
    method=${out#* }
    reach=ok
  elif ! is_ipv4 "$name"; then
    # 没有回显就翻页面。后面几轮只翻第一轮证明有用的目标，省流量；复测要看连不连得上，也翻
    if [[ $round == 1 || $round == r* ]] || grep -qxF "$name" "$WORK/page_names" 2>/dev/null; then
      tmp=$(mktemp "$WORK/p.XXXXXX")
      # 跟随跳转时 curl 会自己去解析跳到的主机，发的是明文查询。加密 DNS 轮不能发，所以把
      # 所有主机都钉在这个 IP 上，curl 太旧钉不了就不跟随。系统 DNS 轮本来就走系统解析，照常
      local -a follow=(-L --max-redirs 3)
      if [[ $pass == E ]]; then
        if (( HAS_CONNECT_TO )); then
          follow+=(--connect-to "::$ip:")
        else
          follow=()
        fi
      fi
      code=$(HTTP_TIMEOUT=10 fetch_own "$name" "$ip" "https://$name/" -i ${follow[@]+"${follow[@]}"} -o "$tmp" -w '%{http_code}')
      # 收到过响应头就是连上了。跟随跳转时跳到的地址连不上，curl 也报 000，所以不看状态码
      if grep -qa '^HTTP/' "$tmp" 2>/dev/null; then reach=ok; else reach=dead; fi
      cands=$(grep -aoE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$tmp" 2>/dev/null | sort -u | head -300 | paste -sd, -)
      rm -f "$tmp"
    fi
  elif [[ -z $PROXY ]]; then
    if tcp_open "$ip" 443; then reach=ok; else reach=dead; fi
  fi
  emit T "$pass" "$group" "$name" "$round" "$ip" "$ex" "$method" "${code:-000}" "${cands:--}" "${path:--}" "$reach"
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
  local pass=$1 total=$2 label=$3 r count group name step
  count=$(ui_lines "$WORK/targets.txt")
  for (( r = 1; r <= total; r++ )); do
    step=$label
    (( total > 1 )) && step="$label 第 $r/$total 轮"
    step_begin "$step" "$count" "$PROGRESS"
    while read -r group name; do
      STEP_DETAIL=$name
      spawn probe_target "$pass" "$group" "$name" "$r"
    done < "$WORK/targets.txt"
    STEP_DETAIL=''
    wait_all
    (( r == 1 )) && update_page_names
    step_end "已发现 $(exits_so_far) 个出口"
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
    ui_warn "没有 dig，跳过明文 DNS 触发测试（Debian: apt install -y dnsutils）"
    return 0
  fi
  local group name
  awk '$2 !~ /^[0-9.]+$/ && c[$1]++ < 3' "$WORK/targets.txt" > "$WORK/samples.txt"
  step_begin "明文 DNS 触发测试" "$(ui_lines "$WORK/samples.txt")" "$WORK/trigger.tsv"
  while read -r group name; do
    STEP_DETAIL=$name
    spawn trigger_one "$group" "$name"
  done < "$WORK/samples.txt"
  STEP_DETAIL=''
  wait_all
  step_end "$(awk -F'\t' '$4 != "-" { t++; if ($4 != $5) f++ } END { printf "触发 %d / 可测 %d", f, t }' "$WORK/trigger.tsv")"
}

# 把当初看到这个出口的那次探测原样再做两遍：同一个目标、同一个 IP
retest_one() {
  local kind=$1 pass=$2 group=$3 name=$4 ip=$5 try out method='' url=''
  for try in 1 2; do
    case $kind in
      C)
        read -r method url < <(awk -v h="$name" -v i="$ip" '$2 == h && $4 == i { print $1, $3; exit }' "$WORK/cal_pinned.txt")
        [[ -z $url ]] || probe_calibration "$method" "$name" "$url" "$ip" "r$try"
        ;;
      X)
        out=$(echo_by_ip "$name" "$ip")
        if [[ -n $out ]]; then
          emit X "$pass" "$group" "$name" "r$try" "$ip" "${out% *}" "${out#* }" - - -
        else
          emit X "$pass" "$group" "$name" "r$try" "$ip" - - - - -
        fi
        ;;
      *) probe_ip "$pass" "$group" "$name" "r$try" "$ip" ;;
    esac
  done
}

# 触发测试里的偶发读数按没变处理，免得出口已经不算数了，报告里还写着“触发”
settle_triggers() {
  [[ -s $WORK/unstable.tsv && -s $WORK/trigger.tsv ]] || return 0
  awk -F'\t' -v OFS='\t' -v F_BAD="$WORK/unstable.tsv" '
    FILENAME == F_BAD { bad[$1] = 1; next }
    { if ($4 in bad) $4 = $5; else if ($5 in bad) $5 = $4; print }' "$WORK/unstable.tsv" "$WORK/trigger.tsv" > "$WORK/trigger.new" &&
    mv "$WORK/trigger.new" "$WORK/trigger.tsv"
}

# 只回显过一次的出口，可能只是出口池轮换或临时的线路切换，不能直接算成分流；一次连不上也可能
# 只是超时。先复测，算不算数由 analyze 决定：出口再出现就算，同一个目标同一个 IP 看到的成了
# 别的出口就按偶发处理；连不上的 IP 再连两次都不通才算
run_retest() {
  local kind pass group name ip count
  analyze
  sort -u "$WORK/once.tsv" > "$WORK/retest.txt"
  [[ -s $WORK/retest.txt ]] || return 0
  count=$(ui_lines "$WORK/retest.txt")
  step_begin "复测偶发的读数" "$count" "$PROGRESS"
  while IFS=$'\t' read -r kind pass group name ip; do
    STEP_DETAIL=$name
    spawn retest_one "$kind" "$pass" "$group" "$name" "$ip"
  done < "$WORK/retest.txt"
  STEP_DETAIL=''
  wait_all
  analyze
  settle_triggers
  local note dead
  note="$count 个，$(ui_lines "$WORK/unstable.tsv") 个出口没有再出现"
  dead=$(awk -F'\t' '$17 == "partial" || $17 == "dead" { n++ } END { print n + 0 }' "$WORK/targets.tsv")
  (( dead == 0 )) || note+="，$dead 个目标有 IP 确实连不上"
  step_end "$note"
}

sniff_one() {
  local sni=$1 try tmp r='' code=000
  tmp=$(mktemp "$WORK/s.XXXXXX")
  # 没拿到回显就再试一次，偶发的超时不能当成结论
  for try in 1 2; do
    : > "$tmp"
    code=$(curl -4 -sk --connect-timeout 4 --max-time 8 --resolve "$sni:443:$IPINFO_IP" -H 'Host: ipinfo.io' -o "$tmp" -w '%{http_code}' "https://$sni/ip" 2>/dev/null)
    r=$(extract plain < "$tmp")
    [[ -z $r ]] || break
  done
  rm -f "$tmp"
  printf '%s\t%s\t%s\n' "$sni" "${r:--}" "${code:-000}" >> "$WORK/sniff.tsv"
}

# 把目标域名放进 SNI 发给中立回显。回显服务不看 SNI，所以出口变了是上游按 TLS 域名换了线路，
# 有应答却不是回显，是连接被按 TLS 域名转去了别的服务器
run_sniff() {
  (( USE_SNIFF )) || return 0
  [[ -n $IPINFO_IP ]] || return 0
  local base sni
  base=$(pinned ipinfo.io "$IPINFO_IP" https://ipinfo.io/ip | extract plain)
  [[ -n $base ]] || return 0
  printf 'sniff_base\t%s\n' "$base" >> "$WORK/env.tsv"
  awk '$2 !~ /^[0-9.]+$/ && c[$1]++ < 2 { print $2 }' "$WORK/targets.txt" > "$WORK/sni.txt"
  step_begin "SNI 嗅探测试" "$(ui_lines "$WORK/sni.txt")" "$WORK/sniff.tsv"
  while read -r sni; do
    STEP_DETAIL=$sni
    spawn sniff_one "$sni"
  done < "$WORK/sni.txt"
  STEP_DETAIL=''
  wait_all
  # 429 是回显服务自己在限流，和完全连不上的一样不算变化
  step_end "$(awk -F'\t' -v b="$base" '
    $2 == b { next }
    $2 != "-" || ($3 + 0 > 0 && $3 + 0 != 429) { c++; next }
    { f++ }
    END { printf "%d 个域名，%d 个有变化", NR, c; if (f) printf "，%d 个没连上", f }' "$WORK/sniff.tsv")"
}

# DNS 权威看到的来源 IP，走 UDP，可以顺带对比 UDP 的出口
dns_query_exits() {
  [[ -z $PROXY ]] || return 0
  command -v dig >/dev/null 2>&1 || return 0
  local a b c
  a=$(dig +short +time=2 +tries=1 TXT whoami.cloudflare CH @1.1.1.1 2>/dev/null | tr -d '"' | head -1)
  b=$(dig +short +time=2 +tries=1 whoami.akamai.net @ns1-1.akamaitech.net 2>/dev/null | head -1)
  c=$(dig +short +time=2 +tries=1 TXT o-o.myaddr.l.google.com @8.8.8.8 2>/dev/null | grep -oE 'edns0-client-subnet [0-9./]+' | awk '{ print $2 }' | head -1)
  # 超时的时候 dig +short 会把 “;; connection timed out” 这种提示写到 stdout
  is_ipv4 "$a" || a=''
  is_ipv4 "$b" || b=''
  printf 'Cloudflare\t%s\nAkamai\t%s\nGoogle\t%s\n' "${a:--}" "${b:--}" "${c:--}" > "$WORK/dnsq.tsv"
  # 192.0.2.53 是保留地址，不存在 DNS 服务。能收到应答，说明 53 端口被中途拦截了
  a=$(dig +short +time=2 +tries=1 example.com A @192.0.2.53 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
  printf 'dns_hijack\t%s\n' "$([[ -n $a ]] && echo 1 || echo 0)" >> "$WORK/env.tsv"
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
  v=$(proxy_label)
  printf 'proxy\t%s\n' "${v:--}" >> "$WORK/env.tsv"
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
  local f="$WORK/targets.txt" e bad
  {
    catalog | awk -v r="@$REGION" '$1 == r { print $2, $3 }'
    catalog | awk '$1 !~ /^@/ { print $1, $2 }'
  } | awk -v want=",$CATS," 'want == ",," || index(want, "," $1 ",")' > "$f.raw"
  # Windows 上编辑的文件可能带 BOM 和 CRLF
  [[ -z $TARGET_FILE ]] || tr -d '\r' < "$TARGET_FILE" |
    awk 'NR == 1 { sub(/^\357\273\277/, "") } !/^[ \t]*(#|$)/' >> "$f.raw"
  for e in ${EXTRA[@]+"${EXTRA[@]}"}; do
    [[ $e == *:* ]] || die "-a 的格式是 分类:域名，收到 $e"
    printf '%s %s\n' "${e%%:*}" "${e#*:}" >> "$f.raw"
  done
  # 域名不能以 - 开头，否则会被 getent、dig 当成选项
  awk 'NF >= 2 && $2 ~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ && !seen[$2]++ { print $1, $2 }' "$f.raw" > "$f"
  bad=$(awk 'NF < 2 || $2 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/' "$f.raw" | head -5 | paste -sd';' -)
  [[ -z $bad ]] || warn "跳过格式不对的目标（应为“分类 域名”）：$bad"
  [[ -s $f ]] || die "没有可测的目标，检查 --category 和 --region"
}

find_baseline() {
  BASE_IP=$(http https://1.1.1.1/cdn-cgi/trace | extract trace)
  [[ -n $BASE_IP ]] || BASE_IP=$(http https://www.cloudflare.com/cdn-cgi/trace | extract trace)
  [[ -n $BASE_IP ]] || BASE_IP=$(http https://ifconfig.me/ip | extract plain)
  [[ -n $BASE_IP ]] || die "拿不到出口 IP，检查网络${PROXY:+或代理 $(proxy_label)}"
  EXIT_NET="${BASE_IP%.*}.0/24"
}

json_str() {
  printf '%s' "$1" | sed -n "s/.*\"$2\": *\"\([^\"]*\)\".*/\1/p" | head -1
}

detect_region() {
  [[ $REGION == auto ]] || return 0
  local cc
  # 限流时 ipinfo 返回的是一句话，不是国家代码
  cc=$(ipinfo_get "$BASE_IP/country" | tr -d ' \r\n' | tr 'A-Z' 'a-z')
  [[ $cc =~ ^[a-z][a-z]$ ]] || cc=$(json_str "$(ipapi_get "$BASE_IP" | tr -d '\n')" countryCode | tr 'A-Z' 'a-z')
  case $cc in
    tw|jp|hk|us|sg|kr|vn) REGION=$cc ;;
    '')
      REGION=none
      warn "查不到出口所在国家，跳过本地银行和电商清单，可用 -r 手动指定"
      ;;
    *) REGION=none ;;
  esac
}

lookup_exits() {
  local letter ip seen def sig j alt org cc city host kind
  : > "$WORK/exits_info.tsv"
  step_begin "查询出口信息" "$(ui_lines "$WORK/exits.tsv")" "$WORK/exits_info.tsv"
  while IFS=$'\t' read -r letter ip seen def sig; do
    ui_paint
    j=$(ipinfo_get "$ip/json" | tr -d '\n')
    alt=$(ipapi_get "$ip" | tr -d '\n')
    org=$(json_str "$j" org)
    [[ -n $org ]] || org=$(json_str "$alt" as)
    cc=$(json_str "$j" country)
    [[ -n $cc ]] || cc=$(json_str "$alt" countryCode)
    city=$(json_str "$j" city)
    [[ -n $city ]] || city=$(json_str "$alt" city)
    host=$(json_str "$j" hostname)
    kind=-
    [[ $alt == *'"hosting":true'* ]] && kind=hosting
    [[ $alt == *'"mobile":true'* ]] && kind=mobile
    [[ $alt == *'"proxy":true'* ]] && kind=proxy
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$letter" "$ip" "$seen" "$def" "$sig" \
      "${org:--}" "${cc:--}" "${city:--}" "${host:--}" "$kind" >> "$WORK/exits_info.tsv"
  done < "$WORK/exits.tsv"
  step_end "$(ui_lines "$WORK/exits_info.tsv") 个出口"
}

# ---------- 分析 ----------

analyze() {
  cat > "$WORK/analyze.awk" <<'AWK'
BEGIN { FS = OFS = "\t"; LET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }

function is_private(ip, a) {
  split(ip, a, ".")
  a[1] += 0; a[2] += 0
  return a[1] == 10 || (a[1] == 172 && a[2] >= 16 && a[2] <= 31) || (a[1] == 192 && a[2] == 168) ||
         (a[1] == 100 && a[2] >= 64 && a[2] <= 127) || (a[1] == 169 && a[2] == 254) ||
         (a[1] == 198 && (a[2] == 18 || a[2] == 19))
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
  if (FAKE[key, p] + 0 > 0) S_E = "fakeip"
  else if (BLOCKED[key, p] + 0 > 0 && BLOCKED[key, p] + DNSFAIL[key, p] == S_T) S_E = "dnsblock"
  else if (DNSFAIL[key, p] + 0 == S_T) S_E = "dns"
  else if ((key, p) in AMB) { S_E = "ambiguous"; S_M = AMB[key, p] }
  else if (NOCONN[key, p] + 0 > 0 && NOCONN[key, p] + DNSFAIL[key, p] == S_T) S_E = "noconn"
  else S_E = "unknown"
}

# 这个目标各个 IP 连不连得上：ok 都连得上，partial 有的连不上，dead 全连不上，- 没试过。
# 连不上要复测确认过，任何一次连上过就算连得上。同时把逐 IP 的结果拼成“IP=出口:连通”写进 IP_MAP
function reach(key, j, ip, k3, nd, nl, r, s) {
  nd = 0; nl = 0; s = ""
  for (j = 1; j <= NIP[key] + 0; j++) {
    ip = IPO[key, j]; k3 = key SUBSEP ip
    if (k3 in LIVE) { r = "ok"; nl++ }
    else if (k3 in DEADC) { r = "dead"; nd++ }
    else r = "-"
    s = s (s == "" ? "" : " ") ip "=" (LETS[k3] == "" ? "?" : LETS[k3]) ":" r
  }
  IP_MAP = (s == "" ? "-" : s)
  if (nd > 0) return nl > 0 ? "partial" : "dead"
  return nl > 0 ? "ok" : "-"
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
  # 第 12 列：这个 IP 连不连得上。没有这一列的行按回显和状态码算，000 就是没连上
  if ($12 != "") RC[n] = $12
  else if ($9 == "000") RC[n] = "dead"
  else if ($9 ~ /^[0-9]+$/ || ($1 == "T" && $7 != "-")) RC[n] = "ok"
  else RC[n] = "-"
  if ($7 != "-") known[$7] = 1
}

END {
  # 页面里出现已知出口，也算直接证据
  for (i = 1; i <= n; i++) {
    if (EX[i] != "-" || CD[i] == "-") continue
    m = split(CD[i], c, ",")
    for (j = 1; j <= m; j++) if (c[j] in known) { EX[i] = c[j]; MT[i] = "page"; break }
  }

  # 每个出口回显过几次
  for (i = 1; i <= n; i++) {
    EV[i] = "unknown"
    if (EX[i] == "-") continue
    EV[i] = "direct"
    SEENX[EX[i]]++
    if (KD[i] == "C" && (MT[i] == "trace" || MT[i] == "plain")) NEUTRAL[EX[i]]++
  }

  # 默认出口：中立回显里最多的那个，并列时取基线
  best = -1; DEF = BASE
  for (e in SEENX) {
    v = NEUTRAL[e] + 0
    if (v > best || (v == best && e == BASE)) { best = v; DEF = e }
  }

  # 只回显过一次的出口不能直接算数：出口池轮换、临时的线路切换都会留下这样的读数。
  # 轮次以 r 开头的行是复测，是用同一个目标、同一个 IP 再做的探测。复测看到的成了别的出口，
  # 这一次就按偶发处理，读数改成复测看到的；还没复测过的写进 once.tsv，交给 run_retest
  fo = OUT "/once.tsv"; fu = OUT "/unstable.tsv"
  for (i = 1; i <= n; i++) {
    e = EX[i]
    if (EV[i] != "direct" || e == DEF || SEENX[e] != 1) continue
    if (RD[i] ~ /^r/) { GONE[i] = 1; continue }
    tried = 0; saw = ""; alt = "-"
    for (j = 1; j <= n; j++) {
      if (RD[j] !~ /^r/ || KD[j] != KD[i] || PS[j] != PS[i] || NM[j] != NM[i] || IP[j] != IP[i]) continue
      tried++
      if (EV[j] != "direct") continue
      saw = saw (saw == "" ? "" : " ") EX[j]
      if (EX[j] == DEF || SEENX[EX[j]] > 1) alt = EX[j]
    }
    if (tried == 0) print KD[i], PS[i], CT[i], NM[i], IP[i] > fo
    else if (saw != "") {
      print e, NM[i], IP[i], saw > fu
      EX[i] = alt
      if (alt == "-") EV[i] = "unknown"
    }
  }

  # 连不上的读数同样先复测：同一个目标、同一个 IP 再连两次都不通才算，偶发的超时不算拦截。
  # 复测连上了，这一次就按连得上处理
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T" || RD[i] ~ /^r/ || RC[i] != "dead") continue
    tried = 0; up = 0
    for (j = 1; j <= n; j++) {
      if (RD[j] !~ /^r/ || KD[j] != "T" || PS[j] != PS[i] || NM[j] != NM[i] || IP[j] != IP[i]) continue
      tried++
      if (RC[j] == "ok") up = 1
    }
    if (up) { RC[i] = "ok"; continue }
    EV[i] = "noconn"
    if (tried == 0) print KD[i], PS[i], CT[i], NM[i], IP[i] > fo
    else DEADC[CT[i], NM[i], IP[i]] = 1
  }
  # 复测时才冒出来、同样只有一次的出口，也不算数
  for (i in GONE) { EX[i] = "-"; EV[i] = "unknown" }

  # 校准表：所有拿到回显的路径。上面改过读数，回显次数重新数
  split("", SEENX)
  for (i = 1; i <= n; i++) {
    if (EV[i] != "direct") continue
    SEENX[EX[i]]++
    if (PT[i] != "-" && PT[i] != "") { nc++; CP[nc] = PT[i]; CX[nc] = EX[i] }
  }
  if (!(DEF in SEENX)) SEENX[DEF] = 0
  nx = 1; ORDER[1] = DEF
  for (e in SEENX) if (e != DEF) { nx++; ORDER[nx] = e }
  for (a = 2; a <= nx; a++)
    for (b = a + 1; b <= nx; b++)
      if (SEENX[ORDER[b]] > SEENX[ORDER[a]]) { t = ORDER[a]; ORDER[a] = ORDER[b]; ORDER[b] = t }
  for (j = 1; j <= nx; j++) LETTER[ORDER[j]] = substr(LET, j, 1)

  # 没有回显的行用路由推断。连不上的 IP 不推断：路由走得通，流量也过不去
  for (i = 1; i <= n; i++) {
    if (EX[i] != "-" || MT[i] == "dns" || MT[i] == "dnsblock" || MT[i] == "fakeip" || RC[i] == "dead") continue
    infer(PT[i])
    EV[i] = INF_E; CAND[i] = INF_CAND
    if (INF_X != "-") EX[i] = INF_X
  }

  # 逐 IP 汇总。同一种解析方式下，同一个域名的几个 IP 各自稳定地走了不同出口，是按 IP 分流；
  # 同一个 IP 前后走法不同不算，那是时间上的变化
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T") continue
    k3 = CT[i] SUBSEP NM[i] SUBSEP IP[i]
    if (RC[i] == "ok") LIVE[k3] = 1
    if (RD[i] ~ /^r/ || IP[i] == "-" || MT[i] == "dnsblock" || MT[i] == "fakeip") continue
    key = CT[i] SUBSEP NM[i]
    if (!(k3 in IPN)) { IPN[k3] = ++NIP[key]; IPO[key, NIP[key]] = IP[i] }
    if (EX[i] == "-") continue
    l = LETTER[EX[i]]
    if (index("/" LETS[k3] "/", "/" l "/") == 0) LETS[k3] = LETS[k3] (LETS[k3] == "" ? "" : "/") l
    if (EV[i] != "direct" && EV[i] != "inferred") continue
    kp = k3 SUBSEP PS[i]
    if (!(kp in IPX)) IPX[kp] = EX[i]
    else if (IPX[kp] != EX[i]) IPX[kp] = "*"
  }
  for (kp in IPX) {
    if (IPX[kp] == "*") continue
    split(kp, q, SUBSEP)
    kq = q[1] SUBSEP q[2] SUBSEP q[4]
    if (!(kq in FIRSTX)) FIRSTX[kq] = IPX[kp]
    else if (FIRSTX[kq] != IPX[kp]) BYIP[q[1], q[2]] = 1
  }

  # 按目标汇总。复测的行只用来判断出口算不算数，不算目标的轮次
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T" || RD[i] ~ /^r/) continue
    key = CT[i] SUBSEP NM[i]
    if (!(key in SEEN)) { nt++; SEEN[key] = nt; KEYS[nt] = key; TC[nt] = CT[i]; TN[nt] = NM[i] }
    p = PS[i]
    TOT[key, p]++
    if (IP[i] != "-" && !((key, IP[i]) in IPSEEN)) { IPSEEN[key, IP[i]] = 1; IPC[key]++ }
    if (HC[i] != "-" && !(key in CODE)) CODE[key] = HC[i]
    if (MT[i] == "dns") DNSFAIL[key, p]++
    if (MT[i] == "dnsblock") BLOCKED[key, p]++
    if (MT[i] == "fakeip") FAKE[key, p]++
    if (RC[i] == "dead") NOCONN[key, p]++
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
    # 系统 DNS 解析成不可用的地址，或查不到而 DoH 查得到，都算 DNS 屏蔽
    if (pe == "dnsblock" || (pe == "dns" && ex != "-")) { cls = "dnsblock"; pl = "X"; pe = "dnsblock" }
    else if (pe == "fakeip") cls = "fakeip"
    else if (key in BYIP) cls = "byip"
    else if (px == "-") cls = "unknown"
    else if (el == "-") cls = (px == DEF ? "none" : "split")
    else if (ex == "-") cls = (px == DEF ? "none" : "split")
    else if (ex == DEF && px == DEF) cls = "none"
    else if (ex == DEF && px != DEF) cls = "dns"
    else if (ex != DEF && px != DEF) cls = "static"
    else cls = "mixed"
    # 第 19 列单独标按 IP 分流：系统 DNS 那一轮是 fake-ip 时，类别写的是 fakeip，这一条不能丢
    rc = reach(key)
    print TC[t2], TN[t2], pl, px, pe, pm, pa, pt, po, el, ex, ee, em, cls, IPC[key] + 0, (key in CODE ? CODE[key] : "-"), rc, IP_MAP, ((key in BYIP) ? 1 : 0) > f
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
  # 这两个文件只在有内容时才会被 awk 写，先清空，不留上一遍分析的结果
  : > "$WORK/once.tsv"
  : > "$WORK/unstable.tsv"
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
  cat > "$WORK/report.awk" <<'AWK'
BEGIN { FS = "\t" }

# 按显示宽度补空格：C locale 下 length 数字节，汉字 3 字节占 2 格
function pad(s, w, t, hb, cells) {
  t = s; hb = gsub(/[^\001-\177]/, "", t)
  cells = length(s) - hb + int(hb * 2 / 3)
  return s (w > cells ? sprintf("%" (w - cells) "s", "") : "")
}
function dwidth(s, t, hb) {
  t = s; hb = gsub(/[^\001-\177]/, "", t)
  return length(s) - hb + int(hb * 2 / 3)
}
# 分区标题：── 标题（说明）─────
function sec(title, note, n, i, rule) {
  n = 62 - dwidth(title) - (note == "" ? 0 : dwidth(note) + 4)
  rule = ""
  for (i = 1; i <= n; i++) rule = rule "─"
  print DIM "── " R B title R DIM (note == "" ? "" : "（" note "）") " " rule R
}
function lc(l, s) {
  if (l == "A") return GRN s R
  if (l == "B") return YEL s R
  if (l == "C") return MAG s R
  if (l == "X") return RED s R
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
  if (e == "fakeip") return "fake-ip，透明代理"
  if (e == "dnsblock") return "系统 DNS 不给真实地址"
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
  RCH[nt] = $17; IPM[nt] = $18; BI[nt] = $19 + 0
  if (!($1 in CL)) { nc++; CO[nc] = $1; CL[$1] = $1 }
  CCOUNT[$1]++
  MP[$1, $3]++
  if ($10 != "-") { HASE = 1; ME[$1, $10]++ }
  if ($14 == "dns") ndns++
  if ($14 == "static") nstatic++
  if ($14 == "split") nsplit++
  if ($14 == "mixed") nmixed++
  if (BI[nt]) nbyip++
  if ($17 == "partial") { npart++; part = part (part == "" ? "" : "、") $2 }
  if ($17 == "dead") { nalldead++; alldead = alldead (alldead == "" ? "" : "、") $2 }
  if (BI[nt] || $17 == "partial" || $17 == "dead") nipshow++
  next
}
FILENAME == F_TRIGGER { ntr++; GN[ntr] = $2; GI[ntr] = $3; GB[ntr] = $4; GA[ntr] = $5; next }
FILENAME == F_SNIFF { nsn++; SN[nsn] = $1; SR[nsn] = $2; SC[nsn] = $3; next }
FILENAME == F_DNSQ { nq++; QN[nq] = $1; QV[nq] = $2; next }
FILENAME == F_UNSTABLE { nun++; UE[nun] = $1; UN[nun] = $2; next }
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

  # 结论。判断在 judge 里做，这里只管怎么说
  V = ENVV["verdict"]
  nblock = ENVV["n_dnsblock"] + 0; nfake = ENVV["n_fakeip"] + 0; nweak = ENVV["n_weak"] + 0
  nunk = ENVV["n_unknown"] + 0; ndead = ENVV["n_unreachable"] + 0
  nopen = nunk + nweak + nfake
  # 运营商查不到的出口不参与比较，不能算作“相同”或“不同”
  nother = 0; norg = 0
  for (j = 1; j <= nx; j++) if (XORG[j] == "-") norg++
  if (XORG[1] != "-")
    for (j = 2; j <= nx; j++) if (XORG[j] != "-" && asn(XORG[j]) != asn(XORG[1])) nother++
  if (V == "split") {
    line = "有分流，发现 " nx " 个出口"
    if (nother > 0) line = line "，其中 " nother " 个不是默认运营商"
    else if (norg == 0) line = line "，都属于默认运营商"
    else line = line "，运营商信息没查全"
    print B "结论" R "  " RED line R
  } else if (V == "dns_tampered") {
    print B "结论" R "  " YEL "出口没有分流，都从 " XI[1] " 出去，但 DNS 被动了手脚" R
  } else if (V == "blocked") {
    print B "结论" R "  " YEL "出口没有分流，都从 " XI[1] " 出去，但有目标的部分 IP 连不上，像是被按 IP 拦截" R
  } else if (V == "inconclusive") {
    # 证据不足不等于没有分流
    print B "结论" R "  " YEL "没发现第二个出口，能确认的目标都从 " XI[1] " 出去，但 " nopen "/" nt " 个目标证据不足，不能排除分流" R
  } else {
    print B "结论" R "  " GRN "未发现分流，能确认的目标都从 " XI[1] " 出去" R
  }
  if (ENVV["dns_hijack"] == 1)
    print "      53 端口被上游劫持：发给任何解析器的明文查询都由它应答，换公共 DNS 没用，要用 DoH/DoT"
  if (nblock > 0)
    print "      " RED nblock " 个目标被 DNS 屏蔽" R "：系统 DNS 解析成 0.0.0.0 或查不到，加密 DNS 能拿到真实地址"
  if (nfake > 0)
    print "      " YEL nfake " 个目标的系统 DNS 返回 fake-ip（198.18.x.x）" R "：有透明代理接管了解析，系统 DNS 这一轮测不到真实出口。要测线路本身先关掉它，要测它的分流用 -x 指向它的本地端口"
  if (nun > 0) {
    line = ""
    for (i = 1; i <= nun; i++) line = line (i > 1 ? "、" : "") UE[i] "（" UN[i] "）"
    print "      " YEL nun " 个出口只出现过 1 次，复测时同一个目标、同一个 IP 看到的成了别的出口" R "，按偶发处理，没有算进结论：" line
  }
  if (nx >= 2) {
    same24 = 1
    pre = XI[1]; sub(/\.[0-9]+$/, ".", pre)
    for (j = 2; j <= nx; j++) if (index(XI[j], pre) != 1) same24 = 0
    if (same24) print "      " DIM "这些出口在同一个 /24，也可能是运营商的出口池轮换，不一定是分流" R
    once = 0
    for (j = 2; j <= nx; j++) if (XS[j] + 0 <= 1) once++
    if (once > 0) print "      " DIM once " 个出口只回显过 1 次，复测没能确认，可能是误报，看明细确认" R
  }
  if (npart > 0)
    print "      " YEL npart " 个目标有部分 IP 连不上，复测两次仍不通，同一个域名的其他 IP 正常" R "：可能是上游按 IP 拦截，" part
  if (nbyip > 0) print "      " nbyip " 个目标按 IP 分流：同一个域名解析出的几个 IP 走了不同出口，只测一个 IP 会漏掉"
  if (ndns > 0) print "      " ndns " 个目标由明文 DNS 触发：加密 DNS 下走默认出口，系统 DNS 下走分流"
  if (nstatic > 0) print "      " nstatic " 个目标在分流名单内：加密 DNS 下也走分流"
  if (nsplit > 0) print "      " nsplit " 个目标走了非默认出口"
  if (nmixed > 0) print "      " nmixed " 个目标系统 DNS 走默认出口、加密 DNS 反而走分流，通常是解析到的 IP 不同"
  if (nunk > 0) print "      " DIM nunk " 个目标无法确认出口" R
  if (nweak > 0) print "      " DIM nweak " 个目标只有弱推断：路由在内网段就和校准线路分开了，可能走了没发现的出口" R
  if (ndead > 0) print "      " DIM ndead " 个目标解析失败或连不上，不影响结论" R
  if (nalldead > 0)
    print "      " DIM alldead " 的 IP 复测两次全都连不上：从这里分不清是目标挂了还是被按 IP 拦截，换个网络打开看看" R
  print ""

  # 出口
  sec("出口")
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
  sec("分类概览", "目标数")
  w = (nx + 1) * 4 + (nblock > 0 ? 5 : 0)
  PH = (ENVV["proxy"] != "-") ? "节点 DNS" : "系统 DNS"
  print "  " pad("", 10) pad(" " PH, w) (HASE ? "   " pad(" 加密 DNS", w) : "")
  line = "  " pad("", 10)
  for (j = 1; j <= nx; j++) line = line lc(XL[j], sprintf("%4s", XL[j]))
  line = line DIM sprintf("%4s", "?") R
  if (nblock > 0) line = line RED " 屏蔽" R
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
    if (nblock > 0) { v = MP[k, "X"] + 0; line = line (v ? RED sprintf("%5d", v) R : DIM sprintf("%5s", ".") R) }
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
    sec("明文 DNS 触发测试")
    print "  " DIM "没有 dig，已跳过（Debian: apt install -y dnsutils）" R
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
    sec("明文 DNS 触发测试", "外地节点 IP，明文查询前后的真实出口")
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
    sec("明细")
    print DIM head "证据" R
    for (c = 1; c <= nc; c++) {
      k = CO[c]
      if (!(k in CCOUNT)) continue
      print "  " B CL[k] R
      for (t = 1; t <= nt; t++) {
        if (TC[t] != k) continue
        v = (PL[t] == "X") ? "X 被 DNS 屏蔽" : PL[t] " " (PX[t] == "-" ? "" : PX[t])
        line = "    " pad(TN[t], 34) lc(PL[t], pad(v, 21)) pad(PX[t] == "-" ? "" : PA[t] "/" PT[t], 6)
        if (HASE) line = line lc(EL[t], pad(EL[t], 6))
        line = line evid(PE[t], PM[t])
        if (PO[t] != "-") { o = PO[t]; gsub(/:/, "×", o); line = line DIM "  另 " o R }
        if (KC[t] == "dns") line = line "  " YEL "DNS触发" R
        else if (KC[t] == "static") line = line "  " MAG "名单内" R
        else if (KC[t] == "mixed") line = line "  " DIM "解析不同" R
        if (BI[t]) line = line "  " MAG "按IP" R
        if (RCH[t] == "partial") line = line "  " YEL "部分IP不通" R
        print line
      }
    }
    print ""
  }

  # 逐 IP：只列各个 IP 结果不一样、或者有 IP 连不上的目标
  if (!BRIEF && nipshow > 0) {
    sec("逐 IP", "各个 IP 结果不一样或连不上的目标")
    for (t = 1; t <= nt; t++) {
      if (!(BI[t] || RCH[t] == "partial" || RCH[t] == "dead")) continue
      m = split(IPM[t], ipa, " ")
      for (i = 1; i <= m; i++) {
        split(ipa[i], ipb, "="); split(ipb[2], ipc, ":")
        if (ipc[2] == "dead") v = RED "×  复测两次都连不上" R
        else if (ipc[1] == "?") v = DIM "?" (ipc[2] == "ok" ? "  连得上，出口未知" : "") R
        else v = lc(substr(ipc[1], 1, 1), ipc[1])
        print "  " pad(i == 1 ? TN[t] : "", 34) pad(ipb[1], 17) v
      }
    }
    print ""
  }

  # 其他检查
  has_other = nsn > 0 || nq > 0 || ("route_defaults" in ENVV) || ("ipv6" in ENVV) || (ENVV["tracer"] == "none" && ENVV["use_route"] == 1)
  if (has_other) sec("其他检查")
  if (nsn > 0) {
    # 回显服务不看 SNI，谁来问都照常应答。出口变了，是上游按 SNI 换了线路；有应答却不是回显，
    # 是连接被按 SNI 转去了别的服务器。完全连不上的可能只是网络抖动，429 是回显服务在限流，都不下结论
    changed = ""; nc2 = 0; moved = ""; nmv = 0; nsf = 0
    for (i = 1; i <= nsn; i++) {
      if (SR[i] == ENVV["sniff_base"]) continue
      if (SR[i] != "-") { nc2++; changed = changed " " SN[i] "=" SR[i] }
      else if (SC[i] + 0 > 0 && SC[i] + 0 != 429) { nmv++; moved = moved " " SN[i] }
      else nsf++
    }
    label = pad("SNI 嗅探", 12)
    if (nc2 > 0) { print "  " label YEL nc2 "/" nsn " 个域名出口变了：" changed R; label = pad("", 12) }
    if (nmv > 0) { print "  " label YEL nmv "/" nsn " 个域名的连接被转去了别处，回来的不是回显服务的应答：" moved R; label = pad("", 12) }
    if (nc2 + nmv == 0) {
      if (nsf == nsn) print "  " label DIM nsn " 个域名都没连上，无法判断" R
      else print "  " label (nsn - nsf) " 个域名放进 SNI，出口都没变，没有按 TLS 域名分流" (nsf > 0 ? DIM "（另有 " nsf " 个没连上）" R : "")
    } else if (nsf > 0) print "  " label DIM "另有 " nsf " 个没连上" R
  }
  if ("dns_hijack" in ENVV) {
    if (ENVV["dns_hijack"] == 1) print "  " pad("DNS 劫持", 12) YEL "发给保留地址 192.0.2.53 的查询也有应答，53 端口被中途拦截" R
    else print "  " pad("DNS 劫持", 12) "未发现"
  }
  # 被劫持时下面这些来源都是拦截方的，没有参考价值
  if (nq > 0 && ENVV["dns_hijack"] != 1) {
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
    sec("每轮明细", "E=加密 DNS，P=系统 DNS，E0=校准，r=复测")
    for (i = 1; i <= ndt; i++) {
      split(DL[i], d, "\t")
      print "  " d[2] d[5] " " pad(d[4], 34) pad(d[6], 17) lc(d[7], d[7]) " " pad(d[8], 16) " " pad(d[9] (d[10] == "-" ? "" : "/" d[10]), 20) DIM d[11] R
    }
    print ""
  }

  print DIM "直接：目标或同一 IP 上的 CDN 回显的访问者 IP。推断：路由和已校准出口的线路相同，没有直接证据。" R
  print DIM "弱推断：只有一个出口可比，目标又在内网段就分开了，可信度低。" R
  if (nipshow > 0)
    print DIM "加密 DNS 那一轮把 Google 和 Cloudflare 的应答合起来，每个 /24 测一个 IP；系统 DNS 每轮测一个。" R
  if (ndns + nstatic > 0) {
    print DIM "DNS触发：这个目标解析到的 IP 只有经明文查询才会进分流名单。名单内：解析到的 IP 已在名单里，" R
    print DIM "可能是静态名单，也可能是被其他明文查询写进去的；上面的触发测试能看出上游是否按 DNS 写名单。" R
  }
  if (ENVV["proxy"] != "-") print DIM "经代理时只有回显证据，不回显的目标显示未知。" R
  else print DIM "这里测的是上游这一层。节点上的 xray/sing-box 可能另有路由规则，要检查这一层请用 -x 经节点测。" R
}
AWK
  touch "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" "$WORK/env.tsv" "$WORK/detail.tsv" "$WORK/unstable.tsv"
  awk -v R="$R" -v B="$B" -v DIM="$DIM" -v GRN="$GRN" -v YEL="$YEL" -v MAG="$MAG" -v CYN="$CYN" -v RED="$RED" \
    -v BRIEF="$BRIEF" -v VERBOSE="$VERBOSE" \
    -v F_CATS="$WORK/cats.txt" -v F_EXITS="$WORK/exits_info.tsv" -v F_TARGETS="$WORK/targets.tsv" \
    -v F_TRIGGER="$WORK/trigger.tsv" -v F_SNIFF="$WORK/sniff.tsv" -v F_DNSQ="$WORK/dnsq.tsv" \
    -v F_ENV="$WORK/env.tsv" -v F_DETAIL="$WORK/detail.tsv" -v F_UNSTABLE="$WORK/unstable.tsv" \
    -f "$WORK/report.awk" \
    "$WORK/cats.txt" "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" \
    "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" "$WORK/unstable.tsv" "$WORK/detail.tsv" || die "生成报告时出错"
}

# 方便分享的报告：summary 是几行纯文本，markdown 是完整表格。默认打码 IP，不带主机名、反解和路由
report_share() {
  cat > "$WORK/share.awk" <<'AWK'
BEGIN { FS = "\t" }
function mask(ip, a) {
  if (!MASK) return ip
  split(ip, a, ".")
  return a[1] "." a[2] ".*.*"
}
function mname(m) {
  if (m == "cloudflare") return "Cloudflare"
  if (m == "akamai") return "Akamai"
  if (m == "fastly") return "Fastly"
  if (m == "cloudfront") return "CloudFront"
  if (m == "google") return "Google"
  if (m == "meta") return "Meta"
  if (m == "page") return "页面"
  return m
}
function evid(e, m) {
  if (e == "direct") return "直接（" mname(m) "）"
  if (e == "inferred") return "推断"
  if (e == "weak") return "弱推断"
  if (e == "ambiguous") return "不确定"
  if (e == "fakeip") return "fake-ip，透明代理"
  if (e == "dnsblock") return "系统 DNS 不给真实地址"
  if (e == "dns") return "解析失败"
  if (e == "noconn") return "连不上"
  return "未知"
}
function asn(s, a) { split(s, a, " "); return a[1] }
function kind(k) {
  if (k == "dns") return "DNS 触发"
  if (k == "static") return "名单内"
  if (k == "mixed") return "解析不同"
  if (k == "dnsblock") return "DNS 屏蔽"
  if (k == "fakeip") return "fake-ip"
  if (k == "byip") return "按 IP"
  return ""
}
FILENAME == F_CATS { split($0, a, " "); if (!(a[1] in CL)) { nc++; CO[nc] = a[1]; CL[a[1]] = a[2] } next }
FILENAME == F_ENV { ENVV[$1] = $2; next }
FILENAME == F_EXITS {
  nx++; XL[nx] = $1; XI[nx] = $2; XDEF[nx] = $4; XORG[nx] = $6; XCC[nx] = $7; XKIND[nx] = $10
  next
}
FILENAME == F_TARGETS {
  nt++; TC[nt] = $1; TN[nt] = $2; PL[nt] = $3; PE[nt] = $5; PM[nt] = $6; PA[nt] = $7; PT[nt] = $8
  EL[nt] = $10; KC[nt] = $14; RCH[nt] = $17; BI[nt] = $19 + 0
  if (!($1 in CL)) { nc++; CO[nc] = $1; CL[$1] = $1 }
  CCOUNT[$1]++; MP[$1, $3]++
  if ($14 == "dns") ndns++
  if ($14 == "static") nstatic++
  if (BI[nt]) nbyip++
  if ($17 == "partial") npart++
  if ($17 == "dead") nalldead++
  if ($10 != "-") HASE = 1
  next
}
FILENAME == F_TRIGGER { if ($4 != "-") { tested++; if ($4 != $5) fired++ } next }
FILENAME == F_UNSTABLE { nun++; next }
function exit_line(j, s) {
  s = XL[j] (XDEF[j] ? " 默认" : "") "  " mask(XI[j]) "  " XORG[j]
  if (XCC[j] != "-") s = s "  " XCC[j]
  if (XKIND[j] == "hosting") s = s "  标记为机房"
  return s
}
function cat_line(k, j, v, s) {
  s = ""
  for (j = 1; j <= nx; j++) { v = MP[k, XL[j]] + 0; if (v) s = s (s == "" ? "" : " · ") XL[j] " " v }
  v = MP[k, "X"] + 0
  if (v) s = s (s == "" ? "" : " · ") "DNS 屏蔽 " v
  v = MP[k, "?"] + 0
  if (v) s = s (s == "" ? "" : " · ") "未知 " v
  return s
}
END {
  V = ENVV["verdict"]
  nblock = ENVV["n_dnsblock"] + 0; nfake = ENVV["n_fakeip"] + 0; nweak = ENVV["n_weak"] + 0
  nopen = ENVV["n_unknown"] + nweak + nfake
  nother = 0; norg = 0
  for (j = 1; j <= nx; j++) if (XORG[j] == "-") norg++
  if (XORG[1] != "-")
    for (j = 2; j <= nx; j++) if (XORG[j] != "-" && asn(XORG[j]) != asn(XORG[1])) nother++
  if (V == "split") verdict = "有分流，" nx " 个出口" (nother > 0 ? "，其中 " nother " 个不是默认运营商" : (norg == 0 ? "，都属于默认运营商" : "，运营商信息没查全"))
  else if (V == "dns_tampered") verdict = "出口没有分流，但 DNS 被动了手脚"
  else if (V == "blocked") verdict = "出口没有分流，但有目标的部分 IP 连不上，像是被按 IP 拦截"
  else if (V == "inconclusive") verdict = "没发现第二个出口，但 " nopen "/" nt " 个目标证据不足，不能排除分流"
  else verdict = "未发现分流"
  dnsnote = ""
  if (ENVV["dns_hijack"] == 1) dnsnote = "53 端口被上游劫持"
  if (nblock > 0) dnsnote = dnsnote (dnsnote == "" ? "" : "，") nblock " 个目标被 DNS 屏蔽"
  if (nfake > 0) dnsnote = dnsnote (dnsnote == "" ? "" : "，") nfake " 个目标返回 fake-ip，有透明代理"
  ipnote = ""
  if (nbyip > 0) ipnote = nbyip " 个目标按 IP 分流"
  if (npart > 0) ipnote = ipnote (ipnote == "" ? "" : "，") npart " 个目标部分 IP 连不上"
  if (nalldead > 0) ipnote = ipnote (ipnote == "" ? "" : "，") nalldead " 个目标全部 IP 连不上"
  date = substr(ENVV["time"], 1, 10)
  region = (ENVV["region"] == "none" ? "" : " · 地区 " ENVV["region"])
  if (ENVV["proxy"] != "-") region = region " · 经代理"
  trig = ""
  if (tested > 0) trig = (fired > 0 ? "是" : "未发现") "（触发 " fired + 0 " / 可测 " tested "）"
  unote = ""
  if (nun > 0) unote = "另有 " nun " 个出口只出现过一次，复测没有再出现，没有算进结论"

  if (MODE == "summary") {
    print "splitcheck 分流检测 · " date region " · " nt " 个目标"
    print "结论：" verdict
    if (unote != "") print unote
    if (dnsnote != "") print "DNS：" dnsnote
    if (ipnote != "") print "逐 IP：" ipnote
    for (j = 1; j <= nx; j++) print exit_line(j)
    for (c = 1; c <= nc; c++) if (CO[c] in CCOUNT) print CL[CO[c]] "：" cat_line(CO[c])
    if (trig != "") print "明文 DNS 触发：" trig
    line = "证据：直接 " (ENVV["n_direct"] + 0) " · 推断 " (ENVV["n_inferred"] + 0)
    if (nweak > 0) line = line " · 弱推断 " nweak
    print line " · 未确认 " (ENVV["n_unknown"] + ENVV["n_unreachable"] + nfake)
    print "https://github.com/YePiXpert/splitcheck"
    exit
  }

  print "# 分流检测报告"
  print ""
  print "- 时间：" date
  if (ENVV["region"] != "none") print "- 地区：" ENVV["region"]
  print "- 目标：" nt " 个"
  print "- **结论：" verdict "**"
  if (unote != "") print "- " unote
  if (dnsnote != "") print "- DNS：" dnsnote
  if (ipnote != "") print "- 逐 IP：" ipnote
  if (trig != "") print "- 明文 DNS 触发：" trig
  if (ndns > 0) print "- " ndns " 个目标由明文 DNS 触发，" nstatic + 0 " 个目标在分流名单内"
  print ""
  print "## 出口"
  print ""
  print "| 出口 | IP | 运营商 | 国家 |"
  print "|---|---|---|---|"
  for (j = 1; j <= nx; j++) print "| " XL[j] (XDEF[j] ? "（默认）" : "") " | " mask(XI[j]) " | " XORG[j] " | " XCC[j] " |"
  print ""
  print "## 分类概览"
  print ""
  head = "| 分类 |"; sep = "|---|"
  for (j = 1; j <= nx; j++) { head = head " " XL[j] " |"; sep = sep "---:|" }
  if (nblock > 0) { head = head " DNS 屏蔽 |"; sep = sep "---:|" }
  print head " 未知 |"
  print sep "---:|"
  for (c = 1; c <= nc; c++) {
    k = CO[c]
    if (!(k in CCOUNT)) continue
    line = "| " CL[k] " |"
    for (j = 1; j <= nx; j++) line = line " " MP[k, XL[j]] + 0 " |"
    if (nblock > 0) line = line " " MP[k, "X"] + 0 " |"
    print line " " MP[k, "?"] + 0 " |"
  }
  print ""
  print "## 明细"
  for (c = 1; c <= nc; c++) {
    k = CO[c]
    if (!(k in CCOUNT)) continue
    print ""
    print "### " CL[k]
    print ""
    print "| 目标 | 出口 |" (HASE ? " 加密 DNS |" : "") " 证据 | 方式 |"
    print "|---|---|" (HASE ? "---|" : "") "---|---|"
    for (t = 1; t <= nt; t++) {
      if (TC[t] != k) continue
      how = kind(KC[t])
      if (BI[t] && KC[t] != "byip") how = how (how == "" ? "" : "，") "按 IP"
      if (RCH[t] == "partial") how = how (how == "" ? "" : "，") "部分 IP 连不上"
      if (PL[t] == "X") print "| " TN[t] " | 屏蔽 |" (HASE ? " " EL[t] " |" : "") " " evid(PE[t], PM[t]) " | " how " |"
      else print "| " TN[t] " | " PL[t] (PA[t] + 0 < PT[t] + 0 ? "（" PA[t] "/" PT[t] " 轮）" : "") " |" (HASE ? " " EL[t] " |" : "") " " evid(PE[t], PM[t]) " | " how " |"
    }
  }
  print ""
  print "直接：目标或同一 IP 上的 CDN 回显的访问者 IP。推断：路由和已确认出口的线路相同。"
  print "DNS 触发：加密 DNS 下走默认出口，系统 DNS 下走分流。名单内：加密 DNS 下也走分流。"
  print ""
  print "由 [splitcheck](https://github.com/YePiXpert/splitcheck) 生成"
}
AWK
  awk -v MODE="$1" -v MASK="$MASK" \
    -v F_CATS="$WORK/cats.txt" -v F_ENV="$WORK/env.tsv" -v F_EXITS="$WORK/exits_info.tsv" \
    -v F_TARGETS="$WORK/targets.tsv" -v F_TRIGGER="$WORK/trigger.tsv" -v F_UNSTABLE="$WORK/unstable.tsv" \
    -f "$WORK/share.awk" \
    "$WORK/cats.txt" "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" "$WORK/trigger.tsv" \
    "$WORK/unstable.tsv" || die "生成分享报告时出错"
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
  # 逐 IP 的结果：$18 是“IP=出口:连通”，空格分隔，出口可以是 A/B，不知道是 ?
  ips = ""
  m = split($18 == "-" ? "" : $18, ia, " ")
  for (k = 1; k <= m; k++) {
    split(ia[k], ib, "="); split(ib[2], ic, ":")
    ids = ""
    if (ic[1] != "?") { q = split(ic[1], id, "/"); for (z = 1; z <= q; z++) ids = ids (z > 1 ? "," : "") s(id[z]) }
    ips = ips (k > 1 ? "," : "") "{\"ip\":" s(ib[1]) ",\"exit_ids\":[" ids "],\"reachable\":" (ic[2] == "ok" ? "true" : (ic[2] == "dead" ? "false" : "null")) "}"
  }
  T[nt] = "{\"category\":" s($1) ",\"name\":" s($2) \
    ",\"system_dns\":{\"exit_id\":" sn($3) ",\"exit\":" sn($4) ",\"evidence\":" sn($5) ",\"method\":" sn($6) ",\"agree\":" ($7 + 0) ",\"rounds\":" ($8 + 0) ",\"others\":" sn($9) "}" \
    ",\"encrypted_dns\":{\"exit_id\":" sn($10) ",\"exit\":" sn($11) ",\"evidence\":" sn($12) ",\"method\":" sn($13) "}" \
    ",\"class\":" s($14) ",\"ip_count\":" ($15 + 0) ",\"http\":" sn($16) ",\"reach\":" sn($17) \
    ",\"split_by_ip\":" ($19 == 1 ? "true" : "false") ",\"ips\":[" ips "]}"
  next
}
FILENAME == F_TRIGGER {
  ng++
  G[ng] = "{\"category\":" s($1) ",\"name\":" s($2) ",\"ip\":" sn($3) ",\"before\":" sn($4) ",\"after\":" sn($5) "}"
  if ($4 != "-" && $4 != $5) fired = 1
  next
}
FILENAME == F_SNIFF { nn++; N[nn] = "{\"sni\":" s($1) ",\"exit\":" sn($2) ",\"http\":" sn($3) "}"; next }
FILENAME == F_DNSQ { nq++; Q[nq] = s($1) ":" sn($2); next }
FILENAME == F_UNSTABLE {
  nu++
  m = split($4, w, " "); r = ""
  for (k = 1; k <= m; k++) r = r (k > 1 ? "," : "") s(w[k])
  U[nu] = "{\"ip\":" s($1) ",\"target\":" s($2) ",\"target_ip\":" sn($3) ",\"retest\":[" r "]}"
  next
}
function arr(a, n, i, o) { o = "["; for (i = 1; i <= n; i++) o = o (i > 1 ? "," : "") a[i]; return o "]" }
END {
  printf "{\"version\":%s,\"host\":%s,\"time\":%s,\"elapsed\":%d,\"proxy\":%s,\"region\":%s,\"tracer\":%s,", \
    s(ENVV["version"]), s(ENVV["host"]), s(ENVV["time"]), ENVV["elapsed"], sn(ENVV["proxy"]), s(ENVV["region"]), s(ENVV["tracer"])
  # split 只说有没有发现第二个出口。没发现不等于没有，要看 verdict 和 coverage
  printf "\"split\":%s,\"verdict\":%s,\"dns_triggered\":%s,\"default_exit\":%s,", (nx >= 2 ? "true" : "false"), s(ENVV["verdict"]), (fired ? "true" : "false"), s(DEF)
  printf "\"coverage\":{\"direct\":%d,\"inferred\":%d,\"weak\":%d,\"unknown\":%d,\"unreachable\":%d,\"fake_ip\":%d,\"dns_blocked\":%d,\"ip_blocked\":%d,\"split_by_ip\":%d},", \
    ENVV["n_direct"], ENVV["n_inferred"], ENVV["n_weak"], ENVV["n_unknown"], ENVV["n_unreachable"], ENVV["n_fakeip"], ENVV["n_dnsblock"], ENVV["n_ipblock"], ENVV["n_byip"]
  # unstable_exits：只出现过一次、复测时又没再出现的出口，不算进 exits
  printf "\"exits\":%s,\"unstable_exits\":%s,\"targets\":%s,\"dns_trigger_test\":%s,\"sni_test\":{\"baseline\":%s,\"results\":%s},", \
    arr(X, nx), arr(U, nu), arr(T, nt), arr(G, ng), sn(ENVV["sniff_base"]), arr(N, nn)
  printf "\"dns_query\":{"
  for (i = 1; i <= nq; i++) printf "%s%s", (i > 1 ? "," : ""), Q[i]
  printf "},\"dns_hijack\":%s,\"ipv6\":%s}\n", (ENVV["dns_hijack"] == 1 ? "true" : "false"), sn(ENVV["ipv6"])
}
AWK
  touch "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" "$WORK/env.tsv" "$WORK/unstable.tsv"
  awk -v F_ENV="$WORK/env.tsv" -v F_EXITS="$WORK/exits_info.tsv" -v F_TARGETS="$WORK/targets.tsv" \
    -v F_TRIGGER="$WORK/trigger.tsv" -v F_SNIFF="$WORK/sniff.tsv" -v F_DNSQ="$WORK/dnsq.tsv" \
    -v F_UNSTABLE="$WORK/unstable.tsv" \
    -f "$WORK/json.awk" \
    "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" \
    "$WORK/unstable.tsv" || die "生成 JSON 时出错"
}

# 结论只在这里判断一次，三种报告和退出码都读它，不会各说各的
judge() {
  awk -F'\t' -v F_ENV="$WORK/env.tsv" -v F_EXITS="$WORK/exits.tsv" '
    FILENAME == F_ENV { if ($1 == "dns_hijack" && $2 == 1) hijack = 1; next }
    FILENAME == F_EXITS { nx++; next }
    # 同一个域名有的 IP 连得上、有的复测两次都连不上，是按 IP 拦截，不是目标自己挂了
    $17 == "partial" { ipblock++ }
    $19 == 1 { byip++ }
    $14 == "dnsblock" { block++; next }
    $14 == "fakeip" { fake++; next }
    # 解析失败、全部 IP 都连不上的目标没有流量可分，单独计数，不影响结论：清单里总会有失效的域名，
    # 从一个地方也分不清是目标挂了还是被拦了
    $4 == "-" { if ($5 == "dns" || $5 == "noconn") dead++; else unknown++; next }
    $5 == "direct" { direct++; next }
    $5 == "weak" { weak++; next }
    { inferred++ }
    END {
      if (nx >= 2) v = "split"
      else if (block > 0 || hijack) v = "dns_tampered"
      else if (ipblock > 0) v = "blocked"
      # 没有证据、只有弱推断、被 fake-ip 挡住的目标，都可能走了没发现的出口
      else if (unknown + weak + fake > 0) v = "inconclusive"
      else v = "clean"
      printf "verdict\t%s\nn_direct\t%d\nn_inferred\t%d\nn_weak\t%d\nn_unknown\t%d\n", v, direct, inferred, weak, unknown
      printf "n_unreachable\t%d\nn_fakeip\t%d\nn_dnsblock\t%d\nn_ipblock\t%d\nn_byip\t%d\n", dead, fake, block, ipblock, byip
    }' "$WORK/env.tsv" "$WORK/exits.tsv" "$WORK/targets.tsv" > "$WORK/verdict.tsv" || die "分析结果时出错"
  cat "$WORK/verdict.tsv" >> "$WORK/env.tsv"
}

# --exit-code 用：0 未发现分流，2 有分流、DNS 被动了手脚或按 IP 拦截，3 证据不足
exit_status() {
  case $(awk -F'\t' '$1 == "verdict" { v = $2 } END { print v }' "$WORK/env.tsv") in
    clean) printf 0 ;;
    inconclusive) printf 3 ;;
    *) printf 2 ;;
  esac
}

main() {
  parse_args "$@"
  check_deps
  ui_setup
  if (( $# == 0 && STDIN_TTY )) && [[ -t 1 && -r /dev/tty ]]; then
    show_menu
  fi
  (( LOW_RESOURCE )) && low_resource
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/splitcheck.XXXXXX") || die "建不了临时目录"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  mkdir -p "$WORK/fp" "$WORK/path" "$WORK/rows.d"
  PROGRESS="$WORK/progress"
  touch "$WORK/rows.tsv" "$WORK/page_names" "$WORK/env.tsv" "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$PROGRESS"
  cat_labels > "$WORK/cats.txt"
  ui_title

  # 到系统 DNS 那一轮之前，所有解析都走 DoH，请求都钉到 IP，不发任何明文查询
  step_begin "确认出口"
  find_baseline
  if [[ -z $PROXY ]]; then
    IPINFO_IP=$(doh ipinfo.io | head -1)
    IPAPI_IP=$(doh ip-api.com | head -1)
  fi
  detect_region
  step_end "$BASE_IP$([[ $REGION == none ]] || printf ' · 地区 %s' "$REGION")"
  step_begin "准备探测"
  load_targets
  detect_tracer
  local count est eta route=$TRACER
  count=$(ui_lines "$WORK/targets.txt")
  # 加密 DNS 那一轮每个目标平均要测两个左右的 IP
  est=$(( count * (ROUNDS + USE_DNS_TEST * 2) * 3 / PARALLEL + 15 ))
  eta="$est 秒"
  (( est >= 90 )) && eta="$(( (est + 30) / 60 )) 分钟"
  [[ $route != none ]] || route=无
  step_end "$count 个目标 · 路由 $route · 预计约 $eta"
  (( USE_ROUTE )) && [[ $TRACER == none ]] && ui_warn "没有路由工具，不回显的目标无法判断（Debian: apt install -y mtr-tiny）"
  run_calibration
  if (( USE_DNS_TEST )); then
    run_pass E 1 "加密 DNS"
    run_trigger
  fi
  run_pass P "$ROUNDS" "系统 DNS"
  run_retest
  run_sniff
  step_begin "收集环境信息"
  dns_query_exits
  env_info
  analyze
  judge
  step_end "完成"
  lookup_exits
  ui_finish
  if (( JSON )); then
    report_json
  elif (( MARKDOWN )); then
    report_share markdown
  else
    report_text
    printf '\n── 分享摘要（%s，可直接复制）──\n\n' "$( (( MASK )) && echo 'IP 已打码' || echo '含完整 IP' )"
    report_share summary
    printf '\n'
    if (( STDIN_TTY )) && [[ -t 1 && -r /dev/tty ]]; then
      local c=''
      printf '输出完整的 Markdown 报告，方便贴到论坛？[y/N]: ' >&2
      IFS= read -r c </dev/tty || c=''
      case $c in
        y|Y) printf '\n'; report_share markdown ;;
      esac
    else
      printf '要完整的 Markdown 报告，运行时加 -m，例如 -m > report.md\n'
    fi
  fi
  (( EXIT_CODE )) && exit "$(exit_status)"
  return 0
}

# 测试时只加载函数
[[ ${SPLITCHECK_SOURCE_ONLY:-0} == 1 ]] && return 0

# 脚本可能经 bash -s 从 stdin 读入，子命令不能碰 stdin
[[ -t 0 ]] && STDIN_TTY=1
main "$@" </dev/null
