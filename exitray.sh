#!/usr/bin/env bash
#
# ExitRay — VPS / 家宽出口分流检测
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
# 连不连得上分三层看：TCP 连不上、TCP 连上了但 TLS 握手不成、收到了响应。只有 TCP 连不上才算
# “连不上”，证书不被信任不算。连不上的 IP 要复测，路由在内网段就离开已确认线路的算“改道”。
#
# 全程只读：不改系统配置，临时文件放在 mktemp 目录，退出时删除。
# 用法见 --help，项目地址 https://github.com/YePiXpert/exitray

if [ -z "${BASH_VERSINFO+x}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "exitray: 需要 bash 4 或更新版本" >&2
  exit 1
fi

set -u
set -f # 路径里的 ? 不能被当成通配符
export LC_ALL=C

VERSION="2.4.0"
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
INSTALL=1
JSON=0
MARKDOWN=0
SUMMARY=0
IMAGE=0
PKG_SUDO=()
PKG_ERR=""
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
# 拿到基线出口的那个回显：“提取方式 主机 URL IP”，IP 是 - 表示不用钉。稳定性检查反复问它
BASE_ECHO=""
EXIT_NET=""
IPINFO_IP=""
IPAPI_IP=""
# SNI 嗅探用的中立回显的 IP
SNI_IP=""
# 有透明代理按 HTTP 的 Host 改写目的地时为 1，这时不能靠 Host 认 CDN、取回显
HOST_SNIFF=0
PG_CODE=000
PG_CANDS=-
PG_REACH=dead
# 放到后台的路由探测：进程号、它写结果的文件，和结束后读到的路径
ROUTE_PID=""
ROUTE_FILE=""
ROUTE_PATH=""
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
用法: exitray.sh [选项]

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
      --no-install      缺 mtr 或 dig 时不自动安装
  -b, --brief           只输出结论、出口、分类概览、DNS 和连通汇总
  -v, --verbose         明细列出全部目标，外加每一轮和每个 IP 的结果、路径和证据
  -j, --json            输出 JSON
  -m, --markdown        输出方便分享的 Markdown 报告，IP 默认打码，可重定向到文件
  -s, --summary         只输出十几行可直接复制的摘要，IP 默认打码
  -i, --image           另存一张概览图片（PNG，IP 默认打码），方便发给别人
      --no-mask         -s 和 -m 的输出里显示完整 IP
      --exit-code       用退出码表示结论，方便 cron 和监控（见下）
  -y, --yes             不显示启动菜单，直接测全部分类
      --color           输出不是终端时也用颜色，例如接 less -R 或 tee
      --no-color        不用颜色（设了环境变量 NO_COLOR 也一样）
  -V, --version         显示版本
  -h, --help            显示帮助

退出码：0 检测完成，1 运行出错。加 --exit-code 后，0 未发现分流，
2 有分流、DNS 被动了手脚或有 IP 被拦截，3 没发现分流但部分目标证据不足。

依赖：bash 4+、curl、awk。mtr、traceroute 或 tracepath 用于探测路由，dig 用于明文 DNS
触发测试。缺少时用系统的包管理器（apt、dnf、yum、apk、pacman、zypper）一次装好，
要 root 或免密 sudo；装不了就跳过对应检查。-i 存 PNG 要 rsvg-convert 和中文字体，
同样自动装，装不了就存成 SVG。

明文解析过的 IP 会在上游名单里留一段时间，两次运行建议间隔 15 分钟以上，
否则加密 DNS 那一轮可能受上一次运行影响。

例子:
  bash <(curl -fsSL https://raw.githubusercontent.com/YePiXpert/exitray/main/exitray.sh)
  bash exitray.sh -c ai,meta,telegram -n 3
  bash exitray.sh -x socks5h://127.0.0.1:1080 -c ai,meta
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
ai sora.com
ai chat.deepseek.com
ai www.midjourney.com
ai poe.com
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
social obs.line-apps.com
social bsky.app
social chat.signal.org
google www.google.com
google www.youtube.com
google accounts.google.com
google i.ytimg.com
google play.google.com
stream www.netflix.com
stream www.disneyplus.com
stream www.primevideo.com
stream www.hbomax.com
stream www.spotify.com
stream tv.apple.com
stream music.apple.com
stream www.paramountplus.com
stream www.dazn.com
stream www.crunchyroll.com
stream www.bilibili.com
finance www.paypal.com
finance wise.com
finance stripe.com
finance www.visa.com
finance www.mastercard.com
finance www.interactivebrokers.com
finance www.tradingview.com
finance www.revolut.com
finance www.payoneer.com
finance www.moomoo.com
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
crypto polymarket.com
crypto app.hyperliquid.xyz
crypto www.bitfinex.com
shop www.amazon.com
shop www.ebay.com
shop www.aliexpress.com
shop www.temu.com
shop www.taobao.com
shop www.shein.com
shop www.apple.com
shop apps.apple.com
dev github.com
dev raw.githubusercontent.com
dev objects.githubusercontent.com
dev ghcr.io
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
game www.roblox.com
game www.ea.com
game battle.net
@tw bank www.ctbcbank.com
@tw bank www.cathaybk.com.tw
@tw bank www.esunbank.com
@tw bank www.fubon.com
@tw bank www.taishinbank.com.tw
@tw bank www.megabank.com.tw
@tw bank www.bot.com.tw
@tw bank www.firstbank.com.tw
@tw bank www.sinopac.com
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
@tw local ani.gamer.com.tw
@tw local www.104.com.tw
@tw local www.591.com.tw
@tw local www.kktv.me
@tw local www.litv.tv
@tw local hamivideo.hinet.net
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
@jp local tver.jp
@jp local video.unext.jp
@hk bank www.hsbc.com.hk
@hk bank www.bochk.com
@hk bank www.hangseng.com
@hk bank www.sc.com
@hk shop www.hktvmall.com
@hk local www.viu.com
@hk local www.gov.hk
@hk local www.mytvsuper.com
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
@us local www.peacocktv.com
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
  printf 'exitray: %s\n' "$*" >&2
  exit 1
}

warn() {
  (( UI_ON )) && printf '\r\033[K' >&2
  printf 'exitray: %s\n' "$*" >&2
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
UI_DEPTH=0
U_R='' U_B='' U_D='' U_F='' U_G='' U_C='' U_Y='' U_E=''
SPIN=0
SPIN_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
STEP_LABEL='' STEP_TOTAL=0 STEP_FILE='' STEP_BASE=0 STEP_T0=0 STEP_DETAIL=''
# 字标三行，每行一样宽；LOGO_RAMP 是渐变用的 256 色色号，从青到紫
LOGO=('┌─┐ ─┐┌─ ┬ ┌┬┐ ┬─┐ ┌─┐ ┬ ┬' '├┤   ├┤  │  │  ├┬┘ ├─┤ └┬┘' '└─┘ ─┘└─ ┴  ┴  ┴└─ ┴ ┴  ┴ ')
LOGO_RAMP=(44 38 39 33 69 105 141)
BAR_ON='━━━━━━━━━━━━━━━━━━━━━━━━'
BAR_OFF='────────────────────────'

# 颜色深度，结果写进 COLOR_DEPTH：0 不用颜色，8 基本色，256。$1 是要写的文件描述符。
# 要直接调用，不能放进命令替换：命令替换里的标准输出是管道，永远判成不是终端
color_depth() {
  COLOR_DEPTH=0
  case $USE_COLOR in
    0) return 0 ;;
    2) COLOR_DEPTH=256; return 0 ;;
  esac
  [[ -t $1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]] || return 0
  if [[ -n ${COLORTERM:-} || ${TERM:-} == *256color* || ${TERM:-} == *-direct* || ${TERM:-} == xterm-kitty ||
    ${TERM:-} == alacritty || ${TERM:-} == foot* || ${TERM:-} == wezterm ]]; then
    COLOR_DEPTH=256
  elif command -v tput >/dev/null 2>&1 && [[ $(tput colors 2>/dev/null) -ge 256 ]]; then
    COLOR_DEPTH=256
  else
    COLOR_DEPTH=8
  fi
}

ui_setup() {
  color_depth 2
  UI_DEPTH=$COLOR_DEPTH
  [[ -t 2 ]] || return 0
  UI=1
  ui_colors
}

# 界面用的颜色，按 UI_DEPTH 选
ui_colors() {
  case $UI_DEPTH in
    256)
      U_R=$'\033[0m'; U_B=$'\033[1m'; U_D=$'\033[38;5;245m'; U_F=$'\033[38;5;239m'
      U_G=$'\033[38;5;78m'; U_C=$'\033[38;5;80m'; U_Y=$'\033[38;5;221m'; U_E=$'\033[38;5;203m'
      ;;
    8)
      U_R=$'\033[0m'; U_B=$'\033[1m'; U_D=$'\033[2m'; U_F=$'\033[2m'
      U_G=$'\033[32m'; U_C=$'\033[36m'; U_Y=$'\033[33m'; U_E=$'\033[31m'
      ;;
  esac
}

# 三行的字标，256 色时从青到紫逐列渐变，色号按字标的列数平均铺开。参数是三行各自跟在后面的字
ui_logo() {
  local i c col ch out line sp width
  local -a tail=("${1:-}" "${2:-}" "${3:-}")
  for i in 0 1 2; do
    line=${LOGO[i]}
    case $UI_DEPTH in
      256)
        # C locale 下按字节取：空格 1 字节，框线 3 字节
        sp=${line//[! ]/}
        width=$(( ${#sp} + (${#line} - ${#sp}) / 3 ))
        out='' c=0 col=0
        while (( c < ${#line} )); do
          if [[ ${line:c:1} == ' ' ]]; then
            ch=' '
            c=$((c + 1))
          else
            ch=${line:c:3}
            c=$((c + 3))
          fi
          out+=$'\033[38;5;'"${LOGO_RAMP[col * ${#LOGO_RAMP[@]} / width]}m$ch"
          col=$((col + 1))
        done
        out+=$U_R
        ;;
      8) out="$U_C$U_B$line$U_R" ;;
      *) out=$line ;;
    esac
    printf '  %s%s\n' "$out" "${tail[i]}" >&2
  done
}

ui_banner() {
  printf '\n' >&2
  ui_logo '' "   ${U_D}v$VERSION$U_R" "   ${U_D}VPS / 家宽出口分流检测$U_R"
}

ui_title() {
  (( UI )) || return 0
  UI_ON=1
  # 刷新进度时隐藏光标、关闭自动换行，退出时恢复
  printf '\033[?25l\033[?7l' >&2
  # 菜单已经显示过字标
  (( MENU_SHOWN )) || ui_banner
  printf '\n' >&2
}

ui_finish() {
  (( UI_ON )) || return 0
  printf '\r\033[K\033[?7h\033[?25h' >&2
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
  local frame=${SPIN_FRAMES[SPIN % 10]} finished filled line count clock
  SPIN=$((SPIN + 1))
  line="  ${U_C}${frame}${U_R} $(ui_pad "$STEP_LABEL" 20)"
  if (( STEP_TOTAL > 0 )); then
    finished=$(( $(ui_lines "$STEP_FILE") - STEP_BASE ))
    (( finished > STEP_TOTAL )) && finished=$STEP_TOTAL
    filled=$(( finished * 24 / STEP_TOTAL ))
    # 细线进度条：走过的一段亮，剩下的一段暗；没有颜色时剩下的换成细线
    if (( UI_DEPTH )); then
      line+="${U_C}${BAR_ON:0:filled * 3}${U_F}${BAR_ON:filled * 3}${U_R}"
    else
      line+="${BAR_ON:0:filled * 3}${BAR_OFF:filled * 3}"
    fi
    printf -v count '%3d/%-3d' "$finished" "$STEP_TOTAL"
    line+=" $count"
  fi
  printf -v clock '%d:%02d' $(( (SECONDS - STEP_T0) / 60 )) $(( (SECONDS - STEP_T0) % 60 ))
  line+=" ${U_D}${clock}${STEP_DETAIL:+  $STEP_DETAIL}${U_R}"
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
  local clock
  printf -v clock '%d:%02d' $(( (SECONDS - STEP_T0) / 60 )) $(( (SECONDS - STEP_T0) % 60 ))
  printf '\r\033[K  %s✓%s %s%s  %s%s%s\n' "$U_G" "$U_R" "$(ui_pad "$STEP_LABEL" 20)" "$(ui_pad "$1" 46)" "$U_D" "$clock" "$U_R" >&2
}

ui_warn() {
  (( UI_ON )) || return 0
  printf '\r\033[K  %s! %s%s\n' "$U_Y" "$1" "$U_R" >&2
}

# 菜单的一项：按键做成小色块，没有颜色时是 [1]
menu_item() {
  local key
  case $UI_DEPTH in
    256) key=$'\033[48;5;238m\033[38;5;255m\033[1m '"$1"$' \033[0m' ;;
    8) key=$'\033[7m '"$1"$' \033[0m' ;;
    *) key="[$1]" ;;
  esac
  printf '   %s  %s%s%s%s%s%s\n' "$key" "$U_B" "$(ui_pad "$2" 14)" "$U_R$U_D" "$3" "$U_R" "${4:+  $U_C← $4$U_R}" >&2
}

# 没带参数、在终端里直接运行时显示
show_menu() {
  local choice cats c
  MENU_SHOWN=1
  menu_draw
  while :; do
    printf '\n  %s❯%s 请输入 [默认 1]: ' "$U_C" "$U_R" >&2
    IFS= read -r choice </dev/tty || choice=1
    case ${choice:-1} in
      1) return 0 ;;
      2) CATS=ai,meta,telegram,social,google; return 0 ;;
      3) CATS=finance,crypto,bank,shop; return 0 ;;
      4) CATS=stream,google; return 0 ;;
      5)
        printf '  %s可选：%s%s\n  用逗号分隔: ' "$U_D" "$CATEGORIES" "$U_R" >&2
        IFS= read -r cats </dev/tty || cats=''
        cats=${cats// /}
        for c in ${cats//,/ }; do
          is_category "$c" || { printf '  %s没有这个分类: %s%s\n' "$U_E" "$c" "$U_R" >&2; cats=''; break; }
        done
        [[ -n $cats ]] && { CATS=$cats; return 0; }
        ;;
      6) USE_DNS_TEST=0; USE_SNIFF=0; return 0 ;;
      7) LOW_RESOURCE=1; return 0 ;;
      0|q) exit 0 ;;
      *) printf '  %s请输入 0 到 7%s\n' "$U_E" "$U_R" >&2 ;;
    esac
  done
}

# 菜单的样子：字标和各个选项。README 的配图（docs/tools/build.py）也用它画
menu_draw() {
  ui_banner
  printf '\n  %s选择检测范围%s\n\n' "$U_B" "$U_R" >&2
  menu_item 1 '完整检测' '全部分类 · 约 5 分钟' '默认'
  menu_item 2 'AI 和社媒' 'AI · Meta · Telegram · 社媒 · Google'
  menu_item 3 '金融和购物' '金融支付 · 虚拟币 · 银行 · 电商购物'
  menu_item 4 '流媒体' '流媒体 · Google'
  menu_item 5 '自选分类' '输入分类名'
  menu_item 6 '快速检测' '全部分类 · 不测 DNS 触发 · 约 3 分钟'
  menu_item 7 '低压力检测' '全部分类 · 降低并发 · 适合小内存 VPS'
  menu_item 0 '退出' ''
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
      --no-install)  INSTALL=0; shift ;;
      -b|--brief)    BRIEF=1; shift ;;
      -v|--verbose)  VERBOSE=1; shift ;;
      -j|--json)     JSON=1; shift ;;
      -m|--markdown) MARKDOWN=1; shift ;;
      -s|--summary)  SUMMARY=1; shift ;;
      -i|--image)    IMAGE=1; shift ;;
      --no-mask)     MASK=0; shift ;;
      -y|--yes)      shift ;;
      --color)       USE_COLOR=2; shift ;;
      --no-color)    USE_COLOR=0; shift ;;
      -V|--version)  echo "exitray $VERSION"; exit 0 ;;
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
  # 经代理时只能看回显，节点的 DNS 行为也由节点决定。SNI 嗅探照做：节点按域名分流时，它是最直接的证据
  if [[ -n $PROXY ]]; then
    USE_ROUTE=0
    USE_DNS_TEST=0
  fi
}

# 缺路由工具或 dig 时，用系统的包管理器一条命令装齐，之后再运行就不用装了。要 root 或免密
# sudo；--no-install 或 EXITRAY_NO_INSTALL=1 时不装，照旧跳过对应检查（改名前的 SPLITCHECK_NO_INSTALL 也认）
install_deps() {
  (( INSTALL )) && [[ ${EXITRAY_NO_INSTALL:-${SPLITCHECK_NO_INSTALL:-}} != 1 ]] || return 0
  local route=0 dig=0 img=0 font=0 pm='' p missing=''
  local -a pkgs=() imgs=()
  if (( USE_ROUTE )) && ! command -v mtr >/dev/null 2>&1 && ! command -v traceroute >/dev/null 2>&1 &&
    ! command -v tracepath >/dev/null 2>&1; then
    route=1
  fi
  (( USE_DNS_TEST )) && ! command -v dig >/dev/null 2>&1 && dig=1
  if (( IMAGE )); then
    command -v rsvg-convert >/dev/null 2>&1 || img=1
    has_cjk_font || font=1
  fi
  (( route + dig + img + font > 0 )) || return 0
  for p in apt-get dnf yum apk pacman zypper; do
    command -v "$p" >/dev/null 2>&1 && { pm=$p; break; }
  done
  [[ -n $pm ]] || return 0
  PKG_SUDO=()
  if (( EUID != 0 )); then
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
      PKG_SUDO=(sudo -n)
    else
      (( route )) && missing+=' mtr'
      (( dig )) && missing+=' dig'
      (( img )) && missing+=' rsvg-convert'
      (( font )) && missing+=' 中文字体'
      install_say "缺少$missing，不是 root 也没有免密 sudo，不自动安装，跳过对应检查"
      return 0
    fi
  fi
  case $pm in
    apt-get)
      (( route )) && pkgs+=(mtr-tiny); (( dig )) && pkgs+=(dnsutils)
      (( img )) && imgs+=(librsvg2-bin); (( font )) && imgs+=(fontconfig fonts-wqy-microhei) ;;
    apk)
      (( route )) && pkgs+=(mtr); (( dig )) && pkgs+=(bind-tools)
      (( img )) && imgs+=(rsvg-convert); (( font )) && imgs+=(fontconfig font-wqy-zenhei) ;;
    pacman)
      (( route )) && pkgs+=(mtr); (( dig )) && pkgs+=(bind)
      (( img )) && imgs+=(librsvg); (( font )) && imgs+=(fontconfig wqy-microhei) ;;
    zypper)
      (( route )) && pkgs+=(mtr); (( dig )) && pkgs+=(bind-utils)
      (( img )) && imgs+=(rsvg-convert); (( font )) && imgs+=(fontconfig wqy-microhei-fonts) ;;
    *)
      (( route )) && pkgs+=(mtr); (( dig )) && pkgs+=(bind-utils)
      (( img )) && imgs+=(librsvg2-tools); (( font )) && imgs+=(fontconfig wqy-microhei-fonts) ;;
  esac
  if (( ${#pkgs[@]} > 0 )); then
    install_say "安装依赖 ${pkgs[*]}（$pm，只装这一次；不想装加 --no-install）"
    if pkg_install "$pm" "${pkgs[@]}"; then
      install_say "已装好 ${pkgs[*]}"
    else
      install_say "安装失败，跳过对应检查：$PKG_ERR"
    fi
  fi
  if (( ${#imgs[@]} > 0 )); then
    install_say "安装出图片要用的 ${imgs[*]}（$pm，只装这一次；不想装加 --no-install）"
    if pkg_install "$pm" "${imgs[@]}"; then
      install_say "已装好 ${imgs[*]}"
    else
      install_say "安装失败，图片改存成 SVG：$PKG_ERR"
    fi
  fi
}

# 用系统的包管理器装一批包。PKG_SUDO 要先设好；装不上时最后一行输出放进 PKG_ERR
pkg_install() {
  local pm=$1 log ok=0
  shift
  PKG_ERR=''
  log=$(mktemp "${TMPDIR:-/tmp}/exitray-install.XXXXXX") || return 1
  local -a lim=()
  command -v timeout >/dev/null 2>&1 && lim=(timeout 300)
  case $pm in
    apt-get)
      # 软件源索引太旧时先装不上，更新一次再装
      if ${PKG_SUDO[@]+"${PKG_SUDO[@]}"} ${lim[@]+"${lim[@]}"} env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >"$log" 2>&1 ||
        { ${PKG_SUDO[@]+"${PKG_SUDO[@]}"} ${lim[@]+"${lim[@]}"} apt-get update -qq >>"$log" 2>&1 &&
          ${PKG_SUDO[@]+"${PKG_SUDO[@]}"} ${lim[@]+"${lim[@]}"} env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >>"$log" 2>&1; }; then
        ok=1
      fi ;;
    dnf|yum) ${PKG_SUDO[@]+"${PKG_SUDO[@]}"} ${lim[@]+"${lim[@]}"} "$pm" install -y -q "$@" >"$log" 2>&1 && ok=1 ;;
    apk) ${PKG_SUDO[@]+"${PKG_SUDO[@]}"} ${lim[@]+"${lim[@]}"} apk add -q --no-progress "$@" >"$log" 2>&1 && ok=1 ;;
    pacman) ${PKG_SUDO[@]+"${PKG_SUDO[@]}"} ${lim[@]+"${lim[@]}"} pacman -S --noconfirm --needed "$@" >"$log" 2>&1 && ok=1 ;;
    zypper) ${PKG_SUDO[@]+"${PKG_SUDO[@]}"} ${lim[@]+"${lim[@]}"} zypper -n -q install "$@" >"$log" 2>&1 && ok=1 ;;
  esac
  hash -r
  (( ok )) || PKG_ERR=$(tail -1 "$log" 2>/dev/null)
  rm -f "$log"
  (( ok ))
}

# 有没有能显示中文的字体。转 PNG 时没有它，汉字全是方块
has_cjk_font() {
  command -v fc-list >/dev/null 2>&1 && [[ -n $(fc-list :lang=zh family 2>/dev/null | head -1) ]]
}

install_say() {
  if (( UI )); then
    printf '  %s↓%s %s\n' "$U_C" "$U_R" "$1" >&2
  else
    warn "$1"
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
  # 先让它停住再列子进程：停住的进程不会再派生新进程。否则列完之后才起的子进程（比如正要
  # 跑的 mtr）不在名单上，脚本退出后还挂着
  kill -STOP "$1" 2>/dev/null
  children=$({ ps -eo pid=,ppid= 2>/dev/null || ps -o pid,ppid 2>/dev/null; } | awk -v p="$1" '$2 == p { print $1 }')
  for child in $children; do
    stop_tree "$child"
  done
  kill "$1" 2>/dev/null
  kill -CONT "$1" 2>/dev/null
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
  curl -4 -s --connect-timeout "${CONNECT_TIMEOUT:-4}" --max-time "${HTTP_TIMEOUT:-8}" -A "$UA" ${PROXY:+-x "$PROXY"} "$@" 2>/dev/null
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

# 只看 TCP 能不能连上，不管对方说不说 HTTP。IP 目标没有页面可翻，用它判断连不连得通；
# 后面几轮不翻页面的域名、复测连不上的 IP，也只用它
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

# 同一轮同一 IP 只测一次；复测（轮次以 r 开头）沿用之前测到的路径，不再探测
route_of() {
  (( USE_ROUTE )) || return 0
  [[ $TRACER != none ]] || return 0
  local ip=$1 cache="$WORK/path/$2.$1" p q
  [[ $2 != ?r* || ! -s $WORK/path/last.$1 ]] || cache="$WORK/path/last.$1"
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
  [[ -z $p ]] || printf '%s\n' "$p" > "$WORK/path/last.$ip"
  printf '%s\n' "$p"
}

# 把路由探测放到后台，好和取回显同时进行：两件事互不相干，一个 IP 的用时从两者之和降到较长的那个。
# 参数和 route_of 一样。之后用 route_wait 等它结束，路径在 ROUTE_PATH 里
route_start() {
  ROUTE_PID='' ROUTE_PATH=''
  (( USE_ROUTE )) && [[ $TRACER != none ]] || return 0
  # 文件名先在这里算好：写在后台命令或命令替换里的 $BASHPID 是那个子进程自己的
  ROUTE_FILE="$WORK/r.$BASHPID"
  route_of "$1" "$2" > "$ROUTE_FILE" &
  ROUTE_PID=$!
}

route_wait() {
  [[ -n $ROUTE_PID ]] || return 0
  wait "$ROUTE_PID"
  IFS= read -r ROUTE_PATH < "$ROUTE_FILE" || true
  ROUTE_PID=''
}

# ---------- 回显 ----------

# 用一次明文 HTTP 请求判断这个 IP 属于哪家 CDN
fingerprint() {
  local ip=$1 cache="$WORK/fp/$1" tmp body kind=other since=0
  if [[ -s $cache ]]; then
    cat "$cache"
    return 0
  fi
  tmp=$(mktemp "$WORK/h.XXXXXX")
  if (( HOST_SNIFF )); then
    # 有透明代理按 Host 改写目的地时，带着 Akamai 的 Host 会被转去别处，只能照常请求、看响应头
    body=$(HTTP_TIMEOUT=5 http -D "$tmp" "http://$ip/" | head -c 3000)
  else
    body=$(HTTP_TIMEOUT=5 http -D "$tmp" -H 'Host: whatismyip.akamai.com' "http://$ip/" | head -c 3000)
  fi
  if [[ ! -s $tmp ]]; then
    kind=none
  elif (( ! HOST_SNIFF )) && is_public_ipv4 "$(printf '%s' "$body" | tr -d ' \r\n\t')"; then
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
  # 没连上可能只是这一次超时，先不下结论，下次探测再认，免得这个 IP 整场都拿不到回显。
  # 隔了 20 秒以上又没连上才记下来：80 端口不通的 IP 每问一次要等好几秒，后面几轮不再为它等。
  # 要隔开，是因为同一阵抖动会让同时发出的几个请求一起超时，那只能算一次
  if [[ $kind != none ]]; then
    printf '%s' "$kind" > "$cache"
  elif [[ -s $cache.miss ]]; then
    read -r since < "$cache.miss" || true
    (( SECONDS - ${since:-0} < 20 )) || printf none > "$cache"
  else
    printf '%s\n' "$SECONDS" > "$cache.miss"
  fi
  printf '%s' "$kind"
}

# 输出“出口 方法”，拿不到就不输出。调用方设了 NOCONN（一个文件名）时顺带记一件事：
# 这一次连目标的 443 端口，是不是连 TCP 都没连上。没连上文件里有内容，否则是空的
echo_by_ip() {
  local name=$1 ip=$2 kind ex='' m='' tmp t
  [[ -z ${NOCONN:-} ]] || : > "$NOCONN"
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
        # 这个回显也靠 Host，被改写目的地时拿到的是别处的出口，宁可不要
        (( HOST_SNIFF )) || ex=$(HTTP_TIMEOUT=6 http -H 'Host: www.fastly-debug.com' "http://$ip/" | extract fastly)
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
        if ! is_ipv4 "$name"; then
          tmp="$WORK/e.$BASHPID"
          : > "$tmp"
          t=$(HTTP_TIMEOUT=5 fetch_own "$name" "$ip" "https://$name/cdn-cgi/trace" -o "$tmp" -w '%{time_connect}')
          ex=$(extract trace < "$tmp")
          rm -f "$tmp"
          # 经代理时看到的是到代理的连接，说明不了目标连不连得上
          [[ $t =~ [1-9] || -n $PROXY || -z ${NOCONN:-} ]] || echo dead > "$NOCONN"
        fi
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
    route_start "$ip" cal
    # 回显页的源站在某些地区可能躲在别家 CDN 后面，这时看到的是 CDN 的 IP，不能算数
    case $method in
      akamai|fastly|cloudfront|meta) want=$method ;;
      youtube) want=google ;;
    esac
    if [[ -z $want || $(fingerprint "$ip") == "$want" ]]; then
      ex=$(pinned "$host" "$ip" "$url" | head -c 400000 | extract "$method")
    fi
    route_wait
    path=$ROUTE_PATH
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
  STEP_TOTAL=0
  STEP_LABEL='校准出口'
  stability_check s 5
  rows_merge
  local pool
  pool=$(awk -F'\t' '$1 == "S" && $7 != "-" && !s[$7]++ { n++ } END { print n + 0 }' "$WORK/rows.tsv")
  if (( pool > 1 )); then
    step_end "已发现 $(exits_so_far) 个出口，同一个目标连问几次出口在轮换"
  else
    step_end "已发现 $(exits_so_far) 个出口"
  fi
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

# 翻目标的首页：看连不连得上，顺带把页面里出现的 IP 记下来。结果写进 PG_CODE、PG_CANDS 和 PG_REACH：
#   ok    收到了响应头
#   tls   TCP 连上了，却没等到任何 HTTP 响应：握手被掐断、被重置或者超时
#   dead  TCP 都连不上
# 经代理时看到的是到代理的连接，分不出后两种，没有响应一律算 dead
page_fetch() {
  local pass=$1 name=$2 ip=$3 tmp out
  local -a follow=(-L --max-redirs 3)
  PG_CODE=000 PG_CANDS=- PG_REACH=dead
  tmp=$(mktemp "$WORK/p.XXXXXX")
  # 跟随跳转时 curl 会自己去解析跳到的主机，发的是明文查询。加密 DNS 轮不能发，所以把
  # 所有主机都钉在这个 IP 上，curl 太旧钉不了就不跟随。系统 DNS 轮本来就走系统解析，照常
  if [[ $pass == E ]]; then
    if (( HAS_CONNECT_TO )); then
      follow+=(--connect-to "::$ip:")
    else
      follow=()
    fi
  fi
  # -k：证书对不对不影响连不连得上。自签 CA（Signal）、证书链不全的站点，不能因为校验不过就算成连不上。
  # 握手慢的站点要好几秒，连接阶段多给一点时间
  out=$(HTTP_TIMEOUT=12 CONNECT_TIMEOUT=6 fetch_own "$name" "$ip" "https://$name/" -k -i ${follow[@]+"${follow[@]}"} -o "$tmp" -w '%{http_code} %{time_connect}')
  PG_CODE=${out%% *}
  # 收到过响应头就是连上了。跟随跳转时跳到的地址连不上，curl 也报 000，所以不看状态码
  if grep -qa '^HTTP/' "$tmp" 2>/dev/null; then
    PG_REACH=ok
  elif [[ -z $PROXY && ${out#* } =~ [1-9] ]]; then
    PG_REACH=tls
  fi
  PG_CANDS=$(grep -aoE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$tmp" 2>/dev/null | sort -u | head -300 | paste -sd, -)
  rm -f "$tmp"
}

# 对一个定下来的 IP 取证：路由、回显，没有回显再翻页面，顺带记下连不连得上：
# ok 收到了响应，tcp 只验证过 TCP 连得上，tls 是 TCP 连上了但握手不成，dead 是 TCP 连不上，- 没试过。
# 换出口的复测也用它，轮次写成 r1、r2
probe_ip() {
  local pass=$1 group=$2 name=$3 round=$4 ip=$5 path out ex='-' method='-' code='-' cands='-' reach='-'
  local NOCONN="$WORK/n.$BASHPID"
  # 加密 DNS 这一轮没有明文查询，路由和回显谁先谁后都一样，同时做。系统 DNS 那一轮照旧先探路由：
  # 刚发过明文查询，上游的名单要过一会儿才生效，探路由的这一两秒正好让出来，回显才看得到生效后的出口
  if [[ $pass == E ]]; then
    route_start "$ip" "$pass$round"
  else
    path=$(route_of "$ip" "$pass$round")
  fi
  out=$(echo_by_ip "$name" "$ip")
  if [[ -n $out ]]; then
    ex=${out% *}
    method=${out#* }
    reach=ok
  elif ! is_ipv4 "$name" && { [[ $round == 1 || $round == r* ]] || grep -qxF "$name" "$WORK/page_names" 2>/dev/null; }; then
    if [[ -s $NOCONN ]]; then
      # 刚才取回显时连它的 443 端口，TCP 就没连上，页面也翻不了，不用再等一遍超时。
      # 记成连不上，算不算数由复测决定
      code=000 reach=dead
    else
      # 没有回显就翻页面。后面几轮只翻第一轮证明有用的目标，省流量；复测要看连不连得上，也翻
      page_fetch "$pass" "$name" "$ip"
      code=$PG_CODE cands=$PG_CANDS reach=$PG_REACH
    fi
  elif [[ -z $PROXY ]]; then
    # IP 目标没有页面可翻；后面几轮不翻页面的域名也照样连一次。没试过的 IP 不能当成连得上
    if [[ ! -s $NOCONN ]] && tcp_open "$ip" 443; then reach=tcp; else reach=dead; fi
  fi
  if [[ $pass == E ]]; then
    route_wait
    path=$ROUTE_PATH
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

# 用外地节点 IP 做对照：查询前后的真实出口。这些 IP 本机没解析过，不受之前的结果影响。
# 测不了的记下卡在哪一步：nofar 拿不到外地节点的 IP，noecho 那个 IP 不回显，
# mismatch 明文应答里没有那个 IP（53 端口被劫持时，应答是劫持方按自己的位置给的）
trigger_one() {
  local group=$1 name=$2 sub ip out before after m answers why=nofar silent=' '
  for sub in $FAR_SUBNETS; do
    ip=$(doh "$name" "$sub" | head -1)
    [[ -n $ip ]] || continue
    # 这个 IP 刚才就没给回显，换一个外地子网问到的还是它：结果不会变，不用再等一遍
    [[ $silent != *" $ip "* ]] || continue
    out=$(echo_by_ip "$name" "$ip")
    if [[ -z $out ]]; then
      [[ $why == mismatch ]] || why=noecho
      silent+="$ip "
      continue
    fi
    before=${out% *}
    m=${out#* }
    answers=$(dig +short +time=2 +tries=1 +subnet="$sub" "$name" A @8.8.8.8 2>/dev/null)
    if ! grep -qxF "$ip" <<<"$answers"; then
      why=mismatch
      continue
    fi
    sleep 0.3
    out=$(echo_by_ip "$name" "$ip")
    [[ -n $out ]] || continue
    after=${out% *}
    # 上游的名单可能要过一会儿才生效。出口没变就等一等再看一次，免得漏掉写得慢的
    if [[ $after == "$before" ]]; then
      sleep 1.2
      out=$(echo_by_ip "$name" "$ip")
      [[ -z $out ]] || after=${out% *}
    fi
    emit X E "$group" "$name" 0 "$ip" "$before" "$m" - - -
    emit X E "$group" "$name" 0 "$ip" "$after" "$m" - - -
    printf '%s\t%s\t%s\t%s\t%s\tok\n' "$group" "$name" "$ip" "$before" "$after" >> "$WORK/trigger.tsv"
    return 0
  done
  printf '%s\t%s\t-\t-\t-\t%s\n' "$group" "$name" "$why" >> "$WORK/trigger.tsv"
}

run_trigger() {
  if ! command -v dig >/dev/null 2>&1; then
    printf 'trigger\tno-dig\n' >> "$WORK/env.tsv"
    ui_warn "没有 dig，跳过明文 DNS 触发测试（Debian: apt install -y dnsutils）"
    return 0
  fi
  local group name
  # 这一步只发 DNS 查询和 HTTP 请求，中间还要等名单生效，不跑路由工具，可以多开一倍。低压力模式照旧
  local PARALLEL=$PARALLEL
  (( LOW_RESOURCE )) || PARALLEL=$(( PARALLEL * 2 ))
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

# 复测两遍，同一个目标、同一个 IP。$6 是复测的原因：
#   exit  只回显过一次的出口：把当初那次探测原样再做
#   tls   TCP 连上了但握手不成：再翻两次页面
#   dead  TCP 连不上：再连两次。只看 TCP，不用再走一遍路由和回显
#   sib   同一个目标别的 IP 连不上：这个 IP 也再连两次，免得把碰巧连上的一次当成正常
retest_one() {
  local kind=$1 pass=$2 group=$3 name=$4 ip=$5 why=${6:-exit} try out method='' url='' reach
  for try in 1 2; do
    case $kind:$why in
      C:*)
        read -r method url < <(awk -v h="$name" -v i="$ip" '$2 == h && $4 == i { print $1, $3; exit }' "$WORK/cal_pinned.txt")
        [[ -z $url ]] || probe_calibration "$method" "$name" "$url" "$ip" "r$try"
        ;;
      N:*)
        out=$(sniff_echo "$name")
        emit N "$pass" "$group" "$name" "r$try" "$ip" "${out% *}" plain "${out#* }" - -
        ;;
      X:*)
        out=$(echo_by_ip "$name" "$ip")
        if [[ -n $out ]]; then
          emit X "$pass" "$group" "$name" "r$try" "$ip" "${out% *}" "${out#* }" - - -
        else
          emit X "$pass" "$group" "$name" "r$try" "$ip" - - - - -
        fi
        ;;
      T:exit) probe_ip "$pass" "$group" "$name" "r$try" "$ip" ;;
      *)
        if [[ $why == tls || -n $PROXY ]] && ! is_ipv4 "$name"; then
          page_fetch "$pass" "$name" "$ip"
          reach=$PG_REACH
        elif [[ -n $PROXY ]]; then
          reach=-
        elif tcp_open "$ip" 443; then
          reach=tcp
        else
          reach=dead
        fi
        emit T "$pass" "$group" "$name" "r$try" "$ip" - - - - - "$reach"
        # 两次之间隔一下，免得两次都撞上同一阵抖动
        (( try == 2 )) || sleep 0.5
        ;;
    esac
  done
}

# 触发测试里的偶发读数按没变处理，免得出口已经不算数了，报告里还写着“触发”
settle_triggers() {
  [[ -s $WORK/trigger.tsv ]] || return 0
  touch "$WORK/unstable.tsv" "$WORK/pool.tsv"
  [[ -s $WORK/unstable.tsv || -s $WORK/pool.tsv ]] || return 0
  # 出口池里的出口算同一个：前后只是在池里换了一个 IP，不是触发
  awk -F'\t' -v OFS='\t' -v F_BAD="$WORK/unstable.tsv" -v F_POOL="$WORK/pool.tsv" '
    FILENAME == F_POOL { member[$1] = 1; if ($4 == 1) canon = $1; next }
    FILENAME == F_BAD { bad[$1] = 1; next }
    {
      if ($4 in member) $4 = canon
      if ($5 in member) $5 = canon
      if ($4 in bad) $4 = $5; else if ($5 in bad) $5 = $4
      print
    }' "$WORK/pool.tsv" "$WORK/unstable.tsv" "$WORK/trigger.tsv" > "$WORK/trigger.new" &&
    mv "$WORK/trigger.new" "$WORK/trigger.tsv"
}

# 只回显过一次的出口，可能只是出口池轮换或临时的线路切换，不能直接算成分流；一次连不上也可能
# 只是超时。先复测，算不算数由 analyze 决定：出口再出现就算，同一个目标同一个 IP 看到的成了
# 别的出口就按偶发处理；连不上的 IP 再连两次都不通才算
run_retest() {
  local kind pass group name ip why count
  analyze
  sort -u "$WORK/once.tsv" > "$WORK/retest.txt"
  [[ -s $WORK/retest.txt ]] || return 0
  count=$(ui_lines "$WORK/retest.txt")
  # 复测沿用之前探到的路径，不再跑路由工具，时间多半花在等连不上的 IP 超时，多开几路不会给路由器
  # 添负担。低压力模式照旧
  local PARALLEL=$PARALLEL
  (( LOW_RESOURCE )) || PARALLEL=$(( PARALLEL * 3 ))
  step_begin "复测偶发的读数" "$count" "$PROGRESS"
  while IFS=$'\t' read -r kind pass group name ip why; do
    STEP_DETAIL=$name
    spawn retest_one "$kind" "$pass" "$group" "$name" "$ip" "${why:-exit}"
  done < "$WORK/retest.txt"
  STEP_DETAIL=''
  wait_all
  analyze
  settle_triggers
  # 复测有三种结果：看到别的出口（偶发，不算数）、又看到同一个出口（确认）、没拿到回显（还是只有
  # 一次，没能确认）。分开说，免得“0 个被推翻”读成“都确认了”
  local note gone open dead
  note="$count 个"
  gone=$(ui_lines "$WORK/unstable.tsv")
  open=$(awk -F'\t' '$4 != 1 && $3 + 0 <= 1 { n++ } END { print n + 0 }' "$WORK/exits.tsv")
  dead=$(awk -F'\t' '$17 == "partial" || $17 == "dead" { n++ } END { print n + 0 }' "$WORK/targets.tsv")
  (( gone == 0 )) || note+="，$gone 个出口复测看到的是别的出口，按偶发处理"
  (( open == 0 )) || note+="，$open 个出口复测没拿到回显，没能确认"
  (( dead == 0 )) || note+="，$dead 个目标有 IP 确实连不上"
  (( gone + open + dead > 0 )) || note+="，复测都通过了"
  step_end "$note"
}

# 把一个域名放进 SNI 发给中立回显，输出“出口 状态码”，拿不到回显时出口是 -
sniff_echo() {
  local sni=$1 try tmp r='' code=000 proxy=$PROXY
  # 经代理时由本机把域名钉到回显的 IP 上，节点看到的只有 IP 和 SNI
  [[ $proxy != socks5h://* ]] || proxy=socks5://${proxy#socks5h://}
  tmp=$(mktemp "$WORK/s.XXXXXX")
  # 没拿到回显就再试一次，偶发的超时不能当成结论
  for try in 1 2; do
    : > "$tmp"
    code=$(curl -4 -sk --connect-timeout 4 --max-time 8 ${proxy:+-x "$proxy"} --resolve "$sni:443:$SNI_IP" -H 'Host: ipinfo.io' -o "$tmp" -w '%{http_code}' "https://$sni/ip" 2>/dev/null)
    r=$(extract plain < "$tmp")
    [[ -z $r ]] || break
  done
  rm -f "$tmp"
  printf '%s %s' "${r:--}" "${code:-000}"
}

sniff_one() {
  local group=$1 sni=$2 out
  out=$(sniff_echo "$sni")
  printf '%s\t%s\t%s\n' "$sni" "${out% *}" "${out#* }" >> "$WORK/sniff.tsv"
  # 同时记成一行读数（N）：换了 SNI 才出现的出口同样是出口，只出现一次的同样要复测
  emit N E "$group" "$sni" 0 "$SNI_IP" "${out% *}" plain "${out#* }" - -
}

# 一批域名的嗅探：$1 是这一步的名字，$2 是每行“分类 域名”的清单
sniff_batch() {
  local group sni
  step_begin "$1" "$(ui_lines "$2")" "$WORK/sniff.tsv"
  while read -r group sni; do
    STEP_DETAIL=$sni
    spawn sniff_one "$group" "$sni"
  done < "$2"
  STEP_DETAIL=''
  wait_all
  # 429 是回显服务自己在限流，和完全连不上的一样不算变化
  step_end "$(awk -F'\t' -v b="$3" '
    $2 == b { next }
    $2 != "-" || ($3 + 0 > 0 && $3 + 0 != 429) { c++; next }
    { f++ }
    END { printf "%d 个域名，%d 个有变化", NR, c; if (f) printf "，%d 个没连上", f }' "$WORK/sniff.tsv")"
}

# 把目标域名放进 SNI 发给中立回显。回显服务不看 SNI，所以出口变了是上游按 TLS 域名换了线路，
# 有应答却不是回显，是连接被按 TLS 域名转去了别的服务器。这一步也不发明文 DNS
run_sniff() {
  (( USE_SNIFF )) || return 0
  local base changed
  SNI_IP=$IPINFO_IP
  # 经代理时 ipinfo 没有钉 IP，这里单独解析一次；HTTP 代理钉不住 IP，下面拿不到基线就不测
  [[ -n $SNI_IP ]] || SNI_IP=$(doh ipinfo.io '' | head -1)
  [[ -n $SNI_IP ]] || return 0
  base=$(pinned ipinfo.io "$SNI_IP" https://ipinfo.io/ip | extract plain)
  [[ -n $base ]] || return 0
  printf 'sniff_base\t%s\n' "$base" >> "$WORK/env.tsv"
  # 先每个分类抽两个
  awk '$2 !~ /^[0-9.]+$/ && c[$1]++ < 2 { print $1, $2 }' "$WORK/targets.txt" > "$WORK/sni.txt"
  sniff_batch "SNI 嗅探测试" "$WORK/sni.txt" "$base"
  # 抽样里有域名换了 SNI 出口就变，说明按域名的规则确实存在：把其余的域名也都问一遍，
  # 每个目标真实访问时走哪个出口才说得清
  changed=$(awk -F'\t' -v b="$base" '$2 != "-" && $2 != b { n++ } END { print n + 0 }' "$WORK/sniff.tsv")
  (( changed > 0 )) || return 0
  awk 'FILENAME == ARGV[1] { seen[$2] = 1; next } $2 !~ /^[0-9.]+$/ && !($2 in seen) { print $1, $2 }' \
    "$WORK/sni.txt" "$WORK/targets.txt" > "$WORK/sni_rest.txt"
  [[ ! -s $WORK/sni_rest.txt ]] || sniff_batch "SNI 嗅探其余域名" "$WORK/sni_rest.txt" "$base"
}

# DNS 权威看到的来源 IP，走 UDP，可以顺带对比 UDP 的出口
dns_query_exits() {
  [[ -z $PROXY ]] || return 0
  command -v dig >/dev/null 2>&1 || return 0
  local a b c dir="$WORK/dnsq.d"
  mkdir -p "$dir"
  # 四个查询互不相干，同时发。192.0.2.53 是保留地址，不存在 DNS 服务：没被劫持时那一个总要等到超时，
  # 一个一个发，这一步至少白等两秒
  dig +short +time=2 +tries=1 TXT whoami.cloudflare CH @1.1.1.1 > "$dir/cf" 2>/dev/null &
  dig +short +time=2 +tries=1 whoami.akamai.net @ns1-1.akamaitech.net > "$dir/akamai" 2>/dev/null &
  dig +short +time=2 +tries=1 TXT o-o.myaddr.l.google.com @8.8.8.8 > "$dir/google" 2>/dev/null &
  dig +short +time=2 +tries=1 example.com A @192.0.2.53 > "$dir/reserved" 2>/dev/null &
  wait
  a=$(tr -d '"' < "$dir/cf" | head -1)
  b=$(head -1 "$dir/akamai")
  c=$(grep -oE 'edns0-client-subnet [0-9./]+' "$dir/google" | awk '{ print $2 }' | head -1)
  # 超时的时候 dig +short 会把 “;; connection timed out” 这种提示写到 stdout
  is_ipv4 "$a" || a=''
  is_ipv4 "$b" || b=''
  printf 'Cloudflare\t%s\nAkamai\t%s\nGoogle\t%s\n' "${a:--}" "${b:--}" "${c:--}" > "$WORK/dnsq.tsv"
  # 发给保留地址的查询能收到应答，说明 53 端口被中途拦截了
  a=$(grep -E '^[0-9.]+$' "$dir/reserved" | head -1)
  printf 'dns_hijack\t%s\n' "$([[ -n $a ]] && echo 1 || echo 0)" >> "$WORK/env.tsv"
}

# 本机的 IPv6 出口，没有就输出 -
ipv6_exit() {
  local v
  v=$(curl -6 -s --connect-timeout 3 --max-time 5 https://api64.ipify.org 2>/dev/null | tr -d ' \r\n' | head -c 45)
  [[ $v == *:* ]] || v='-'
  printf '%s\n' "$v"
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
  # main 已经在后台问过了，结果在 ipv6.txt 里；单独调用时现问
  v=''
  [[ ! -s $WORK/ipv6.txt ]] || IFS= read -r v < "$WORK/ipv6.txt" || true
  [[ -n $v ]] || v=$(ipv6_exit)
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
  local method host url ip
  BASE_IP=$(http https://1.1.1.1/cdn-cgi/trace | extract trace)
  BASE_ECHO='trace 1.1.1.1 https://1.1.1.1/cdn-cgi/trace -'
  if [[ -z $BASE_IP ]]; then
    # 1.1.1.1 不通时换别的中立回显。先经 DoH 解析再钉到 IP 上，这里也不发明文查询
    while read -r method host url; do
      if [[ -n $PROXY ]]; then
        ip=-
        BASE_IP=$(http "$url" | extract "$method")
      else
        ip=$(doh "$host" '' | head -1)
        [[ -n $ip ]] || continue
        BASE_IP=$(pinned "$host" "$ip" "$url" | extract "$method")
      fi
      if [[ -n $BASE_IP ]]; then
        BASE_ECHO="$method $host $url $ip"
        break
      fi
    done < <(cal_list | awk '$1 == "trace" || $1 == "plain"')
  fi
  if [[ -z $BASE_IP ]]; then
    # DoH 也用不了，只剩系统解析这一条路
    BASE_IP=$(http https://ifconfig.me/ip | extract plain)
    BASE_ECHO='plain ifconfig.me https://ifconfig.me/ip -'
  fi
  [[ -n $BASE_IP ]] || die "拿不到出口 IP，检查网络${PROXY:+或代理 $(proxy_label)}"
  EXIT_NET="${BASE_IP%.*}.0/24"
}

# 再问一次拿到基线的那个回显
base_echo() {
  local method host url ip
  read -r method host url ip <<<"$BASE_ECHO"
  if [[ $ip == - ]]; then
    http "$url" | extract "$method"
  else
    pinned "$host" "$ip" "$url" | extract "$method"
  fi
}

# 同一个中立回显连问几次。目标没变而出口变了，是出口池或多线负载均衡在轮换，不是按目标分流；
# 结束时再问几次，检测期间出口 IP 换了也能看出来。$1 是阶段（s 开始、e 结束），$2 是次数
stability_check() {
  local phase=$1 n=$2 i ex method host url ip varied=0
  read -r method host url ip <<<"$BASE_ECHO"
  for (( i = 1; i <= n; i++ )); do
    ex=$(base_echo)
    emit S E stab "$host" "$phase$i" "$ip" "${ex:--}" "$method" - - -
    [[ -z $ex || $ex == "$BASE_IP" ]] || varied=1
    # 发现在轮换就多问几次，尽量把池里的出口都问出来
    (( varied && n < 16 )) && n=16
    ui_paint
  done
  return 0
}

# 钉 IP 的探测靠的是“连哪个 IP 就到哪个 IP”。有的透明代理按 HTTP 的 Host 改写目的地：
# 给 1.1.1.1 发一个 Host 是 Akamai 回显的请求，正常只会得到 Cloudflare 的报错页；
# 收到了 IP，说明请求半路被转去了别处，靠 Host 认 CDN、取回显都不能信
check_intercept() {
  [[ -z $PROXY ]] || return 0
  local body
  body=$(HTTP_TIMEOUT=5 http -H 'Host: whatismyip.akamai.com' http://1.1.1.1/ | head -c 64 | tr -d ' \r\n\t')
  is_public_ipv4 "$body" || return 0
  HOST_SNIFF=1
  printf 'intercept\thost\n' >> "$WORK/env.tsv"
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

function net24(ip) { sub(/\.[0-9]+$/, "", ip); return ip }

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

# 改道：路径上第一个没在任何已确认线路的同一位置出现过的跳，如果是内网地址，说明这个 IP 在上游的
# 内网段就被导去了别处。返回那一跳的位置，DIVH 是它的地址；先在公网地址上分开是正常的路由差异，
# 返回 0。只看内网段附近的前几跳（DLIM），再往后的内网地址多半是运营商骨干网自己的
function divert(path, h, m, j) {
  DIVH = "-"
  if (path == "-" || path == "") return 0
  m = split(path, h, " ")
  for (j = 1; j <= m && j <= DLIM; j++) {
    if (h[j] == "?" || !(j in ALLN) || ((j, h[j]) in KNOWN)) continue
    if (is_private(h[j])) { DIVH = h[j]; return j }
    return 0
  }
  return 0
}

# 找相同跳数最多的已校准线路。这些线路都指向同一个出口才算推断成立。dv 是这条路径改道的位置
function infer(path, dv, c, m, best, nl, e, only, j, lab, cand, total, top) {
  INF_X = "-"; INF_E = "unknown"; INF_CAND = "-"
  if (path == "-" || path == "" || nc == 0) return
  best = 0; total = 0; split("", lab)
  for (c = 1; c <= nc; c++) {
    m = common(path, CP[c])
    if (m > best) { best = m; split("", lab); lab[CX[c]] = 1; total = 1 }
    else if (m == best && m > 0) { lab[CX[c]]++; total++ }
  }
  if (best == 0) return
  nl = 0; top = 0; cand = ""
  for (j = 1; j <= nx; j++) {
    e = ORDER[j]
    if (!(e in lab)) continue
    nl++; cand = cand (cand == "" ? "" : "/") LETTER[e]
    if (lab[e] > top) { top = lab[e]; only = e }
  }
  # 个别校准数据可能赶上线路切换：少数派不超过 2 条且不到一成时忽略
  if (nl > 1 && !(total - top <= 2 && (total - top) * 10 <= total)) { INF_E = "ambiguous"; INF_CAND = cand; return }
  INF_X = only; INF_E = "inferred"
  # 在内网段就离开了所有已确认的线路，可能走了没发现的出口，只算弱推断
  if (dv > 0) INF_E = "weak"
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
  S_L = "?"; best = 0; top = ""
  for (j = 1; j <= nx; j++) {
    e = ORDER[j]; c = CNT[key, p, e] + 0
    # 取读数最多的出口。次数一样多时不让默认出口占先：有一半的读数确凿地走了别的出口（回显或
    # 推断，弱推断不算），这个目标就是会被分流的，画成默认出口等于把它藏了起来
    if (c > best || (c == best && c > 0 && top == DEF && (((key, p, e) in DIR) || ((key, p, e) in INFD)))) {
      best = c; top = e; S_L = substr(LET, j, 1)
    }
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

# 一个 IP 连不连得上，看它所有的读数（两种解析方式、每一轮、复测都算）：
#   dead   TCP 一次都没连上，而且复测过
#   flaky  连上过，但多数时候连不上（至少两次，且不少于一半）
#   tls    TCP 连得上，握手至少两次不成，一次响应都没收到过
#   ok     连得上；-  没试过，或者连不上但还没复测，先不下结论
function ipstate(k3, f) {
  if (NTRY[k3] + 0 == 0) return "-"
  if (NOK[k3] + 0 == 0) return (NRT[k3] + 0 > 0) ? "dead" : "-"
  f = NTRY[k3] - NOK[k3]
  if (f >= 2 && f * 2 >= NTRY[k3]) return "flaky"
  if (NFULL[k3] + 0 == 0 && NTLS[k3] + 0 >= 2) return "tls"
  return "ok"
}

# 这个目标各个 IP 连不连得上：ok 都连得上，partial 有的连不上，dead 全连不上，- 没试过。
# 同时把逐 IP 的结果拼成“IP=出口:状态:连上次数/尝试次数:改道”写进 IP_MAP，
# 改道写成“位置@那一跳”，没有是 0。R_* 是连不上且改道、连得上但改道、握手不成、不稳定的 IP 数
function reach(key, j, ip, k3, nd, nl, r, s, dv) {
  nd = 0; nl = 0; s = ""; R_DD = 0; R_DL = 0; R_TLS = 0; R_FLAKY = 0
  for (j = 1; j <= NIP[key] + 0; j++) {
    ip = IPO[key, j]; k3 = key SUBSEP ip
    r = ipstate(k3)
    if (r == "dead") nd++
    else if (r != "-") nl++
    if (r == "tls") R_TLS++
    if (r == "flaky") R_FLAKY++
    dv = "0"
    if (k3 in IPDV) {
      dv = IPDV[k3] "@" IPDH[k3]
      if (r == "dead") R_DD++; else R_DL++
    }
    s = s (s == "" ? "" : " ") ip "=" (LETS[k3] == "" ? "?" : LETS[k3]) ":" r ":" (NOK[k3] + 0) "/" (NTRY[k3] + 0) ":" dv
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
  # 后面会把偶发的超时改成连得上，每轮明细里要看的是当时的读数
  RO[n] = RC[n]
  if ($7 != "-") known[$7] = 1
}

END {
  # 页面里出现已知出口，也算直接证据
  for (i = 1; i <= n; i++) {
    if (EX[i] != "-" || CD[i] == "-") continue
    m = split(CD[i], c, ",")
    for (j = 1; j <= m; j++) if (c[j] in known) { EX[i] = c[j]; MT[i] = "page"; break }
  }

  # 出口池：同一个中立回显连问几次（S 行），目标没变而出口不止一个，就是出口在轮换。这些出口
  # 合成一个来看，后面的判断都当它们是同一个出口；和它们同一个 /24 的出口多半也在池里。
  # 一个出口至少出现两次才算在轮换：只冒出来一次的可能是偶发的读数，那个出口也许正是
  # 别的目标的分流出口，不能因此并进默认出口
  nstab = 0
  for (i = 1; i <= n; i++) if (KD[i] == "S" && EX[i] != "-") STAB[EX[i]]++
  for (e in STAB) if (STAB[e] >= 2) nstab++
  if (nstab >= 2) {
    for (e in STAB) if (STAB[e] >= 2) POOL[e] = 1
    for (e in known) {
      if (e in POOL) continue
      for (pm in STAB) if (STAB[pm] >= 2 && net24(e) == net24(pm)) POOL[e] = 1
    }
    for (i = 1; i <= n; i++) if (EX[i] in POOL) PCNT[EX[i]]++
    canon = ""
    if (BASE in POOL) canon = BASE
    else for (e in POOL) if (canon == "" || PCNT[e] > PCNT[canon]) canon = e
    f = OUT "/pool.tsv"
    for (e in POOL) print e, PCNT[e] + 0, STAB[e] + 0, (e == canon ? 1 : 0) > f
    for (i = 1; i <= n; i++) if (EX[i] in POOL) EX[i] = canon
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
    if (tried == 0) { print KD[i], PS[i], CT[i], NM[i], IP[i], "exit" > fo; QX[KD[i], PS[i], NM[i], IP[i]] = 1 }
    else if (saw != "") {
      print e, NM[i], IP[i], saw > fu
      EX[i] = alt
      if (alt == "-") EV[i] = "unknown"
    }
  }

  # 连通：每个目标的每个 IP 试过几次、TCP 连上几次。ok 是收到了响应，tcp 只验证过 TCP，
  # tls 是 TCP 连上了但握手不成，dead 是 TCP 都连不上
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T" || RC[i] == "-" || IP[i] == "-") continue
    k3 = CT[i] SUBSEP NM[i] SUBSEP IP[i]
    NTRY[k3]++
    if (RC[i] != "dead") NOK[k3]++
    if (RC[i] == "ok") NFULL[k3]++
    if (RC[i] == "tls") NTLS[k3]++
    if (RD[i] ~ /^r/) { NRT[k3]++; continue }
    if (RC[i] == "dead") { if (!(k3 in DEADROW)) DEADROW[k3] = i; HASDEAD[CT[i], NM[i]] = 1 }
    else if (RC[i] == "tls" && !(k3 in TLSROW)) TLSROW[k3] = i
  }
  # 连不上、握手不成的读数先复测，同一个目标、同一个 IP 再试两次才下结论，偶发的超时不算拦截。
  # 同一个目标有 IP 连不上时，它其余的 IP 也再连两次，免得把碰巧连上的一次当成正常
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T" || RD[i] ~ /^r/ || RC[i] == "-" || IP[i] == "-") continue
    k3 = CT[i] SUBSEP NM[i] SUBSEP IP[i]
    if (NRT[k3] + 0 > 0 || (k3 in QD)) continue
    if (k3 in DEADROW) { why = "dead"; j = DEADROW[k3] }
    else if ((k3 in TLSROW) && NFULL[k3] + 0 == 0) { why = "tls"; j = TLSROW[k3] }
    else if ((CT[i], NM[i]) in HASDEAD) { why = "sib"; j = i }
    else continue
    QD[k3] = 1
    if (!((KD[j], PS[j], NM[j], IP[j]) in QX)) print KD[j], PS[j], CT[j], NM[j], IP[j], why > fo
  }
  # 这个 IP 别的时候连上过，这一次就按偶发的超时处理，照常用路由推断；一次都没连上的不推断
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T" || RC[i] != "dead") continue
    if (NOK[CT[i] SUBSEP NM[i] SUBSEP IP[i]] + 0 > 0) RC[i] = "tcp"
    else EV[i] = "noconn"
  }
  # 复测时才冒出来、同样只有一次的出口，也不算数
  for (i in GONE) { EX[i] = "-"; EV[i] = "unknown" }

  # 校准表：所有拿到回显的路径。上面改过读数，回显次数重新数。同时记下已确认的线路上
  # 每个位置出现过哪些跳，判断改道时用
  split("", SEENX)
  for (i = 1; i <= n; i++) {
    if (EV[i] != "direct") continue
    SEENX[EX[i]]++
    if (PT[i] == "-" || PT[i] == "") continue
    nc++; CP[nc] = PT[i]; CX[nc] = EX[i]
    m = split(PT[i], h, " ")
    for (j = 1; j <= m; j++) {
      if (h[j] == "?") continue
      KNOWN[j, h[j]] = 1; ALLN[j]++
      if (is_private(h[j])) PRIVN[j]++
    }
  }
  # 内网段有多深：过半的已确认路径在这一跳还是内网地址。改道只在它后一跳以内看，至少看前 3 跳
  INB = 0
  for (j = 1; j <= 8; j++) if ((j in ALLN) && PRIVN[j] * 2 >= ALLN[j]) INB = j
  DLIM = (INB + 1 > 3) ? INB + 1 : 3

  if (!(DEF in SEENX)) SEENX[DEF] = 0
  nx = 1; ORDER[1] = DEF
  for (e in SEENX) if (e != DEF) { nx++; ORDER[nx] = e }
  for (a = 2; a <= nx; a++)
    for (b = a + 1; b <= nx; b++)
      if (SEENX[ORDER[b]] > SEENX[ORDER[a]] || (SEENX[ORDER[b]] == SEENX[ORDER[a]] && ORDER[b] < ORDER[a])) { t = ORDER[a]; ORDER[a] = ORDER[b]; ORDER[b] = t }
  for (j = 1; j <= nx; j++) LETTER[ORDER[j]] = substr(LET, j, 1)

  # SNI 嗅探的读数（N 行）：把目标域名放进 SNI 发给中立回显，出口和平时不一样，就是路径上
  # 有设备按 TLS 域名分流；有应答却不是回显，是连接被转去了别的服务器
  sb = SNIBASE
  if (sb in POOL) sb = canon
  f = OUT "/sni.tsv"
  for (i = 1; i <= n; i++) {
    if (KD[i] != "N" || RD[i] ~ /^r/) continue
    if (EX[i] != "-") st = (sb == "" || EX[i] == sb) ? "same" : "changed"
    else st = (HC[i] + 0 > 0 && HC[i] + 0 != 429) ? "moved" : "failed"
    print NM[i], st, EX[i], ((EX[i] in LETTER) ? LETTER[EX[i]] : "-") > f
    if (st == "changed") { SNIL[CT[i], NM[i]] = LETTER[EX[i]]; SNIX[CT[i], NM[i]] = EX[i] }
  }

  # 没有回显的行用路由推断。连不上的 IP 不推断：路由走得通，流量也过不去。
  # 改道不管连不连得上都看：连不上又改了道，正说明是上游在处理这个 IP
  for (i = 1; i <= n; i++) {
    DV[i] = 0
    if (KD[i] == "T" && EV[i] != "direct") { DV[i] = divert(PT[i]); DH[i] = DIVH }
    if (EX[i] != "-" || MT[i] == "dns" || MT[i] == "dnsblock" || MT[i] == "fakeip" || RC[i] == "dead") continue
    infer(PT[i], DV[i])
    EV[i] = INF_E; CAND[i] = INF_CAND
    if (INF_X != "-") EX[i] = INF_X
  }

  # 逐 IP 汇总。同一种解析方式下，同一个域名的几个 IP 各自稳定地走了不同出口，是按 IP 分流；
  # 同一个 IP 前后走法不同不算，那是时间上的变化
  for (i = 1; i <= n; i++) {
    if (KD[i] != "T") continue
    k3 = CT[i] SUBSEP NM[i] SUBSEP IP[i]
    if (DV[i] > 0 && (!(k3 in IPDV) || DV[i] < IPDV[k3])) { IPDV[k3] = DV[i]; IPDH[k3] = DH[i] }
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
    # 这个 IP 在这种解析方式下走过非默认出口，哪怕只有一轮
    if (EX[i] != DEF) IPND[kp] = 1
  }
  for (kp in IPX) {
    if (IPX[kp] == "*") continue
    split(kp, q, SUBSEP)
    kq = q[1] SUBSEP q[2] SUBSEP q[4]
    if (!(kq in FIRSTX)) FIRSTX[kq] = IPX[kp]
    else if (FIRSTX[kq] != IPX[kp]) BYIP[q[1], q[2]] = 1
  }
  # 同一个 IP：加密 DNS 下走默认出口，明文查询之后换了出口，这才是确凿的 DNS 触发。上游的名单
  # 可能过一会儿才生效，系统 DNS 的头一轮还走默认出口、后一轮才换，也算
  for (kp in IPND) {
    split(kp, q, SUBSEP)
    if (q[4] != "P") continue
    ek = q[1] SUBSEP q[2] SUBSEP q[3] SUBSEP "E"
    if ((ek in IPX) && IPX[ek] == DEF) FLIP[q[1], q[2]] = 1
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
    # 换了 SNI 出口就变的目标：真实访问时带着的就是这个 SNI，走的是 SNI 看到的那个出口，
    # 钉 IP 借别的域名取的回显不算数。目标自己页面给的证据（Cloudflare 的回显、页面里的出口）
    # 本来就带着它的 SNI，以那个为准；被 DNS 屏蔽、fake-ip 的照旧
    if ((key in SNIX) && cls != "dnsblock" && cls != "fakeip" && pm != "cloudflare" && pm != "page" && px != SNIX[key]) {
      pl = SNIL[key]; px = SNIX[key]; pe = "direct"; pm = "sni"; cls = "sni"
      if (pt == 0) pt = 1
      pa = pt; po = "-"
    }
    # 第 19 列单独标按 IP 分流：系统 DNS 那一轮是 fake-ip 时，类别写的是 fakeip，这一条不能丢。
    # 第 20 列是确凿的 DNS 触发，第 21 到 24 列是连不上且改道、连得上但改道、握手不成、不稳定的 IP 数，
    # 第 25 列是换了 SNI 之后走的出口，没变是 -
    rc = reach(key)
    # DNS 触发只标在系统 DNS 下确实走了非默认出口的目标上：三轮里只有一轮换过出口的，照旧只在备注里写“另”
    print TC[t2], TN[t2], pl, px, pe, pm, pa, pt, po, el, ex, ee, em, cls, IPC[key] + 0, (key in CODE ? CODE[key] : "-"), rc, IP_MAP, \
      ((key in BYIP) ? 1 : 0), (((key in FLIP) && px != DEF) ? 1 : 0), R_DD, R_DL, R_TLS, R_FLAKY, ((key in SNIL) ? SNIL[key] : "-") > f
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
    print KD[i], PS[i], CT[i], NM[i], RD[i], IP[i], (EX[i] in LETTER ? LETTER[EX[i]] : "?"), EX[i], EV[i], MT[i], PT[i], RO[i] > f
  }
}
AWK
  touch "$WORK/targets.tsv" "$WORK/exits.tsv" "$WORK/detail.tsv"
  # 这几个文件只在有内容时才会被 awk 写，先清空，不留上一遍分析的结果
  : > "$WORK/once.tsv"
  : > "$WORK/unstable.tsv"
  : > "$WORK/pool.tsv"
  : > "$WORK/sni.tsv"
  local sni_base
  sni_base=$(awk -F'\t' '$1 == "sniff_base" { print $2; exit }' "$WORK/env.tsv" 2>/dev/null)
  awk -v BASE="$BASE_IP" -v SNIBASE="$sni_base" -v OUT="$WORK" -v F_ORDER="$WORK/targets.txt" -f "$WORK/analyze.awk" "$WORK/targets.txt" "$WORK/rows.tsv" ||
    die "分析结果时出错"
  # 分析出错不能当成“没有分流”
  [[ -s $WORK/exits.tsv && -s $WORK/targets.tsv ]] || die "分析结果时出错：没有出口数据"
}

# ---------- 输出 ----------

report_text() {
  local depth
  color_depth 1
  depth=$COLOR_DEPTH
  cat > "$WORK/report.awk" <<'AWK'
BEGIN {
  FS = "\t"; E = sprintf("%c", 27); W = 76
  # 256 色终端用柔和的色号，其余退回 8 色；不用颜色时这些全是空串
  if (DEPTH == 256) {
    R = E "[0m"; B = E "[1m"; DIM = E "[38;5;245m"; FNT = E "[38;5;240m"
    GRN = E "[38;5;78m"; YEL = E "[38;5;221m"; RED = E "[38;5;203m"; MAG = E "[38;5;177m"; CYN = E "[38;5;80m"
    split("78 215 177 75 221 80 211 250", XC, " ")
  } else if (DEPTH == 8) {
    R = E "[0m"; B = E "[1m"; DIM = E "[2m"; FNT = E "[2m"
    GRN = E "[32m"; YEL = E "[33m"; RED = E "[31m"; MAG = E "[35m"; CYN = E "[36m"
    split("2 3 5 4 6 7 1 7", XC, " ")
  }
  # 字标和渐变的色号是 bash 传进来的
  LOGO[1] = LOGO1; LOGO[2] = LOGO2; LOGO[3] = LOGO3
  NRAMP = split(RAMPS, RAMP, " ")
  LOGOW = dwidth(LOGO1)
}

# 显示宽度。C locale 下 length 数字节：· × 这类 2 字节字符占 1 格；3 字节里 E2 开头的
# （框线、方块、✓ ✗）占 1 格，汉字和全角标点占 2 格
function dwidth(s, t, hb, n2, e2) {
  t = s; hb = gsub(/[^\001-\177]/, "", t)
  if (hb == 0) return length(s)
  t = s; n2 = gsub(/\302|\303/, "", t)
  t = s; e2 = gsub(/\342/, "", t)
  return length(s) - hb + n2 + e2 + (int((hb - 2 * n2) / 3) - e2) * 2
}
# 去掉颜色码之后的显示宽度
function vis(s, t) { t = s; gsub(/\033\[[0-9;]*m/, "", t); return dwidth(t) }
function spc(n) { return n > 0 ? sprintf("%" n "s", "") : "" }
function pad(s, w) { return s spc(w - vis(s)) }
function padl(s, w) { return spc(w - vis(s)) s }
function rep(ch, n, s, i) { s = ""; for (i = 1; i <= n; i++) s = s ch; return s }
# 取下一个字符，写进 CH（字符）和 CW（占几格），返回它之后的位置
function nextch(s, i, c) {
  c = substr(s, i, 1)
  if (c ~ /[\001-\177]/) { CH = c; CW = 1; return i + 1 }
  if (c ~ /[\300-\337]/) { CH = substr(s, i, 2); CW = 1; return i + 2 }
  if (c ~ /[\340-\357]/) { CH = substr(s, i, 3); CW = (c ~ /\342/) ? 1 : 2; return i + 3 }
  CH = substr(s, i, 4); CW = 2; return i + 4
}
# 太长就截断，末尾补省略号
function fit(s, w, i, out, tot) {
  if (dwidth(s) <= w) return s
  out = ""; tot = 0; i = 1
  while (i <= length(s)) {
    i = nextch(s, i)
    if (tot + CW > w - 1) break
    out = out CH; tot += CW
  }
  return out "…"
}
# 按显示宽度折行，结果在 WL[1..WLN]。只在汉字、全角标点和空格处断，不拆开英文单词、域名和 IP
function wraptext(s, w, i, line, lw, word, ww, pl, lt, ltw) {
  WLN = 0; line = ""; lw = 0; word = ""; ww = 0; i = 1; pl = ""; lt = ""; ltw = 0
  while (i <= length(s)) {
    i = nextch(s, i)
    if (CW == 1 && CH != " ") { word = word CH; ww++; continue }
    if (word != "") {
      if (lw + ww > w && line != "") { WL[++WLN] = line; line = ""; lw = 0 }
      # pl 是放下这个词之前的那一行，lt 是这个词：标点放不下时要把它一起带走
      pl = line; lt = word; ltw = ww
      line = line word; lw += ww; word = ""; ww = 0
    }
    if (CH == " ") { if (lw > 0 && lw < w) { line = line " "; lw++ } continue }
    if (lw + CW > w && line != "") {
      # 行首不放标点：把前一个词（或前一个字）一起带到下一行
      if (CH ~ /^(，|。|：|；|、|）|】)$/ && pl != "") { WL[++WLN] = pl; line = lt; lw = ltw }
      else { WL[++WLN] = line; line = ""; lw = 0 }
    }
    pl = line; lt = CH; ltw = CW
    line = line CH; lw += CW
  }
  if (word != "") {
    if (lw + ww > w && line != "") { WL[++WLN] = line; line = "" }
    line = line word
  }
  if (line != "") WL[++WLN] = line
}
# 把 a[1..n] 排成几行，每行不超过 w 格，最多 maxl 行，放不下的收成“等 N 个”。结果在 FL[1..FLN]
function flow(a, n, w, maxl, sp, i, line, s, tail, st, it) {
  FLN = 0; line = ""
  for (i = 1; i <= n; i++) {
    it = (vis(a[i]) > w) ? fit(a[i], w) : a[i]
    s = (line == "" ? "" : line sp) it
    if (line != "" && vis(s) > w) { FL[++FLN] = line; line = it; st[FLN + 1] = i }
    else { if (line == "") st[FLN + 1] = i; line = s }
  }
  if (line != "") FL[++FLN] = line
  if (FLN <= maxl) return
  tail = " 等 " n " 个"; line = ""
  for (i = st[maxl]; i <= n; i++) {
    it = (vis(a[i]) > w - vis(tail)) ? fit(a[i], w - vis(tail)) : a[i]
    s = (line == "" ? "" : line sp) it
    if (line != "" && vis(s) + vis(tail) > w) break
    line = s
  }
  FLN = maxl; FL[maxl] = line tail
}
# 顿号分隔的列表太长就截断：a、b、c 等 N 个
function clip(s, w, a, n, i, out) {
  n = split(s, a, "、"); out = ""
  for (i = 1; i <= n; i++) {
    if (out != "" && dwidth(out "、" a[i]) > w) return out " 等 " n " 个"
    out = out (out == "" ? "" : "、") a[i]
  }
  return out
}

# 分享用的图片把出口 IP 打码（--no-mask 时不打）
function mask(ip, a) {
  split(ip, a, ".")
  return a[1] "." a[2] ".*.*"
}
function maskall(s, out) {
  if (!SHARE || !MASK) return s
  out = ""
  while (match(s, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
    out = out substr(s, 1, RSTART - 1) mask(substr(s, RSTART, RLENGTH))
    s = substr(s, RSTART + RLENGTH)
  }
  return out s
}
# 字标：256 色时从青到紫逐列渐变，色号按列数平均铺开
function logo(i, s, p, col, out, ch) {
  s = LOGO[i]
  if (DEPTH == 0) return s
  if (DEPTH == 8) return CYN B s R
  out = ""; p = 1; col = 0
  while (p <= length(s)) {
    if (substr(s, p, 1) == " ") { ch = " "; p++ } else { ch = substr(s, p, 3); p += 3 }
    out = out E "[38;5;" RAMP[int(col * NRAMP / LOGOW) + 1] "m" ch
    col++
  }
  return out R
}
# 出口字母的前景色。? 和 - 是未知，X 是被 DNS 屏蔽，! 是连不上
function lfg(l, j) {
  if (DEPTH == 0) return ""
  if (l == "?" || l == "-" || l == "") return DIM
  if (l == "X" || l == "!") return RED
  j = (l in LIX) ? LIX[l] : 8
  if (j > 8) j = 8
  return DEPTH == 256 ? E "[38;5;" XC[j] "m" : E "[3" XC[j] "m"
}
function lc(l, s) { return DEPTH == 0 ? s : lfg(l) s R }
# “A/B” 这样的几个字母，各用各的颜色
function lcs(s, a, n, i, out) {
  n = split(s, a, "/"); out = ""
  for (i = 1; i <= n; i++) out = out (i > 1 ? "/" : "") lc(a[i], a[i])
  return out
}
# 出口字母做成小色块，没有颜色时是 [A]
function badge(l, j) {
  if (DEPTH == 0) return "[" l "]"
  j = (l in LIX) ? LIX[l] : 8
  if (j > 8) j = 8
  if (DEPTH == 256) return E "[48;5;" XC[j] "m" E "[38;5;16m" B " " l " " R
  return E "[4" XC[j] "m" E "[30m " l " " R
}
# 结论做成一个色块，没有颜色时是【…】
function pill(kind, s, bg) {
  if (DEPTH == 0) return "【" s "】"
  if (DEPTH == 256) {
    bg = (kind == "bad") ? 203 : (kind == "warn" ? 221 : 78)
    return E "[48;5;" bg "m" E "[38;5;16m" B " " s " " R
  }
  bg = (kind == "bad") ? 1 : (kind == "warn" ? 3 : 2)
  return E "[4" bg "m" E "[30m " s " " R
}
function icon(st) {
  if (st == "ok") return GRN "✓" R
  if (st == "bad") return RED "✗" R
  if (st == "warn") return YEL "!" R
  if (st == "ask") return DIM "?" R
  return DIM "·" R
}
function tone(st) { return st == "ok" ? GRN : (st == "bad" ? RED : (st == "warn" ? YEL : DIM)) }

# 分区标题：标题 ─────── 说明
function sec(title, tip, n) {
  n = W - dwidth(title) - 1 - (tip == "" ? 0 : dwidth(tip) + 1)
  print ""
  print "  " B title R " " FNT rep("─", n) R (tip == "" ? "" : " " DIM tip R)
}
# 要点：图标、标签、说明。说明太长就折行，续行和说明对齐
function note(st, tag, text, i) {
  wraptext(text, W - 12)
  print "  " icon(st) " " tone(st) pad(tag, 9) R " " WL[1]
  for (i = 2; i <= WLN; i++) print spc(14) WL[i]
}
function more(text, i) {
  wraptext(text, W - 12)
  for (i = 1; i <= WLN; i++) print spc(14) DIM WL[i] R
}
# 检查项：名称、图标、结果
function chk(key, st, text, i) {
  wraptext(text, W - 13)
  print "  " pad(key, 10) " " icon(st) " " WL[1]
  for (i = 2; i <= WLN; i++) print spc(15) WL[i]
}
function chkmore(text, i) {
  wraptext(text, W - 13)
  for (i = 1; i <= WLN; i++) print spc(15) DIM WL[i] R
}
function term(w, s, i) {
  wraptext(s, W - 10)
  print "  " pad(w, 10) DIM WL[1] R
  for (i = 2; i <= WLN; i++) print spc(12) DIM WL[i] R
}
# 概览里的小卡片
function tile_top(title) { return FNT "╭ " R B title R FNT " " rep("─", 14 - dwidth(title)) "╮" R }
function tile_mid(s) { return FNT "│" R " " pad(s, 15) FNT "│" R }
function tile_bot() { return FNT "╰" rep("─", 16) "╯" R }
function minibar(v, mx, col, n) {
  if (v <= 0 || mx <= 0) return ""
  n = int(v * 5 / mx + 0.999)
  if (n < 1) n = 1
  return col rep("■", n) R
}

# 分类概览的一条：每格一个目标。有颜色时是按出口上色的方块，没有颜色时直接写出口字母
function cells(st, n) {
  if (n <= 0) return ""
  if (DEPTH == 0) return rep(st == "X" ? "x" : st, n)
  if (st == "?") return DIM rep("□", n) R
  if (st == "X") return RED rep("×", n) R
  return lfg(st) rep("■", n) R
}
# 弱推断：出口多半是它，但没有确凿的证据
function wcells(st, n) {
  if (n <= 0) return ""
  if (DEPTH == 0) return rep(tolower(st), n)
  return lfg(st) rep("□", n) R
}
function bar(k, enc, j, st, v, w, n, nw, s) {
  s = ""; BARW = 0; BART = 0
  for (j = 1; j <= nx + 3; j++) {
    st = (j <= nx) ? XL[j] : (j == nx + 1 ? "X" : (j == nx + 2 ? "!" : "?"))
    v = (enc ? ME[k, st] : MP[k, st]) + 0
    if (v == 0) continue
    w = (j <= nx) ? (enc ? MEW[k, st] : MPW[k, st]) + 0 : 0
    n = (BSCALE < 1) ? int(v * BSCALE + 0.5) : v
    if (n < 1) n = 1
    nw = (BSCALE < 1) ? int(w * BSCALE + 0.5) : w
    if (w > 0 && nw < 1) nw = 1
    if (nw > n) nw = n
    s = s cells(st, n - nw) wcells(st, nw); BARW += n; BART += v
  }
  return s
}

# 逐 IP 按网段汇总：每个 /24 连上几次、试了几次、走哪个出口、有没有改道；同一个 /16 里几段
# 结果都一样就并成一行
function nets(t, m, i, j, na, ipa, ipb, ipc, a, q, n24, n16, s, rk, r, st) {
  nn = 0; nrow = 0
  for (t = 1; t <= nt; t++) {
    if (!SHOW[t]) continue
    m = split(IPM[t], ipa, " ")
    for (i = 1; i <= m; i++) {
      split(ipa[i], ipb, "="); split(ipb[2], ipc, ":")
      n24 = ipb[1]; sub(/\.[0-9]+$/, "", n24)
      if (!(n24 in NI)) { nn++; N24[nn] = n24 }
      NI[n24]++
      st = ipc[2]
      split(ipc[3], q, "/"); NOKS[n24] += q[1]; NTRS[n24] += q[2]
      if (st == "dead") ND[n24]++
      else {
        if (st == "flaky") NFK24[n24]++
        if (st == "tls") NTL24[n24]++
        if (st == "-") NU24[n24]++
        na = split(ipc[1], a, "/")
        for (j = 1; j <= na; j++)
          if (a[j] != "?" && a[j] != "" && index("/" NL[n24] "/", "/" a[j] "/") == 0) NL[n24] = NL[n24] (NL[n24] == "" ? "" : "/") a[j]
      }
      if (ipc[4] != "0" && ipc[4] != "") {
        split(ipc[4], q, "@")
        if (!(n24 in NDV) || q[1] + 0 < NDV[n24]) { NDV[n24] = q[1] + 0; NDH[n24] = q[2] }
      }
      NT[n24, t] = 1
    }
  }
  for (i = 1; i <= nn; i++) {
    n24 = N24[i]
    if (ND[n24] + 0 == NI[n24]) s = "dead"
    else if (ND[n24] + 0 > 0) s = "part:" NL[n24]
    else if (NFK24[n24] + 0 > 0) s = "flaky:" NL[n24]
    else if (NTL24[n24] + 0 == NI[n24]) s = "tls:" NL[n24]
    else if (NU24[n24] + 0 == NI[n24]) s = "untested:" NL[n24]
    else s = "ok:" NL[n24]
    SG[n24] = s
    s = s "|" ((n24 in NDV) ? NDV[n24] "@" NDH[n24] : "")
    n16 = n24; sub(/\.[0-9]+$/, "", n16)
    if (!(n16 in S16)) S16[n16] = s
    else if (S16[n16] != s) S16[n16] = "*"
    C16[n16]++
  }
  for (i = 1; i <= nn; i++) {
    n24 = N24[i]; n16 = n24; sub(/\.[0-9]+$/, "", n16)
    rk = (S16[n16] != "*" && C16[n16] > 1) ? n16 ".x.x" : n24 ".0/24"
    if (!(rk in RIX)) { nrow++; RIX[rk] = nrow; RLAB[nrow] = rk; RSIG[nrow] = SG[n24] }
    r = RIX[rk]
    ROK[r] += NOKS[n24]; RTR[r] += NTRS[n24]
    if ((n24 in NDV) && (!(r in RDV) || NDV[n24] < RDV[r])) { RDV[r] = NDV[n24]; RDH[r] = NDH[n24] }
    for (t = 1; t <= nt; t++)
      if (((n24, t) in NT) && !((r, t) in ROWT)) { ROWT[r, t] = 1; RTC[r]++; if (RTC[r] == 1) RT1[r] = TN[t]; RTN[r] = RTN[r] (RTN[r] == "" ? "" : "、") TN[t] }
  }
  deadnets = ""; ndivnet = 0; ndivdead = 0; divhops = ""; nhop = 0
  for (r = 1; r <= nrow; r++) {
    if (RSIG[r] == "dead") deadnets = deadnets (deadnets == "" ? "" : "、") RLAB[r]
    if (!(r in RDV)) continue
    ndivnet++
    if (RSIG[r] == "dead") ndivdead++
    if (divpos == "" || RDV[r] < divpos) divpos = RDV[r]
    # 改道后的下一跳去重，最多列两个
    if (!(RDH[r] in HOPSEEN)) { HOPSEEN[RDH[r]] = 1; nhop++; if (nhop <= 2) divhops = divhops (divhops == "" ? "" : "、") RDH[r] }
  }
  if (nhop > 2) divhops = divhops " 等 " nhop " 处"
}
function mname(m) {
  if (m == "cloudflare") return "Cloudflare"
  if (m == "akamai") return "Akamai"
  if (m == "fastly") return "Fastly"
  if (m == "cloudfront") return "CloudFront"
  if (m == "google") return "Google"
  if (m == "meta") return "Meta"
  if (m == "page") return "页面"
  if (m == "sni") return "SNI"
  return m
}
function evid(e, m) {
  if (e == "direct") return "直接·" mname(m)
  if (e == "inferred") return "推断"
  if (e == "weak") return "弱推断"
  if (e == "ambiguous") return "不确定 " m
  if (e == "fakeip") return "fake-ip"
  if (e == "dnsblock") return "DNS 不给地址"
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
# 这个目标要不要单独列出来：走了非默认出口、证据不硬、连通有问题的才列，其余的折成一行
function notable(t) {
  if (KC[t] != "none") return 1
  if (PE[t] != "direct" && PE[t] != "inferred") return 1
  if (EL[t] != "-" && EE[t] != "direct" && EE[t] != "inferred") return 1
  if (SHOW[t] || SNX[t] != "-") return 1
  if (PO[t] != "-" || PA[t] + 0 < PT[t] + 0) return 1
  return 0
}
# 明细里的一行
function row(t, sysc, encc, ev, rm, o) {
  if (PL[t] == "X") sysc = RED (down ? "× 查不到" : "× 屏蔽") R
  else if (PE[t] == "fakeip") sysc = YEL "fake-ip" R
  else if (PL[t] == "?" && PE[t] == "noconn") sysc = RED "! 不通" R
  else if (PL[t] == "?") sysc = DIM "?" R
  else sysc = lc(PL[t], B PL[t]) (PE[t] == "weak" ? DIM "?" R : "") ((PA[t] + 0 < PT[t] + 0) ? DIM " " PA[t] "/" PT[t] R : "")
  if (EL[t] == "-") encc = DIM "-" R
  else if (EL[t] == "?" && EE[t] == "noconn") encc = RED "!" R
  else if (EL[t] == "?") encc = DIM "?" R
  else encc = lc(EL[t], B EL[t]) (EE[t] == "weak" ? DIM "?" R : "")
  if (PX[t] != "-") ev = evid(PE[t], PM[t])
  else if (EX[t] != "-") ev = evid(EE[t], EM[t])
  else ev = evid(PE[t], PM[t])
  if (PE[t] == "weak" || PE[t] == "ambiguous" || ev == "未知" || ev == "解析失败" || ev == "连不上") ev = DIM ev R
  NRM = 0
  if (KC[t] == "dns") RMK[++NRM] = YEL (FLP[t] ? "DNS触发" : "DNS相关") R
  else if (KC[t] == "static") RMK[++NRM] = MAG "名单内" R
  else if (KC[t] == "mixed") RMK[++NRM] = DIM "解析不同" R
  if (BI[t]) RMK[++NRM] = MAG "按IP" R
  if (KC[t] == "sni") RMK[++NRM] = MAG "按SNI" R
  else if (SNX[t] != "-") RMK[++NRM] = MAG "SNI→" SNX[t] R
  if (RCH[t] == "partial") RMK[++NRM] = YEL "部分不通" R
  else if (RCH[t] == "dead" && PL[t] != "?") RMK[++NRM] = RED "IP不通" R
  if (NDD[t] + NDL[t] > 0) RMK[++NRM] = YEL "改道" R
  if (NTL[t] > 0) RMK[++NRM] = DIM "TLS不通" R
  if (NFK[t] > 0) RMK[++NRM] = DIM "不稳定" R
  if (PO[t] != "-") { o = PO[t]; gsub(/:/, "×", o); RMK[++NRM] = DIM "另 " o R }
  rm = ""
  for (o = 1; o <= NRM; o++) {
    if (rm != "" && vis(rm) + 2 + vis(RMK[o]) > 14) { rm = rm DIM "…" R; break }
    rm = rm (rm == "" ? "" : "  ") RMK[o]
  }
  print "    " pad(fit(TN[t], 29), 30) pad(sysc, 8) pad(encc, 5) pad(ev, 17) rm
}

FILENAME == F_CATS { split($0, a, " "); if (!(a[1] in CL)) { nc++; CO[nc] = a[1]; CL[a[1]] = a[2] } next }
FILENAME == F_ENV { ENVV[$1] = $2; next }
FILENAME == F_EXITS {
  nx++; XL[nx] = $1; XI[nx] = $2; XS[nx] = $3; XDEF[nx] = $4; XSIG[nx] = $5
  XORG[nx] = $6; XCC[nx] = $7; XCITY[nx] = $8; XHOST[nx] = $9; XKIND[nx] = $10
  IDX[$2] = nx; LIX[$1] = nx; next
}
FILENAME == F_TARGETS {
  nt++; TC[nt] = $1; TN[nt] = $2; PL[nt] = $3; PX[nt] = $4; PE[nt] = $5; PM[nt] = $6; PA[nt] = $7; PT[nt] = $8; PO[nt] = $9
  EL[nt] = $10; EX[nt] = $11; EE[nt] = $12; EM[nt] = $13; KC[nt] = $14; IC[nt] = $15; HC[nt] = $16
  RCH[nt] = $17; IPM[nt] = $18; BI[nt] = $19 + 0; FLP[nt] = $20 + 0
  NDD[nt] = $21 + 0; NDL[nt] = $22 + 0; NTL[nt] = $23 + 0; NFK[nt] = $24 + 0
  SNX[nt] = ($25 == "" ? "-" : $25)
  if (!($1 in CL)) { nc++; CO[nc] = $1; CL[$1] = $1 }
  CCOUNT[$1]++
  # 概览里这个目标占的那一格：出口字母，X 被 DNS 屏蔽，! 连不上，? 未知
  st = $3
  if (st == "?" && $5 == "noconn") st = "!"
  MP[$1, st]++
  if ($5 == "weak") { MPW[$1, st]++; HASW = 1 }
  if ($10 != "-") {
    HASE = 1; st = $10
    if (st == "?" && $12 == "noconn") st = "!"
    ME[$1, st]++
    if ($12 == "weak") { MEW[$1, st]++; HASW = 1 }
  }
  if ($3 == "X") { nxb++; BN[nxb] = $2 }
  if ($14 == "dns") { if ($20 + 0) nflip++; else nrel++ }
  if ($14 == "static") nstatic++
  if ($14 == "split") nsplit++
  if ($14 == "mixed") nmixed++
  if (BI[nt]) nbyip++
  if ($17 == "partial") { npart++; part = part (part == "" ? "" : "、") $2 }
  if ($17 == "dead") {
    if ($21 + 0 > 0) { nupdead++; updead = updead (updead == "" ? "" : "、") $2 }
    else { nalldead++; alldead = alldead (alldead == "" ? "" : "、") $2 }
    # judge 也把它算进“解析失败或连不上”，结论里不重复说
    if ($4 == "-" && ($5 == "dns" || $5 == "noconn")) ndeadover++
  }
  if ($23 + 0 > 0 && $17 != "partial" && $17 != "dead") { ntlst++; tlsn = tlsn (tlsn == "" ? "" : "、") $2 }
  if ($24 + 0 > 0) nflk++
  SHOW[nt] = (BI[nt] || $17 == "partial" || $17 == "dead" || $21 + $22 + $23 + $24 > 0) ? 1 : 0
  if (SHOW[nt]) nipshow++
  # 靠路由推断到各个出口的目标数，一个目标只算一次
  if ($5 == "inferred") INFT[$4]++
  else if ($12 == "inferred") INFT[$11]++
  next
}
FILENAME == F_TRIGGER { ntr++; GN[ntr] = $2; GI[ntr] = $3; GB[ntr] = $4; GA[ntr] = $5; GW[ntr] = $6; next }
FILENAME == F_SNI { nsn++; SN[nsn] = $1; SS[nsn] = $2; SR[nsn] = $3; SLT[nsn] = $4; next }
FILENAME == F_DNSQ { nq++; QN[nq] = $1; QV[nq] = $2; next }
FILENAME == F_UNSTABLE { nun++; UE[nun] = $1; UN[nun] = $2; next }
FILENAME == F_POOL { np++; PIP[np] = $1; PCN[np] = $2; next }
FILENAME == F_DETAIL { ndt++; DL[ndt] = $0; next }

END {
  V = ENVV["verdict"]
  nblock = ENVV["n_dnsblock"] + 0; nfake = ENVV["n_fakeip"] + 0; nweak = ENVV["n_weak"] + 0
  nunk = ENVV["n_unknown"] + 0; ndead = ENVV["n_unreachable"] + 0
  nopen = nunk + nweak + nfake
  hijack = (ENVV["dns_hijack"] == 1)
  down = (ENVV["sysdns_down"] == 1)
  proxy = (ENVV["proxy"] != "-" && ENVV["proxy"] != "")
  PH = proxy ? "节点 DNS" : "系统 DNS"
  nets()
  # 运营商查不到的出口不参与比较，不能算作“相同”或“不同”
  nother = 0; norg = 0
  for (j = 1; j <= nx; j++) if (XORG[j] == "-") norg++
  if (XORG[1] != "-")
    for (j = 2; j <= nx; j++) if (XORG[j] != "-" && asn(XORG[j]) != asn(XORG[1])) nother++
  tested = 0; fired = 0; nmis = 0; nnoecho = 0; nnofar = 0
  for (i = 1; i <= ntr; i++) {
    if (GB[i] == "-") { if (GW[i] == "mismatch") nmis++; else if (GW[i] == "nofar") nnofar++; else nnoecho++; continue }
    tested++
    if (GB[i] != GA[i]) fired++
  }
  # SNI 嗅探：回显服务不看 SNI，谁来问都照常应答。出口变了，是上游按 SNI 换了线路；有应答却不是
  # 回显，是连接被按 SNI 转去了别的服务器。完全连不上的可能只是网络抖动，429 是回显服务在限流，都不下结论
  changed = ""; nc2 = 0; moved = ""; nmv = 0; nsf = 0
  for (i = 1; i <= nsn; i++) {
    if (SS[i] == "changed") { nc2++; changed = changed (changed == "" ? "" : "、") SN[i] " → " SLT[i] }
    else if (SS[i] == "moved") { nmv++; moved = moved (moved == "" ? "" : "、") SN[i] }
    else if (SS[i] == "failed") nsf++
  }

  # ---------- 抬头 ----------
  el = ENVV["elapsed"] + 0
  line = nt " 个目标"
  if (ENVV["region"] != "none" && ENVV["region"] != "") line = line " · 地区 " ENVV["region"]
  line = line " · 用时 " (el >= 60 ? int(el / 60) " 分 " (el % 60) " 秒" : el " 秒")
  print ""
  print "  " logo(1) "   " B "分流检测报告" R "  " DIM "v" ENVV["version"] (proxy ? " · 经代理" : "") R
  print "  " logo(2) "   " (SHARE ? DIM ENVV["time"] R : fit(ENVV["host"], 22) DIM " · " ENVV["time"] R)
  print "  " logo(3) "   " DIM line R
  print ""

  # ---------- 结论。判断在 judge 里做，这里只管怎么说 ----------
  if (V == "split") {
    kind = "bad"; label = "有分流"
    head = "发现 " nx " 个出口"
    if (nother > 0) head = head "，其中 " nother " 个不是默认运营商"
    else if (norg == 0) head = head "，都属于默认运营商"
    else head = head "，运营商信息没查全"
  } else if (V == "dns_tampered") {
    kind = "warn"; label = "DNS 异常"
    head = "出口没有分流，但 DNS 被动了手脚"
    if (npart + nupdead > 0) head = head "，还有 " (npart + nupdead) " 个目标被按 IP 拦"
  } else if (V == "blocked") {
    kind = "warn"; label = "IP 拦截"
    head = "出口没有分流，但有目标连不上，像是被按 IP 拦截"
  } else if (V == "inconclusive") {
    # 证据不足不等于没有分流
    kind = "warn"; label = "证据不足"
    if (down) head = "没发现第二个出口，但系统 DNS 用不了，只测了加密 DNS，不能排除分流"
    else head = "没发现第二个出口，但 " nopen "/" nt " 个目标证据不足，不能排除分流"
  } else {
    kind = "ok"; label = "无分流"
    head = "未发现分流，能确认的目标都从 " maskall(XI[1]) " 出去"
  }
  print "  " pill(kind, label) " " B head R
  print ""

  # ---------- 概览：出口、DNS、连通、证据各一张小卡片 ----------
  if (np > 1 && nx == 1) { T1[1] = YEL "~ 出口池" R; T2[1] = np " 个 IP 轮换"; T3[1] = DIM "未见按目标分流" R }
  else if (nx >= 2) {
    T1[1] = RED "✗ 有分流" R; T2[1] = nx " 个出口"
    T3[1] = DIM (nother > 0 ? nother " 个不同运营商" : (norg == 0 ? "同一个运营商" : "运营商没查全")) R
  } else if (nopen > 0) { T1[1] = YEL "? 未见分流" R; T2[1] = "1 个出口"; T3[1] = DIM nopen " 个待确认" R }
  else { T1[1] = GRN "✓ 无分流" R; T2[1] = "1 个出口"; T3[1] = DIM maskall(XI[1]) R }

  if (proxy) { T1[2] = DIM "- 由节点解析" R; T2[2] = DIM "经代理时不测" R; T3[2] = "" }
  else {
    if (nblock > 0 && !down) T1[2] = RED "✗ 屏蔽 " nblock " 个" R
    else if (down) T1[2] = YEL "! 系统 DNS 故障" R
    else if (hijack) T1[2] = YEL "! 53 被劫持" R
    else if (nfake > 0) T1[2] = YEL "! fake-ip" R
    else if (!("dns_hijack" in ENVV) && ntr == 0) T1[2] = DIM "- 未检测" R
    else T1[2] = GRN "✓ 正常" R
    if (!("dns_hijack" in ENVV)) T2[2] = DIM "53 端口没测" R
    else T2[2] = hijack ? "53 端口被劫持" : DIM "53 端口正常" R
    if (ENVV["trigger"] == "no-dig" || ntr == 0) T3[2] = DIM "触发测试没做" R
    else if (tested == 0) T3[2] = DIM "触发测试测不了" R
    else if (fired > 0) T3[2] = YEL "DNS 触发 " fired "/" tested R
    else T3[2] = DIM "未见 DNS 触发" R
  }

  nblk = npart + nupdead
  if (nblk > 0) {
    T1[3] = RED "✗ 按 IP 拦截" R
    T2[3] = (npart > 0) ? npart " 个部分不通" : nupdead " 个全不通"
    T3[3] = (npart > 0 && nupdead + nalldead > 0) ? (nupdead + nalldead) " 个全不通" : (ndivnet > 0 ? DIM ndivnet " 个网段改道" R : "")
  } else if (nalldead > 0) { T1[3] = YEL "? " nalldead " 个连不上" R; T2[3] = DIM "原因不明" R; T3[3] = "" }
  else { T1[3] = GRN "✓ 正常" R; T2[3] = DIM "没有 IP 被拦" R; T3[3] = "" }

  d1 = ENVV["n_direct"] + 0; d2 = ENVV["n_inferred"] + 0; d3 = nopen; mx = d1
  if (d2 > mx) mx = d2
  if (d3 > mx) mx = d3
  T1[4] = pad("直接", 5) padl(d1, 3) " " minibar(d1, mx, GRN)
  T2[4] = pad("推断", 5) padl(d2, 3) " " minibar(d2, mx, CYN)
  T3[4] = pad("存疑", 5) padl(d3, 3) " " minibar(d3, mx, YEL)

  print "  " tile_top("出口") " " tile_top("DNS") " " tile_top("连通") " " tile_top("证据")
  print "  " tile_mid(T1[1]) " " tile_mid(T1[2]) " " tile_mid(T1[3]) " " tile_mid(T1[4])
  print "  " tile_mid(T2[1]) " " tile_mid(T2[2]) " " tile_mid(T2[3]) " " tile_mid(T2[4])
  print "  " tile_mid(T3[1]) " " tile_mid(T3[2]) " " tile_mid(T3[3]) " " tile_mid(T3[4])
  print "  " tile_bot() " " tile_bot() " " tile_bot() " " tile_bot()

  # ---------- 要点 ----------
  NOTES = 0
  if (ENVV["intercept"] == "host") {
    if (!NOTES++) print ""
    note("warn", "透明代理", "有透明代理按 HTTP 的 Host 改写目的地，钉 IP 的探测不可靠")
    more("这时测到的是代理规则的分流，不是线路本身的。要测线路先关掉它，要测它的分流用 -x 指向它的本地端口")
  }
  if (nc2 + nmv > 0) {
    if (!NOTES++) print ""
    if (nc2 > 0) note("warn", "SNI 分流", nc2 "/" nsn " 个域名换了 SNI 出口就变：" (proxy ? "节点" : "路径上有设备") "按 TLS 域名分流")
    else note("warn", "SNI 分流", nmv "/" nsn " 个域名的连接被按 TLS 域名转去了别处")
    if (nc2 > 0) more("这些域名真实访问时带的就是这个 SNI，下面按 SNI 看到的出口算")
    else more("连接被改写了目的地，钉到 IP 上的探测测到的不是那个 IP")
  }
  if (nbyip > 0) { if (!NOTES++) print ""; note("warn", "按 IP", nbyip " 个目标按 IP 分流：同一个域名的几个 IP 走了不同出口") }
  if (nflip > 0) { if (!NOTES++) print ""; note("warn", "DNS 触发", nflip " 个目标由明文 DNS 触发：同一个 IP，明文查询之后换了出口") }
  if (nrel > 0) {
    if (!NOTES++) print ""
    note("warn", "DNS 相关", nrel " 个目标系统 DNS 解析到的 IP 走分流，加密 DNS 解析到的走默认出口")
    more("两边 IP 不同，分不清是明文查询触发的，还是那个 IP 本来就在名单里")
  }
  if (nstatic > 0) { if (!NOTES++) print ""; note("warn", "名单内", nstatic " 个目标在分流名单内：加密 DNS 下也走分流") }
  if (nsplit > 0) { if (!NOTES++) print ""; note("warn", "非默认", nsplit " 个目标走了非默认出口") }
  if (nmixed > 0) { if (!NOTES++) print ""; note("info", "解析不同", nmixed " 个目标系统 DNS 走默认出口、加密 DNS 反而走分流"); more("通常是两边解析到的 IP 不同") }
  if (nblock > 0 && !down) {
    if (!NOTES++) print ""
    note("bad", "DNS 屏蔽", nblock " 个目标被 DNS 屏蔽：系统 DNS 不给真实地址，加密 DNS 正常")
  }
  if (down) { if (!NOTES++) print ""; note("warn", "系统 DNS", "系统 DNS 对 " nblock " 个域名都不给地址：解析器本身用不了") }
  if (hijack) {
    if (!NOTES++) print ""
    note("warn", "DNS 劫持", "53 端口被上游劫持：明文查询都由它应答，换公共 DNS 也没用")
    more("要绕开只能用 DoH/DoT")
    if (ENVV["route_tunnels"] != "-" && ENVV["route_tunnels"] != "") more("本机有隧道接口 " ENVV["route_tunnels"] "，也可能是本机的透明代理接管了 53 端口")
  }
  if (nfake > 0) {
    if (!NOTES++) print ""
    note("warn", "fake-ip", nfake " 个目标的系统 DNS 返回 fake-ip：有透明代理接管了解析")
    more("系统 DNS 这一轮测不到真实出口。要测线路本身先关掉它，要测它的分流用 -x 指向它的本地端口")
  }
  if (npart > 0) {
    if (!NOTES++) print ""
    note("bad", "IP 拦截", npart " 个目标有部分 IP 连不上：其他 IP 正常，像是上游按 IP 拦截")
    if (deadnets != "") more("连不上的网段：" clip(deadnets, 40))
  }
  if (nupdead > 0) {
    if (!NOTES++) print ""
    note("bad", "IP 拦截", nupdead " 个目标全部 IP 连不上，且路由在内网段改了道：是上游在拦截")
    more(clip(updead, 52))
  }
  if (ndivnet > 0) {
    if (!NOTES++) print ""
    note("warn", "改道", ndivnet " 个网段在第 " divpos " 跳改道，走 " maskall(divhops) "；" (ndivdead > 0 ? ndivdead " 个改道后连不上" : "还连得上，出口未知"))
  }
  if (np > 1) {
    if (!NOTES++) print ""
    note("info", "出口池", "默认出口在 " np " 个 IP 之间轮换：同一个目标连问几次，出口也在变")
    more("这是出口池或多线负载均衡，不是按目标分流")
  }
  if (nun > 0) {
    if (!NOTES++) print ""
    line = ""
    for (i = 1; i <= nun; i++) line = line (i > 1 ? "、" : "") maskall(UE[i]) "（" UN[i] "）"
    note("warn", "偶发出口", nun " 个出口只出现过 1 次：复测看到的是别的出口，按偶发处理")
    more(line "，没有算进结论")
  }
  if (nx >= 2) {
    same24 = 1
    pre = XI[1]; sub(/\.[0-9]+$/, ".", pre)
    for (j = 2; j <= nx; j++) if (index(XI[j], pre) != 1) same24 = 0
    if (same24) { if (!NOTES++) print ""; note("info", "同网段", "这些出口在同一个 /24，也可能是运营商的出口池轮换，不一定是分流") }
    # 只回显过一次的出口，若另有至少 2 个目标的路由走它那条线路（推断到它），就算有旁证：
    # 偶发的读数和默认出口同一条线路，推断不会落到它上面
    once = 0
    for (j = 2; j <= nx; j++) if (XS[j] + 0 <= 1 && INFT[XI[j]] + 0 < 2) once++
    if (once > 0) { if (!NOTES++) print ""; note("info", "待确认", once " 个出口只回显过 1 次，复测没能确认，可能是误报，看明细确认") }
  }
  if (nalldead > 0) {
    if (!NOTES++) print ""
    note("ask", "连不上", nalldead " 个目标的 IP 复测两次全都连不上：分不清是目标挂了还是被拦")
    more("换个网络打开就能确认：" clip(alldead, 40))
  }
  if (ntlst > 0) {
    if (!NOTES++) print ""
    note("info", "TLS 不通", ntlst " 个目标 TCP 连得上、TLS 握手不成：可能按 SNI 拦截，或目标拒绝")
    more(clip(tlsn, 52))
  }
  if (nunk > 0) { if (!NOTES++) print ""; note("info", "未知", nunk " 个目标无法确认出口") }
  if (nweak > 0) { if (!NOTES++) print ""; note("info", "弱推断", nweak " 个目标只有弱推断：路由在内网段改了道，可能走了没发现的出口") }
  if (ndead - ndeadover > 0) { if (!NOTES++) print ""; note("info", "没测成", (ndead - ndeadover) " 个目标解析失败或连不上，不影响结论") }

  # ---------- 出口 ----------
  sec("出口", nx " 个" (np > 1 ? " · 默认出口是 " np " 个 IP 的出口池" : ""))
  for (j = 1; j <= nx; j++) {
    other = (j > 1 && XORG[j] != "-" && XORG[1] != "-" && asn(XORG[j]) != asn(XORG[1]))
    line = "  " badge(XL[j]) " " (XDEF[j] ? "默认" : "    ") "  " B pad(maskall(XI[j]), 16) R " " fit(XORG[j] == "-" ? "运营商没查到" : XORG[j], other ? 35 : 49)
    if (other) line = line "  " YEL "非默认运营商" R
    print line
    n2 = 0
    s = (XCC[j] != "-" ? XCC[j] : "") (XCITY[j] != "-" ? " " XCITY[j] : "")
    if (s != "") IT[++n2] = s
    if (XKIND[j] == "hosting") IT[++n2] = "标记为机房"
    if (XKIND[j] == "mobile") IT[++n2] = "标记为移动网络"
    if (XKIND[j] == "proxy") IT[++n2] = "标记为代理"
    s = "回显 " XS[j] " 次"
    if (j > 1 && XS[j] + 0 <= 1 && INFT[XI[j]] + 0 >= 2) s = s "，另有 " INFT[XI[j]] " 个目标的路由走同一条线路"
    IT[++n2] = s
    if (XSIG[j] != "-" && !SHARE) { s = XSIG[j]; gsub(/ > /, " › ", s); IT[++n2] = "线路 " s }
    if (XHOST[j] != "-" && !SHARE) IT[++n2] = fit(XHOST[j], 60)
    flow(IT, n2, W - 10, 3, " · ")
    for (i = 1; i <= FLN; i++) print spc(12) DIM FL[i] R
    if (XDEF[j] && np > 1) {
      n2 = 0
      for (i = 1; i <= np; i++) IT[++n2] = maskall(PIP[i]) "（" PCN[i] " 次）"
      flow(IT, n2, W - 18, 2, "、")
      for (i = 1; i <= FLN; i++) print spc(12) DIM (i == 1 ? "出口池  " : "        ") FL[i] R
    }
  }

  # ---------- 分类概览。每格一个目标；分类很大时按比例缩到 24 格以内 ----------
  sec("分类", "每格一个目标")
  maxc = 0
  for (c = 1; c <= nc; c++) if ((CO[c] in CCOUNT) && CCOUNT[CO[c]] > maxc) maxc = CCOUNT[CO[c]]
  BSCALE = (maxc > 24) ? 24 / maxc : 1
  BW = 0; ncr = 0
  for (c = 1; c <= nc; c++) {
    k = CO[c]
    if (!(k in CCOUNT)) continue
    ncr++; CRK[ncr] = k
    CBP[ncr] = bar(k, 0); CWP[ncr] = BARW; CTP[ncr] = BART
    if (BARW > BW) BW = BARW
    if (HASE) { CBE[ncr] = bar(k, 1); CWE[ncr] = BARW; if (BARW > BW) BW = BARW }
  }
  if (BW < 10) BW = 10
  print "  " spc(17) DIM pad(PH, BW + 4) (HASE ? "加密 DNS" : "") R
  for (i = 1; i <= ncr; i++) {
    line = "  " pad(CL[CRK[i]], 10) DIM padl(CTP[i], 4) R "   " CBP[i]
    if (HASE) line = line spc(BW - CWP[i]) "    " CBE[i]
    print line
  }
  line = ""
  for (j = 1; j <= nx; j++) line = line (line == "" ? "" : "   ") (DEPTH == 0 ? "" : cells(XL[j], 1) " ") XL[j] (XDEF[j] ? " 默认" : "")
  for (c = 1; c <= nc; c++) { if (MP[CO[c], "X"] + ME[CO[c], "X"] > 0) hx = 1; if (MP[CO[c], "!"] + ME[CO[c], "!"] > 0) hd = 1; if (MP[CO[c], "?"] + ME[CO[c], "?"] > 0) hq = 1 }
  if (HASW) line = line "   " (DEPTH == 0 ? "小写" : wcells(XL[1], 1)) " 弱推断"
  if (hx) line = line "   " cells("X", 1) (down ? " 系统 DNS 查不到" : " DNS 屏蔽")
  if (hd) line = line "   " cells("!", 1) " 连不上"
  if (hq) line = line "   " cells("?", 1) " 未知"
  print "  " spc(17) line
  # 分享用的图片只要概览，到这里为止
  if (SHARE) {
    print ""
    print "  " DIM "github.com/YePiXpert/exitray" R
    exit
  }

  # ---------- DNS ----------
  if (!proxy && (("resolver" in ENVV) || ("dns_hijack" in ENVV) || ntr > 0 || ENVV["trigger"] == "no-dig" || nblock + nfake > 0 || nq > 0)) {
    sec("DNS", ("resolver" in ENVV) ? "系统解析器 " ENVV["resolver"] : "")
    if ("dns_hijack" in ENVV) {
      if (hijack) chk("53 端口", "warn", "被劫持：发给保留地址 192.0.2.53 的查询也收到了应答")
      else chk("53 端口", "ok", "未发现劫持")
    }
    if (down) chk("系统 DNS", "warn", nblock " 个域名都查不到地址，解析器本身用不了")
    else if (nblock > 0) {
      chk("DNS 屏蔽", "bad", nblock " 个域名系统 DNS 不给真实地址")
      flow(BN, nxb, W - 13, BRIEF ? 1 : 4, "  ")
      for (i = 1; i <= FLN; i++) print spc(15) DIM FL[i] R
    } else if (!hijack && HASE && nfake == 0) chk("DNS 屏蔽", "ok", "系统 DNS 和加密 DNS 都能解析")
    if (nfake > 0) chk("fake-ip", "warn", nfake " 个域名的系统 DNS 返回 198.18.x.x，透明代理接管了解析")
    if (ENVV["trigger"] == "no-dig") chk("触发测试", "info", "没有 dig，已跳过（Debian: apt install -y dnsutils）")
    else if (ntr > 0) {
      if (tested == 0) chk("触发测试", "ask", "抽样的 " ntr " 个域名都测不了")
      else if (fired > 0) chk("触发测试", "warn", "触发 " fired " / 可测 " tested "：明文查询之后出口变了，上游按 DNS 应答写名单")
      else chk("触发测试", "ok", "触发 0 / 可测 " tested "：用外地节点的 IP 做对照，明文查询前后出口没变")
      for (i = 1; i <= ntr; i++) {
        if (GB[i] == "-" || GB[i] == GA[i]) continue
        print spc(15) pad(fit(GN[i], 30), 31) pad(GI[i], 16) lc(letter_of(GB[i]), letter_of(GB[i])) " → " lc(letter_of(GA[i]), letter_of(GA[i]))
      }
      if (ntr - tested > 0) {
        s = ""
        if (nmis > 0) s = nmis " 个的明文应答里没有外地节点的 IP" (hijack ? "（53 端口被劫持，应答是劫持方给的）" : "")
        if (nnoecho > 0) s = s (s == "" ? "" : "，") nnoecho " 个拿不到回显"
        if (nnofar > 0) s = s (s == "" ? "" : "，") nnofar " 个查不到外地节点的 IP"
        chkmore((tested > 0 ? "另有 " (ntr - tested) " 个测不了：" : "") s)
      }
      if (!BRIEF) {
        before = ""; same = ""
        for (i = 1; i <= ntr; i++) {
          if (GB[i] == "-" || GB[i] != GA[i]) continue
          if (GB[i] == XI[1]) same = same (same == "" ? "" : "、") GN[i]
          else before = before (before == "" ? "" : "、") GN[i] "(" letter_of(GB[i]) ")"
        }
        if (before != "") chkmore("查询前就在分流线：" clip(before, 96))
        if (same != "" && VERBOSE) chkmore("不受影响：" same)
      }
    }
    # 被劫持时下面这些来源都是拦截方的，没有参考价值
    if (nq > 0 && !hijack) {
      line = ""
      for (i = 1; i <= nq; i++) {
        if (QV[i] == "-") continue
        v = (QV[i] ~ /\//) ? letter_net(QV[i]) : letter_of(QV[i])
        line = line (line == "" ? "" : " · ") QN[i] " " v
      }
      if (line != "") chk("查询来源", "info", line "（UDP，权威服务器看到的来源）")
    }
  }

  # ---------- 连通：只列各个 IP 结果不一样、有 IP 连不上或者改了道的目标，按网段汇总 ----------
  if (nrow > 0) {
    sec("连通", "连上次数/尝试次数 · 复测两次才下结论")
    print "  " DIM pad("网段", 18) pad("结果", 14) pad("连通", 6) pad("路由", 12) "目标" R
    for (pass = 1; pass <= 6; pass++)
      for (r = 1; r <= nrow; r++) {
        s = RSIG[r]
        k = (s == "dead") ? 1 : (s ~ /^part/ ? 2 : (s ~ /^flaky/ ? 3 : (s ~ /^tls/ ? 4 : (s ~ /^untested/ ? 6 : 5))))
        if (k != pass) continue
        lets = s; sub(/^[a-z]*:?/, "", lets)
        if (k == 1) res = RED "✗ 连不上" R
        else if (k == 2) res = YEL "! 部分不通" R
        else if (k == 3) res = YEL "! 时通时断" R
        else if (k == 4) res = YEL "! TLS 不通" R
        else if (k == 6) res = DIM "· 没试过" R (lets == "" ? "" : " " lcs(lets))
        else if (lets == "") res = GRN "✓" R DIM " 出口未知" R
        else res = GRN "✓" R " " lcs(lets)
        if ((k == 2 || k == 3) && lets != "") res = res " " lcs(lets)
        rt = (r in RDV) ? YEL "第 " RDV[r] " 跳改道" R : DIM "-" R
        tg = (RTC[r] > 1) ? fit(RT1[r], 26 - vis(" 等 " RTC[r] " 个")) " 等 " RTC[r] " 个" : fit(RT1[r], 26)
        print "  " pad(RLAB[r], 18) pad(res, 14) pad(DIM ROK[r] "/" RTR[r] R, 6) pad(rt, 12) tg
      }
    print "  " DIM (ndivnet > 0 ? "改道后的下一跳：" divhops "。" : "") "每个 IP 的结果加 -v 查看" R
  }
  # 每个目标每个 IP 的结果，-v 时才列
  if (VERBOSE && nipshow > 0) {
    sec("逐 IP 明细", "连不上是复测两次都不通")
    print "  " DIM pad("目标", 24) pad("IP", 16) pad("连通", 6) pad("结果", 13) "改道去了" R
    for (t = 1; t <= nt; t++) {
      if (!SHOW[t]) continue
      m = split(IPM[t], ipa, " ")
      for (i = 1; i <= m; i++) {
        split(ipa[i], ipb, "="); split(ipb[2], ipc, ":")
        if (ipc[2] == "dead") v = RED "✗ 连不上" R
        else if (ipc[2] == "flaky") v = YEL "! 时通时断" R (ipc[1] == "?" ? "" : " " lcs(ipc[1]))
        else if (ipc[2] == "tls") v = YEL "! TLS 不通" R
        else if (ipc[2] == "-") v = DIM "· 没试过" R
        else if (ipc[1] == "?") v = GRN "✓" R DIM " 出口未知" R
        else v = GRN "✓" R " " lcs(ipc[1])
        s = ""
        if (ipc[4] != "0" && ipc[4] != "") { split(ipc[4], q, "@"); s = YEL "→ " q[2] R }
        print "  " pad(i == 1 ? fit(TN[t], 23) : "", 24) pad(ipb[1], 16) pad(DIM ipc[3] R, 6) pad(v, 13) s
      }
    }
  }

  # ---------- 明细：默认只列需要留意的目标，其余的每个分类折成一行 ----------
  if (!BRIEF) {
    nnot = 0
    for (t = 1; t <= nt; t++) { NB[t] = notable(t); if (NB[t]) { nnot++; CNOT[TC[t]]++ } }
    if (VERBOSE) sec("明细", "全部 " nt " 个目标")
    else if (nnot == 0) sec("明细", "没有需要留意的目标")
    else sec("明细", "需要留意的 " nnot " 个 · 全部目标加 -v")
    if (VERBOSE || nnot > 0) print "    " DIM pad("目标", 30) pad(proxy ? "节点" : "系统", 8) pad(HASE ? "加密" : "", 5) pad("证据", 17) "备注" R
    for (c = 1; c <= nc; c++) {
      k = CO[c]
      if (!(k in CCOUNT)) continue
      if (!VERBOSE && CNOT[k] + 0 == 0) { NOKC[++nokc] = CL[k] " " CCOUNT[k]; continue }
      print "  " B CL[k] R DIM "  " CCOUNT[k] " 个" (VERBOSE || CNOT[k] == CCOUNT[k] ? "" : "，" CNOT[k] " 个需要留意") R
      n2 = 0
      for (t = 1; t <= nt; t++) {
        if (TC[t] != k) continue
        if (VERBOSE || NB[t]) row(t)
        else IT[++n2] = TN[t]
      }
      if (n2 > 0) {
        flow(IT, n2, W - 20, 2, " · ")
        for (i = 1; i <= FLN; i++) print "    " DIM (i == 1 ? pad("其余 " n2 " 个正常", 16) : spc(16)) FL[i] R
      }
    }
    if (nokc > 0) {
      flow(NOKC, nokc, W - 4, 3, " · ")
      print "  " DIM (nnot > 0 ? "其余分类全部正常" : "全部目标") "：都走默认出口 " XL[1] "，证据是直接或推断" R
      for (i = 1; i <= FLN; i++) print "    " DIM FL[i] R
    }
  }

  # ---------- 其他检查 ----------
  has_other = nsn > 0 || ("route_defaults" in ENVV) || ("ipv6" in ENVV) || (ENVV["tracer"] == "none" && ENVV["use_route"] == 1) || proxy
  if (has_other && !BRIEF) sec("其他检查")
  if (nsn > 0 && !BRIEF) {
    if (nc2 > 0) chk("SNI 嗅探", "warn", nc2 "/" nsn " 个域名出口变了：" changed)
    if (nmv > 0) chk(nc2 > 0 ? "" : "SNI 嗅探", "warn", nmv "/" nsn " 个域名的连接被转去了别处，回来的不是回显服务的应答：" moved)
    if (nc2 + nmv == 0) {
      if (nsf == nsn) chk("SNI 嗅探", "ask", nsn " 个域名都没连上，无法判断")
      else {
        chk("SNI 嗅探", "ok", (nsn - nsf) " 个域名放进 SNI，出口都没变，没有按 TLS 域名分流")
        if (nsf > 0) chkmore("另有 " nsf " 个没连上")
      }
    } else if (nsf > 0) chkmore("另有 " nsf " 个没连上")
  }
  if (("route_defaults" in ENVV) && !BRIEF) {
    line = ENVV["route_defaults"] " 条默认路由"
    if (ENVV["route_rules"] + 0 > 0) line = line "，" ENVV["route_rules"] " 条策略规则"
    if (ENVV["route_tunnels"] != "-") line = line "，隧道 " ENVV["route_tunnels"]
    if (nx >= 2 && ENVV["route_defaults"] + 0 <= 1 && ENVV["route_rules"] + 0 == 0 && ENVV["route_tunnels"] == "-")
      line = line "，分流发生在上游，不在本机"
    chk("本机路由", (ENVV["route_rules"] + 0 > 0 || ENVV["route_tunnels"] != "-") ? "warn" : "info", line)
  }
  if (!BRIEF) {
    if (ENVV["tracer"] == "none" && ENVV["use_route"] == 1)
      chk("路由探测", "warn", "没有可用的路由工具，不回显的目标无法判断（Debian: apt install -y mtr-tiny）")
    else if (!proxy && ENVV["use_route"] == 1) chk("路由探测", "info", ENVV["tracer"])
    if ("ipv6" in ENVV) {
      if (ENVV["ipv6"] == "-") chk("IPv6", "info", "没有 IPv6 出口")
      else chk("IPv6", "warn", ENVV["ipv6"] "：支持 IPv6 的目标可能从这里出去，本次只测 IPv4")
    }
    if (proxy) chk("经代理", "info", ENVV["proxy"] "：只有回显证据，不回显的目标显示未知")
  }

  if (VERBOSE) {
    sec("每轮明细", "E 加密 · P 系统 DNS · C 校准 · S 稳定性 · N 换 SNI · r 复测")
    for (i = 1; i <= ndt; i++) {
      split(DL[i], d, "\t")
      print "  " pad(d[1] d[2] d[5], 6) pad(fit(d[4], 28), 29) pad(d[6], 16) lc(d[7], d[7]) " " pad(d[8], 16) pad(d[9] (d[10] == "-" ? "" : "/" d[10]), 18) pad(d[12], 5) DIM d[11] R
    }
  }

  # ---------- 说明：只解释这份报告里出现过的词 ----------
  if (!BRIEF) {
    sec("说明")
    term("直接", "目标自己，或同一个 IP 上的 CDN，回显了访问者的 IP")
    term("推断", "目标不回显，但路由和已确认出口的线路相同")
    if (nweak > 0 || ndivnet > 0) term("弱推断", "路由在内网段就离开了已确认的线路（改道），出口可能不是默认的那个")
    if (nipshow > 0) {
      term("连通", "加密 DNS 合并 Google 和 Cloudflare 的应答，每个 /24 测一个 IP；连不上的 IP 再连两次才下结论，只看 TCP 能不能连上，证书不被信任不算连不上")
    }
    if (nflip > 0) term("DNS触发", "同一个 IP 在明文查询之后换了出口，是上游按 DNS 应答把它写进了分流名单")
    if (nrel > 0) term("DNS相关", "系统 DNS 解析到的 IP 走分流，加密 DNS 解析到的是别的 IP、走默认出口")
    if (nstatic > 0) term("名单内", "加密 DNS 下也走分流：可能是静态名单，也可能被别的明文查询写了进去")
    if (nc2 > 0) term("按SNI", "把域名放进 SNI 发给中立回显，出口就变了：真实访问走的是这个出口")
    if (proxy) term("测的范围", "节点这一层。经代理时没有路由信息，只有回显证据")
    else term("测的范围", "上游这一层。节点上的 xray、sing-box 可能另有路由规则，要检查那一层用 -x 经节点测")
  }
}
AWK
  touch "$WORK/trigger.tsv" "$WORK/sni.tsv" "$WORK/dnsq.tsv" "$WORK/env.tsv" "$WORK/detail.tsv" "$WORK/unstable.tsv" "$WORK/pool.tsv"
  # 出口池按回显次数排，默认的那个排最前
  sort -t "$(printf '\t')" -k4,4nr -k2,2nr "$WORK/pool.tsv" > "$WORK/pool_sorted.tsv"
  awk -v DEPTH="$depth" -v BRIEF="$BRIEF" -v VERBOSE="$VERBOSE" -v SHARE="${REPORT_SHARE:-0}" -v MASK="$MASK" \
    -v LOGO1="${LOGO[0]}" -v LOGO2="${LOGO[1]}" -v LOGO3="${LOGO[2]}" -v RAMPS="${LOGO_RAMP[*]}" \
    -v F_CATS="$WORK/cats.txt" -v F_EXITS="$WORK/exits_info.tsv" -v F_TARGETS="$WORK/targets.tsv" \
    -v F_TRIGGER="$WORK/trigger.tsv" -v F_SNI="$WORK/sni.tsv" -v F_DNSQ="$WORK/dnsq.tsv" \
    -v F_ENV="$WORK/env.tsv" -v F_DETAIL="$WORK/detail.tsv" -v F_UNSTABLE="$WORK/unstable.tsv" \
    -v F_POOL="$WORK/pool_sorted.tsv" \
    -f "$WORK/report.awk" \
    "$WORK/cats.txt" "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" \
    "$WORK/trigger.tsv" "$WORK/sni.tsv" "$WORK/dnsq.tsv" "$WORK/unstable.tsv" "$WORK/pool_sorted.tsv" "$WORK/detail.tsv" || die "生成报告时出错"
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
  if (m == "sni") return "SNI"
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
function kind(k, flip) {
  if (k == "dns") return flip ? "DNS 触发" : "DNS 相关"
  if (k == "static") return "名单内"
  if (k == "mixed") return "解析不同"
  if (k == "dnsblock") return "DNS 屏蔽"
  if (k == "fakeip") return "fake-ip"
  if (k == "byip") return "按 IP"
  if (k == "sni") return "按 SNI"
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
  EL[nt] = $10; KC[nt] = $14; RCH[nt] = $17; BI[nt] = $19 + 0; FLP[nt] = $20 + 0; DIV[nt] = $21 + $22
  SNX[nt] = ($25 == "" ? "-" : $25)
  if (!($1 in CL)) { nc++; CO[nc] = $1; CL[$1] = $1 }
  # 概览里连不上的目标单独数，不混在“未知”里
  st = $3
  if (st == "?" && $5 == "noconn") { st = "!"; ndeadc++ }
  CCOUNT[$1]++; MP[$1, st]++
  if ($14 == "dns") { if ($20 + 0) nflip++; else nrel++ }
  if ($14 == "static") nstatic++
  if (BI[nt]) nbyip++
  if ($17 == "partial") npart++
  if ($17 == "dead") { if ($21 + 0 > 0) nupdead++; else nalldead++ }
  if ($21 + $22 > 0) ndiv++
  if ($10 != "-") HASE = 1
  next
}
FILENAME == F_TRIGGER { if ($4 != "-") { tested++; if ($4 != $5) fired++ } next }
FILENAME == F_UNSTABLE { nun++; next }
FILENAME == F_POOL { np++; next }
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
  if (v) s = s (s == "" ? "" : " · ") (ENVV["sysdns_down"] == 1 ? "系统 DNS 查不到 " : "DNS 屏蔽 ") v
  v = MP[k, "!"] + 0
  if (v) s = s (s == "" ? "" : " · ") "连不上 " v
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
  else if (V == "blocked") verdict = "出口没有分流，但有目标连不上，像是被按 IP 拦截"
  else if (V == "inconclusive" && ENVV["sysdns_down"] == 1) verdict = "没发现第二个出口，但系统 DNS 用不了，不能排除分流"
  else if (V == "inconclusive") verdict = "没发现第二个出口，但 " nopen "/" nt " 个目标证据不足，不能排除分流"
  else verdict = "未发现分流"
  dnsnote = ""
  if (ENVV["dns_hijack"] == 1) dnsnote = "53 端口被上游劫持"
  if (nblock > 0 && ENVV["sysdns_down"] != 1) dnsnote = dnsnote (dnsnote == "" ? "" : "，") nblock " 个目标被 DNS 屏蔽"
  if (nblock > 0 && ENVV["sysdns_down"] == 1) dnsnote = dnsnote (dnsnote == "" ? "" : "，") "系统 DNS 对 " nblock " 个域名都不给地址，解析器本身用不了"
  if (nfake > 0) dnsnote = dnsnote (dnsnote == "" ? "" : "，") nfake " 个目标返回 fake-ip，有透明代理"
  ipnote = ""
  if (nbyip > 0) ipnote = nbyip " 个目标按 IP 分流"
  if (npart > 0) ipnote = ipnote (ipnote == "" ? "" : "，") npart " 个目标部分 IP 连不上"
  if (nupdead > 0) ipnote = ipnote (ipnote == "" ? "" : "，") nupdead " 个目标全部 IP 连不上且路由改道"
  if (nalldead > 0) ipnote = ipnote (ipnote == "" ? "" : "，") nalldead " 个目标全部 IP 连不上"
  if (ndiv > 0) ipnote = ipnote (ipnote == "" ? "" : "，") ndiv " 个目标的路由在内网段改道"
  sninote = ""
  if (ENVV["n_sni_changed"] + 0 > 0) sninote = ENVV["n_sni_changed"] "/" ENVV["n_sni"] " 个域名换了 SNI 出口就变，路径上有设备按 TLS 域名分流"
  else if (ENVV["n_sni_moved"] + 0 > 0) sninote = ENVV["n_sni_moved"] "/" ENVV["n_sni"] " 个域名的连接被按 TLS 域名转去了别处"
  poolnote = ""
  if (np > 1) poolnote = "默认出口是 " np " 个 IP 的出口池，同一个目标连问几次出口在轮换"
  if (ENVV["intercept"] == "host") poolnote = poolnote (poolnote == "" ? "" : "；") "本机有透明代理改写连接，测到的是代理的分流"
  date = substr(ENVV["time"], 1, 10)
  region = (ENVV["region"] == "none" ? "" : " · 地区 " ENVV["region"])
  if (ENVV["proxy"] != "-") region = region " · 经代理"
  trig = ""
  if (tested > 0) trig = (fired > 0 ? "是" : "未发现") "（触发 " fired + 0 " / 可测 " tested "）"
  unote = ""
  if (nun > 0) unote = "另有 " nun " 个出口只出现过一次，复测没有再出现，没有算进结论"

  if (MODE == "summary") {
    print "ExitRay 分流检测 · " date region " · " nt " 个目标"
    print "结论：" verdict
    if (unote != "") print unote
    if (poolnote != "") print "注意：" poolnote
    if (dnsnote != "") print "DNS：" dnsnote
    if (sninote != "") print "SNI：" sninote
    if (ipnote != "") print "逐 IP：" ipnote
    for (j = 1; j <= nx; j++) print exit_line(j)
    for (c = 1; c <= nc; c++) if (CO[c] in CCOUNT) print CL[CO[c]] "：" cat_line(CO[c])
    if (trig != "") print "明文 DNS 触发：" trig
    line = "证据：直接 " (ENVV["n_direct"] + 0) " · 推断 " (ENVV["n_inferred"] + 0)
    if (nweak > 0) line = line " · 弱推断 " nweak
    print line " · 未确认 " (ENVV["n_unknown"] + ENVV["n_unreachable"] + nfake)
    print "https://github.com/YePiXpert/exitray"
    exit
  }

  print "# 分流检测报告"
  print ""
  print "- 时间：" date
  if (ENVV["region"] != "none") print "- 地区：" ENVV["region"]
  print "- 目标：" nt " 个"
  print "- **结论：" verdict "**"
  if (unote != "") print "- " unote
  if (poolnote != "") print "- 注意：" poolnote
  if (dnsnote != "") print "- DNS：" dnsnote
  if (sninote != "") print "- SNI：" sninote
  if (ipnote != "") print "- 逐 IP：" ipnote
  if (trig != "") print "- 明文 DNS 触发：" trig
  if (nflip + nrel + nstatic > 0) print "- " nflip + 0 " 个目标由明文 DNS 触发，" nrel + 0 " 个目标随系统 DNS 的解析走分流，" nstatic + 0 " 个目标在分流名单内"
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
  if (nblock > 0) { head = head (ENVV["sysdns_down"] == 1 ? " 系统 DNS 查不到 |" : " DNS 屏蔽 |"); sep = sep "---:|" }
  if (ndeadc > 0) { head = head " 连不上 |"; sep = sep "---:|" }
  print head " 未知 |"
  print sep "---:|"
  for (c = 1; c <= nc; c++) {
    k = CO[c]
    if (!(k in CCOUNT)) continue
    line = "| " CL[k] " |"
    for (j = 1; j <= nx; j++) line = line " " MP[k, XL[j]] + 0 " |"
    if (nblock > 0) line = line " " MP[k, "X"] + 0 " |"
    if (ndeadc > 0) line = line " " MP[k, "!"] + 0 " |"
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
      how = kind(KC[t], FLP[t])
      if (BI[t] && KC[t] != "byip") how = how (how == "" ? "" : "，") "按 IP"
      if (RCH[t] == "partial") how = how (how == "" ? "" : "，") "部分 IP 连不上"
      if (RCH[t] == "dead") how = how (how == "" ? "" : "，") "全部 IP 连不上"
      if (DIV[t] > 0) how = how (how == "" ? "" : "，") "路由改道"
      if (SNX[t] != "-" && KC[t] != "sni") how = how (how == "" ? "" : "，") "换 SNI 走 " SNX[t]
      if (PL[t] == "X") print "| " TN[t] " | 屏蔽 |" (HASE ? " " EL[t] " |" : "") " " evid(PE[t], PM[t]) " | " how " |"
      else print "| " TN[t] " | " PL[t] (PA[t] + 0 < PT[t] + 0 ? "（" PA[t] "/" PT[t] " 轮）" : "") " |" (HASE ? " " EL[t] " |" : "") " " evid(PE[t], PM[t]) " | " how " |"
    }
  }
  print ""
  print "直接：目标或同一 IP 上的 CDN 回显的访问者 IP。推断：路由和已确认出口的线路相同。弱推断：路由在内网段改了道。"
  print "DNS 触发：同一个 IP 在明文查询之后换了出口。DNS 相关：系统 DNS 解析到的 IP 走分流，加密 DNS 解析到的走默认出口。名单内：加密 DNS 下也走分流。"
  print ""
  print "由 [ExitRay](https://github.com/YePiXpert/exitray) 生成"
}
AWK
  touch "$WORK/trigger.tsv" "$WORK/unstable.tsv" "$WORK/pool.tsv"
  awk -v MODE="$1" -v MASK="$MASK" \
    -v F_CATS="$WORK/cats.txt" -v F_ENV="$WORK/env.tsv" -v F_EXITS="$WORK/exits_info.tsv" \
    -v F_TARGETS="$WORK/targets.tsv" -v F_TRIGGER="$WORK/trigger.tsv" -v F_UNSTABLE="$WORK/unstable.tsv" \
    -v F_POOL="$WORK/pool.tsv" \
    -f "$WORK/share.awk" \
    "$WORK/cats.txt" "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" "$WORK/trigger.tsv" \
    "$WORK/unstable.tsv" "$WORK/pool.tsv" || die "生成分享报告时出错"
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
  # 逐 IP 的结果：$18 是“IP=出口:状态:连上次数/尝试次数:改道”，空格分隔。出口可以是 A/B，不知道是 ?；
  # 状态是 ok、flaky、tls、dead，没试过是 -；改道写成“位置@那一跳”，没有是 0
  ips = ""
  m = split($18 == "-" ? "" : $18, ia, " ")
  for (k = 1; k <= m; k++) {
    split(ia[k], ib, "="); split(ib[2], ic, ":")
    ids = ""
    if (ic[1] != "?") { q = split(ic[1], id, "/"); for (z = 1; z <= q; z++) ids = ids (z > 1 ? "," : "") s(id[z]) }
    split(ic[3], tr, "/")
    dv = "null"
    if (ic[4] != "0" && ic[4] != "") { split(ic[4], dh, "@"); dv = "{\"hop\":" (dh[1] + 0) ",\"ip\":" s(dh[2]) "}" }
    ips = ips (k > 1 ? "," : "") "{\"ip\":" s(ib[1]) ",\"exit_ids\":[" ids "],\"reachable\":" (ic[2] == "dead" ? "false" : (ic[2] == "-" ? "null" : "true")) \
      ",\"state\":" sn(ic[2]) ",\"connected\":" (tr[1] + 0) ",\"attempts\":" (tr[2] + 0) ",\"diverted\":" dv "}"
  }
  T[nt] = "{\"category\":" s($1) ",\"name\":" s($2) \
    ",\"system_dns\":{\"exit_id\":" sn($3) ",\"exit\":" sn($4) ",\"evidence\":" sn($5) ",\"method\":" sn($6) ",\"agree\":" ($7 + 0) ",\"rounds\":" ($8 + 0) ",\"others\":" sn($9) "}" \
    ",\"encrypted_dns\":{\"exit_id\":" sn($10) ",\"exit\":" sn($11) ",\"evidence\":" sn($12) ",\"method\":" sn($13) "}" \
    ",\"class\":" s($14) ",\"ip_count\":" ($15 + 0) ",\"http\":" sn($16) ",\"reach\":" sn($17) \
    ",\"split_by_ip\":" ($19 == 1 ? "true" : "false") ",\"dns_flip\":" ($20 == 1 ? "true" : "false") ",\"sni_exit_id\":" sn($25) ",\"ips\":[" ips "]}"
  next
}
FILENAME == F_TRIGGER {
  ng++
  G[ng] = "{\"category\":" s($1) ",\"name\":" s($2) ",\"ip\":" sn($3) ",\"before\":" sn($4) ",\"after\":" sn($5) ",\"untestable\":" (($6 == "ok" || $6 == "") ? "null" : s($6)) "}"
  if ($4 != "-" && $4 != $5) fired = 1
  next
}
FILENAME == F_SNIFF { nn++; N[nn] = "{\"sni\":" s($1) ",\"exit\":" sn($2) ",\"http\":" sn($3) "}"; next }
FILENAME == F_DNSQ { nq++; Q[nq] = s($1) ":" sn($2); next }
FILENAME == F_POOL { npl++; PL[npl] = "{\"ip\":" s($1) ",\"seen\":" ($2 + 0) "}"; next }
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
  printf "\"coverage\":{\"direct\":%d,\"inferred\":%d,\"weak\":%d,\"unknown\":%d,\"unreachable\":%d,\"fake_ip\":%d,\"dns_blocked\":%d,\"ip_blocked\":%d,\"split_by_ip\":%d,\"diverted\":%d,\"tls_failed\":%d},", \
    ENVV["n_direct"], ENVV["n_inferred"], ENVV["n_weak"], ENVV["n_unknown"], ENVV["n_unreachable"], ENVV["n_fakeip"], ENVV["n_dnsblock"], ENVV["n_ipblock"], ENVV["n_byip"], ENVV["n_diverted"], ENVV["n_tls"]
  # exit_pool：默认出口是出口池时，池里的 IP。它们在 exits 里合成了一个默认出口
  printf "\"exit_pool\":%s,\"intercepted\":%s,\"system_dns_down\":%s,", arr(PL, npl), (ENVV["intercept"] == "host" ? "true" : "false"), (ENVV["sysdns_down"] == 1 ? "true" : "false")
  # unstable_exits：只出现过一次、复测时又没再出现的出口，不算进 exits
  printf "\"exits\":%s,\"unstable_exits\":%s,\"targets\":%s,\"dns_trigger_test\":%s,\"sni_test\":{\"baseline\":%s,\"changed\":%d,\"moved\":%d,\"results\":%s},", \
    arr(X, nx), arr(U, nu), arr(T, nt), arr(G, ng), sn(ENVV["sniff_base"]), ENVV["n_sni_changed"], ENVV["n_sni_moved"], arr(N, nn)
  printf "\"dns_query\":{"
  for (i = 1; i <= nq; i++) printf "%s%s", (i > 1 ? "," : ""), Q[i]
  printf "},\"dns_hijack\":%s,\"ipv6\":%s}\n", (ENVV["dns_hijack"] == 1 ? "true" : "false"), sn(ENVV["ipv6"])
}
AWK
  touch "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" "$WORK/env.tsv" "$WORK/unstable.tsv" "$WORK/pool.tsv"
  awk -v F_ENV="$WORK/env.tsv" -v F_EXITS="$WORK/exits_info.tsv" -v F_TARGETS="$WORK/targets.tsv" \
    -v F_TRIGGER="$WORK/trigger.tsv" -v F_SNIFF="$WORK/sniff.tsv" -v F_DNSQ="$WORK/dnsq.tsv" \
    -v F_UNSTABLE="$WORK/unstable.tsv" -v F_POOL="$WORK/pool.tsv" \
    -f "$WORK/json.awk" \
    "$WORK/env.tsv" "$WORK/exits_info.tsv" "$WORK/targets.tsv" "$WORK/trigger.tsv" "$WORK/sniff.tsv" "$WORK/dnsq.tsv" \
    "$WORK/unstable.tsv" "$WORK/pool.tsv" || die "生成 JSON 时出错"
}

# 结论只在这里判断一次，三种报告和退出码都读它，不会各说各的
judge() {
  awk -F'\t' -v F_ENV="$WORK/env.tsv" -v F_EXITS="$WORK/exits.tsv" '
    FILENAME == F_ENV { if ($1 == "dns_hijack" && $2 == 1) hijack = 1; next }
    FILENAME == F_EXITS { nx++; next }
    # 同一个域名有的 IP 连得上、有的复测两次都连不上，是按 IP 拦截，不是目标自己挂了。
    # 全部 IP 都连不上，但路由在上游的内网段就改了道，同样是上游在处理这个 IP
    $17 == "partial" || ($17 == "dead" && $21 + 0 > 0) { ipblock++ }
    $19 == 1 { byip++ }
    $21 + $22 > 0 { diverted++ }
    $23 + 0 > 0 { tls++ }
    $2 !~ /^[0-9.]+$/ && $8 + 0 > 0 { names++ }
    $14 == "dnsblock" { block++; next }
    $14 == "fakeip" { fake++; next }
    # 解析失败、全部 IP 都连不上的目标没有流量可分，单独计数，不影响结论：清单里总会有失效的域名，
    # 从一个地方也分不清是目标挂了还是被拦了
    $4 == "-" { if ($5 == "dns" || $5 == "noconn") dead++; else unknown++; next }
    $5 == "direct" { direct++; next }
    $5 == "weak" { weak++; next }
    { inferred++ }
    END {
      # 系统 DNS 对绝大多数域名都不给地址，是解析器本身用不了，不是有选择的屏蔽
      down = (block >= 5 && block * 5 >= names * 4) ? 1 : 0
      if (nx >= 2) v = "split"
      else if (down) v = "inconclusive"
      else if (block > 0 || hijack) v = "dns_tampered"
      else if (ipblock > 0) v = "blocked"
      # 没有证据、只有弱推断、被 fake-ip 挡住的目标，都可能走了没发现的出口
      else if (unknown + weak + fake > 0) v = "inconclusive"
      else v = "clean"
      printf "verdict\t%s\nn_direct\t%d\nn_inferred\t%d\nn_weak\t%d\nn_unknown\t%d\n", v, direct, inferred, weak, unknown
      printf "n_unreachable\t%d\nn_fakeip\t%d\nn_dnsblock\t%d\nn_ipblock\t%d\nn_byip\t%d\n", dead, fake, block, ipblock, byip
      printf "n_diverted\t%d\nn_tls\t%d\nsysdns_down\t%d\n", diverted, tls, down
    }' "$WORK/env.tsv" "$WORK/exits.tsv" "$WORK/targets.tsv" > "$WORK/verdict.tsv" || die "分析结果时出错"
  # 默认出口是出口池时，池里有几个 IP
  printf 'pool\t%s\n' "$(ui_lines "$WORK/pool.tsv")" >> "$WORK/verdict.tsv"
  # 换了 SNI 出口就变、连接被转去别处的域名各有几个
  touch "$WORK/sni.tsv"
  awk -F'\t' '$2 == "changed" { c++ } $2 == "moved" { m++ } END { printf "n_sni\t%d\nn_sni_changed\t%d\nn_sni_moved\t%d\n", NR, c, m }' "$WORK/sni.tsv" >> "$WORK/verdict.tsv"
  cat "$WORK/verdict.tsv" >> "$WORK/env.tsv"
}

# 把带颜色码的终端输出画成 SVG。按终端的字符格排版，汉字占 2 格；每个字单独放进自己的格子，
# 框线、方块、对勾这些符号画成路径，换了字体也不会错位。$1 是输入文件，$2 是窗口标题
render_svg() {
  cat > "$WORK/svg.awk" <<'AWK'
BEGIN {
  E = sprintf("%c", 27)
  CW = 8.4; LH = 19; PX = 20; PY = 18; BAR = 30
  BG = "#14161b"; FG = "#d7dae0"; FRAME = "#262a33"
  FONT = "'DejaVu Sans Mono','Noto Sans Mono CJK SC','WenQuanYi Micro Hei Mono','WenQuanYi Zen Hei Mono',ui-monospace,Menlo,Consolas,'PingFang SC','Microsoft YaHei',monospace"
  split("#1e1e1e #e06c75 #98c379 #e5c07b #61afef #c678dd #56b6c2 #d4d4d4", B16, " ")
  # 框线字符从格子中心伸向哪几个方向
  BOX["─"] = "LR"; BOX["│"] = "UD"; BOX["┌"] = "RD"; BOX["┐"] = "LD"; BOX["└"] = "UR"; BOX["┘"] = "UL"
  BOX["├"] = "UDR"; BOX["┤"] = "UDL"; BOX["┬"] = "LRD"; BOX["┴"] = "LRU"; BOX["┼"] = "UDLR"; BOX["━"] = "LR"
  BOX["╭"] = "RD"; BOX["╮"] = "LD"; BOX["╰"] = "UR"; BOX["╯"] = "UL"
  ROUND["╭"] = 1; ROUND["╮"] = 1; ROUND["╰"] = 1; ROUND["╯"] = 1
}
{ L[++n] = $0 }
function f(v) { return sprintf("%.2f", v) }
function hx(v) { return sprintf("%02x", v) }
function pt(c, x, y) { return c f(x) "," f(y) }
function sgn(v) { return v > 0 ? 1 : (v < 0 ? -1 : 0) }
function c256(k, r, g, b, v) {
  k = k + 0
  if (k < 8) return B16[k + 1]
  if (k < 16) return B16[k - 7]
  if (k < 232) {
    k -= 16; r = int(k / 36); g = int(k / 6) % 6; b = k % 6
    return "#" hx(r ? 55 + 40 * r : 0) hx(g ? 55 + 40 * g : 0) hx(b ? 55 + 40 * b : 0)
  }
  v = 8 + 10 * (k - 232)
  return "#" hx(v) hx(v) hx(v)
}
function sgr(p, a, k, i, c) {
  k = split(p, a, ";")
  if (k == 0) { k = 1; a[1] = 0 }
  for (i = 1; i <= k; i++) {
    c = a[i] + 0
    if (c == 0) { FGC = ""; BGC = ""; BOLD = 0; DIMM = 0 }
    else if (c == 1) BOLD = 1
    else if (c == 2) DIMM = 1
    else if (c >= 30 && c <= 37) FGC = B16[c - 29]
    else if (c >= 40 && c <= 47) BGC = B16[c - 39]
    else if ((c == 38 || c == 48) && a[i + 1] + 0 == 5) {
      if (c == 38) FGC = c256(a[i + 2]); else BGC = c256(a[i + 2])
      i += 2
    }
  }
}
function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); return s }
# 下一个字符写进 CH，占几格写进 CWD，返回之后的位置
function nextc(s, i, c) {
  c = substr(s, i, 1)
  if (c ~ /[\001-\177]/) { CH = c; CWD = 1; return i + 1 }
  if (c ~ /[\300-\337]/) { CH = substr(s, i, 2); CWD = 1; return i + 2 }
  if (c ~ /[\340-\357]/) { CH = substr(s, i, 3); CWD = (c ~ /\342/) ? 1 : 2; return i + 3 }
  CH = substr(s, i, 4); CWD = 2; return i + 4
}
function plain(s) { gsub(E "\\[[0-9;?]*[A-Za-z]", "", s); return s }
function width(s, i, w) {
  s = plain(s); w = 0; i = 1
  while (i <= length(s)) { i = nextc(s, i); w += CWD }
  return w
}
function endp(d, x, y) {
  if (d == "L") { EX = x; EY = y + LH / 2 }
  else if (d == "R") { EX = x + CW; EY = y + LH / 2 }
  else if (d == "U") { EX = x + CW / 2; EY = y }
  else { EX = x + CW / 2; EY = y + LH }
}
function boxpath(ch, x, y, d, cx, cy, ax, ay, bx, by, r, s, m, k, i) {
  d = BOX[ch]; cx = x + CW / 2; cy = y + LH / 2
  if (d == "LR" || d == "UD") {
    endp(substr(d, 1, 1), x, y); s = pt("M", EX, EY)
    endp(substr(d, 2, 1), x, y)
    return s pt("L", EX, EY)
  }
  if (length(d) == 2) {
    endp(substr(d, 1, 1), x, y); ax = EX; ay = EY
    endp(substr(d, 2, 1), x, y); bx = EX; by = EY
    if (!(ch in ROUND)) return pt("M", ax, ay) pt("L", cx, cy) pt("L", bx, by)
    r = 3.78
    return pt("M", ax, ay) pt("L", cx + sgn(ax - cx) * r, cy + sgn(ay - cy) * r) pt("Q", cx, cy) pt(" ", cx + sgn(bx - cx) * r, cy + sgn(by - cy) * r) pt("L", bx, by)
  }
  # 丁字和十字：一条直线穿过去，其余的从中心伸出来
  if (index(d, "L") && index(d, "R")) { endp("L", x, y); s = pt("M", EX, EY); endp("R", x, y); m = "UD" }
  else { endp("U", x, y); s = pt("M", EX, EY); endp("D", x, y); m = "LR" }
  s = s pt("L", EX, EY)
  for (i = 1; i <= 2; i++) {
    k = substr(m, i, 1)
    if (index(d, k)) { endp(k, x, y); s = s pt("M", cx, cy) pt("L", EX, EY) }
  }
  return s
}
# 画成路径的符号。不是这些符号的返回空串，当文字画
function glyph(ch, x, y, col, op, cx, cy, o, st) {
  cx = x + CW / 2; cy = y + LH / 2
  o = (op < 1) ? " opacity=\"" op "\"" : ""
  st = " fill=\"none\" stroke=\"" col "\" stroke-linecap=\"round\" stroke-linejoin=\"round\"" o
  if (ch in BOX) return "<path d=\"" boxpath(ch, x, y) "\" fill=\"none\" stroke=\"" col "\" stroke-width=\"" (ch == "━" ? "2.6" : "1.15") "\" stroke-linecap=\"" (ch == "━" ? "butt" : "square") "\" stroke-linejoin=\"round\"" o "/>"
  if (ch == "■") return "<rect x=\"" f(cx - 3.2) "\" y=\"" f(cy - 2.7) "\" width=\"6.4\" height=\"6.4\" rx=\"1\" fill=\"" col "\"" o "/>"
  if (ch == "□") return "<rect x=\"" f(cx - 2.7) "\" y=\"" f(cy - 2.2) "\" width=\"5.4\" height=\"5.4\" rx=\"1\" fill=\"none\" stroke=\"" col "\" stroke-width=\"1.1\"" o "/>"
  if (ch == "✓") return "<path d=\"" pt("M", cx - 3.2, cy + 0.4) pt("L", cx - 0.9, cy + 3) pt("L", cx + 3.4, cy - 3.2) "\" stroke-width=\"1.6\"" st "/>"
  if (ch == "✗") return "<path d=\"" pt("M", cx - 2.9, cy - 2.9) pt("L", cx + 2.9, cy + 2.9) pt("M", cx + 2.9, cy - 2.9) pt("L", cx - 2.9, cy + 2.9) "\" stroke-width=\"1.6\"" st "/>"
  if (ch == "×") return "<path d=\"" pt("M", cx - 2.3, cy - 1.8) pt("L", cx + 2.3, cy + 2.8) pt("M", cx + 2.3, cy - 1.8) pt("L", cx - 2.3, cy + 2.8) "\" stroke-width=\"1.4\"" st "/>"
  if (ch == "→") return "<path d=\"" pt("M", cx - 3.4, cy + 0.5) pt("L", cx + 3.4, cy + 0.5) pt("M", cx + 0.8, cy - 2.3) pt("L", cx + 3.4, cy + 0.5) pt("L", cx + 0.8, cy + 3.3) "\" stroke-width=\"1.3\"" st "/>"
  if (ch == "←") return "<path d=\"" pt("M", cx + 3.4, cy + 0.5) pt("L", cx - 3.4, cy + 0.5) pt("M", cx - 0.8, cy - 2.3) pt("L", cx - 3.4, cy + 0.5) pt("L", cx - 0.8, cy + 3.3) "\" stroke-width=\"1.3\"" st "/>"
  if (ch == "↓") return "<path d=\"" pt("M", cx, cy - 3.4) pt("L", cx, cy + 3.6) pt("M", cx - 2.8, cy + 0.9) pt("L", cx, cy + 3.6) pt("L", cx + 2.8, cy + 0.9) "\" stroke-width=\"1.3\"" st "/>"
  if (ch == "›") return "<path d=\"" pt("M", cx - 1.6, cy - 2.1) pt("L", cx + 1.8, cy + 0.5) pt("L", cx - 1.6, cy + 3.1) "\" stroke-width=\"1.2\"" st "/>"
  if (ch == "·") return "<circle cx=\"" f(cx) "\" cy=\"" f(cy + 0.5) "\" r=\"1.05\" fill=\"" col "\"" o "/>"
  if (ch == "…") return "<circle cx=\"" f(cx - 2.6) "\" cy=\"" f(cy + 4) "\" r=\"0.8\" fill=\"" col "\"" o "/><circle cx=\"" f(cx) "\" cy=\"" f(cy + 4) "\" r=\"0.8\" fill=\"" col "\"" o "/><circle cx=\"" f(cx + 2.6) "\" cy=\"" f(cy + 4) "\" r=\"0.8\" fill=\"" col "\"" o "/>"
  return ""
}
function bgrect(a, b, y, col) {
  return "<rect x=\"" f(PX + a * CW) "\" y=\"" f(y + 1.5) "\" width=\"" f((b - a) * CW) "\" height=\"" (LH - 3) "\" rx=\"3\" fill=\"" col "\"/>\n"
}
# 一行：背景色块先画，字和符号画在上面
function row(s, y, i, j, c, col, x, g, color, op, a, rects, texts, rbg, rstart) {
  FGC = ""; BGC = ""; BOLD = 0; DIMM = 0
  i = 1; col = 0; rects = ""; texts = ""; rbg = ""; rstart = 0
  while (i <= length(s)) {
    c = substr(s, i, 1)
    if (c == E) {
      j = i + 1
      while (j <= length(s) && substr(s, j, 1) !~ /[A-Za-z]/) j++
      if (substr(s, i + 1, 1) == "[" && substr(s, j, 1) == "m") sgr(substr(s, i + 2, j - i - 2))
      i = j + 1
      continue
    }
    i = nextc(s, i)
    if (BGC != rbg) {
      if (rbg != "") rects = rects bgrect(rstart, col, y, rbg)
      rbg = BGC; rstart = col
    }
    if (CH != " ") {
      x = PX + col * CW
      color = (FGC != "") ? FGC : FG
      op = (DIMM && FGC == "") ? 0.55 : 1
      g = glyph(CH, x, y, color, op)
      if (g == "") {
        a = " x=\"" f(x + CWD * CW / 2) "\" y=\"" f(y + LH * 0.72) "\" text-anchor=\"middle\" fill=\"" color "\""
        if (CWD == 2) a = a " font-size=\"15.4\""
        if (BOLD) a = a " font-weight=\"700\""
        if (op < 1) a = a " opacity=\"" op "\""
        g = "<text" a ">" esc(CH) "</text>"
      }
      texts = texts g "\n"
    }
    col += CWD
  }
  if (rbg != "") rects = rects bgrect(rstart, col, y, rbg)
  printf "%s%s", rects, texts
}
END {
  first = 1
  while (first <= n && plain(L[first]) ~ /^ *$/) first++
  last = n
  while (last >= first && plain(L[last]) ~ /^ *$/) last--
  cols = 78
  for (r = first; r <= last; r++) { w = width(L[r]); if (w > cols) cols = w }
  top = (TITLE != "") ? BAR : 0
  W = int(PX * 2 + cols * CW + 0.5); H = int(top + PY * 2 + (last - first + 1) * LH + 0.5)
  printf "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" font-family=\"%s\" font-size=\"14\">\n", W, H, W, H, FONT
  printf "<rect x=\"0.5\" y=\"0.5\" width=\"%d\" height=\"%d\" rx=\"10\" fill=\"%s\" stroke=\"%s\"/>\n", W - 1, H - 1, BG, FRAME
  if (TITLE != "") {
    printf "<path d=\"M0.5,%dH%.1f\" stroke=\"%s\"/>\n", BAR, W - 0.5, FRAME
    printf "<circle cx=\"20\" cy=\"15\" r=\"5.5\" fill=\"#ff5f57\"/><circle cx=\"38\" cy=\"15\" r=\"5.5\" fill=\"#febc2e\"/><circle cx=\"56\" cy=\"15\" r=\"5.5\" fill=\"#28c840\"/>\n"
    printf "<text x=\"%d\" y=\"19.5\" text-anchor=\"middle\" fill=\"#8b90a0\" font-size=\"12.5\">%s</text>\n", W / 2, esc(TITLE)
  }
  for (r = first; r <= last; r++) row(L[r], top + PY + (r - first) * LH)
  print "</svg>"
}
AWK
  awk -v TITLE="${2:-}" -f "$WORK/svg.awk" "$1"
}

# -i：把概览存成一张图片，IP 默认打码。有 rsvg-convert 和中文字体就转成 PNG，没有就存 SVG
save_image() {
  local dir name why=''
  REPORT_SHARE=1 USE_COLOR=2 report_text > "$WORK/image.ansi" &&
    render_svg "$WORK/image.ansi" ExitRay > "$WORK/image.svg" || { warn "图片没生成出来"; return 0; }
  for dir in "$PWD" "${HOME:-}" "${TMPDIR:-/tmp}"; do
    [[ -n $dir && -d $dir && -w $dir ]] && break
  done
  # exitray-report 开头：仓库的 .gitignore 和隐私检查都把这样的文件当成运行报告，不会被误提交
  name="$dir/exitray-report-$(date +%Y%m%d-%H%M%S)"
  if ! command -v rsvg-convert >/dev/null 2>&1; then
    why='没有 rsvg-convert'
  elif ! has_cjk_font; then
    why='没有中文字体'
  elif rsvg-convert -z 2 -o "$name.png" "$WORK/image.svg" 2>/dev/null && [[ -s $name.png ]]; then
    printf '  图片已保存：%s\n' "$name.png" >&2
    return 0
  else
    why='rsvg-convert 转换失败'
    rm -f "$name.png"
  fi
  cp "$WORK/image.svg" "$name.svg" && printf '  图片已保存：%s（%s，存成了 SVG，用浏览器打开）\n' "$name.svg" "$why" >&2
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
  if (( ($# == 0 || ($# == 1 && IMAGE)) && STDIN_TTY )) && [[ -t 1 && -r /dev/tty ]]; then
    show_menu
  fi
  (( LOW_RESOURCE )) && low_resource
  # 菜单选完才知道要不要路由工具和 dig
  install_deps
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/exitray.XXXXXX") || die "建不了临时目录"
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
  check_intercept
  step_end "$BASE_IP$([[ $REGION == none ]] || printf ' · 地区 %s' "$REGION")"
  (( HOST_SNIFF )) && ui_warn "有透明代理按 HTTP 的 Host 改写目的地：测到的是代理的分流，不是线路本身的"
  step_begin "准备探测"
  load_targets
  detect_tracer
  local count est eta route=$TRACER
  count=$(ui_lines "$WORK/targets.txt")
  # 加密 DNS 那一轮每个目标平均要测两个左右的 IP，连不上的还要复测；按 HiNet、Seednet 实测的用时定的系数
  est=$(( count * (ROUNDS + USE_DNS_TEST * 2) * 4 / PARALLEL + 15 ))
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
  # 嗅探放在复测前面：换了 SNI 才出现、又只出现一次的出口，也要复测过才算数
  run_sniff
  run_retest
  step_begin "收集环境信息"
  # 查询来源和 IPv6 这两项多半是在等超时，放到后台，和下面的稳定性检查同时做
  dns_query_exits &
  [[ -n $PROXY ]] || ipv6_exit > "$WORK/ipv6.txt" &
  # 结束前再问几次基线回显：检测期间出口 IP 换了，前后两轮的对比就不能当成分流
  stability_check e 3
  wait_all
  env_info
  analyze
  settle_triggers
  judge
  step_end "完成"
  lookup_exits
  ui_finish
  if (( JSON )); then
    report_json
  elif (( MARKDOWN )); then
    report_share markdown
  elif (( SUMMARY )); then
    report_share summary
  else
    report_text
    printf '\n'
  fi
  (( IMAGE )) && save_image
  (( EXIT_CODE )) && exit "$(exit_status)"
  return 0
}

# 测试时只加载函数
[[ ${EXITRAY_SOURCE_ONLY:-0} == 1 ]] && return 0

# 脚本可能经 bash -s 从 stdin 读入，子命令不能碰 stdin
[[ -t 0 ]] && STDIN_TTY=1
main "$@" </dev/null
