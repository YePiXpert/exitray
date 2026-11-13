#!/usr/bin/env bash
#
# splitcheck 已改名为 ExitRay，脚本是 exitray.sh。
#
# 留着这个文件，是为了让改名前的命令继续可用：旁边有 exitray.sh 就运行它；没有（旧的一键命令
# bash <(curl …/splitcheck.sh) 就是这样）就把 exitray.sh 下载来运行。参数原样传下去。

if [ -z "${BASH_VERSION:-}" ]; then
  echo "splitcheck: 请用 bash 运行" >&2
  exit 1
fi

url='https://raw.githubusercontent.com/YePiXpert/exitray/main/exitray.sh'
echo "splitcheck 已改名为 ExitRay，这条旧命令还能用。新命令：bash <(curl -fsSL $url)" >&2

src=${BASH_SOURCE[0]:-}
if [[ -f $src ]]; then
  dir=$(cd "$(dirname "$src")" && pwd)
  [[ -f $dir/exitray.sh ]] && exec "$BASH" "$dir/exitray.sh" "$@"
fi
# 先下载完再运行：下载失败时报错，不拿半截脚本去跑
code=$(curl -fsSL "$url") && [[ -n $code ]] || { echo "splitcheck: 下载不了 $url" >&2; exit 1; }
exec "$BASH" <(printf '%s\n' "$code") "$@"
