#!/usr/bin/env bash
# MeshLink agent — 在 Linux 节点上运行的客户端
#
# 安装:  curl -fsSL https://<你的域名>/agent.sh | sudo bash -s -- install --server https://<你的域名> --token <令牌>
# Docker: 见后台“添加节点”里的 Docker / iStoreOS 标签
# 其他:  meshlink-agent status | sync | stun | upgrade | uninstall
#
# 私钥只在本机生成并保存在 /etc/meshlink/private.key，不会上传。
#
# 连接策略: 优先直连；STUN 探测真实公网端点；直连打不通时由路径管理器 (meshlink-path.py)
# 自动改走 Hub 中转，并持续探测直连是否恢复。没有 python3 时退化为纯直连（旧行为）。

set -uo pipefail

CONF_DIR=/etc/meshlink
ENV_FILE=$CONF_DIR/agent.env
BIN=/usr/local/bin/meshlink-agent
PYBIN=/usr/local/lib/meshlink/meshlink-path.py
UNIT=/etc/systemd/system/meshlink-agent.service
INTERVAL=60
HELPER_PID=""

log() { echo "[meshlink] $*" >&2; }
die() { log "错误: $*"; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "请使用 root 或 sudo 运行"; }

ensure_deps() {
  if ! { command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; }; then
    log "正在安装依赖 (wireguard-tools, curl) ..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y </dev/null >/dev/null
      DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools curl iproute2 </dev/null >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y wireguard-tools curl </dev/null >/dev/null
    elif command -v yum >/dev/null 2>&1; then
      yum install -y epel-release wireguard-tools curl </dev/null >/dev/null
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache wireguard-tools curl bash iproute2 </dev/null >/dev/null
    elif command -v pacman >/dev/null 2>&1; then
      pacman -Sy --noconfirm wireguard-tools curl </dev/null >/dev/null
    else
      die "无法自动安装依赖，请手动安装 wireguard-tools 和 curl 后重试"
    fi
    command -v wg >/dev/null 2>&1 || die "wireguard-tools 安装失败"
  fi
  ensure_python
}

have_python() { command -v python3 >/dev/null 2>&1 && python3 -I -c 'import socket,struct,json,subprocess' >/dev/null 2>&1; }

# python3 只用于 STUN 探测和直连/中转自动切换；装不上不影响基本组网
ensure_python() {
  have_python && return 0
  log "正在安装 python3（用于 STUN 探测与直连/中转自动切换）..."
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 </dev/null >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 </dev/null >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 </dev/null >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 </dev/null >/dev/null 2>&1
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python </dev/null >/dev/null 2>&1
  fi
  have_python || log "警告: 未能安装 python3，将只做直连，不会自动回落到 Hub 中转"
  return 0
}

# 下载路径管理器；失败不致命
fetch_helper() {
  local server="$1" tmp
  have_python || return 0
  mkdir -p "$(dirname "$PYBIN")"
  tmp=$(mktemp) || return 0
  if curl -fsSL --max-time 30 "$server/meshlink-path.py" -o "$tmp" && python3 -I -m py_compile "$tmp" 2>/dev/null; then
    install -m 755 "$tmp" "$PYBIN"
  else
    log "警告: 下载路径管理器失败，跳过（不影响直连）"
  fi
  rm -f "$tmp" "${tmp}c"
}

load_env() {
  [ -f "$ENV_FILE" ] || die "未找到 $ENV_FILE，请先执行 install"
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  : "${SERVER:?}" "${SECRET:?}" "${IFACE:?}"
}

# 拓扑签名: 地址/端口/对端公钥/路由变化时需要重建接口；仅 Endpoint 变化可热更新
conf_sig() {
  grep -E '^(Address|ListenPort|MTU|PostUp|PostDown|AllowedIPs|PublicKey)' "$1" | sha256sum | cut -d' ' -f1
}

# 去掉注释后的签名: 只有注释（对端在线状态等元信息，供路径管理器读取）变化时不需要动隧道
plain_sig() {
  grep -vE '^[[:space:]]*#' "$1" | sha256sum | cut -d' ' -f1
}

iface_down() {
  if ip link show "$IFACE" >/dev/null 2>&1; then
    wg-quick down "$IFACE" >/dev/null 2>&1 && log "接口 $IFACE 已关闭"
  fi
}

apply_config() {
  local src="$1" new="$2" conf="/etc/wireguard/$IFACE.conf" priv
  grep -q '^\[Interface\]' "$src" || { log "收到无效配置，已忽略"; return 1; }

  INTERVAL=$(sed -n 's/^# interval=\([0-9]\{1,4\}\)$/\1/p' "$src" | head -n1)
  INTERVAL=${INTERVAL:-60}

  priv=$(cat "$CONF_DIR/private.key")
  awk -v k="$priv" '{ if ($0 == "PrivateKey = __PRIVATE_KEY__") print "PrivateKey = " k; else print }' "$src" > "$new"

  mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
  if ip link show "$IFACE" >/dev/null 2>&1; then
    [ -f "$conf" ] && cmp -s "$new" "$conf" && return 0
    if [ -f "$conf" ] && [ "$(plain_sig "$new")" = "$(plain_sig "$conf")" ]; then
      install -m 600 "$new" "$conf"   # 只有注释变化: 更新文件即可，不打扰运行中的隧道
    elif [ -f "$conf" ] && [ "$(conf_sig "$new")" = "$(conf_sig "$conf")" ]; then
      install -m 600 "$new" "$conf"
      wg syncconf "$IFACE" <(wg-quick strip "$IFACE") && log "已热更新对端信息"
    else
      install -m 600 "$new" "$conf"
      wg-quick down "$IFACE" >/dev/null 2>&1
      wg-quick up "$IFACE" >/dev/null 2>&1 && log "拓扑已变化，接口已重建" || log "接口重建失败"
    fi
  else
    install -m 600 "$new" "$conf"
    wg-quick up "$IFACE" >/dev/null 2>&1 && log "接口 $IFACE 已启动" || log "接口启动失败，请检查内核是否支持 WireGuard"
  fi
}

# 本机出网用的公网 IPv6（只用于后台展示，不参与隧道）；没有 IPv6 或只有 ULA/链路本地时返回空
local_ipv6() {
  local a
  a=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | sed -n 's/.* src \([0-9a-fA-F:]*\).*/\1/p' | head -n1)
  case "$a" in
    "" | ::1 | fe[89abAB]* | f[cdCD]*) return 0 ;;
  esac
  printf '%s' "$a"
}

# iStoreOS / OpenWrt (fw4/nftables) 默认丢弃“防火墙不认识的接口”的流量：自动放行 WireGuard 接口与监听端口。
# 规则加在 fw4 的 input/forward 链最前面并带 meshlink-agent 备注；防火墙重载后规则会丢，下一次同步（≤1 分钟）自动补回。
# 没有 nft 或没有 fw4 表（普通 Linux）时什么都不做。
fw_ensure() {
  command -v nft >/dev/null 2>&1 || return 0
  ip link show "$IFACE" >/dev/null 2>&1 || return 0
  nft list chain inet fw4 input >/dev/null 2>&1 || return 0
  local port tag="meshlink-agent"
  port=$(sed -n 's/^ListenPort[[:space:]]*=[[:space:]]*\([0-9]\{1,5\}\).*/\1/p' "/etc/wireguard/$IFACE.conf" 2>/dev/null | head -n1)
  if ! nft list chain inet fw4 input 2>/dev/null | grep -q "$tag"; then
    nft "insert rule inet fw4 input iifname \"$IFACE\" accept comment \"$tag\"" 2>/dev/null \
      && log "防火墙(fw4): 已放行 $IFACE 入站"
    [ -n "$port" ] && nft "insert rule inet fw4 input udp dport $port accept comment \"$tag\"" 2>/dev/null \
      && log "防火墙(fw4): 已放行 UDP $port 入站"
  fi
  if ! nft list chain inet fw4 forward 2>/dev/null | grep -q "$tag"; then
    nft "insert rule inet fw4 forward iifname \"$IFACE\" accept comment \"$tag\"" 2>/dev/null \
      && nft "insert rule inet fw4 forward oifname \"$IFACE\" accept comment \"$tag\"" 2>/dev/null \
      && log "防火墙(fw4): 已放行 $IFACE 转发"
  fi
  return 0
}

do_sync() {
  local tmp new code v6 hdr=()
  tmp=$(mktemp) && new=$(mktemp) || return 1
  v6=$(local_ipv6)
  [ -n "$v6" ] && hdr=(-H "X-Meshlink-IPv6: $v6")
  code=$(curl -sS --max-time 20 -o "$tmp" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $SECRET" ${hdr[@]+"${hdr[@]}"} "$SERVER/api/agent/sync" 2>/dev/null) || code=000
  case "$code" in
    200) apply_config "$tmp" "$new"; fw_ensure ;;
    401 | 403) log "节点已被禁用、删除或重置 (HTTP $code)，关闭隧道"; iface_down ;;
    000) log "无法连接控制面，保持现有隧道，稍后重试" ;;
    *) log "控制面返回 HTTP $code，稍后重试" ;;
  esac
  rm -f "$tmp" "$new"
}

cmd_install() {
  need_root
  local server="" token="" iface="meshlink"
  while [ $# -gt 0 ]; do
    case "$1" in
      --server) server="${2%/}"; shift 2 ;;
      --token) token="${2:-}"; shift 2 ;;
      --interface) iface="${2:-meshlink}"; shift 2 ;;
      *) die "未知参数: $1" ;;
    esac
  done
  [ -n "$server" ] && [ -n "$token" ] || die "用法: install --server https://域名 --token 令牌"

  ensure_deps
  umask 077
  mkdir -p "$CONF_DIR"
  [ -f "$CONF_DIR/private.key" ] || wg genkey > "$CONF_DIR/private.key"
  local pub resp secret addr
  pub=$(wg pubkey < "$CONF_DIR/private.key")

  resp=$(curl -fsS --max-time 20 "$server/api/agent/register" \
    --data-urlencode "token=$token" --data-urlencode "public_key=$pub" \
    --data-urlencode "hostname=$(hostname)") || die "注册失败：令牌无效/已使用，或无法连接 $server"
  secret=$(printf '%s\n' "$resp" | sed -n 's/^NODE_SECRET=//p')
  addr=$(printf '%s\n' "$resp" | sed -n 's/^ADDRESS=//p')
  [ -n "$secret" ] || die "注册响应异常: $resp"

  printf 'SERVER=%s\nSECRET=%s\nIFACE=%s\n' "$server" "$secret" "$iface" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  curl -fsSL --max-time 30 "$server/agent.sh" -o "$BIN" || die "下载 agent 失败"
  chmod 755 "$BIN"
  fetch_helper "$server"
  log "注册成功，虚拟地址: $addr"

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat > "$UNIT" <<EOF
[Unit]
Description=MeshLink agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now meshlink-agent >/dev/null 2>&1
    log "已安装并启动 systemd 服务 meshlink-agent（日志: journalctl -u meshlink-agent -f）"
  else
    log "未检测到 systemd。请手动运行: $BIN run &"
    load_env && do_sync
  fi
}

start_helper() {
  [ -f "$PYBIN" ] && have_python || return 0
  if [ -n "$HELPER_PID" ] && kill -0 "$HELPER_PID" 2>/dev/null; then return 0; fi
  python3 -I -u "$PYBIN" run &
  HELPER_PID=$!
}

stop_helper() {
  if [ -n "$HELPER_PID" ]; then
    kill "$HELPER_PID" 2>/dev/null
    wait "$HELPER_PID" 2>/dev/null
  fi
  HELPER_PID=""
}

cmd_run() {
  load_env
  log "agent 启动，控制面: $SERVER"
  mkdir -p /run/meshlink && chmod 700 /run/meshlink
  trap 'stop_helper; exit 0' TERM INT
  while true; do
    start_helper
    do_sync
    # sleep 放后台再 wait，收到 SIGTERM 时 trap 能立刻执行，不用等 sleep 结束
    sleep $((INTERVAL + RANDOM % 5)) &
    wait $! 2>/dev/null
  done
}

cmd_status() {
  load_env
  echo "控制面: $SERVER"
  if ip link show "$IFACE" >/dev/null 2>&1; then
    ip -brief addr show "$IFACE"
    wg show "$IFACE"
    if [ -f "$PYBIN" ] && have_python; then
      echo
      python3 -I "$PYBIN" status
    fi
  else
    echo "接口 $IFACE 未启动"
  fi
}

cmd_stun() {
  [ -f "$PYBIN" ] && have_python || die "未安装路径管理器或 python3，请先执行 upgrade"
  python3 -I "$PYBIN" stun "$@"
}

# 升级 agent 本体和路径管理器（控制面更新后，已安装的节点执行一次即可）
cmd_upgrade() {
  need_root
  load_env
  ensure_deps
  local tmp
  tmp=$(mktemp) || die "无法创建临时文件"
  curl -fsSL --max-time 30 "$SERVER/agent.sh" -o "$tmp" || { rm -f "$tmp"; die "下载 agent 失败"; }
  bash -n "$tmp" || { rm -f "$tmp"; die "下载的 agent 语法检查未通过，已取消升级"; }
  fetch_helper "$SERVER"
  chmod 755 "$tmp"
  mv -f "$tmp" "$BIN"      # 换 inode，不影响正在运行的旧进程
  log "升级完成"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled meshlink-agent >/dev/null 2>&1; then
    systemctl restart meshlink-agent && log "服务已重启"
  else
    log "请手动重启 agent（meshlink-agent run）使新版本生效"
  fi
}

cmd_uninstall() {
  need_root
  if [ -f "$ENV_FILE" ]; then load_env; else IFACE=meshlink; fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now meshlink-agent >/dev/null 2>&1
    rm -f "$UNIT"
    systemctl daemon-reload >/dev/null 2>&1
  fi
  iface_down
  rm -f "/etc/wireguard/$IFACE.conf"
  rm -rf "$CONF_DIR" /run/meshlink "$(dirname "$PYBIN")"
  rm -f "$BIN"
  log "已卸载（请记得在管理后台删除该节点）"
}

# 容器模式（iStoreOS / OpenWrt 的 Docker）：装依赖 → 首次注册（之后复用 /etc/meshlink 里的凭证）→ 前台运行
# 需要环境变量 SERVER、TOKEN；由 docker run 的短命令通过 curl | bash -s -- container 调用
cmd_container() {
  need_root
  : "${SERVER:?缺少环境变量 SERVER}"
  SERVER="${SERVER%/}"
  export DEBIAN_FRONTEND=noninteractive
  if ! command -v wg-quick >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1; then
    apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables nftables procps python3 curl ca-certificates hostname </dev/null \
      || die "依赖安装失败（容器需要能访问 Debian 软件源）"
  fi
  if [ ! -f "$ENV_FILE" ]; then
    : "${TOKEN:?缺少环境变量 TOKEN}"
    cmd_install --server "$SERVER" --token "$TOKEN"
  else
    # 容器被重建过：凭证还在，只需把 agent 程序重新下载回来
    curl -fsSL --max-time 30 "$SERVER/agent.sh" -o "$BIN" || die "下载 agent 失败"
    chmod 755 "$BIN"
    have_python || ensure_python
    fetch_helper "$SERVER"
  fi
  exec "$BIN" run
}

main() {
  local cmd="${1:-}"
  [ $# -gt 0 ] && shift
  case "$cmd" in
    install) cmd_install "$@" ;;
    container) cmd_container ;;
    run) cmd_run ;;
    sync) need_root; load_env; do_sync ;;
    status) cmd_status ;;
    stun) cmd_stun "$@" ;;
    upgrade) cmd_upgrade ;;
    uninstall) cmd_uninstall ;;
    *) echo "用法: $0 {install --server URL --token TOKEN | run | sync | status | stun | upgrade | uninstall}"; exit 1 ;;
  esac
}

main "$@"
