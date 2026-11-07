#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MeshLink 路径管理器 —— 由 meshlink-agent 拉起，与 WireGuard 配合工作。

做三件事:
  1. STUN 端口探测: 用 WireGuard 的监听端口向 STUN 服务器探测 NAT 后面真实的公网 ip:port，
     并判断 NAT 类型（public / cone / symmetric），上报控制面；其他节点用这个端点来直连。
  2. 直连优先: 每个对端默认直连；双方都有公网 IPv6 时先走 IPv6，握手不成功再改试 IPv4，
     两个都不通（或已建立的会话长时间收不到包）才判定直连失败。
  3. 自动回落: 直连失败的对端，把它的 AllowedIPs 挪到 Hub 上，流量经 Hub 中转；之后定期探测，
     直连恢复后自动切回。

只依赖 Python 3.6+ 标准库、wg 和 curl。用法:
  meshlink-path.py run        守护进程（agent 调用）
  meshlink-path.py status     显示当前 NAT 与各对端路径
  meshlink-path.py stun [port]  单次 STUN 探测（不动 WireGuard，用随机端口）
"""
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

ENV_FILE = '/etc/meshlink/agent.env'
RUN_DIR = '/run/meshlink'
STATUS_FILE = RUN_DIR + '/status.json'

DEFAULT_STUN = [
    'stun.cloudflare.com:3478',
    'stun.l.google.com:19302',
    'stun1.l.google.com:19302',
    'stun.miwifi.com:3478',
]

TICK = 5               # 秒；主循环间隔
STUN_INTERVAL = 300    # 秒；STUN 重新探测 / 定期上报间隔
STUN_MIN_GAP = 60      # 秒；两次 STUN 探测的最小间隔
STUN_BUDGET = 4.0      # 秒；一次探测的总时限（期间 WireGuard 端口被短暂让出）
GRACE = 40             # 秒；新对端握手不成功多久判定直连失败
GRACE_SYM = 15         # 秒；任一端是对称 NAT 时缩短等待（基本不可能打通）
GRACE_V6 = 20          # 秒；IPv6 没有 NAT，打不通多半是防火墙拦了入站，缩短等待尽快改试 IPv4
RX_STALL = 75          # 秒；已建立的会话超过这么久没有收到任何包判定失效（正常至少每 25 秒一个保活包）
SESSION_MAX = 180      # 秒；WireGuard 会话最长有效期，握手超过这个时间视为没有会话
PROBE_EVERY = 45       # 秒；中转状态下每隔多久主动触发一次直连握手探测
RELAY_MIN_DWELL = 30   # 秒；进入中转后至少停留多久才允许切回直连
RECOVER_FRESH = 60     # 秒；切回直连要求握手新鲜度
RECOVER_OK = 2         # 连续几次检查都满足才切回，防抖
REPORT_HEARTBEAT = 900  # 秒；状态没变化时的心跳上报间隔（控制面 30 分钟后视 STUN 结果过期）
REPORT_MIN_GAP = 5
REPORT_RETRY = 30


def out(s=''):
    sys.stdout.buffer.write((s + '\n').encode('utf-8'))
    sys.stdout.buffer.flush()


def log(msg):
    sys.stderr.buffer.write(('[meshlink-path] %s\n' % msg).encode('utf-8'))
    sys.stderr.buffer.flush()


# ───────────────────────── STUN ─────────────────────────

MAGIC = 0x2112A442


def stun_request():
    tid = os.urandom(12)
    return struct.pack('>HHI', 0x0001, 0, MAGIC) + tid, tid


def stun_parse(data, tid):
    """解析 Binding Success Response，返回 (ip, port) 或 None。"""
    if len(data) < 20:
        return None
    mtype, mlen, magic = struct.unpack('>HHI', data[:8])
    if mtype != 0x0101 or magic != MAGIC or data[8:20] != tid:
        return None
    pos, end, legacy = 20, min(len(data), 20 + mlen), None
    while pos + 4 <= end:
        atype, alen = struct.unpack('>HH', data[pos:pos + 4])
        val = data[pos + 4:pos + 4 + alen]
        if atype == 0x0020 and alen >= 8 and val[1] == 1:       # XOR-MAPPED-ADDRESS (IPv4)
            port = struct.unpack('>H', val[2:4])[0] ^ (MAGIC >> 16)
            ip = struct.unpack('>I', val[4:8])[0] ^ MAGIC
            return socket.inet_ntoa(struct.pack('>I', ip)), port
        if atype == 0x0001 and alen >= 8 and val[1] == 1 and legacy is None:  # MAPPED-ADDRESS（老服务器）
            legacy = (socket.inet_ntoa(val[4:8]), struct.unpack('>H', val[2:4])[0])
        pos += 4 + ((alen + 3) & ~3)
    return legacy


def stun_resolve(servers):
    """把 host:port 解析成 [(ip, port)]，按不同 IP 去重。放在让出端口之前做，避免 DNS 慢拖长空档期。"""
    addrs, seen = [], set()
    for item in servers:
        host, _, port = item.strip().rpartition(':')
        if not host or not port.isdigit():
            continue
        try:
            ip = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
        except OSError:
            continue
        if ip not in seen:
            seen.add(ip)
            addrs.append((ip, int(port)))
    return addrs


def stun_probe(local_port, addrs, per_try=1.0, tries=2, budget=STUN_BUDGET, want=2):
    """从 local_port 依次向不同的 STUN 服务器发 Binding Request。
    返回 [(server_ip, mapped_ip, mapped_port)]，拿到 want 个结果或超时即停。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    results = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', local_port))
        deadline = time.time() + budget
        for addr in addrs:
            if len(results) >= want or time.time() >= deadline:
                break
            got = None
            for _ in range(tries):
                req, tid = stun_request()
                try:
                    sock.sendto(req, addr)
                except OSError:
                    break
                t_end = min(time.time() + per_try, deadline)
                while got is None and time.time() < t_end:
                    sock.settimeout(max(0.05, t_end - time.time()))
                    try:
                        data, frm = sock.recvfrom(2048)
                    except socket.timeout:
                        break
                    except OSError:
                        break
                    if frm[0] == addr[0]:
                        got = stun_parse(data, tid)   # 端口上偶尔会收到别的包（比如 WG 流量），忽略即可
                if got:
                    break
            if got:
                results.append((addr[0], got[0], got[1]))
    finally:
        sock.close()
    return results


def local_ip_for(dest_ip):
    """到 dest_ip 的出口本机地址（UDP connect 不会真的发包）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def stun_classify(results, local_ip):
    """返回 (端点 'ip:port' 或 None, nat 类型)。
    public    映射地址就是本机地址（有公网 IP，没有 NAT）
    cone      不同服务器看到同一个映射（端点无关映射，适合打洞）
    symmetric 不同服务器看到不同端口（对称 NAT，两端都是它基本打不通）
    unknown   只有一个服务器响应，无法判断"""
    if not results:
        return None, 'unknown'
    ip, port = results[0][1], results[0][2]
    endpoint = '%s:%d' % (ip, port)
    if local_ip and ip == local_ip:
        return endpoint, 'public'
    if len(results) < 2:
        return endpoint, 'unknown'
    same = all((r[1], r[2]) == (ip, port) for r in results)
    return endpoint, 'cone' if same else 'symmetric'


# ───────────────────────── 配置 / wg 输出解析 ─────────────────────────

META_RE = re.compile(r'^#\s*meshlink\s+(self|peer)\s+(.*)$')


def parse_conf(text):
    """解析控制面下发的配置。返回 (self_meta, peers)。
    peers: [{pub, allowed, endpoint, keepalive, name, meta}]"""
    selfm, peers, cur, section = {}, [], None, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = META_RE.match(line)
        if m:
            meta = dict(kv.split('=', 1) for kv in m.group(2).split() if '=' in kv)
            if m.group(1) == 'self':
                selfm.update(meta)
            elif cur is not None:
                cur['meta'].update(meta)
            continue
        if line.startswith('#'):
            if cur is not None and not cur['name']:
                cur['name'] = line.lstrip('#').strip()
            continue
        if line.startswith('['):
            section = line.strip('[] ').lower()
            if section == 'peer':
                cur = {'pub': None, 'allowed': [], 'endpoint': '', 'keepalive': '25', 'name': '', 'meta': {}}
                peers.append(cur)
            else:
                cur = None
            continue
        if '=' not in line:
            continue
        k, v = [x.strip() for x in line.split('=', 1)]
        k = k.lower()
        if section == 'interface':
            if k == 'listenport':
                selfm['listen_port'] = v
        elif cur is not None:
            if k == 'publickey':
                cur['pub'] = v
            elif k == 'allowedips':
                cur['allowed'] += [x.strip() for x in v.split(',') if x.strip()]
            elif k == 'endpoint':
                cur['endpoint'] = v
            elif k == 'persistentkeepalive':
                cur['keepalive'] = v
    return selfm, [p for p in peers if p['pub']]


def ep_is_v6(ep):
    """'[2408::1]:51820' -> True；'1.2.3.4:51820' -> False"""
    return bool(ep) and (ep.startswith('[') or ep.count(':') > 1)


def grace_for(ep, sym):
    """握手宽限期: IPv6 端点没有 NAT 问题，用较短的；IPv4 遇到对称 NAT 更短（基本打不通）。"""
    if ep and ep_is_v6(ep):
        return GRACE_V6
    return GRACE_SYM if sym else GRACE


def candidates(peer):
    """控制面在双方都有 IPv6 时才会下发 ep6 / ep4，返回按优先级排好的 [IPv6 端点, IPv4 端点]；否则 []（沿用 Endpoint 行）。"""
    m = peer['meta']
    c = [m.get('ep6'), m.get('ep4')]
    return c if all(c) else []


def parse_dump(text):
    """解析 `wg show <if> dump`。返回 (dev, {pub: {endpoint, allowed, hs, rx, tx}}) 或 None。"""
    lines = [l for l in text.split('\n') if l.strip()]
    if not lines:
        return None
    first = lines[0].split('\t')
    dev = {'listen_port': int(first[2]) if len(first) > 2 and first[2].isdigit() else 0}
    peers = {}
    for ln in lines[1:]:
        f = ln.split('\t')
        if len(f) < 8:
            continue
        peers[f[0]] = {
            'endpoint': f[2],
            'allowed': [] if f[3] == '(none)' else f[3].split(','),
            'hs': int(f[4] or 0), 'rx': int(f[5] or 0), 'tx': int(f[6] or 0),
        }
    return dev, peers


class Wg:
    def __init__(self, iface):
        self.iface = iface

    def _run(self, args):
        try:
            r = subprocess.run(['wg'] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return r if r.returncode == 0 else None

    def dump(self):
        r = self._run(['show', self.iface, 'dump'])
        return parse_dump(r.stdout) if r else None

    def set_allowed(self, changes):
        args = ['set', self.iface]
        for pub, lst in changes.items():
            args += ['peer', pub, 'allowed-ips', ','.join(lst)]
        return self._run(args) is not None

    def set_endpoint(self, pub, endpoint):
        return self._run(['set', self.iface, 'peer', pub, 'endpoint', endpoint]) is not None

    def set_listen_port(self, port):
        return self._run(['set', self.iface, 'listen-port', str(port)]) is not None

    def kick(self, pub, keepalive):
        """关掉再打开 persistent-keepalive，内核会立刻发一个保活包，没有会话时就触发握手。
        （WireGuard 握手重试 90 秒后会放弃，中转期间没有数据流量，必须靠这个主动探测。）"""
        self._run(['set', self.iface, 'peer', pub, 'persistent-keepalive', '0'])
        return self._run(['set', self.iface, 'peer', pub, 'persistent-keepalive', keepalive or '25']) is not None


# ───────────────────────── 路径状态机 ─────────────────────────

class PathManager:
    """每个对端 direct / relay 两种状态，纯逻辑，不碰系统，方便测试。

    direct → relay: 该对端在线，且
        - 没有有效会话，且超过宽限期仍未握手；或
        - 有会话但 RX_STALL 秒没收到任何包
      并且至少有一个 Hub 当前可达（否则是本机断网或 Hub 故障，切过去也没用）。
    relay → direct: 进入中转之后出现了新的握手，且握手足够新，连续 RECOVER_OK 次检查成立。"""

    def __init__(self):
        self.st = {}      # 直连/中转状态（仅非 Hub 对端、mesh 模式）
        self.fam = {}     # IPv6 / IPv4 端点选择状态（所有拿到 ep6+ep4 的对端，含 Hub）

    def preload(self, modes, t):
        for pub, mode in (modes or {}).items():
            if mode == 'relay':
                self.st[pub] = self._new(t, 'relay')

    @staticmethod
    def _new(t, mode='direct'):
        return {'mode': mode, 'since': t, 'rx_t': t, 'rx': None, 'relay_at': t if mode == 'relay' else 0,
                'ok': 0, 'probe_at': t, 'ep': None}

    def tick(self, t, selfm, peers, dump, self_nat):
        desired = {p['pub']: list(p['allowed']) for p in peers}
        res = {'desired': desired, 'kicks': [], 'labels': {}, 'newly_relayed': False, 'events': [], 'relay_hub': None,
               'endpoints': {}}
        hubs = [p for p in peers if p['meta'].get('hub') == '1']
        managed = selfm.get('mode', 'mesh') == 'mesh' and selfm.get('hub') != '1' and bool(hubs)
        if not managed:
            self.st.clear()

        live = {p['pub'] for p in peers}
        for k in [k for k in self.st if k not in live]:
            del self.st[k]
        for k in [k for k in self.fam if k not in live]:
            del self.fam[k]

        # 先做 IPv6 / IPv4 端点选择（对所有对端生效，不管是不是 mesh 模式、是不是 Hub）
        for p in peers:
            sym = 'symmetric' in (self_nat, p['meta'].get('nat'))
            self._family(t, p, dump.get(p['pub']), sym, managed and p['meta'].get('hub') != '1', res)
        if not managed:
            return res

        def age(pub):
            hs = dump.get(pub, {}).get('hs', 0)
            return (t - hs) if hs else None

        fresh_hubs = [h for h in hubs if age(h['pub']) is not None and age(h['pub']) < SESSION_MAX]
        hub_ok = bool(fresh_hubs)
        relay_hub = (fresh_hubs or hubs)[0]
        res['relay_hub'] = relay_hub['pub']

        for p in peers:
            if p['meta'].get('hub') == '1':
                continue
            pub, d = p['pub'], dump.get(p['pub'])
            if d is None:
                continue
            s = self.st.get(pub)
            if s is None:
                s = self.st[pub] = self._new(t)
            if s['ep'] != p['endpoint']:
                if s['ep'] is not None and s['mode'] == 'direct':
                    s['since'] = s['rx_t'] = t          # 对端地址变了，重新给一个宽限期
                s['ep'] = p['endpoint']
            if s['rx'] is None or d['rx'] != s['rx']:   # 接口重建后计数器会归零，不等也算变化
                s['rx'], s['rx_t'] = d['rx'], t

            a = age(pub)
            ff = self.fam.get(pub)
            have = a is not None and a < SESSION_MAX and (ff is None or d['hs'] >= ff['sw'])   # 切换 IPv6/IPv4 之前的旧握手不算
            online = p['meta'].get('online', '1') == '1'
            sym = 'symmetric' in (self_nat, p['meta'].get('nat'))

            if s['mode'] == 'direct':
                if not online:
                    s['since'] = s['rx_t'] = t          # 对端离线不算直连失败，上线后重新计时
                else:
                    f = self.fam.get(pub)
                    cur_ep = f['cands'][f['fi']] if f else None
                    if have:
                        dead = t - s['rx_t'] > RX_STALL
                        why = '已建立的会话 %ds 没有收到任何包' % RX_STALL
                    else:
                        dead = t - s['since'] > grace_for(cur_ep, sym)
                        why = '握手超时%s' % ('（存在对称 NAT）' if sym and not (cur_ep and ep_is_v6(cur_ep)) else '')
                    if f and f['tried'] < len(f['cands']):
                        dead = False                    # IPv6 / IPv4 还有没试过的，先别走中转
                    if dead and hub_ok:
                        s.update(mode='relay', relay_at=t, ok=0, probe_at=t)
                        res['newly_relayed'] = True
                        res['events'].append('对端 %s 直连失败（%s），改走 Hub 中转' % (p['name'] or pub[:8], why))
            else:
                fresh = d['hs'] > s['relay_at'] and a is not None and a < RECOVER_FRESH
                s['ok'] = s['ok'] + 1 if (fresh and t - s['relay_at'] >= RELAY_MIN_DWELL) else 0
                if s['ok'] >= RECOVER_OK:
                    s.update(mode='direct', since=t, rx_t=t, ok=0)
                    f = self.fam.get(pub)
                    if f:
                        f.update(tried=1, since=t, rx_t=t, sw=0)
                    res['events'].append('对端 %s 直连已恢复，切回直连' % (p['name'] or pub[:8]))
                elif t - s['probe_at'] >= PROBE_EVERY:
                    s['probe_at'] = t
                    f = self.fam.get(pub)
                    if f:                               # 每次探测换一族，IPv6 / IPv4 轮流试
                        f['fi'] = (f['fi'] + 1) % len(f['cands'])
                        f['sw'] = t
                        f['applied'] = f['cands'][f['fi']]
                        res['endpoints'][pub] = f['applied']
                    res['kicks'].append(pub)

            res['labels'][pub] = 'r' if s['mode'] == 'relay' else ('d' if have else 'p')

        moved = []
        for p in peers:
            s = self.st.get(p['pub'])
            if s and s['mode'] == 'relay' and p['meta'].get('hub') != '1':
                desired[p['pub']] = []                  # 一个 IP 只能属于一个对端: 从直连对端摘掉，挂到 Hub 上
                moved += p['allowed']
        if moved:
            desired[relay_hub['pub']] = list(dict.fromkeys(relay_hub['allowed'] + moved))
        return res

    # ---- IPv6 优先、IPv4 兜底 ----
    def _family(self, t, p, d, sym, relayable, res):
        """双方都有 IPv6 时先试 IPv6（没有 NAT，通了就是真直连），一个握手宽限期内没通再改试 IPv4。
        两个都试过仍不通，relayable 的对端交给下面的中转逻辑；Hub / 非 mesh 模式没有中转可退，就持续轮换。
        返回 True 表示该对端启用了族选择。"""
        pub = p['pub']
        cands = candidates(p)
        if not cands or d is None:
            self.fam.pop(pub, None)
            return False
        hs = d['hs']
        age = (t - hs) if hs else None
        live = age is not None and age < SESSION_MAX
        f = self.fam.get(pub)
        if f is None or f['cands'] != cands:
            f = {'cands': cands, 'fi': 0, 'tried': 1, 'since': t, 'rx': None, 'rx_t': t, 'sw': 0, 'applied': None}
            cur = d.get('endpoint') or ''
            if live and cur not in ('', '(none)'):
                # agent 重启或端点信息刷新时已经有会话在跑: 沿用它正在用的那一族，不去打断
                for i, c in enumerate(cands):
                    if ep_is_v6(c) == ep_is_v6(cur):
                        f['fi'], f['applied'] = i, c
                        break
            self.fam[pub] = f
        if f['rx'] is None or d['rx'] != f['rx']:
            f['rx'], f['rx_t'] = d['rx'], t
        s = self.st.get(pub)
        in_relay = bool(s and s['mode'] == 'relay')
        online = p['meta'].get('online', '1') == '1'
        have = live and hs >= f['sw']          # 必须是切换端点之后才出现的握手，才算这一族通了
        cur_ep = cands[f['fi']]
        name = p['name'] or pub[:8]

        dead = False
        if not online:
            f['since'] = f['rx_t'] = t
        elif have:
            if t - f['rx_t'] > RX_STALL:
                dead = True
            else:
                f['tried'] = 1
        else:
            dead = t - f['since'] > grace_for(cur_ep, sym)
        if dead and not in_relay and (not relayable or f['tried'] < len(cands)):
            nxt = (f['fi'] + 1) % len(cands)
            res['events'].append('对端 %s 经 %s 直连失败，改试 %s' % (
                name, 'IPv6' if ep_is_v6(cur_ep) else 'IPv4', 'IPv6' if ep_is_v6(cands[nxt]) else 'IPv4'))
            f.update(fi=nxt, tried=f['tried'] + 1, since=t, rx_t=t, sw=t)
            if s:
                s['since'] = s['rx_t'] = t
            cur_ep = cands[nxt]
            have = False

        need = f['applied'] != cur_ep
        if not need and not have:
            seen = d.get('endpoint') or ''
            # wg syncconf 会把端点重置成配置文件里的地址: 没有可用会话时，族对不上就重新设回来
            need = seen not in ('', '(none)') and ep_is_v6(seen) != ep_is_v6(cur_ep)
        if need:
            res['endpoints'][pub] = cur_ep
            f['applied'] = cur_ep
        return True

    def fam_unapply(self, pub):
        """wg set endpoint 失败时调用: 下一次 tick 重试。"""
        if pub in self.fam:
            self.fam[pub]['applied'] = None

    def endpoint_family(self, pub):
        f = self.fam.get(pub)
        return None if not f else ('v6' if ep_is_v6(f['cands'][f['fi']]) else 'v4')

    def modes(self):
        return {k: v['mode'] for k, v in self.st.items()}


# ───────────────────────── 守护进程 ─────────────────────────

def load_env(path=ENV_FILE):
    env = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                env[k.strip()] = v.strip()
    return env


def http_report(server, secret, endpoint, nat, paths):
    """用 curl 上报（与 agent 同一套网络/证书环境）；令牌走 stdin 的 curl 配置，不出现在进程参数里。"""
    cfg = 'header = "Authorization: Bearer %s"\n' % secret
    cmd = ['curl', '-sS', '--max-time', '15', '-o', '/dev/null', '-w', '%{http_code}', '-K', '-', '-X', 'POST',
           '--data-urlencode', 'stun=' + endpoint, '--data-urlencode', 'nat=' + nat,
           '--data-urlencode', 'paths=' + paths, server.rstrip('/') + '/api/agent/report']
    try:
        r = subprocess.run(cmd, input=cfg, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.stdout.strip() == '200'


class Daemon:
    def __init__(self, iface, server, secret, conf_path, stun_servers=None, wg=None, report_fn=None,
                 stun_fn=None, clock=time.time, status_file=STATUS_FILE):
        self.iface, self.server, self.secret = iface, server, secret
        self.conf_path, self.status_file = conf_path, status_file
        self.stun_servers = stun_servers or DEFAULT_STUN
        self.wg = wg or Wg(iface)
        self.report_fn = report_fn or (lambda e, n, p: http_report(server, secret, e, n, p))
        self.stun_fn = stun_fn or self._real_stun
        self.now = clock
        self.pm = PathManager()
        self.endpoint, self.nat = None, 'unknown'
        self.stun_fail = 0
        self.last_stun = 0.0
        self.next_stun = 0.0
        self.reported, self.last_report, self.last_try = None, 0.0, 0.0
        self.paths_str = ''
        self.last_labels = {}
        self._conf_cache = (None, None)
        self.pm.preload(self._load_modes(), self.now())

    # ---- 状态持久化: 重启 agent 时保持已经在中转的对端，不要先切回直连再重新检测 ----
    def _load_modes(self):
        try:
            with open(self.status_file, encoding='utf-8') as f:
                return json.load(f).get('modes', {})
        except (OSError, ValueError):
            return {}

    def _write_status(self, t, peers, dump, labels):
        rows = []
        for p in peers:
            d = dump.get(p['pub'], {})
            rows.append({'id': p['meta'].get('id'), 'name': p['name'], 'pub': p['pub'],
                         'hub': p['meta'].get('hub') == '1', 'state': labels.get(p['pub'], ''),
                         'hs_age': int(t - d['hs']) if d.get('hs') else None, 'nat': p['meta'].get('nat', 'unknown'),
                         'family': self.pm.endpoint_family(p['pub']) or
                                   (('v6' if ep_is_v6(d.get('endpoint')) else 'v4') if d.get('endpoint') not in (None, '', '(none)') else '')})
        data = {'ts': int(t), 'nat': self.nat, 'endpoint': self.endpoint, 'peers': rows, 'modes': self.pm.modes()}
        try:
            os.makedirs(os.path.dirname(self.status_file), mode=0o700, exist_ok=True)
            tmp = self.status_file + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, self.status_file)
        except OSError:
            pass

    # ---- STUN ----
    def _real_stun(self, port, rebind):
        addrs = stun_resolve(self.stun_servers)           # 先解析 DNS，再让出端口
        if not addrs:
            return [], None
        local_ip = local_ip_for(addrs[0][0])
        if rebind:
            # WireGuard 占着监听端口；先让它临时换到随机端口，探测完立刻换回来（空档期 < 几秒，WG 会自动重连）
            if not self.wg.set_listen_port(0):
                return [], local_ip
        try:
            return stun_probe(port, addrs), local_ip
        finally:
            if rebind:
                for _ in range(5):
                    if self.wg.set_listen_port(port):
                        break
                    time.sleep(0.2)

    def stun_due(self, t, selfm):
        if selfm.get('hub') == '1' or selfm.get('override') == '1':
            return False          # Hub / 手动指定了对外地址的节点，端点由管理员保证，不用探测也不干扰端口
        if t - self.last_stun < STUN_MIN_GAP:
            return False
        return t >= self.next_stun

    def run_stun(self, t, port):
        self.last_stun = t
        self.next_stun = t + STUN_INTERVAL
        results, local_ip = self.stun_fn(port, True)
        endpoint, nat = stun_classify(results, local_ip)
        if endpoint:
            self.stun_fail = 0
            if (endpoint, nat) != (self.endpoint, self.nat):
                log('STUN: 公网端点 %s，NAT 类型 %s' % (endpoint, nat))
            self.endpoint, self.nat = endpoint, nat
        else:
            self.stun_fail += 1
            log('STUN 探测失败（第 %d 次），UDP 出站被拦截或 STUN 服务器不可达' % self.stun_fail)
            if self.stun_fail >= 3:
                self.endpoint, self.nat = None, 'unknown'

    # ---- 上报 ----
    def maybe_report(self, t):
        """状态变化立即上报；没变化也每 REPORT_HEARTBEAT 秒上报一次（控制面据此判断 STUN 结果是否过期）。"""
        snap = (self.endpoint or '', self.nat, self.paths_str)
        if snap == self.reported and t - self.last_report < REPORT_HEARTBEAT:
            return
        failed_before = self.last_try > self.last_report
        if t - self.last_try < (REPORT_RETRY if failed_before else REPORT_MIN_GAP):
            return
        self.last_try = t
        if self.report_fn(*snap):
            self.reported, self.last_report = snap, t

    # ---- 主流程 ----
    def load_conf(self):
        try:
            mt = os.stat(self.conf_path).st_mtime
            if self._conf_cache[0] != mt:
                with open(self.conf_path, encoding='utf-8') as f:
                    self._conf_cache = (mt, parse_conf(f.read()))
            return self._conf_cache[1]
        except OSError:
            return None

    def tick(self):
        t = self.now()
        conf = self.load_conf()
        if conf is None:
            return
        selfm, peers = conf
        d = self.wg.dump()
        if d is None:
            return                # 接口没起来，等 agent 下一次同步
        dev, dump = d
        port = int(selfm.get('listen_port') or 0)
        if port and dev['listen_port'] != port:
            self.wg.set_listen_port(port)       # 上次探测被打断时兜底，确保监听端口回到配置值

        if selfm.get('hub') == '1':
            self.nat = 'public'
        if port and self.stun_due(t, selfm):
            self.run_stun(t, port)
            d = self.wg.dump()
            if d is None:
                return
            dev, dump = d

        res = self.pm.tick(t, selfm, peers, dump, self.nat)
        for ev in res['events']:
            log(ev)
        if res['newly_relayed']:
            self.next_stun = min(self.next_stun, t)   # 可能是自己的映射变了，尽快重新探测一次
        changes = {pub: lst for pub, lst in res['desired'].items()
                   if pub in dump and set(lst) != set(dump[pub]['allowed'])}
        if changes:
            self.wg.set_allowed(changes)
        for pub, ep in res['endpoints'].items():
            if pub not in dump:
                continue
            if self.wg.set_endpoint(pub, ep):
                log('对端 %s 端点切到 %s（%s）' % (next((p['name'] for p in peers if p['pub'] == pub), pub[:8]), ep,
                                                  'IPv6' if ep_is_v6(ep) else 'IPv4'))
            else:
                self.pm.fam_unapply(pub)
        keep = {p['pub']: p['keepalive'] for p in peers}
        for pub in res['kicks']:
            self.wg.kick(pub, keep.get(pub))

        self.last_labels = res['labels']
        self.paths_str = ','.join('%s:%s' % (p['meta']['id'], res['labels'][p['pub']])
                                  for p in peers if p['pub'] in res['labels'] and p['meta'].get('id', '').isdigit())
        self._write_status(t, peers, dump, res['labels'])
        self.maybe_report(t)

    def run_forever(self):
        log('路径管理器启动: 接口 %s' % self.iface)
        self._ensure_port_on_start()
        while True:
            try:
                self.tick()
            except Exception as e:                      # 守护进程不能因为一次异常退出
                log('内部错误: %r' % (e,))
            time.sleep(TICK)

    def _ensure_port_on_start(self):
        conf = self.load_conf()
        d = self.wg.dump()
        if conf and d:
            port = int(conf[0].get('listen_port') or 0)
            if port and d[0]['listen_port'] != port:
                self.wg.set_listen_port(port)


# ───────────────────────── 命令行 ─────────────────────────

NAT_TEXT = {'public': '公网直连（无 NAT）', 'cone': '锥形 NAT（适合打洞）', 'symmetric': '对称 NAT（直连困难，会走 Hub 中转）',
            'unknown': '未知'}
STATE_TEXT = {'d': '直连', 'p': '尝试直连中', 'r': '经 Hub 中转', '': '-'}


def cmd_status():
    try:
        with open(STATUS_FILE, encoding='utf-8') as f:
            st = json.load(f)
    except (OSError, ValueError):
        out('路径管理器未运行（尚无状态）')
        return 1
    out('NAT 类型: %s' % NAT_TEXT.get(st.get('nat'), st.get('nat')))
    out('STUN 公网端点: %s' % (st.get('endpoint') or '-'))
    out('状态更新于 %d 秒前' % max(0, int(time.time()) - st.get('ts', 0)))
    rows = [p for p in st.get('peers', []) if not p.get('hub')]
    if rows:
        out('对端路径:')
        for p in rows:
            hs = ('握手 %ds 前' % p['hs_age']) if p.get('hs_age') is not None else '尚未握手'
            fam = {'v6': 'IPv6', 'v4': 'IPv4'}.get(p.get('family'), '-')
            out('  %-20s %-12s %-5s %s' % (p.get('name') or p['pub'][:8], STATE_TEXT.get(p.get('state'), '-'), fam, hs))
    return 0


def cmd_stun(argv):
    port = int(argv[0]) if argv else 0
    servers = (os.environ.get('MESHLINK_STUN') or ','.join(DEFAULT_STUN)).split(',')
    addrs = stun_resolve(servers)
    if not addrs:
        out('无法解析任何 STUN 服务器')
        return 1
    # 用 0（随机端口）探测，只反映本机 NAT 的行为，不会干扰正在运行的 WireGuard
    results = stun_probe(port, addrs)
    for srv, ip, p in results:
        out('%s -> 映射 %s:%d' % (srv, ip, p))
    endpoint, nat = stun_classify(results, local_ip_for(addrs[0][0]))
    out('端点: %s  NAT: %s' % (endpoint or '-', NAT_TEXT.get(nat, nat)))
    return 0 if endpoint else 1


def main(argv):
    cmd = argv[1] if len(argv) > 1 else 'run'
    if cmd == 'status':
        return cmd_status()
    if cmd == 'stun':
        return cmd_stun(argv[2:])
    if cmd != 'run':
        out('用法: %s {run|status|stun [port]}' % argv[0])
        return 1
    env = load_env()
    iface = env.get('IFACE', 'meshlink')
    servers = [s for s in env.get('STUN_SERVERS', '').split(',') if s.strip()] or None
    d = Daemon(iface, env['SERVER'], env['SECRET'], '/etc/wireguard/%s.conf' % iface, stun_servers=servers)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # 让 finally 有机会把 WG 端口换回去
    try:
        d.run_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
