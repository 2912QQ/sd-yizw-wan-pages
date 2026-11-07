#!/usr/bin/env python3
"""路径管理器测试: python3 -I tests/test_path.py（不需要 root，也不需要 wg）"""
import importlib.util
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('mp', os.path.join(HERE, '..', 'public', 'meshlink-path.py'))
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)
sys.dont_write_bytecode = True
mp.ping_rtt = lambda *a, **k: None      # 测试里不发真实 ICMP；需要延迟的用例自己传 ping_fn

HUB, A, B = 'H' * 43 + '=', 'A' * 43 + '=', 'B' * 43 + '='


# ───────── 假 STUN 服务器 ─────────
class FakeStun(threading.Thread):
    """回复固定的映射地址；mode: xor | legacy | wrongtid | silent"""
    def __init__(self, ip, mapped, mode='xor'):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, 0))
        self.addr, self.mapped, self.mode, self.stop = self.sock.getsockname(), mapped, mode, False
        self.sock.settimeout(0.2)

    def run(self):
        while not self.stop:
            try:
                data, frm = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            if self.mode == 'silent' or len(data) < 20:
                continue
            tid = data[8:20]
            ip, port = self.mapped
            if self.mode == 'xor':
                val = struct.pack('>BBH', 0, 1, port ^ (mp.MAGIC >> 16)) + struct.pack('>I', struct.unpack('>I', socket.inet_aton(ip))[0] ^ mp.MAGIC)
                attr = struct.pack('>HH', 0x0020, 8) + val
            else:
                val = struct.pack('>BBH', 0, 1, port) + socket.inet_aton(ip)
                attr = struct.pack('>HH', 0x0001, 8) + val
            if self.mode == 'wrongtid':
                tid = os.urandom(12)
            self.sock.sendto(struct.pack('>HHI', 0x0101, len(attr), mp.MAGIC) + tid + attr, frm)
        self.sock.close()


def start(ip, mapped, mode='xor'):
    s = FakeStun(ip, mapped, mode)
    s.start()
    return s


class StunTests(unittest.TestCase):
    def probe(self, servers, **kw):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]; sock.close()
        res = mp.stun_probe(port, [s.addr for s in servers], per_try=0.3, tries=1, **kw)
        for s in servers:
            s.stop = True
        for s in servers:
            s.join()
        return res

    def test_cone(self):
        r = self.probe([start('127.0.0.1', ('203.0.113.7', 41000)), start('127.0.0.2', ('203.0.113.7', 41000))])
        self.assertEqual(mp.stun_classify(r, '192.168.1.5'), ('203.0.113.7:41000', 'cone'))

    def test_symmetric(self):
        r = self.probe([start('127.0.0.1', ('203.0.113.7', 41000)), start('127.0.0.2', ('203.0.113.7', 41007))])
        ep, nat = mp.stun_classify(r, '192.168.1.5')
        self.assertEqual(nat, 'symmetric')
        self.assertEqual(ep, '203.0.113.7:41000')

    def test_public_when_mapped_equals_local(self):
        r = self.probe([start('127.0.0.1', ('198.51.100.9', 51820))])
        self.assertEqual(mp.stun_classify(r, '198.51.100.9'), ('198.51.100.9:51820', 'public'))

    def test_unknown_with_single_server(self):
        r = self.probe([start('127.0.0.1', ('203.0.113.7', 41000))])
        self.assertEqual(mp.stun_classify(r, '192.168.1.5')[1], 'unknown')

    def test_legacy_mapped_address(self):
        r = self.probe([start('127.0.0.1', ('203.0.113.7', 41000), 'legacy')])
        self.assertEqual(r[0][1:], ('203.0.113.7', 41000))

    def test_wrong_transaction_id_and_silent_ignored(self):
        r = self.probe([start('127.0.0.1', ('1.2.3.4', 1), 'wrongtid'), start('127.0.0.2', ('1.2.3.4', 1), 'silent')])
        self.assertEqual(r, [])
        self.assertEqual(mp.stun_classify(r, None), (None, 'unknown'))

    def test_skips_dead_server_uses_next(self):
        r = self.probe([start('127.0.0.1', ('1.2.3.4', 1), 'silent'), start('127.0.0.2', ('203.0.113.7', 41000)),
                        start('127.0.0.3', ('203.0.113.7', 41000))])
        self.assertEqual(mp.stun_classify(r, '10.0.0.2'), ('203.0.113.7:41000', 'cone'))

    def test_parse_garbage(self):
        self.assertIsNone(mp.stun_parse(b'\x00' * 5, b'x' * 12))
        self.assertIsNone(mp.stun_parse(os.urandom(40), b'x' * 12))


# ───────── 配置 / dump 解析 ─────────
CONF = """# MeshLink config for n1
# interval=60
# meshlink self id=2 mode=mesh hub=0 override=0
[Interface]
Address = 10.88.0.2/24
ListenPort = 51820
PrivateKey = xxx

[Peer]
# hub 1
# meshlink peer id=1 hub=1 online=1 nat=public
PublicKey = %s
AllowedIPs = 10.88.0.1/32
Endpoint = 198.51.100.1:51820
PersistentKeepalive = 25

[Peer]
# office sh
# meshlink peer id=3 hub=0 online=1 nat=cone
PublicKey = %s
AllowedIPs = 10.88.0.3/32, 192.168.7.0/24
Endpoint = 203.0.113.7:41000
PersistentKeepalive = 25
""" % (HUB, A)


class ParseTests(unittest.TestCase):
    def test_conf(self):
        selfm, peers = mp.parse_conf(CONF)
        self.assertEqual((selfm['mode'], selfm['hub'], selfm['listen_port'], selfm['override']), ('mesh', '0', '51820', '0'))
        self.assertEqual([p['pub'] for p in peers], [HUB, A])
        self.assertEqual(peers[1]['allowed'], ['10.88.0.3/32', '192.168.7.0/24'])
        self.assertEqual(peers[1]['name'], 'office sh')
        self.assertEqual(peers[1]['meta'], {'id': '3', 'hub': '0', 'online': '1', 'nat': 'cone'})
        self.assertEqual(peers[0]['endpoint'], '198.51.100.1:51820')

    def test_dump(self):
        txt = "priv\tpub\t51820\toff\n%s\t(none)\t1.2.3.4:5\t10.88.0.3/32,192.168.7.0/24\t1700000000\t100\t200\t25\n%s\t(none)\t(none)\t(none)\t0\t0\t0\t25\n" % (A, B)
        dev, peers = mp.parse_dump(txt)
        self.assertEqual(dev['listen_port'], 51820)
        self.assertEqual(peers[A]['allowed'], ['10.88.0.3/32', '192.168.7.0/24'])
        self.assertEqual((peers[A]['hs'], peers[A]['rx']), (1700000000, 100))
        self.assertEqual(peers[B]['allowed'], [])


# ───────── 状态机 ─────────
def peers(online=True, nat='cone', hub_nat='public'):
    return [
        {'pub': HUB, 'allowed': ['10.88.0.1/32'], 'endpoint': '198.51.100.1:51820', 'keepalive': '25', 'name': 'hub',
         'meta': {'id': '1', 'hub': '1', 'online': '1', 'nat': hub_nat}},
        {'pub': A, 'allowed': ['10.88.0.3/32', '192.168.7.0/24'], 'endpoint': '203.0.113.7:41000', 'keepalive': '25', 'name': 'A',
         'meta': {'id': '3', 'hub': '0', 'online': '1' if online else '0', 'nat': nat}},
    ]


def dump(t, hub_hs=-5, a_hs=None, a_rx=0):
    d = {HUB: {'hs': t + hub_hs if hub_hs is not None else 0, 'rx': 1000 + int(t), 'allowed': ['10.88.0.1/32'], 'endpoint': ''},
         A: {'hs': a_hs or 0, 'rx': a_rx, 'allowed': ['10.88.0.3/32', '192.168.7.0/24'], 'endpoint': ''}}
    return d


SELF = {'mode': 'mesh', 'hub': '0'}


class StateTests(unittest.TestCase):
    def run_for(self, pm, secs, make_dump, selfm=SELF, plist=None, nat='cone', t0=1000.0, step=5):
        last, t = None, t0
        while t <= t0 + secs:
            last = pm.tick(t, selfm, plist or peers(), make_dump(t), nat)
            t += step
        return last

    def test_healthy_direct_stays_direct(self):
        pm = mp.PathManager()
        rxs = iter(range(10, 10000, 10))
        last = self.run_for(pm, 600, lambda t: dump(t, a_hs=t - 30, a_rx=int(t)))
        self.assertEqual(last['labels'][A], 'd')
        self.assertEqual(last['desired'][A], ['10.88.0.3/32', '192.168.7.0/24'])
        self.assertEqual(last['desired'][HUB], ['10.88.0.1/32'])

    def test_never_handshakes_falls_back_after_grace(self):
        pm = mp.PathManager()
        r = pm.tick(1000, SELF, peers(), dump(1000), 'cone')
        self.assertEqual(r['labels'][A], 'p')                       # 尝试中，还没判定失败
        r = self.run_for(pm, mp.GRACE - 5, lambda t: dump(t), t0=1005)   # 到 1040 还在宽限期内
        self.assertEqual(r['labels'][A], 'p')
        r = pm.tick(1000 + mp.GRACE + 6, SELF, peers(), dump(1046), 'cone')
        self.assertEqual(r['labels'][A], 'r')
        self.assertTrue(r['newly_relayed'])
        self.assertEqual(r['desired'][A], [])                       # 从直连对端摘掉
        self.assertEqual(r['desired'][HUB], ['10.88.0.1/32', '10.88.0.3/32', '192.168.7.0/24'])  # 挂到 Hub（含内网网段）
        self.assertIn('直连失败', r['events'][0])
        r2 = pm.tick(1052, SELF, peers(), dump(1052), 'cone')
        self.assertFalse(r2['newly_relayed'])                       # 只通知一次

    def test_exit_route_stays_on_exit_peer_when_relayed(self):
        # 出口节点直连不通时，0.0.0.0/0 不能挂到 Hub（否则出口 IP 变成 Hub 的）；其余地址照常挪到 Hub
        pm = mp.PathManager()
        pl = peers()
        pl[1]['allowed'] = ['10.88.0.3/32', '0.0.0.0/0']
        pm.tick(1000, SELF, pl, dump(1000), 'cone')
        r = pm.tick(1000 + mp.GRACE + 6, SELF, pl, dump(1046), 'cone')
        self.assertEqual(r['labels'][A], 'r')
        self.assertEqual(r['desired'][A], ['0.0.0.0/0'])
        self.assertEqual(r['desired'][HUB], ['10.88.0.1/32', '10.88.0.3/32'])
        self.assertNotIn('0.0.0.0/0', r['desired'][HUB])

    def test_symmetric_nat_shortens_grace(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers(nat='symmetric'), dump(1000), 'cone')
        r = pm.tick(1000 + mp.GRACE_SYM + 1, SELF, peers(nat='symmetric'), dump(1016), 'cone')
        self.assertEqual(r['labels'][A], 'r')
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers(), dump(1000), 'symmetric')
        r = pm.tick(1000 + mp.GRACE_SYM + 1, SELF, peers(), dump(1016), 'symmetric')
        self.assertEqual(r['labels'][A], 'r')

    def test_no_fallback_when_hub_unreachable(self):
        pm = mp.PathManager()
        r = self.run_for(pm, 200, lambda t: dump(t, hub_hs=None))   # Hub 也没握手: 多半是本机断网
        self.assertEqual(r['labels'][A], 'p')
        self.assertEqual(r['desired'][A], ['10.88.0.3/32', '192.168.7.0/24'])
        r = self.run_for(pm, 200, lambda t: dump(t, hub_hs=-400), t0=1300)   # Hub 握手过期
        self.assertEqual(r['labels'][A], 'p')

    def test_offline_peer_is_not_a_failure(self):
        pm = mp.PathManager()
        r = self.run_for(pm, 300, lambda t: dump(t), plist=peers(online=False))
        self.assertEqual(r['labels'][A], 'p')
        # 上线后重新给宽限期，而不是立刻切中转
        r = pm.tick(1305, SELF, peers(online=True), dump(1305), 'cone')
        self.assertEqual(r['labels'][A], 'p')

    def test_established_session_rx_stall(self):
        pm = mp.PathManager()
        # 先健康运行（rx 持续增长）
        self.run_for(pm, 100, lambda t: dump(t, a_hs=t - 10, a_rx=int(t)))
        # 之后 rx 不再增长，握手时间停在 t=1100
        frozen = lambda t: dump(t, a_hs=1100, a_rx=1100)
        r = self.run_for(pm, mp.RX_STALL - 10, frozen, t0=1105)
        self.assertEqual(r['labels'][A], 'd')
        r = pm.tick(1100 + mp.RX_STALL + 6, SELF, peers(), frozen(1181), 'cone')
        self.assertEqual(r['labels'][A], 'r')

    def test_relay_probes_and_recovers(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers(), dump(1000), 'cone')
        r = pm.tick(1050, SELF, peers(), dump(1050), 'cone')
        self.assertEqual(r['labels'][A], 'r')
        kicks, t = 0, 1055
        while t < 1050 + 44:                                         # 45 秒内不探测
            kicks += len(pm.tick(t, SELF, peers(), dump(t), 'cone')['kicks']); t += 5
        self.assertEqual(kicks, 0)
        r = pm.tick(1096, SELF, peers(), dump(1096), 'cone')
        self.assertEqual(r['kicks'], [A])                            # 到点触发一次握手探测
        # 旧握手（进入中转之前）不算恢复
        r = pm.tick(1100, SELF, peers(), dump(1100, a_hs=1040), 'cone')
        self.assertEqual(r['labels'][A], 'r')
        # 新握手出现，但中转不足 30 秒不切（这里已过 50 秒，所以第 1 次 ok，第 2 次切回）
        r = pm.tick(1105, SELF, peers(), dump(1105, a_hs=1103), 'cone')
        self.assertEqual(r['labels'][A], 'r')
        r = pm.tick(1110, SELF, peers(), dump(1110, a_hs=1103), 'cone')
        self.assertEqual(r['labels'][A], 'd')
        self.assertEqual(r['desired'][A], ['10.88.0.3/32', '192.168.7.0/24'])
        self.assertEqual(r['desired'][HUB], ['10.88.0.1/32'])
        self.assertIn('恢复', r['events'][0])

    def test_recovery_debounced_and_dwell(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers(), dump(1000), 'cone')
        pm.tick(1050, SELF, peers(), dump(1050), 'cone')           # relay_at=1050
        r = pm.tick(1060, SELF, peers(), dump(1060, a_hs=1058), 'cone')   # 握手新鲜但才中转 10 秒
        self.assertEqual(r['labels'][A], 'r')
        r = pm.tick(1085, SELF, peers(), dump(1085, a_hs=1058), 'cone')   # ok=1
        self.assertEqual(r['labels'][A], 'r')
        r = pm.tick(1150, SELF, peers(), dump(1150, a_hs=1058), 'cone')   # 握手已过期(>60s)，计数归零
        self.assertEqual(r['labels'][A], 'r')

    def test_unmanaged_cases_keep_baseline(self):
        base = {p['pub']: p['allowed'] for p in peers()}
        for selfm, plist in [({'mode': 'hub', 'hub': '0'}, peers()), ({'mode': 'mesh', 'hub': '1'}, peers()), (SELF, peers()[1:])]:
            pm = mp.PathManager()
            r = self.run_for(pm, 200, lambda t: dump(t), selfm=selfm, plist=plist)
            for pub, lst in r['desired'].items():
                self.assertEqual(lst, base[pub])
            self.assertEqual(r['labels'], {})

    def test_endpoint_change_resets_grace(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers(), dump(1000), 'cone')
        p2 = peers(); p2[1]['endpoint'] = '203.0.113.7:42000'
        r = pm.tick(1035, SELF, p2, dump(1035), 'cone')             # 端点刚更新: 不该因为旧端点的失败而切中转
        self.assertEqual(r['labels'][A], 'p')
        r = pm.tick(1035 + mp.GRACE + 1, SELF, p2, dump(1076), 'cone')
        self.assertEqual(r['labels'][A], 'r')

    def test_preload_keeps_relay_after_restart(self):
        pm = mp.PathManager()
        pm.preload({A: 'relay', 'gone': 'relay'}, 1000)
        r = pm.tick(1000, SELF, peers(), dump(1000), 'cone')
        self.assertEqual(r['labels'][A], 'r')
        self.assertEqual(r['desired'][A], [])
        self.assertNotIn('gone', pm.modes())


# ───────── 守护进程整合（假 wg） ─────────
class FakeWg:
    def __init__(self, port=51820):
        self.port, self.state, self.calls = port, dump(1000.0), []
        self.state = {k: dict(v) for k, v in self.state.items()}
        self.fail_port0 = False

    def dump(self):
        return {'listen_port': self.port}, {k: dict(v) for k, v in self.state.items()}

    def set_allowed(self, changes):
        self.calls.append(('allowed', {k: list(v) for k, v in changes.items()}))
        for k, v in changes.items():
            self.state[k]['allowed'] = list(v)
        return True

    def set_listen_port(self, p):
        self.calls.append(('port', p))
        if p == 0 and self.fail_port0:
            return False
        self.port = p or 40000
        return True

    def kick(self, pub, ka):
        self.calls.append(('kick', pub, ka))


class DaemonTests(unittest.TestCase):
    def make(self, stun_result=(([('9.9.9.9', '203.0.113.7', 41000), ('8.8.8.8', '203.0.113.7', 41000)]), '192.168.1.5'), conf=CONF):
        self.tmp = tempfile.mkdtemp()
        self.conf_path = os.path.join(self.tmp, 'm.conf')
        with open(self.conf_path, 'w') as f:
            f.write(conf)
        self.clock = [1000.0]
        self.reports, self.wg = [], FakeWg()
        d = mp.Daemon('meshlink', 'https://x', 's', self.conf_path, wg=self.wg, report_fn=lambda *a: self.reports.append(a) or True,
                      stun_fn=lambda port, rebind: stun_result, clock=lambda: self.clock[0], status_file=os.path.join(self.tmp, 'status.json'))
        return d

    def test_stun_report_and_fallback_flow(self):
        d = self.make()
        d.tick()
        self.assertEqual((d.endpoint, d.nat), ('203.0.113.7:41000', 'cone'))
        self.assertEqual(self.reports[-1][:2], ('203.0.113.7:41000', 'cone'))
        self.assertEqual(self.reports[-1][2], '1:d,3:p')
        n = len(self.reports)
        d.tick(); self.assertEqual(len(self.reports), n)           # 没变化不重复上报
        self.clock[0] += 50
        d.tick()
        self.assertEqual(self.reports[-1][2], '1:d,3:r')                # 状态变化立即上报
        allowed = [c for c in self.wg.calls if c[0] == 'allowed'][-1][1]
        self.assertEqual(allowed[A], [])
        self.assertEqual(allowed[HUB], ['10.88.0.1/32', '10.88.0.3/32', '192.168.7.0/24'])
        with open(os.path.join(self.tmp, 'status.json')) as f:
            st = json.load(f)
        self.assertEqual(st['modes'], {A: 'relay'})
        # 重启 agent: 从状态文件恢复，不会先切回直连
        d2 = mp.Daemon('meshlink', 'https://x', 's', self.conf_path, wg=self.wg, report_fn=lambda *a: True,
                       stun_fn=lambda *a: ([], None), clock=lambda: self.clock[0], status_file=os.path.join(self.tmp, 'status.json'))
        self.assertEqual(d2.pm.modes(), {A: 'relay'})

    def test_syncconf_resets_are_reapplied(self):
        d = self.make()
        d.tick(); self.clock[0] += 50; d.tick()
        self.wg.state = {k: dict(v) for k, v in dump(1000.0).items()}   # 模拟 wg syncconf 把 AllowedIPs 重置成基线
        self.clock[0] += 5; d.tick()
        self.assertEqual(self.wg.state[A]['allowed'], [])
        self.assertIn('10.88.0.3/32', self.wg.state[HUB]['allowed'])

    def test_stun_rebind_restores_port_even_on_failure(self):
        d = mp.Daemon('meshlink', 'https://x', 's', '/nonexistent', wg=FakeWg(), report_fn=lambda *a: True)
        def boom(*a, **k):
            raise RuntimeError('boom')
        with mock.patch.object(mp, 'stun_resolve', lambda servers: [('127.0.0.1', 9)]), \
                mock.patch.object(mp, 'stun_probe', boom):
            with self.assertRaises(RuntimeError):
                d._real_stun(51820, True)
        self.assertEqual(d.wg.calls[0], ('port', 0))
        self.assertEqual(d.wg.calls[-1], ('port', 51820))
        self.assertEqual(d.wg.port, 51820)

    def test_port_repaired_if_interrupted(self):
        d = self.make()
        self.wg.port = 40000                                        # 上次探测被打断，WG 留在随机端口
        d.tick()
        self.assertEqual(self.wg.port, 51820)

    def test_stun_failure_keeps_last_then_clears(self):
        d = self.make(stun_result=([], None))
        d.endpoint, d.nat = '1.2.3.4:5', 'cone'
        for i in range(2):
            d.run_stun(1000.0 + i * 1000, 51820)
        self.assertEqual(d.endpoint, '1.2.3.4:5')
        d.run_stun(5000.0, 51820)
        self.assertEqual((d.endpoint, d.nat), (None, 'unknown'))

    def test_hub_and_override_skip_stun(self):
        for meta in ('hub=1', 'override=1'):
            d = self.make(conf=CONF.replace('hub=0 override=0', meta.replace('hub=1', 'hub=1 override=0') if 'hub' in meta else 'hub=0 override=1'))
            d.stun_fn = lambda *a: (_ for _ in ()).throw(AssertionError('不该探测'))
            d.tick()
        d = self.make(conf=CONF.replace('hub=0', 'hub=1'))
        d.tick()
        self.assertEqual(d.nat, 'public')

    def test_report_retry_backoff_after_failure(self):
        d = self.make()
        calls = []
        d.report_fn = lambda *a: calls.append(self.clock[0]) or False
        d.tick()
        for _ in range(5):
            self.clock[0] += 5; d.tick()                            # 失败后 30 秒内不重试
        self.assertEqual(len(calls), 1)
        self.clock[0] += 30; d.tick()
        self.assertEqual(len(calls), 2)

    def test_kick_uses_conf_keepalive(self):
        d = self.make()
        d.tick(); self.clock[0] += 50; d.tick()
        self.clock[0] += 50; d.tick()
        self.assertIn(('kick', A, '25'), self.wg.calls)


# ───────── IPv6 优先、IPv4 兜底 ─────────
EP6, EP4 = '[2408:8207:1::5]:51820', '203.0.113.7:41000'


def peers6(hub_dual=False):
    ps = peers()
    ps[1]['endpoint'] = EP6
    ps[1]['meta'].update(ep6=EP6, ep4=EP4)
    if hub_dual:
        ps[0]['endpoint'] = '[2001:db8::1]:51820'
        ps[0]['meta'].update(ep6='[2001:db8::1]:51820', ep4='198.51.100.1:51820')
    return ps


def dump6(t, a_hs=None, a_rx=0, a_ep='', hub_ep=''):
    d = dump(t, a_hs=a_hs, a_rx=a_rx)
    d[A]['endpoint'] = a_ep
    d[HUB]['endpoint'] = hub_ep
    return d


class FamilyTests(unittest.TestCase):
    def test_helpers(self):
        self.assertTrue(mp.ep_is_v6('[2408::1]:51820'))
        self.assertFalse(mp.ep_is_v6('1.2.3.4:51820'))
        self.assertFalse(mp.ep_is_v6(''))
        self.assertEqual(mp.candidates(peers()[1]), [])                 # 没有 ep6/ep4: 沿用旧行为
        self.assertEqual(mp.candidates(peers6()[1]), [EP6, EP4])

    def test_ipv6_first_and_stays_when_it_works(self):
        pm = mp.PathManager()
        r = pm.tick(1000, SELF, peers6(), dump6(1000), 'cone')
        self.assertEqual(r['endpoints'], {A: EP6})                      # 先试 IPv6
        t = 1005
        while t < 1300:
            r = pm.tick(t, SELF, peers6(), dump6(t, a_hs=t - 20, a_rx=int(t), a_ep=EP6), 'cone')
            self.assertEqual(r['endpoints'], {}, t)                     # 通了就不再动端点
            self.assertEqual(r['labels'][A], 'd')
            t += 5
        self.assertEqual(pm.endpoint_family(A), 'v6')

    def test_ipv6_fails_then_ipv4_then_relay(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers6(), dump6(1000), 'cone')
        r = pm.tick(1000 + mp.GRACE_V6 + 1, SELF, peers6(), dump6(1021, a_ep=EP6), 'cone')
        self.assertEqual(r['endpoints'], {A: EP4})                      # IPv6 一个宽限期没握手: 改试 IPv4
        self.assertIn('IPv6 直连失败', r['events'][0])
        self.assertEqual(r['labels'][A], 'p')                           # 还没走中转
        self.assertFalse(r['newly_relayed'])
        r = pm.tick(1021 + mp.GRACE - 5, SELF, peers6(), dump6(1056, a_ep=EP4), 'cone')
        self.assertEqual(r['labels'][A], 'p')
        r = pm.tick(1021 + mp.GRACE + 1, SELF, peers6(), dump6(1062, a_ep=EP4), 'cone')
        self.assertEqual(r['labels'][A], 'r')                           # 两个都不通才经 Hub 中转
        self.assertTrue(r['newly_relayed'])

    def test_ipv4_ok_after_ipv6_fails(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers6(), dump6(1000), 'cone')
        pm.tick(1021, SELF, peers6(), dump6(1021, a_ep=EP6), 'cone')
        r = pm.tick(1030, SELF, peers6(), dump6(1030, a_hs=1028, a_rx=50, a_ep=EP4), 'cone')
        self.assertEqual(r['labels'][A], 'd')
        self.assertEqual(r['endpoints'], {})
        self.assertEqual(pm.endpoint_family(A), 'v4')

    def test_old_session_does_not_count_after_switch(self):
        # 切换端点前的旧握手不能算新路径通了
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers6(), dump6(1000, a_hs=990, a_rx=10, a_ep=EP6), 'cone')   # 重启时已有 IPv6 会话
        t, rx = 1005, 10
        r = None
        while t < 1100:
            r = pm.tick(t, SELF, peers6(), dump6(t, a_hs=990, a_rx=rx, a_ep=EP6), 'cone')   # 收不到包了
            if r['endpoints']:
                break
            t += 5
        self.assertEqual(r['endpoints'], {A: EP4})
        self.assertGreater(t - 1000, mp.RX_STALL - 1)                    # 会话停滞才切，不是一上来就切
        r = pm.tick(t + 5, SELF, peers6(), dump6(t + 5, a_hs=990, a_rx=rx, a_ep=EP4), 'cone')
        self.assertEqual(r['labels'][A], 'p')                            # 旧握手不算数，仍在尝试

    def test_live_ipv4_session_not_disturbed_on_start(self):
        pm = mp.PathManager()
        r = pm.tick(1000, SELF, peers6(), dump6(1000, a_hs=980, a_rx=10, a_ep='203.0.113.7:41555'), 'cone')
        self.assertEqual(r['endpoints'], {})                             # 已经在走 IPv4 的会话，不去改它
        self.assertEqual(pm.endpoint_family(A), 'v4')

    def test_syncconf_reset_is_repaired_when_no_session(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers6(), dump6(1000), 'cone')
        pm.tick(1021, SELF, peers6(), dump6(1021, a_ep=EP6), 'cone')     # 现在在试 IPv4
        r = pm.tick(1026, SELF, peers6(), dump6(1026, a_ep=EP6), 'cone')  # syncconf 把端点重置回 IPv6
        self.assertEqual(r['endpoints'], {A: EP4})

    def test_relay_probe_alternates_family(self):
        pm = mp.PathManager()
        pm.tick(1000, SELF, peers6(), dump6(1000), 'cone')
        pm.tick(1021, SELF, peers6(), dump6(1021, a_ep=EP6), 'cone')
        pm.tick(1062, SELF, peers6(), dump6(1062, a_ep=EP4), 'cone')     # 进入中转，停在 IPv4
        self.assertEqual(pm.modes(), {A: 'relay'})
        r = pm.tick(1062 + mp.PROBE_EVERY, SELF, peers6(), dump6(1107, a_ep=EP4), 'cone')
        self.assertEqual(r['kicks'], [A])
        self.assertEqual(r['endpoints'], {A: EP6})                       # 探测时换到 IPv6 再试
        r = pm.tick(1107 + mp.PROBE_EVERY, SELF, peers6(), dump6(1152, a_ep=EP6), 'cone')
        self.assertEqual(r['endpoints'], {A: EP4})                       # 下一次再换回 IPv4

    def test_hub_peer_also_falls_back_to_ipv4(self):
        # Hub 没有中转可退，IPv6 不通就改试 IPv4（中心辐射模式下同样适用）
        pm = mp.PathManager()
        hubmode = {'mode': 'hub', 'hub': '0'}
        ps = peers6(hub_dual=True)
        r = pm.tick(1000, hubmode, ps, dump6(1000, hub_ep='[2001:db8::1]:51820'), 'cone')
        d = dump6(1021, hub_ep='[2001:db8::1]:51820'); d[HUB]['hs'] = 0
        r = pm.tick(1021, hubmode, ps, d, 'cone')
        self.assertEqual(r['endpoints'].get(HUB), '198.51.100.1:51820')

    def test_offline_peer_does_not_burn_ipv6(self):
        pm = mp.PathManager()
        ps = peers6(); ps[1]['meta']['online'] = '0'
        for t in range(1000, 1200, 5):
            r = pm.tick(t, SELF, ps, dump6(t), 'cone')
        self.assertEqual(r['endpoints'], {})
        self.assertEqual(pm.endpoint_family(A), 'v6')


class FamilyDaemonTests(unittest.TestCase):
    def test_daemon_applies_endpoint_switch(self):
        conf = CONF.replace('# meshlink peer id=3 hub=0 online=1 nat=cone',
                            '# meshlink peer id=3 hub=0 online=1 nat=cone ep6=%s ep4=%s' % (EP6, EP4))
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, 'm.conf')
        with open(path, 'w') as fh: fh.write(conf)
        clock = [1000.0]
        wg = FakeWg()
        wg.set_endpoint = lambda pub, ep: wg.calls.append(('endpoint', pub, ep)) or True
        d = mp.Daemon('meshlink', 'https://x', 's', path, wg=wg, report_fn=lambda *a: True,
                      stun_fn=lambda port, rebind: ([('9.9.9.9', '203.0.113.7', 41000), ('8.8.8.8', '203.0.113.7', 41000)], '192.168.1.5'),
                      clock=lambda: clock[0], status_file=os.path.join(tmp, 'status.json'))
        d.tick()
        self.assertIn(('endpoint', A, EP6), wg.calls)
        clock[0] += mp.GRACE_V6 + 1
        d.tick()
        self.assertIn(('endpoint', A, EP4), wg.calls)
        with open(os.path.join(tmp, 'status.json')) as f:
            st = json.load(f)
        self.assertEqual([p['family'] for p in st['peers'] if p['pub'] == A], ['v4'])

    def test_failed_set_endpoint_is_retried(self):
        conf = CONF.replace('# meshlink peer id=3 hub=0 online=1 nat=cone',
                            '# meshlink peer id=3 hub=0 online=1 nat=cone ep6=%s ep4=%s' % (EP6, EP4))
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, 'm.conf')
        with open(path, 'w') as fh: fh.write(conf)
        wg, calls = FakeWg(), []
        wg.set_endpoint = lambda pub, ep: calls.append(ep) or len(calls) > 1
        d = mp.Daemon('meshlink', 'https://x', 's', path, wg=wg, report_fn=lambda *a: True,
                      stun_fn=lambda *a: ([], None), clock=lambda: 1000.0, status_file=os.path.join(tmp, 's.json'))
        d.tick(); d.tick()
        self.assertEqual(calls, [EP6, EP6])


# ───────── 延迟测量 ─────────

class LossFailoverTests(unittest.TestCase):
    """直连能通但丢包严重时，自动改走 Hub；带停留时间和退避，避免来回抖动。"""
    def healthy(self, t):
        return dump(t, a_hs=int(t) - 10, a_rx=int(t))

    def tick(self, pm, t, a_loss=None, hub_loss=None, n=20):
        losses = {}
        if a_loss is not None:
            losses[A] = (a_loss, n)
        if hub_loss is not None:
            losses[HUB] = (hub_loss, n)
        return pm.tick(t, SELF, peers(), self.healthy(t), 'cone', losses)

    def test_high_loss_moves_to_hub(self):
        pm = mp.PathManager()
        r = self.tick(pm, 1000, a_loss=5, hub_loss=0)
        self.assertEqual(r['labels'][A], 'd')
        r = self.tick(pm, 1005, a_loss=40, hub_loss=0)
        self.assertEqual(r['labels'][A], 'r')
        self.assertEqual(r['desired'][A], [])
        self.assertIn('丢包', r['events'][0])

    def test_needs_enough_samples_and_threshold(self):
        pm = mp.PathManager()
        self.assertEqual(self.tick(pm, 1000, a_loss=80, hub_loss=0, n=5)['labels'][A], 'd')    # 样本太少
        self.assertEqual(self.tick(pm, 1005, a_loss=20, hub_loss=0)['labels'][A], 'd')         # 没到阈值

    def test_not_worth_it_when_hub_is_just_as_bad(self):
        pm = mp.PathManager()
        self.assertEqual(self.tick(pm, 1000, a_loss=40, hub_loss=35)['labels'][A], 'd')        # Hub 也丢，切过去没意义
        self.assertEqual(self.tick(pm, 1005, a_loss=40, hub_loss=10)['labels'][A], 'r')

    def test_hold_blocks_recovery_then_allows(self):
        pm = mp.PathManager()
        self.tick(pm, 1000, a_loss=0, hub_loss=0)
        self.tick(pm, 1005, a_loss=40, hub_loss=0)                    # 切到中转，至少停留 LOSS_HOLD_BASE 秒
        t, back = 1010, None
        while t < 1005 + mp.LOSS_HOLD_BASE - 5:
            r = pm.tick(t, SELF, peers(), dump(t, a_hs=t - 1, a_rx=int(t)), 'cone', {A: (3, 20), HUB: (0, 20)})
            self.assertEqual(r['labels'][A], 'r', t)                  # 握手很新也不切回
            t += 5
        while t < 1005 + mp.LOSS_HOLD_BASE + 60:
            r = pm.tick(t, SELF, peers(), dump(t, a_hs=t - 1, a_rx=int(t)), 'cone', {A: (3, 20), HUB: (0, 20)})
            if r['labels'][A] == 'd':
                back = t
                break
            t += 5
        self.assertIsNotNone(back)                                    # 停留期结束后可以回直连

    def test_hold_cancelled_when_relay_is_no_better(self):
        pm = mp.PathManager()
        self.tick(pm, 1000, a_loss=0, hub_loss=0)
        self.tick(pm, 1005, a_loss=40, hub_loss=0)
        r = None
        for t in range(1010, 1100, 5):
            r = pm.tick(t, SELF, peers(), dump(t, a_hs=t - 1, a_rx=int(t)), 'cone', {A: (50, 20), HUB: (0, 20)})
            if r['labels'][A] == 'd':
                break
        self.assertEqual(r['labels'][A], 'd')                         # 中转丢包 50% 比直连的 40% 还差，不必等满停留期

    def test_backoff_doubles(self):
        pm = mp.PathManager()
        self.tick(pm, 1000, a_loss=0, hub_loss=0)
        self.tick(pm, 1005, a_loss=40, hub_loss=0)
        self.assertEqual(pm.st[A]['hold_until'], 1005 + mp.LOSS_HOLD_BASE)
        # 取消停留、回到直连后再次丢包：停留时间翻倍
        pm.st[A].update(mode='direct', since=2000, rx_t=2000, hold_until=0)
        r = pm.tick(2005, SELF, peers(), self.healthy(2005), 'cone', {A: (40, 20), HUB: (0, 20)})
        self.assertEqual(r['labels'][A], 'r')
        self.assertEqual(pm.st[A]['hold_until'], 2005 + mp.LOSS_HOLD_BASE * 2)

    def test_hub_node_unmanaged(self):
        pm = mp.PathManager()
        r = pm.tick(1000, {'mode': 'mesh', 'hub': '1'}, peers(), self.healthy(1000), 'cone', {A: (90, 20), HUB: (0, 20)})
        self.assertEqual(r['desired'][A], ['10.88.0.3/32', '192.168.7.0/24'])    # Hub 自己没有中转可退


class PingHelperTests(unittest.TestCase):
    def test_echo_checksum_is_valid(self):
        pkt = mp.icmp_echo(0x1234, 7)
        self.assertEqual(pkt[0], 8)                                  # Echo Request
        self.assertEqual(mp.icmp_checksum(pkt), 0)                   # 含校验和的整包再算一遍应为 0

    def test_reply_matching(self):
        ip_hdr = bytes([0x45]) + bytes(19)                           # 20 字节 IP 头
        reply = ip_hdr + struct.pack('>BBHHH', 0, 0, 0, 0x1234, 7)
        self.assertTrue(mp.icmp_is_reply(reply, 0x1234, 7))
        self.assertFalse(mp.icmp_is_reply(reply, 0x1234, 8))         # seq 不符
        self.assertFalse(mp.icmp_is_reply(reply, 0x4321, 7))         # id 不符
        req = ip_hdr + struct.pack('>BBHHH', 8, 0, 0, 0x1234, 7)
        self.assertFalse(mp.icmp_is_reply(req, 0x1234, 7))           # 不是 Echo Reply
        self.assertFalse(mp.icmp_is_reply(b'short', 1, 1))

    def test_parse_ping_output(self):
        gnu = '64 bytes from 10.88.0.3: icmp_seq=1 ttl=64 time=23.4 ms\n64 bytes from 10.88.0.3: icmp_seq=2 ttl=64 time=21.9 ms\n'
        busybox = '64 bytes from 10.88.0.3: seq=0 ttl=64 time=0.532 ms\n'
        self.assertAlmostEqual(mp.parse_ping(gnu), 21.9)
        self.assertAlmostEqual(mp.parse_ping(busybox), 0.532)
        self.assertIsNone(mp.parse_ping('100% packet loss'))
        self.assertIsNone(mp.parse_ping(None))

    def test_parse_loss_output(self):
        gnu = '5 packets transmitted, 4 received, 20% packet loss, time 804ms\n'
        self.assertEqual(mp.parse_loss(gnu, 5), (5, 1))
        self.assertEqual(mp.parse_loss('5 packets transmitted, 0 packets received, 100% packet loss', 5), (5, 5))
        self.assertEqual(mp.parse_loss('64 bytes from x: seq=0 ttl=64 time=1 ms\n', 5), (5, 4))   # 没有统计行: 按回包数估算

    def test_icmp_reply_seq(self):
        reply = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]) + struct.pack('>BBHHH', 0, 0, 0, 0x1234, 3)
        self.assertEqual(mp.icmp_reply_seq(reply, 0x1234), 3)
        self.assertIsNone(mp.icmp_reply_seq(reply, 0x9999))
        self.assertIsNone(mp.icmp_reply_seq(b'short', 1))

    def test_peer_ip(self):
        self.assertEqual(mp.peer_ip(peers()[1]), '10.88.0.3')
        self.assertIsNone(mp.peer_ip({'allowed': ['192.168.7.0/24']}))


class LatencyDaemonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.conf_path = os.path.join(self.tmp, 'm.conf')
        with open(self.conf_path, 'w') as f:
            f.write(CONF)
        self.clock, self.wg, self.reports, self.pings = [1000.0], FakeWg(), [], []
        self.values = [20.0]
        self.wg.state[A]['hs'] = 999            # A 已握手 -> 直连

        def ping(ip):
            self.pings.append(ip)
            return self.values[0]
        self.d = mp.Daemon('meshlink', 'https://x', 's', self.conf_path, wg=self.wg,
                           report_fn=lambda *a: self.reports.append(a) or True,
                           stun_fn=lambda port, rebind: ([], None), clock=lambda: self.clock[0],
                           status_file=os.path.join(self.tmp, 'status.json'), ping_fn=ping)

    def item(self, pid):
        """paths_str 里某个对端的条目（'3:d:20:4' 之类）。"""
        return next((x for x in self.d.paths_str.split(',') if x.startswith(pid + ':')), None)

    def tick(self, secs=0):
        self.clock[0] += secs
        self.wg.state[A]['hs'] = int(self.clock[0]) - 1      # 保持握手新鲜
        self.wg.state[A]['rx'] += 10
        self.wg.state[HUB]['hs'] = int(self.clock[0]) - 5
        self.d.tick()

    def test_all_peers_including_hub_report_latency(self):
        self.tick()
        self.assertEqual(sorted(self.pings), ['10.88.0.1', '10.88.0.3'])   # Hub 也测
        self.assertEqual(self.d.paths_str, '1:d:20,3:d:20')
        with open(os.path.join(self.tmp, 'status.json')) as f:
            st = json.load(f)
        self.assertEqual({p['name']: p['rtt'] for p in st['peers']}, {'hub 1': 20, 'office sh': 20})
        self.assertEqual(self.reports[-1][2], '1:d:20,3:d:20')

    def test_hub_node_itself_reports_all_peers(self):
        # Hub 节点自己没有 mesh 状态机的标签，但仍然要报到各对端的状态和延迟
        conf = CONF.replace('mode=mesh hub=0', 'mode=mesh hub=1')
        with open(self.conf_path, 'w') as f:
            f.write(conf)
        self.d._conf_cache = (None, None)
        self.tick()
        self.assertEqual(self.d.paths_str, '1:d:20,3:d:20')

    def test_ip_family_reported_for_direct_peers(self):
        self.wg.state[A]['endpoint'] = '203.0.113.7:41000'
        self.tick()
        self.assertEqual(self.item('3'), '3:d:20:4')
        self.wg.state[A]['endpoint'] = '[2408:8207:1::5]:51820'
        self.tick()
        self.assertEqual(self.item('3'), '3:d:20:6')

    def test_family_without_latency(self):
        self.values[0] = None
        self.wg.state[A]['endpoint'] = '[2408:8207:1::5]:51820'
        self.tick()
        self.assertEqual(self.item('3'), '3:d::6')

    def test_measure_interval(self):
        self.tick(); self.tick(5); self.tick(5)
        self.assertEqual(len(self.pings), 2)                  # 两个对端各测一次，LAT_INTERVAL 内不重复
        self.tick(mp.LAT_INTERVAL)
        self.assertEqual(len(self.pings), 4)

    def test_small_jitter_does_not_change_report(self):
        self.tick()
        n = len(self.reports)
        self.values[0] = 23.0                                 # 抖动在迟滞范围内
        self.tick(mp.LAT_INTERVAL)
        self.assertEqual(self.item('3'), '3:d:20')
        self.assertEqual(self.d.rtt_ms(A), 23)                # 本地状态文件仍是最新值
        self.assertEqual(len(self.reports), n)                # 不会为了抖动多上报一次
        self.values[0] = 60.0                                 # 明显变化才更新
        self.tick(mp.LAT_INTERVAL)
        self.assertEqual(self.item('3'), '3:d:60')

    def test_loss_is_reported_with_hysteresis(self):
        self.values[0] = (20.0, 5, 0)
        self.tick()
        self.assertEqual(self.item('3'), '3:d:20::0')                # 延迟 20，没标记协议，丢包 0
        self.values[0] = (20.0, 5, 1)                                # 5 个包丢 1 个；窗口内累计 1/10 = 10%
        self.tick(mp.LAT_INTERVAL)
        self.assertEqual(self.item('3'), '3:d:20::10')
        with open(os.path.join(self.tmp, 'status.json')) as f:
            self.assertEqual(json.load(f)['peers'][1]['loss'], 10)
        self.values[0] = (20.0, 5, 0)                                # 2/15 -> 13%，变化不到 5 个点: 上报值保持 10
        self.tick(mp.LAT_INTERVAL)
        self.assertEqual(self.item('3'), '3:d:20::10')

    def test_total_loss_still_reported(self):
        self.wg.state[A]['endpoint'] = '203.0.113.7:41000'
        self.values[0] = (None, 5, 5)
        self.tick()
        self.assertEqual(self.item('3'), '3:d::4:100')
        self.assertIsNone(self.d.rtt_ms(A))

    def test_loss_window_expires(self):
        self.values[0] = (20.0, 5, 5)
        self.tick()
        self.values[0] = None
        for _ in range(0, mp.LOSS_WINDOW + mp.LAT_INTERVAL + 1, mp.LAT_INTERVAL):
            self.tick(mp.LAT_INTERVAL)
        self.assertIsNone(self.d.loss_pct(A))

    def test_failed_ping_keeps_state_without_latency(self):
        self.values[0] = None
        self.tick()
        self.assertEqual(self.d.paths_str, '1:d,3:d')
        self.assertIsNone(self.d.rtt_ms(A))

    def test_stale_latency_expires(self):
        self.tick()
        self.values[0] = None
        for _ in range(0, mp.LAT_TTL + mp.LAT_INTERVAL + 1, mp.LAT_INTERVAL):
            self.tick(mp.LAT_INTERVAL)
        self.assertEqual(self.d.paths_str, '1:d,3:d')

    def test_no_ping_while_trying(self):
        self.wg.state[A]['hs'] = 0                            # 从未握手 -> 尝试中
        self.clock[0] += 1
        self.wg.state[HUB]['hs'] = int(self.clock[0]) - 5
        self.d.tick()
        self.assertEqual(self.item('3'), '3:p')
        self.assertNotIn('10.88.0.3', self.pings)

    def test_latency_dropped_when_path_switches_to_relay(self):
        self.tick()
        self.assertEqual(self.item('3'), '3:d:20')
        self.wg.state[A]['hs'] = 0                            # 直连断了
        for _ in range(0, 130, 5):
            self.clock[0] += 5
            self.wg.state[HUB]['hs'] = int(self.clock[0]) - 5
            self.d.tick()
            if (self.item('3') or '').startswith('3:r'):
                break
        self.assertTrue((self.item('3') or '').startswith('3:r'))
        self.values[0] = 95.0                                 # 中转路径的延迟更高
        self.clock[0] += mp.LAT_INTERVAL
        self.wg.state[HUB]['hs'] = int(self.clock[0]) - 5
        self.d.tick()
        self.assertEqual(self.item('3'), '3:r:95')            # 中转状态不带 IPv6/IPv4 标记


class AliveReportTests(unittest.TestCase):
    def test_alive_lists_peers_with_fresh_handshake(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, 'm.conf')
        with open(path, 'w') as fh: fh.write(CONF)
        clock, wg, reports = [1000.0], FakeWg(), []
        d = mp.Daemon('meshlink', 'https://x', 's', path, wg=wg, report_fn=lambda *a: reports.append(a) or True,
                      stun_fn=lambda *a: ([], None), clock=lambda: clock[0], status_file=os.path.join(tmp, 's.json'))
        wg.state[HUB]['hs'] = 995                   # Hub 刚握手；A 从未握手
        d.tick()
        self.assertEqual(reports[-1][3], '1')
        clock[0] += 5; wg.state[A]['hs'] = 1000      # A 也握手了 -> 立刻上报
        wg.state[HUB]['hs'] = 1000
        d.tick()
        self.assertEqual(reports[-1][3], '1,3')
        clock[0] += mp.SESSION_MAX + 10              # 握手都过期 -> 变成空，也要上报
        d.tick()
        self.assertEqual(reports[-1][3], '')


if __name__ == '__main__':
    unittest.main(verbosity=1)
