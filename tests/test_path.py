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
        self.assertEqual(self.reports[-1][2], '3:p')
        n = len(self.reports)
        d.tick(); self.assertEqual(len(self.reports), n)           # 没变化不重复上报
        self.clock[0] += 50
        d.tick()
        self.assertEqual(self.reports[-1][2], '3:r')                # 状态变化立即上报
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


if __name__ == '__main__':
    unittest.main(verbosity=1)
