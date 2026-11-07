// Worker 接口测试: node --test tests/   （Node >= 22.13，用内置 node:sqlite 模拟 D1）
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker from '../public/_worker.js';

function makeEnv(schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')) {
  const db = new DatabaseSync(':memory:');
  db.exec(schema);
  const stmt = (sql, args = []) => ({
    bind: (...a) => stmt(sql, a),
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => {
      const r = db.prepare(sql).run(...args);
      return { meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
    },
  });
  return {
    db,
    DB: { prepare: (sql) => stmt(sql), batch: async (list) => { for (const s of list) await s.run(); return []; } },
    ASSETS: { fetch: async () => new Response('asset') },
    ADMIN_PASSWORD: 'pw', SESSION_SECRET: 'secret',
    IP_LOOKUP: async () => null,   // 测试里不访问外部 IP 库
  };
}

async function call(env, method, path, { body, cookie, bearer, form, ip = '203.0.113.9' } = {}) {
  const headers = { 'CF-Connecting-IP': ip };
  if (cookie) headers.Cookie = cookie;
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  let payload;
  if (body) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body); }
  if (form) payload = new URLSearchParams(form).toString();
  const r = await worker.fetch(new Request('https://mesh.example' + path, { method, headers, body: payload }), env);
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, text, json, headers: r.headers };
}

const pubKey = (c) => c.repeat(43) + '=';

async function setup(mode = 'mesh') {
  const env = makeEnv();
  const login = await call(env, 'POST', '/api/admin/login', { body: { password: 'pw' } });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const net = (await call(env, 'POST', '/api/admin/networks', { cookie, body: { name: 'lab', cidr: '10.88.0.0/24', mode } })).json.id;
  const nodes = {};
  for (const [name, is_hub, c] of [['hub1', true, 'H'], ['alice', false, 'A'], ['bob', false, 'B']]) {
    const id = (await call(env, 'POST', `/api/admin/networks/${net}/nodes`, { cookie, body: { name, is_hub, subnets: name === 'bob' ? '192.168.7.0/24' : '' } })).json.id;
    const list = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes;
    const token = list.find((n) => n.id === id).enroll_token;
    const reg = await call(env, 'POST', '/api/agent/register', { form: { token, public_key: pubKey(c) } });
    assert.equal(reg.status, 200, reg.text);
    nodes[name] = { id, secret: /NODE_SECRET=(\w+)/.exec(reg.text)[1], pub: pubKey(c) };
  }
  return { env, cookie, net, nodes };
}

const sync = (env, node, ip) => call(env, 'POST', '/api/agent/sync', { bearer: node.secret, ip });
const peerBlock = (cfg, name) => cfg.split('\n\n').find((b) => b.includes(`# ${name}\n`));

test('config 包含给路径管理器用的元信息；旧版 agent 可忽略这些注释', async () => {
  const { env, nodes } = await setup();
  await sync(env, nodes.hub1, '198.51.100.1');
  await sync(env, nodes.bob, '203.0.113.50');
  const r = await sync(env, nodes.alice, '203.0.113.60');
  assert.equal(r.status, 200);
  assert.match(r.text, new RegExp(`# meshlink self id=${nodes.alice.id} mode=mesh hub=0 override=0`));
  const hub = peerBlock(r.text, 'hub1');
  assert.match(hub, /# meshlink peer id=\d+ hub=1 online=1 nat=unknown/);
  assert.match(hub, /Endpoint = 198\.51\.100\.1:51820/);
  const bob = peerBlock(r.text, 'bob');
  assert.match(bob, /AllowedIPs = 10\.88\.0\.3\/32, 192\.168\.7\.0\/24/);
  assert.match(bob, /hub=0 online=1/);
  // 所有元信息都是注释行
  for (const l of r.text.split('\n')) if (l.includes('meshlink self') || l.includes('meshlink peer')) assert.ok(l.startsWith('#'));
});

test('report: STUN 端点优先于 CF 看到的 IP，且只在新鲜时使用', async () => {
  const { env, nodes } = await setup();
  await sync(env, nodes.bob, '203.0.113.50');
  let cfg = (await sync(env, nodes.alice, '203.0.113.60')).text;
  assert.match(peerBlock(cfg, 'bob'), /Endpoint = 203\.0\.113\.50:51820/);   // 没有 STUN 时沿用旧行为

  const rep = await call(env, 'POST', '/api/agent/report', { bearer: nodes.bob.secret, form: { stun: '203.0.113.50:44123', nat: 'cone', paths: `${nodes.alice.id}:d,${nodes.hub1.id}:p` } });
  assert.equal(rep.status, 200, rep.text);
  cfg = (await sync(env, nodes.alice, '203.0.113.60')).text;
  assert.match(peerBlock(cfg, 'bob'), /Endpoint = 203\.0\.113\.50:44123/);
  assert.match(peerBlock(cfg, 'bob'), /nat=cone/);

  // 过期后回退
  env.db.exec(`UPDATE nodes SET stun_at = stun_at - 4000 WHERE id=${nodes.bob.id}`);
  cfg = (await sync(env, nodes.alice, '203.0.113.60')).text;
  assert.match(peerBlock(cfg, 'bob'), /Endpoint = 203\.0\.113\.50:51820/);
});

test('report: 手动指定的对外地址优先级最高', async () => {
  const { env, cookie, nodes } = await setup();
  await sync(env, nodes.bob, '203.0.113.50');
  await call(env, 'POST', '/api/agent/report', { bearer: nodes.bob.secret, form: { stun: '203.0.113.50:44123', nat: 'cone' } });
  await call(env, 'PUT', `/api/admin/nodes/${nodes.bob.id}`, { cookie, body: { endpoint_override: 'vpn.example.com:7000' } });
  const cfg = (await sync(env, nodes.alice, '203.0.113.60')).text;
  assert.match(peerBlock(cfg, 'bob'), /Endpoint = vpn\.example\.com:7000/);
});

test('report: 输入校验', async () => {
  const { env, nodes } = await setup();
  const bad = async (form) => (await call(env, 'POST', '/api/agent/report', { bearer: nodes.alice.secret, form })).status;
  assert.equal(await bad({ stun: '127.0.0.1:5000', nat: 'cone' }), 400);
  assert.equal(await bad({ stun: '0.0.0.0:5000', nat: 'cone' }), 400);
  assert.equal(await bad({ stun: '224.0.0.1:5000', nat: 'cone' }), 400);
  assert.equal(await bad({ stun: '1.2.3.4:70000', nat: 'cone' }), 400);
  assert.equal(await bad({ stun: '1.2.3.4:80\nHost: x', nat: 'cone' }), 400);
  assert.equal(await bad({ stun: 'evil.com:80', nat: 'cone' }), 400);
  assert.equal(await bad({ stun: '1.2.3.4:80', nat: 'weird' }), 400);
  assert.equal(await bad({ stun: '1.2.3.4:80', nat: 'cone', paths: "1:d,2:x" }), 400);
  assert.equal(await bad({ stun: '1.2.3.4:80', nat: 'cone', paths: "1:d;DROP TABLE nodes" }), 400);
  assert.equal(await bad({ stun: '', nat: 'unknown', paths: '' }), 200);        // STUN 失败: 清空，回退到 last_ip
  assert.equal(await bad({ stun: '1.2.3.4:80', nat: 'public', paths: '' }), 200);
});

test('report: paths 可附带往返延迟，旧格式仍然兼容', async () => {
  const { env, cookie, net, nodes } = await setup();
  const rep = (paths) => call(env, 'POST', '/api/agent/report', { bearer: nodes.alice.secret, form: { stun: '203.0.113.60:5555', nat: 'cone', paths } });
  assert.equal((await rep(`${nodes.bob.id}:d:23,${nodes.hub1.id}:r:140`)).status, 200);
  const list = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes;
  assert.deepEqual(list.find((n) => n.id === nodes.alice.id).paths, [
    { peer_id: nodes.bob.id, state: 'd', rtt: 23 },
    { peer_id: nodes.hub1.id, state: 'r', rtt: 140 },
  ]);
  assert.equal((await rep(`${nodes.bob.id}:d,${nodes.hub1.id}:p`)).status, 200);     // 旧 agent 的格式
  const old = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === nodes.alice.id);
  assert.deepEqual(old.paths, [{ peer_id: nodes.bob.id, state: 'd' }, { peer_id: nodes.hub1.id, state: 'p' }]);
  assert.equal((await rep(`${nodes.bob.id}:d:23:6,${nodes.hub1.id}:d::4`)).status, 200);   // 带 IPv6/IPv4 标记
  const fam = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === nodes.alice.id);
  assert.deepEqual(fam.paths, [{ peer_id: nodes.bob.id, state: 'd', rtt: 23, family: 'v6' }, { peer_id: nodes.hub1.id, state: 'd', family: 'v4' }]);
  for (const bad of ['1:d:', '1:d:abc', '1:d:123456', '1:x:5', '1:d:5:7', '1:d::']) assert.equal((await rep(bad)).status, 400, bad);
});

test('在线: agent 没同步控制面，但在线节点报告与它有新鲜握手时显示在线（仅隧道）', async () => {
  const { env, cookie, net, nodes } = await setup();
  await sync(env, nodes.hub1, '198.51.100.1');
  await sync(env, nodes.alice, '203.0.113.60');
  // bob 从没同步过（或同步早就断了）: 离线
  const get = async () => (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === nodes.bob.id);
  env.db.exec(`UPDATE nodes SET last_seen = ${Math.floor(Date.now() / 1000) - 3600} WHERE id = ${nodes.bob.id}`);
  assert.equal((await get()).online, false);
  // 在线的 hub 报告和 bob 有新鲜握手
  const rep = (node, alive) => call(env, 'POST', '/api/agent/report', { bearer: node.secret, form: { stun: '', nat: 'public', paths: '', alive } });
  assert.equal((await rep(nodes.hub1, String(nodes.bob.id))).status, 200);
  const b = await get();
  assert.equal(b.online, true); assert.equal(b.observed, true);
  // 其他节点的配置里也把 bob 当成在线（路径管理器不会把它当离线对端）
  const cfg = (await sync(env, nodes.alice, '203.0.113.60')).text;
  assert.match(peerBlock(cfg, 'bob'), /hub=0 online=1/);
  // 握手消失 -> 又变回离线
  await rep(nodes.hub1, '');
  assert.equal((await get()).online, false);
  // 报告者自己离线时，它的 alive 不可信
  await rep(nodes.hub1, String(nodes.bob.id));
  env.db.exec(`UPDATE nodes SET last_seen = ${Math.floor(Date.now() / 1000) - 3600} WHERE id = ${nodes.hub1.id}`);
  assert.equal((await get()).online, false);
  // 格式校验；不带 alive 的旧 agent 不会清掉已有值
  assert.equal((await rep(nodes.alice, '1;DROP')).status, 400);
});

test('report: 需要节点凭证；禁用的节点被拒绝', async () => {
  const { env, cookie, nodes } = await setup();
  assert.equal((await call(env, 'POST', '/api/agent/report', { form: { stun: '1.2.3.4:80', nat: 'cone' } })).status, 401);
  assert.equal((await call(env, 'POST', '/api/agent/report', { bearer: 'f'.repeat(64), form: { stun: '1.2.3.4:80', nat: 'cone' } })).status, 401);
  await call(env, 'PUT', `/api/admin/nodes/${nodes.alice.id}`, { cookie, body: { enabled: false } });
  assert.equal((await call(env, 'POST', '/api/agent/report', { bearer: nodes.alice.secret, form: { stun: '1.2.3.4:80', nat: 'cone' } })).status, 403);
});

test('admin 节点列表暴露 NAT 类型、STUN 端点和路径状态；重置后清空', async () => {
  const { env, cookie, net, nodes } = await setup();
  await sync(env, nodes.alice, '203.0.113.60');
  await call(env, 'POST', '/api/agent/report', { bearer: nodes.alice.secret, form: { stun: '203.0.113.60:5555', nat: 'symmetric', paths: `${nodes.bob.id}:r,${nodes.hub1.id}:d` } });
  let list = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes;
  let alice = list.find((n) => n.id === nodes.alice.id);
  assert.equal(alice.nat_type, 'symmetric');
  assert.equal(alice.stun_endpoint, '203.0.113.60:5555');
  assert.deepEqual(alice.paths, [{ peer_id: nodes.bob.id, state: 'r' }, { peer_id: nodes.hub1.id, state: 'd' }]);
  await call(env, 'POST', `/api/admin/nodes/${nodes.alice.id}/reset`, { cookie });
  list = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes;
  alice = list.find((n) => n.id === nodes.alice.id);
  assert.equal(alice.nat_type, ''); assert.equal(alice.stun_endpoint, ''); assert.deepEqual(alice.paths, []);
});

test('对端离线时 online=0；hub 模式下 self 标记 mode=hub 且辐射节点只看到 Hub', async () => {
  const { env, nodes } = await setup('hub');
  await sync(env, nodes.hub1, '198.51.100.1');
  const r = await sync(env, nodes.alice, '203.0.113.60');
  assert.match(r.text, /# meshlink self .* mode=hub hub=0/);
  assert.ok(!r.text.includes('# bob'));
  env.db.exec(`UPDATE nodes SET last_seen = last_seen - 1000 WHERE id=${nodes.bob.id}`);   // bob 已经 1000 秒没同步
  const h = await sync(env, nodes.hub1, '198.51.100.1');
  assert.match(peerBlock(h.text, 'alice'), /online=1/);
  assert.match(peerBlock(h.text, 'bob'), /online=0/);
});

test('向后兼容: 未执行迁移的旧库上 sync 照常，report 给出明确错误', async () => {
  const oldSchema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')
    .replace(/^\s*(stun_endpoint|stun_at|nat_type|paths)\s.*\n/gm, '');
  const env = makeEnv(oldSchema);
  env.db.exec("INSERT INTO networks (name,cidr,mode,created_at) VALUES ('lab','10.88.0.0/24','mesh',1)");
  const secret = 'a'.repeat(64);
  const crypto = await import('node:crypto');
  const hash = crypto.createHash('sha256').update(secret).digest('hex');
  env.db.exec(`INSERT INTO nodes (network_id,name,ip,public_key,secret_hash,created_at) VALUES (1,'n1','10.88.0.1','${pubKey('A')}','${hash}',1)`);
  const s = await call(env, 'POST', '/api/agent/sync', { bearer: secret });
  assert.equal(s.status, 200, s.text);
  const r = await call(env, 'POST', '/api/agent/report', { bearer: secret, form: { stun: '1.2.3.4:80', nat: 'cone' } });
  assert.equal(r.status, 500);
  assert.match(r.text, /migrations\/0001_stun_paths\.sql/);
});

test('迁移文件可以在旧库上执行', async () => {
  const oldSchema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')
    .replace(/^\s*(stun_endpoint|stun_at|nat_type|paths)\s.*\n/gm, '');
  const env = makeEnv(oldSchema);
  env.db.exec(readFileSync(new URL('../migrations/0001_stun_paths.sql', import.meta.url), 'utf8'));
  const cols = env.db.prepare('PRAGMA table_info(nodes)').all().map((c) => c.name);
  for (const c of ['stun_endpoint', 'stun_at', 'nat_type', 'paths']) assert.ok(cols.includes(c), c);
});

// ───────────── 客户端设备（手机/电脑，官方 WireGuard App）─────────────

const addClient = (env, cookie, net, name, c) =>
  call(env, 'POST', `/api/admin/networks/${net}/clients`, { cookie, body: { name, public_key: pubKey(c) } });

test('客户端: 没有可用 Hub 时拒绝创建；输入校验', async () => {
  const env = makeEnv();
  const login = await call(env, 'POST', '/api/admin/login', { body: { password: 'pw' } });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const net = (await call(env, 'POST', '/api/admin/networks', { cookie, body: { name: 'lab', cidr: '10.88.0.0/24' } })).json.id;
  assert.equal((await addClient(env, cookie, net, 'phone', 'P')).status, 409);
  const bad = await call(env, 'POST', `/api/admin/networks/${net}/clients`, { cookie, body: { name: 'phone', public_key: 'nope' } });
  assert.equal(bad.status, 400);
});

test('客户端: 只有主 Hub 把它当对端；其他节点把它挂在主 Hub 的 AllowedIPs 上', async () => {
  const { env, cookie, net, nodes } = await setup();
  await sync(env, nodes.hub1, '198.51.100.1');
  // 第二个 Hub
  const h2 = (await call(env, 'POST', `/api/admin/networks/${net}/nodes`, { cookie, body: { name: 'hub2', is_hub: true } })).json.id;
  const tok = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === h2).enroll_token;
  const reg = await call(env, 'POST', '/api/agent/register', { form: { token: tok, public_key: pubKey('Z') } });
  const hub2 = { id: h2, secret: /NODE_SECRET=(\w+)/.exec(reg.text)[1] };

  const r = await addClient(env, cookie, net, 'phone', 'P');
  assert.equal(r.status, 201, r.text);
  assert.equal(r.json.hub_name, 'hub1');
  assert.equal(r.json.hub_public_key, pubKey('H'));
  assert.equal(r.json.endpoint, '198.51.100.1:51820');
  assert.equal(r.json.allowed_ips, '10.88.0.0/24, 192.168.7.0/24');
  const cip = r.json.ip;

  // 主 Hub: 客户端是普通对端，没有 Endpoint
  const c1 = (await sync(env, nodes.hub1, '198.51.100.1')).text;
  const blk = c1.split('\n\n').find((b) => b.includes('(client)'));
  assert.match(blk, new RegExp(`PublicKey = ${pubKey('P')}`));
  assert.match(blk, new RegExp(`AllowedIPs = ${cip.replace(/\./g, '\\.')}/32`));
  assert.doesNotMatch(blk, /Endpoint/);

  // 普通节点: 没有客户端对端块，但主 Hub 的 AllowedIPs 里有它
  const c2 = (await sync(env, nodes.alice, '203.0.113.60')).text;
  assert.ok(!c2.includes('(client)'));
  assert.match(peerBlock(c2, 'hub1'), new RegExp(`AllowedIPs = 10\\.88\\.0\\.1/32, ${cip.replace(/\./g, '\\.')}/32`));

  // 第二个 Hub: 同样经主 Hub 访问客户端
  const c3 = (await sync(env, hub2, '198.51.100.2')).text;
  assert.ok(!c3.includes('(client)'));
  assert.match(peerBlock(c3, 'hub1'), new RegExp(`${cip.replace(/\./g, '\\.')}/32`));

  // 禁用后从所有配置里消失
  await call(env, 'PUT', `/api/admin/nodes/${r.json.id}`, { cookie, body: { enabled: false } });
  assert.ok(!(await sync(env, nodes.hub1, '198.51.100.1')).text.includes('(client)'));
  assert.doesNotMatch(peerBlock((await sync(env, nodes.alice, '203.0.113.60')).text, 'hub1'), new RegExp(`${cip.replace(/\./g, '\\.')}/32`));
});

test('客户端: 中心辐射模式下辐射节点已经通过 netCidr 覆盖客户端', async () => {
  const { env, cookie, net, nodes } = await setup('hub');
  await sync(env, nodes.hub1, '198.51.100.1');
  const r = await addClient(env, cookie, net, 'laptop', 'L');
  assert.equal(r.status, 201, r.text);
  const c = (await sync(env, nodes.alice, '203.0.113.60')).text;
  assert.match(peerBlock(c, 'hub1'), /AllowedIPs = [^\n]*10\.88\.0\.0\/24/);
  assert.ok((await sync(env, nodes.hub1, '198.51.100.1')).text.includes('(client)'));
});

test('客户端: 旧库没有 is_client 列时自动补列；换钥匙后公钥更新', async () => {
  const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8').split('\n').filter((l) => !l.includes('is_client')).join('\n');
  const env = makeEnv(schema);
  const login = await call(env, 'POST', '/api/admin/login', { body: { password: 'pw' } });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const net = (await call(env, 'POST', '/api/admin/networks', { cookie, body: { name: 'lab', cidr: '10.88.0.0/24' } })).json.id;
  const id = (await call(env, 'POST', `/api/admin/networks/${net}/nodes`, { cookie, body: { name: 'hub1', is_hub: true, endpoint_override: 'hub.example.com' } })).json.id;
  const tok = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === id).enroll_token;
  await call(env, 'POST', '/api/agent/register', { form: { token: tok, public_key: pubKey('H') } });

  const r = await addClient(env, cookie, net, 'phone', 'P');
  assert.equal(r.status, 201, r.text);
  assert.equal(r.json.endpoint, 'hub.example.com:51820');
  const k = await call(env, 'PUT', `/api/admin/nodes/${r.json.id}/client`, { cookie, body: { public_key: pubKey('Q') } });
  assert.equal(k.status, 200, k.text);
  const list = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes;
  const phone = list.find((n) => n.name === 'phone');
  assert.equal(phone.public_key, pubKey('Q'));
  assert.equal(phone.is_client, true);
  assert.equal(phone.enroll_token, null);
  // 普通节点不能被当成客户端换钥匙
  assert.equal((await call(env, 'PUT', `/api/admin/nodes/${id}/client`, { cookie, body: { public_key: pubKey('Q') } })).status, 404);
});

test('设置: 副标题可自定义、可清空，需要登录，超长被拒绝', async () => {
  const env = makeEnv();
  assert.equal((await call(env, 'GET', '/api/admin/settings')).status, 401);
  const login = await call(env, 'POST', '/api/admin/login', { body: { password: 'pw' } });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  assert.equal((await call(env, 'GET', '/api/admin/settings', { cookie })).json.subtitle, null);
  assert.equal((await call(env, 'PUT', '/api/admin/settings', { cookie, body: { subtitle: '  龍哥的专属组网 ' } })).json.subtitle, '龍哥的专属组网');
  assert.equal((await call(env, 'GET', '/api/admin/settings', { cookie })).json.subtitle, '龍哥的专属组网');
  assert.equal((await call(env, 'PUT', '/api/admin/settings', { cookie, body: { subtitle: '' } })).json.subtitle, '');
  assert.equal((await call(env, 'PUT', '/api/admin/settings', { cookie, body: { subtitle: 'x'.repeat(101) } })).status, 400);
});

test('虚拟 IP: 创建时可指定；修改时校验网段、占用，并体现在配置里', async () => {
  const { env, cookie, net, nodes } = await setup(); // hub1=.1 alice=.2 bob=.3
  const mk = (body) => call(env, 'POST', `/api/admin/networks/${net}/nodes`, { cookie, body });
  assert.equal((await mk({ name: 'c1', ip: '10.88.0.50' })).status, 201);
  assert.equal((await mk({ name: 'c2', ip: '10.88.0.50' })).status, 409);
  assert.equal((await mk({ name: 'c3', ip: '10.99.0.5' })).status, 400);
  assert.equal((await mk({ name: 'c4', ip: '10.88.0.0' })).status, 400);
  assert.equal((await mk({ name: 'c5', ip: '10.88.0.255' })).status, 400);
  assert.equal((await mk({ name: 'c6', ip: 'abc' })).status, 400);
  assert.equal((await mk({ name: 'c7', ip: '' })).status, 201); // 留空仍然自动分配
  const put = (id, ip) => call(env, 'PUT', `/api/admin/nodes/${id}`, { cookie, body: { ip } });
  assert.equal((await put(nodes.alice.id, '10.88.0.2')).status, 200); // 没改
  assert.equal((await put(nodes.alice.id, '10.88.0.3')).status, 409); // 被 bob 占用
  assert.equal((await put(nodes.alice.id, '10.88.1.9')).status, 400);
  assert.equal((await put(nodes.alice.id, '10.88.0.77')).status, 200);
  assert.equal((await put(9999, '10.88.0.78')).status, 404);
  const own = await sync(env, nodes.alice, '203.0.113.60');
  assert.match(own.text, /Address = 10\.88\.0\.77\/24/);
  const peer = await sync(env, nodes.bob, '203.0.113.61');
  assert.match(peerBlock(peer.text, 'alice'), /AllowedIPs = 10\.88\.0\.77\/32/);
});

test('公网端点: IPv4 / IPv6 分开；agent 上报的全局 IPv6 被采用，链路本地和 ULA 被忽略', async () => {
  const { env, cookie, net, nodes } = await setup();
  const syncWith = (node, cf, v6) => worker.fetch(new Request('https://mesh.example/api/agent/sync', {
    method: 'POST', headers: { Authorization: `Bearer ${node.secret}`, 'CF-Connecting-IP': cf, ...(v6 ? { 'X-Meshlink-IPv6': v6 } : {}) },
  }), env);
  const view = async () => (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === nodes.alice.id);

  assert.equal((await syncWith(nodes.alice, '203.0.113.60', '2408:8207:1::5')).status, 200);
  let n = await view();
  assert.equal(n.ipv4, '203.0.113.60');
  assert.equal(n.ipv6, '2408:8207:1::5');

  for (const bad of ['fe80::1', 'fd00::5', '::1', 'not-an-ip', 'x'.repeat(60)]) {
    await syncWith(nodes.alice, '203.0.113.61', bad);
    n = await view();
    assert.equal(n.ipv6, '', bad);        // 无效/内网地址不展示
    assert.equal(n.ipv4, '203.0.113.61'); // IPv4 照常更新
  }

  await syncWith(nodes.alice, '2408:1::9', ''); // 节点是经 IPv6 连上控制面的
  n = await view();
  assert.equal(n.ipv6, '2408:1::9');
  assert.equal(n.ipv4, '');

  // STUN 端点优先作为 IPv4 显示
  await call(env, 'POST', '/api/agent/report', { bearer: nodes.alice.secret, form: { stun: '198.51.100.7:40000', nat: 'cone' } });
  assert.equal((await view()).ipv4, '198.51.100.7:40000');
});

test('IPv6 列: 未迁移的旧库上 sync 照常并自动补列；迁移文件可执行', async () => {
  const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8').replace(/^\s*ipv6\s.*\n/gm, '');
  const env = makeEnv(schema);
  env.db.exec("INSERT INTO networks (name,cidr,mode,created_at) VALUES ('lab','10.88.0.0/24','mesh',1)");
  const secret = 'b'.repeat(64);
  const crypto = await import('node:crypto');
  const hash = crypto.createHash('sha256').update(secret).digest('hex');
  env.db.exec(`INSERT INTO nodes (network_id,name,ip,public_key,secret_hash,created_at) VALUES (1,'n1','10.88.0.1','${pubKey('A')}','${hash}',1)`);
  const r = await worker.fetch(new Request('https://mesh.example/api/agent/sync', {
    method: 'POST', headers: { Authorization: `Bearer ${secret}`, 'CF-Connecting-IP': '203.0.113.5', 'X-Meshlink-IPv6': '2408:8207:1::5' },
  }), env);
  assert.equal(r.status, 200);
  assert.equal(env.db.prepare('SELECT ipv6 FROM nodes WHERE id=1').get().ipv6, '2408:8207:1::5');

  const env2 = makeEnv(schema);
  env2.db.exec(readFileSync(new URL('../migrations/0003_ipv6.sql', import.meta.url), 'utf8'));
  assert.ok(env2.db.prepare('PRAGMA table_info(nodes)').all().some((c) => c.name === 'ipv6'));
});

test('IPv6 优先: 双方都有 IPv6 且 agent 带路径管理器标记时 Endpoint 给 IPv6，并附 ep6/ep4；否则保持 IPv4', async () => {
  const { env, nodes } = await setup();
  const syncWith = (node, cf, v6, path = true) => worker.fetch(new Request('https://mesh.example/api/agent/sync', {
    method: 'POST',
    headers: { Authorization: `Bearer ${node.secret}`, 'CF-Connecting-IP': cf, ...(v6 ? { 'X-Meshlink-IPv6': v6 } : {}), ...(path ? { 'X-Meshlink-Path': '1' } : {}) },
  }), env).then(async (r) => ({ status: r.status, text: await r.text() }));

  await syncWith(nodes.bob, '203.0.113.50', '2408:8207:2::9');
  await call(env, 'POST', '/api/agent/report', { bearer: nodes.bob.secret, form: { stun: '203.0.113.50:41000', nat: 'cone' } });

  // alice 有 IPv6 + 路径管理器: 对 bob 先走 IPv6，IPv4(STUN 端点) 作为兜底写进元信息
  let r = await syncWith(nodes.alice, '203.0.113.60', '2408:8207:1::5');
  let bob = peerBlock(r.text, 'bob');
  assert.match(bob, /Endpoint = \[2408:8207:2::9\]:51820/);
  assert.match(bob, /# meshlink peer id=\d+ hub=0 online=1 nat=cone ep6=\[2408:8207:2::9\]:51820 ep4=203\.0\.113\.50:41000/);
  assert.doesNotMatch(bob, /Endpoint = 203/);

  // 没带路径管理器标记（旧 agent / 没有 python3）: 保持 IPv4，不会因为 IPv6 被拦而断连
  r = await syncWith(nodes.alice, '203.0.113.60', '2408:8207:1::5', false);
  bob = peerBlock(r.text, 'bob');
  assert.match(bob, /Endpoint = 203\.0\.113\.50:41000/);
  assert.doesNotMatch(bob, /ep6=/);

  // 本机没有 IPv6: 用 IPv4
  r = await syncWith(nodes.alice, '203.0.113.60', '');
  bob = peerBlock(r.text, 'bob');
  assert.match(bob, /Endpoint = 203\.0\.113\.50:41000/);

  // 对端没有 IPv6: 用 IPv4
  await syncWith(nodes.bob, '203.0.113.50', '');
  r = await syncWith(nodes.alice, '203.0.113.60', '2408:8207:1::5');
  assert.match(peerBlock(r.text, 'bob'), /Endpoint = 203\.0\.113\.50:41000/);
});

test('IPv6 优先: 对端只有 IPv6（没有 IPv4 端点）时只给 IPv6；手动指定的对外地址永远优先', async () => {
  const { env, cookie, net, nodes } = await setup();
  const syncWith = (node, cf, v6) => worker.fetch(new Request('https://mesh.example/api/agent/sync', {
    method: 'POST', headers: { Authorization: `Bearer ${node.secret}`, 'CF-Connecting-IP': cf, 'X-Meshlink-Path': '1', ...(v6 ? { 'X-Meshlink-IPv6': v6 } : {}) },
  }), env).then((r) => r.text());

  await syncWith(nodes.bob, '2408:8207:2::9', '');            // bob 经 IPv6 连上控制面，没有 IPv4 信息
  let cfg = await syncWith(nodes.alice, '203.0.113.60', '2408:8207:1::5');
  assert.match(peerBlock(cfg, 'bob'), /Endpoint = \[2408:8207:2::9\]:51820/);
  assert.doesNotMatch(peerBlock(cfg, 'bob'), /ep4=/);          // 没有 IPv4 可兜底，不写 ep6/ep4

  await call(env, 'PUT', `/api/admin/nodes/${nodes.bob.id}`, { cookie, body: { endpoint_override: 'bob.example.com' } });
  cfg = await syncWith(nodes.alice, '203.0.113.60', '2408:8207:1::5');
  assert.match(peerBlock(cfg, 'bob'), /Endpoint = bob\.example\.com:51820/);
  assert.doesNotMatch(peerBlock(cfg, 'bob'), /ep6=/);
});

test('运营商 / 归属地: 公网 IP 查询一次后走缓存；运营商归一成中文；私网/文档地址不查询；查询失败不影响列表', async () => {
  const { env, cookie, net, nodes } = await setup();
  const calls = [];
  env.IP_LOOKUP = async (ip) => {
    calls.push(ip);
    if (ip === '1.2.3.4') return { country: '中国', cc: 'CN', region: '广东', city: '深圳', isp: 'Chinanet', asn: '4134' };
    if (ip === '2408:8207:1::5') return { country: '中国', cc: 'CN', region: '广东', city: '广东', isp: 'CHINA UNICOM China169 Backbone', asn: 4837 };
    return null;
  };
  const syncWith = (node, cf, v6) => worker.fetch(new Request('https://mesh.example/api/agent/sync', {
    method: 'POST', headers: { Authorization: `Bearer ${node.secret}`, 'CF-Connecting-IP': cf, ...(v6 ? { 'X-Meshlink-IPv6': v6 } : {}) },
  }), env);
  const list = async () => (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes;
  const get = async (id) => (await list()).find((n) => n.id === id);

  await syncWith(nodes.alice, '1.2.3.4', '2408:8207:1::5');
  await syncWith(nodes.bob, '203.0.113.9');            // 文档网段: 不查询
  await syncWith(nodes.hub1, '10.1.1.1');              // 私网: 不查询

  let a = await get(nodes.alice.id);
  assert.deepEqual(a.ipv4_info, { carrier: '中国电信', isp: 'Chinanet', asn: '4134', cc: 'CN', location: '中国 广东 深圳' });
  assert.equal(a.ipv6_info.carrier, '中国联通');
  assert.equal(a.ipv6_info.asn, '4837');
  assert.equal(a.ipv6_info.location, '中国 广东');       // 省市同名只显示一次
  assert.equal((await get(nodes.bob.id)).ipv4_info, null);
  assert.equal((await get(nodes.hub1.id)).ipv4_info, null);
  assert.deepEqual([...calls].sort(), ['1.2.3.4', '2408:8207:1::5']);

  await list(); await list();                           // 再刷新: 全部走缓存
  assert.equal(calls.length, 2);

  // STUN 端点带端口：按 IP 查询，和缓存共用
  await call(env, 'POST', '/api/agent/report', { bearer: nodes.alice.secret, form: { stun: '1.2.3.4:40000', nat: 'cone' } });
  a = await get(nodes.alice.id);
  assert.equal(a.ipv4, '1.2.3.4:40000');
  assert.equal(a.ipv4_info.carrier, '中国电信');
  assert.equal(calls.length, 2);

  // 查询失败: 列表照常返回，info 为 null；10 分钟内不重复查
  await syncWith(nodes.bob, '5.6.7.8');
  assert.equal((await get(nodes.bob.id)).ipv4_info, null);
  const n1 = calls.length;
  await list();
  assert.equal(calls.length, n1);

  // 抛异常同样不影响列表；第三方返回的 HTML 字符被清掉
  env.IP_LOOKUP = async () => { throw new Error('boom'); };
  await syncWith(nodes.bob, '9.9.9.9');
  assert.equal((await list()).length, 3);
  env.IP_LOOKUP = async () => ({ country: 'X<script>', isp: '<b>ISP</b>' });
  await syncWith(nodes.bob, '9.9.9.8');
  const b = await get(nodes.bob.id);
  assert.ok(!/[<>]/.test(JSON.stringify(b.ipv4_info)));
});

test('运营商 / 归属地: IPINFO_DISABLED 时完全不查询', async () => {
  const { env, cookie, net, nodes } = await setup();
  let n = 0;
  env.IP_LOOKUP = async () => { n++; return { country: '中国', isp: 'Chinanet' }; };
  env.IPINFO_DISABLED = '1';
  await worker.fetch(new Request('https://mesh.example/api/agent/sync', { method: 'POST', headers: { Authorization: `Bearer ${nodes.alice.secret}`, 'CF-Connecting-IP': '1.2.3.4' } }), env);
  const r = await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie });
  assert.equal(r.json.nodes.find((x) => x.id === nodes.alice.id).ipv4_info, null);
  assert.equal(n, 0);
});

test('手机/电脑在线状态: 主 Hub 的配置给客户端带 id 元信息；Hub 上报握手后客户端显示在线', async () => {
  const { env, cookie, net, nodes } = await setup();
  const sync = (n) => worker.fetch(new Request('https://mesh.example/api/agent/sync', {
    method: 'POST', headers: { Authorization: `Bearer ${n.secret}`, 'CF-Connecting-IP': '203.0.113.20' },
  }), env).then((x) => x.text());
  await sync(nodes.hub1);                                     // Hub 先上线，才有对外地址可给手机
  const r = await addClient(env, cookie, net, 'phone', 'P');
  assert.equal(r.status, 201, r.text);
  const cid = r.json.id;

  const hubCfg = await sync(nodes.hub1);
  assert.match(hubCfg, new RegExp(`# phone \\(client\\)\\n# meshlink peer id=${cid} hub=0 online=0 nat=unknown client=1\\nPublicKey`));
  assert.doesNotMatch(await sync(nodes.alice), /client=1/);   // 只有主 Hub 把客户端当对端

  const phone = async () => (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === cid);
  assert.equal((await phone()).online, false);                // 没人报告过握手

  const rep = await call(env, 'POST', '/api/agent/report', { bearer: nodes.hub1.secret, form: { nat: 'public', alive: String(cid) } });
  assert.equal(rep.status, 200, rep.text);
  assert.equal((await phone()).online, true);                 // Hub 报告和手机有新鲜握手

  await call(env, 'POST', '/api/agent/report', { bearer: nodes.hub1.secret, form: { nat: 'public', alive: '' } });
  assert.equal((await phone()).online, false);                // 握手过期后恢复“未连接”
});

test('一键启用/停用: 只改本网络的设备；参数必须是布尔值；需要登录；网络不存在返回 404', async () => {
  const { env, cookie, net, nodes } = await setup();
  const other = (await call(env, 'POST', '/api/admin/networks', { cookie, body: { name: 'other', cidr: '10.99.0.0/24' } })).json.id;
  await call(env, 'POST', `/api/admin/networks/${other}/nodes`, { cookie, body: { name: 'x1' } });
  const list = async (id) => (await call(env, 'GET', `/api/admin/networks/${id}/nodes`, { cookie })).json.nodes;

  assert.equal((await call(env, 'PUT', `/api/admin/networks/${net}/enabled`, { body: { enabled: false } })).status, 401);
  assert.equal((await call(env, 'PUT', `/api/admin/networks/${net}/enabled`, { cookie, body: { enabled: 'no' } })).status, 400);
  assert.equal((await call(env, 'PUT', `/api/admin/networks/9999/enabled`, { cookie, body: { enabled: false } })).status, 404);

  let r = await call(env, 'PUT', `/api/admin/networks/${net}/enabled`, { cookie, body: { enabled: false } });
  assert.equal(r.status, 200);
  assert.equal(r.json.changed, 3);
  assert.ok((await list(net)).every((n) => n.enabled === false));
  assert.ok((await list(other)).every((n) => n.enabled === true));      // 别的网络不受影响

  r = await call(env, 'PUT', `/api/admin/networks/${net}/enabled`, { cookie, body: { enabled: true } });
  assert.equal(r.json.changed, 3);
  assert.ok((await list(net)).every((n) => n.enabled === true));
  assert.equal((await call(env, 'PUT', `/api/admin/networks/${net}/enabled`, { cookie, body: { enabled: true } })).json.changed, 0);

  // 手机/电脑的改名和改 IP 走同一个节点接口
  const sync = (n) => worker.fetch(new Request('https://mesh.example/api/agent/sync', { method: 'POST', headers: { Authorization: `Bearer ${n.secret}`, 'CF-Connecting-IP': '203.0.113.20' } }), env);
  await sync(nodes.hub1);
  const c = (await addClient(env, cookie, net, 'phone', 'P')).json;
  assert.equal((await call(env, 'PUT', `/api/admin/nodes/${c.id}`, { cookie, body: { name: 'my-phone', ip: '10.88.0.77' } })).status, 200);
  const phone = (await list(net)).find((n) => n.id === c.id);
  assert.equal(phone.name, 'my-phone');
  assert.equal(phone.ip, '10.88.0.77');
  assert.equal((await call(env, 'PUT', `/api/admin/nodes/${c.id}`, { cookie, body: { ip: '10.88.0.1' } })).status, 409);   // 与 hub1 等重复
});

test('report: paths 可附带丢包率，格式错误仍然拒绝', async () => {
  const { env, cookie, net, nodes } = await setup();
  const rep = (paths) => call(env, 'POST', '/api/agent/report', { bearer: nodes.alice.secret, form: { stun: '203.0.113.60:5555', nat: 'cone', paths } });
  assert.equal((await rep(`${nodes.bob.id}:d:6:4:0,${nodes.hub1.id}:r:15::12`)).status, 200);
  const a = (await call(env, 'GET', `/api/admin/networks/${net}/nodes`, { cookie })).json.nodes.find((n) => n.id === nodes.alice.id).paths;
  assert.deepEqual(a, [
    { peer_id: nodes.bob.id, state: 'd', rtt: 6, family: 'v4', loss: 0 },
    { peer_id: nodes.hub1.id, state: 'r', rtt: 15, loss: 12 },
  ]);
  assert.equal((await rep(`${nodes.bob.id}:d::6:100`)).status, 200);      // 全丢: 没有延迟
  for (const bad of ['1:d:5:4:1000', '1:d:5:4:x', '1:d:5:7:1', '1:d:5:4:', '1:d:1:4:1:1']) assert.equal((await rep(bad)).status, 400, bad);
});

test('config: 隧道 MTU 1380、保活 15 秒，Hub 带 MSS 钳制', async () => {
  const { env, cookie, net, nodes } = await setup();
  const r = await sync(env, nodes.hub1);
  assert.equal(r.status, 200);
  assert.match(r.text, /^MTU = 1380$/m);
  assert.match(r.text, /^PersistentKeepalive = 15$/m);
  assert.match(r.text, /TCPMSS --clamp-mss-to-pmtu/);
});
