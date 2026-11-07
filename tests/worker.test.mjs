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
