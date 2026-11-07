// MeshLink — WireGuard 异地组网控制面 (Cloudflare Pages Functions，高级模式 _worker.js + D1)
//
// 部署在 Cloudflare Pages：本文件放在构建输出目录 public/ 根下，Pages 会把它当作 Worker 运行；
// /api/*、/healthz 由本文件处理（见 _routes.json），其余路径是 public/ 里的静态文件。
//
// 职责: 管理网络/节点、分配虚拟 IP、为每个节点生成 WireGuard 对端配置。
// 数据流量由各节点之间的 WireGuard 直连传输，不经过 Cloudflare；
// 私钥只存在节点本机，控制面只保存公钥。

const ONLINE_WINDOW = 240;     // 秒；超过这个时间没有同步视为离线
const WRITE_THROTTLE = 90;     // 秒；节点心跳写库的最小间隔，节省 D1 写入额度
const SESSION_TTL = 12 * 3600; // 管理员会话有效期
const SYNC_INTERVAL = 60;      // 秒；下发给 agent 的同步间隔
const STUN_FRESH = 1800;       // 秒；STUN 上报超过这个时间视为过期，回退到 CF 看到的公网 IP
const NAT_TYPES = new Set(['public', 'cone', 'symmetric', 'unknown']);

const enc = new TextEncoder();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const now = () => Math.floor(Date.now() / 1000);

const jsonResp = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });

const textResp = (body, status = 200, headers = {}) =>
  new Response(body, {
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });

// ───────────────────────── 加密 / 会话 ─────────────────────────

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function sha256(s) {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

function randomToken(bytes) {
  return hex(crypto.getRandomValues(new Uint8Array(bytes)));
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(data))));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function sessionKey(env) {
  const k = env.SESSION_SECRET || env.ADMIN_PASSWORD;
  if (!k) throw new HttpError(500, '服务端未设置 ADMIN_PASSWORD，请先执行 npx wrangler pages secret put ADMIN_PASSWORD --project-name meshlink 并重新部署');
  return k;
}

function getCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

async function verifySession(request, env) {
  const token = getCookie(request, 'mesh_session');
  if (!token) return false;
  const [exp, sig] = token.split('.');
  if (!exp || !sig || !(Number(exp) > now())) return false;
  return safeEqual(sig, await hmac(sessionKey(env), 'sess:' + exp));
}

// ───────────────────────── 校验 / IP 工具 ─────────────────────────

function ipToInt(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x) || Number(x) > 255) return null;
    n = n * 256 + Number(x);
  }
  return n;
}

const intToIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');

function parseCidr(str, minBits = 16, maxBits = 29) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(str).trim());
  if (!m) return null;
  const ip = ipToInt(m[1]);
  const bits = Number(m[2]);
  if (ip === null || bits < minBits || bits > maxBits) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { net: (ip & mask) >>> 0, bits, size: 2 ** (32 - bits) };
}

function isPrivateNet(c) {
  const ranges = [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10]];
  return ranges.some(([ip, bits]) => {
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return c.bits >= bits && ((c.net & mask) >>> 0) === ipToInt(ip);
  });
}

function validName(v) {
  const s = String(v ?? '').trim();
  if (!/^[\p{L}\p{N}_\-. ]{1,40}$/u.test(s)) throw new HttpError(400, '名称仅允许字母、数字、空格及 _ - .（1-40 字）');
  return s;
}

function normSubnets(v) {
  const out = [];
  for (const item of String(v ?? '').split(/[,\s]+/).filter(Boolean)) {
    const c = parseCidr(item, 8, 32);
    if (!c) throw new HttpError(400, `无效的网段: ${item.slice(0, 40)}（需为 IPv4 CIDR，掩码 8-32）`);
    const s = `${intToIp(c.net)}/${c.bits}`;
    if (!out.includes(s)) out.push(s);
  }
  return out.join(',');
}

function normEndpoint(v) {
  const s = String(v ?? '').trim();
  if (!s) return '';
  if (!/^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-]+)(:\d{1,5})?$/.test(s)) {
    throw new HttpError(400, '对外地址格式应为 host 或 host:port（IPv6 需加方括号）');
  }
  return s;
}

// agent 上报的 STUN 映射端点: 仅接受 IPv4 ip:port，排除 0/回环/组播
function normStun(v) {
  const s = String(v ?? '').trim();
  if (!s) return '';
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(s);
  const ip = m && ipToInt(m[1]);
  const port = m && Number(m[2]);
  if (!m || ip === null || port < 1 || port > 65535) throw new HttpError(400, 'stun 端点格式无效');
  const first = ip >>> 24;
  if (first === 0 || first === 127 || first >= 224) throw new HttpError(400, 'stun 端点地址不可用');
  return `${m[1]}:${port}`;
}

// 路径状态 "id:d,id:p,id:r"；d=直连 p=尝试中 r=中转
function normPaths(v) {
  const out = [];
  for (const item of String(v ?? '').split(',').filter(Boolean).slice(0, 200)) {
    if (!/^\d{1,10}:[dpr]$/.test(item)) throw new HttpError(400, 'paths 格式无效');
    out.push(item);
  }
  return out.join(',');
}

function parsePaths(v) {
  return String(v || '').split(',').filter(Boolean).map((x) => {
    const [id, state] = x.split(':');
    return { peer_id: Number(id), state };
  });
}

function parseNodeFields(b) {
  const o = {};
  if (b.name !== undefined) o.name = validName(b.name);
  if (b.is_hub !== undefined) o.is_hub = b.is_hub ? 1 : 0;
  if (b.subnets !== undefined) o.subnets = normSubnets(b.subnets);
  if (b.endpoint_override !== undefined) o.endpoint_override = normEndpoint(b.endpoint_override);
  if (b.listen_port !== undefined) {
    const p = Number(b.listen_port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new HttpError(400, '监听端口需在 1-65535 之间');
    o.listen_port = p;
  }
  if (b.enabled !== undefined) o.enabled = b.enabled ? 1 : 0;
  return o;
}

const isUnique = (e) => /UNIQUE constraint failed/i.test(String(e && e.message));

async function readJson(request) {
  try {
    const b = await request.json();
    if (b && typeof b === 'object') return b;
  } catch { /* fallthrough */ }
  throw new HttpError(400, '请求格式错误');
}

// ───────────────────────── 业务逻辑 ─────────────────────────

async function allocateIp(env, net) {
  const c = parseCidr(net.cidr);
  const { results } = await env.DB.prepare('SELECT ip FROM nodes WHERE network_id=?').bind(net.id).all();
  const used = new Set(results.map((r) => ipToInt(r.ip)));
  for (let i = 1; i < c.size - 1; i++) {
    if (!used.has(c.net + i)) return intToIp(c.net + i);
  }
  return null;
}

async function createNode(env, netId, body) {
  const net = await env.DB.prepare('SELECT * FROM networks WHERE id=?').bind(netId).first();
  if (!net) throw new HttpError(404, '网络不存在');
  const f = parseNodeFields(body);
  if (!f.name) throw new HttpError(400, '节点名称必填');
  const token = randomToken(24);
  for (let i = 0; i < 5; i++) {
    const ip = await allocateIp(env, net);
    if (!ip) throw new HttpError(409, '地址池已用尽');
    try {
      const r = await env.DB.prepare(
        'INSERT INTO nodes (network_id,name,ip,enroll_token,is_hub,subnets,endpoint_override,listen_port,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
      ).bind(net.id, f.name, ip, token, f.is_hub || 0, f.subnets || '', f.endpoint_override || '', f.listen_port || 51820, now()).run();
      return r.meta.last_row_id;
    } catch (e) {
      if (isUnique(e)) {
        if (/nodes\.name/.test(String(e.message))) throw new HttpError(409, '该网络下已有同名节点');
        continue; // IP 冲突，重新分配
      }
      throw e;
    }
  }
  throw new HttpError(409, '分配地址失败，请重试');
}

const isOnline = (n, t) => !!(n.enabled && n.last_seen && t - n.last_seen < ONLINE_WINDOW);

function publicNode(n, t) {
  return {
    id: n.id,
    network_id: n.network_id,
    name: n.name,
    ip: n.ip,
    is_hub: !!n.is_hub,
    subnets: n.subnets || '',
    endpoint_override: n.endpoint_override || '',
    listen_port: n.listen_port,
    enabled: !!n.enabled,
    registered: !!n.public_key,
    public_key: n.public_key || '',
    enroll_token: n.enroll_token || null,
    last_ip: n.last_ip || '',
    last_seen: n.last_seen || null,
    online: isOnline(n, t),
    nat_type: n.nat_type || '',
    stun_endpoint: n.stun_endpoint && n.stun_at && t - n.stun_at < STUN_FRESH ? n.stun_endpoint : '',
    paths: parsePaths(n.paths),
    created_at: n.created_at,
  };
}

// 对端地址优先级: 手动指定 > agent 用 STUN 探测到的真实映射端点 > CF 看到的公网 IP + 监听端口
function endpointFor(p, t) {
  if (p.endpoint_override) {
    return /:\d+$/.test(p.endpoint_override) ? p.endpoint_override : `${p.endpoint_override}:${p.listen_port}`;
  }
  if (p.stun_endpoint && p.stun_at && t - p.stun_at < STUN_FRESH) return p.stun_endpoint;
  if (!p.last_ip) return null;
  return p.last_ip.includes(':') ? `[${p.last_ip}]:${p.listen_port}` : `${p.last_ip}:${p.listen_port}`;
}

// 生成节点的 wg-quick 配置；私钥用占位符，由 agent 在本机替换
//
// 注释行 "# meshlink self/peer ..." 是给 agent 的路径管理器看的元信息（wg 会忽略注释）:
//   self: mode=mesh|hub  hub=0|1  override=0|1
//   peer: id  hub  online  nat
// mesh 模式下 agent 会先尝试直连，打不通时把该对端经由 Hub 中转。
function buildConfig(self, net, peers, t) {
  const c = parseCidr(net.cidr);
  const netCidr = `${intToIp(c.net)}/${c.bits}`;
  const L = [
    `# MeshLink config for ${self.name}`,
    `# interval=${SYNC_INTERVAL}`,
    `# meshlink self id=${self.id} mode=${net.mode === 'hub' ? 'hub' : 'mesh'} hub=${self.is_hub ? 1 : 0} override=${self.endpoint_override ? 1 : 0}`,
    '[Interface]',
    `Address = ${self.ip}/${c.bits}`,
    `ListenPort = ${self.listen_port}`,
    'PrivateKey = __PRIVATE_KEY__',
  ];
  if (self.is_hub || self.subnets) {
    L.push(
      'PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null || true; iptables -I FORWARD -i %i -j ACCEPT || true; iptables -I FORWARD -o %i -j ACCEPT || true',
      'PostDown = iptables -D FORWARD -i %i -j ACCEPT || true; iptables -D FORWARD -o %i -j ACCEPT || true'
    );
  }

  const hubs = peers.filter((p) => p.is_hub);
  const spoke = net.mode === 'hub' && !self.is_hub;
  const list = spoke ? hubs : peers;
  const primaryHub = hubs[0];

  for (const p of list) {
    const allowed = [`${p.ip}/32`];
    if (p.subnets) allowed.push(...p.subnets.split(','));
    if (spoke && p === primaryHub) {
      // 中心辐射模式: 其余节点（及其内网网段）的流量经主 Hub 中转
      allowed.push(netCidr);
      for (const o of peers) if (o !== p && o.subnets) allowed.push(...o.subnets.split(','));
    }
    L.push(
      '', '[Peer]', `# ${p.name}`,
      `# meshlink peer id=${p.id} hub=${p.is_hub ? 1 : 0} online=${isOnline(p, t) ? 1 : 0} nat=${NAT_TYPES.has(p.nat_type) ? p.nat_type : 'unknown'}`,
      `PublicKey = ${p.public_key}`, `AllowedIPs = ${[...new Set(allowed)].join(', ')}`
    );
    const ep = endpointFor(p, t);
    if (ep) L.push(`Endpoint = ${ep}`);
    L.push('PersistentKeepalive = 25');
  }
  return L.join('\n') + '\n';
}

// ───────────────────────── 节点 (agent) 接口 ─────────────────────────

async function authNode(request, env) {
  const m = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.get('Authorization') || '');
  if (!m) throw new HttpError(401, 'unauthorized');
  const node = await env.DB.prepare(
    'SELECT n.*, w.cidr AS cidr, w.mode AS mode FROM nodes n JOIN networks w ON w.id=n.network_id WHERE n.secret_hash=?'
  ).bind(await sha256(m[1])).first();
  if (!node) throw new HttpError(401, 'unauthorized');
  if (!node.enabled) throw new HttpError(403, 'node disabled');
  return node;
}

async function handleAgent(request, env, url) {
  const path = url.pathname.slice('/api/agent'.length);
  if (request.method !== 'POST') throw new HttpError(405, 'method not allowed');

  if (path === '/register') {
    const form = new URLSearchParams(await request.text());
    const token = form.get('token') || '';
    const pub = form.get('public_key') || '';
    if (!/^[A-Za-z0-9+/]{43}=$/.test(pub)) throw new HttpError(400, '公钥格式无效');
    if (!/^[0-9a-f]{48}$/.test(token)) throw new HttpError(403, '注册令牌无效或已使用');
    const node = await env.DB.prepare(
      'SELECT n.*, w.cidr AS cidr, w.name AS net_name FROM nodes n JOIN networks w ON w.id=n.network_id WHERE n.enroll_token=?'
    ).bind(token).first();
    if (!node) throw new HttpError(403, '注册令牌无效或已使用');
    if (!node.enabled) throw new HttpError(403, '该节点已被禁用');
    const secret = randomToken(32);
    const r = await env.DB.prepare(
      'UPDATE nodes SET public_key=?, secret_hash=?, enroll_token=NULL, last_seen=? WHERE id=? AND enroll_token=?'
    ).bind(pub, await sha256(secret), now(), node.id, token).run();
    if (r.meta.changes !== 1) throw new HttpError(403, '注册令牌无效或已使用');
    const c = parseCidr(node.cidr);
    return textResp(`NODE_SECRET=${secret}\nADDRESS=${node.ip}/${c.bits}\nNETWORK=${node.net_name}\n`);
  }

  if (path === '/report') {
    const node = await authNode(request, env);
    const form = new URLSearchParams(await request.text());
    const nat = form.get('nat') || 'unknown';
    if (!NAT_TYPES.has(nat)) throw new HttpError(400, 'nat 类型无效');
    const stun = normStun(form.get('stun'));
    const paths = normPaths(form.get('paths'));
    try {
      await env.DB.prepare('UPDATE nodes SET stun_endpoint=?, stun_at=?, nat_type=?, paths=? WHERE id=?')
        .bind(stun || null, stun ? now() : null, nat, paths, node.id).run();
    } catch (e) {
      if (/no such column/i.test(String(e && e.message))) {
        throw new HttpError(500, '数据库结构过旧，请执行 migrations/0001_stun_paths.sql');
      }
      throw e;
    }
    return textResp('ok\n');
  }

  if (path === '/sync') {
    const node = await authNode(request, env);

    const ip = request.headers.get('CF-Connecting-IP') || '';
    const t = now();
    if (ip && (ip !== node.last_ip || t - (node.last_seen || 0) >= WRITE_THROTTLE)) {
      await env.DB.prepare('UPDATE nodes SET last_ip=?, last_seen=? WHERE id=?').bind(ip, t, node.id).run();
      node.last_ip = ip;
    }

    const { results: peers } = await env.DB.prepare(
      'SELECT * FROM nodes WHERE network_id=? AND id!=? AND enabled=1 AND public_key IS NOT NULL ORDER BY id'
    ).bind(node.network_id, node.id).all();
    return textResp(buildConfig(node, node, peers, t));
  }

  throw new HttpError(404, 'not found');
}

// ───────────────────────── 管理后台接口 ─────────────────────────

async function login(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const t = now();
  const r = await env.DB.prepare('SELECT COUNT(*) AS c FROM login_attempts WHERE ip=? AND ts>?').bind(ip, t - 600).first();
  if (r.c >= 5) throw new HttpError(429, '尝试次数过多，请 10 分钟后再试');
  const body = await readJson(request);
  sessionKey(env);
  const ok = safeEqual(await sha256(String(body.password || '')), await sha256(env.ADMIN_PASSWORD || ''));
  if (!ok) {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO login_attempts (ip, ts) VALUES (?,?)').bind(ip, t),
      env.DB.prepare('DELETE FROM login_attempts WHERE ts<?').bind(t - 86400),
    ]);
    throw new HttpError(401, '密码错误');
  }
  await env.DB.prepare('DELETE FROM login_attempts WHERE ip=?').bind(ip).run();
  const exp = t + SESSION_TTL;
  const token = `${exp}.${await hmac(sessionKey(env), 'sess:' + exp)}`;
  return jsonResp({ ok: true }, 200, {
    'Set-Cookie': `mesh_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`,
  });
}

async function handleAdmin(request, env, url) {
  const path = url.pathname.slice('/api/admin'.length) || '/';
  const method = request.method;
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) throw new HttpError(403, 'bad origin');

  if (path === '/login' && method === 'POST') return login(request, env);
  if (!(await verifySession(request, env))) throw new HttpError(401, '未登录或会话已过期');

  if (path === '/logout' && method === 'POST') {
    return jsonResp({ ok: true }, 200, { 'Set-Cookie': 'mesh_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
  }

  const t = now();
  let m;

  if (path === '/networks' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT w.*,
        (SELECT COUNT(*) FROM nodes n WHERE n.network_id=w.id) AS node_count,
        (SELECT COUNT(*) FROM nodes n WHERE n.network_id=w.id AND n.enabled=1 AND n.last_seen>?) AS online_count
       FROM networks w ORDER BY w.id`
    ).bind(t - ONLINE_WINDOW).all();
    return jsonResp({ networks: results });
  }

  if (path === '/networks' && method === 'POST') {
    const b = await readJson(request);
    const name = validName(b.name);
    const c = parseCidr(String(b.cidr || ''));
    if (!c) throw new HttpError(400, '网段无效，示例 10.88.0.0/24（掩码 16-29）');
    if (!isPrivateNet(c)) throw new HttpError(400, '请使用私有网段: 10.0.0.0/8、172.16.0.0/12、192.168.0.0/16 或 100.64.0.0/10');
    const mode = b.mode === 'hub' ? 'hub' : 'mesh';
    try {
      const r = await env.DB.prepare('INSERT INTO networks (name,cidr,mode,created_at) VALUES (?,?,?,?)')
        .bind(name, `${intToIp(c.net)}/${c.bits}`, mode, t).run();
      return jsonResp({ id: r.meta.last_row_id }, 201);
    } catch (e) {
      if (isUnique(e)) throw new HttpError(409, '网络名称已存在');
      throw e;
    }
  }

  if ((m = path.match(/^\/networks\/(\d+)$/))) {
    const id = Number(m[1]);
    if (method === 'PUT') {
      const b = await readJson(request);
      const name = validName(b.name);
      const mode = b.mode === 'hub' ? 'hub' : 'mesh';
      try {
        const r = await env.DB.prepare('UPDATE networks SET name=?, mode=? WHERE id=?').bind(name, mode, id).run();
        if (!r.meta.changes) throw new HttpError(404, '网络不存在');
      } catch (e) {
        if (isUnique(e)) throw new HttpError(409, '网络名称已存在');
        throw e;
      }
      return jsonResp({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM nodes WHERE network_id=?').bind(id),
        env.DB.prepare('DELETE FROM networks WHERE id=?').bind(id),
      ]);
      return jsonResp({ ok: true });
    }
  }

  if ((m = path.match(/^\/networks\/(\d+)\/nodes$/))) {
    const id = Number(m[1]);
    if (method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM nodes WHERE network_id=? ORDER BY id').bind(id).all();
      return jsonResp({ nodes: results.map((n) => publicNode(n, t)) });
    }
    if (method === 'POST') {
      const nodeId = await createNode(env, id, await readJson(request));
      return jsonResp({ id: nodeId }, 201);
    }
  }

  if ((m = path.match(/^\/nodes\/(\d+)$/))) {
    const id = Number(m[1]);
    if (method === 'PUT') {
      const f = parseNodeFields(await readJson(request));
      const keys = Object.keys(f); // 键名全部来自 parseNodeFields 白名单
      if (!keys.length) throw new HttpError(400, '没有可更新的字段');
      try {
        const r = await env.DB.prepare(`UPDATE nodes SET ${keys.map((k) => k + '=?').join(', ')} WHERE id=?`)
          .bind(...keys.map((k) => f[k]), id).run();
        if (!r.meta.changes) throw new HttpError(404, '节点不存在');
      } catch (e) {
        if (isUnique(e)) throw new HttpError(409, '该网络下已有同名节点');
        throw e;
      }
      return jsonResp({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM nodes WHERE id=?').bind(id).run();
      return jsonResp({ ok: true });
    }
  }

  if ((m = path.match(/^\/nodes\/(\d+)\/reset$/)) && method === 'POST') {
    const token = randomToken(24);
    const r = await env.DB.prepare(
      'UPDATE nodes SET enroll_token=?, secret_hash=NULL, public_key=NULL, last_seen=NULL, last_ip=NULL WHERE id=?'
    ).bind(token, Number(m[1])).run();
    if (!r.meta.changes) throw new HttpError(404, '节点不存在');
    // 清掉旧的 STUN/路径数据（未执行迁移时列不存在，忽略即可）
    await env.DB.prepare('UPDATE nodes SET stun_endpoint=NULL, stun_at=NULL, nat_type=NULL, paths=NULL WHERE id=?')
      .bind(Number(m[1])).run().catch(() => {});
    return jsonResp({ ok: true, enroll_token: token });
  }

  throw new HttpError(404, 'not found');
}

// ───────────────────────── 入口 ─────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/agent/')) return await handleAgent(request, env, url);
      if (url.pathname.startsWith('/api/admin/')) return await handleAdmin(request, env, url);
      if (url.pathname === '/healthz') return textResp('ok');
      return await env.ASSETS.fetch(request);
    } catch (e) {
      if (e instanceof HttpError) {
        return url.pathname.startsWith('/api/agent/')
          ? textResp(e.message + '\n', e.status)
          : jsonResp({ error: e.message }, e.status);
      }
      console.error(e);
      return jsonResp({ error: 'internal error' }, 500);
    }
  },
};
