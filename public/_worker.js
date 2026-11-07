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

// 节点虚拟 IP 必须落在网络网段内，且不能是网络地址/广播地址
function validNodeIp(net, v) {
  const c = parseCidr(net.cidr);
  const x = ipToInt(String(v ?? '').trim());
  if (!c || x === null || x <= c.net || x >= c.net + c.size - 1) {
    throw new HttpError(400, `虚拟 IP 必须在 ${net.cidr} 网段内，且不能是网络地址或广播地址`);
  }
  return intToIp(x);
}

// agent 上报的本机公网 IPv6：只收全局单播地址，忽略回环/链路本地/ULA；格式不对直接忽略，不影响同步
function normIpv6(v) {
  const s = String(v ?? '').trim().toLowerCase();
  if (!s || s.length > 45 || !s.includes(':') || !/^[0-9a-f:]+$/.test(s)) return '';
  if (s === '::1' || s === '::' || /^fe[89ab]/.test(s) || /^f[cd]/.test(s)) return '';
  return s;
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

const validPubKey = (v) => {
  const k = String(v || '').trim();
  if (!/^[A-Za-z0-9+/]{43}=$/.test(k)) throw new HttpError(400, '公钥格式无效');
  return k;
};

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
  const fixedIp = body.ip !== undefined && String(body.ip).trim() ? validNodeIp(net, body.ip) : '';
  for (let i = 0; i < 5; i++) {
    const ip = fixedIp || await allocateIp(env, net);
    if (!ip) throw new HttpError(409, '地址池已用尽');
    try {
      const r = await env.DB.prepare(
        'INSERT INTO nodes (network_id,name,ip,enroll_token,is_hub,subnets,endpoint_override,listen_port,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
      ).bind(net.id, f.name, ip, token, f.is_hub || 0, f.subnets || '', f.endpoint_override || '', f.listen_port || 51820, now()).run();
      return r.meta.last_row_id;
    } catch (e) {
      if (isUnique(e)) {
        if (/nodes\.name/.test(String(e.message))) throw new HttpError(409, '该网络下已有同名节点');
        if (fixedIp) throw new HttpError(409, `虚拟 IP ${fixedIp} 已被占用`);
        continue; // IP 冲突，重新分配
      }
      throw e;
    }
  }
  throw new HttpError(409, '分配地址失败，请重试');
}

// ───────────────────────── 客户端设备（手机/电脑，用官方 WireGuard App，不跑 agent）─────────────────────────
// 客户端只和“主 Hub”（本网络里 id 最小的、启用且已注册的 Hub）建立连接；
// 其余节点通过主 Hub 的 AllowedIPs 访问客户端。私钥只在管理员浏览器里生成，服务端只存公钥。

async function clientInfo(env, net) {
  const { results } = await env.DB.prepare(
    'SELECT * FROM nodes WHERE network_id=? AND enabled=1 AND public_key IS NOT NULL ORDER BY id'
  ).bind(net.id).all();
  const hub = results.find((n) => n.is_hub && !n.is_client);
  if (!hub) throw new HttpError(409, '本网络还没有可用的 Hub：请先把一个有公网 IP 的节点设为 Hub 并让它上线，手机/电脑才能接入');
  const endpoint = endpointFor(hub, now());
  if (!endpoint) throw new HttpError(409, `Hub“${hub.name}”还没有可用的对外地址：请等它上线，或在编辑节点里手动指定“对外地址”`);
  const c = parseCidr(net.cidr);
  const allowed = [`${intToIp(c.net)}/${c.bits}`];
  for (const n of results) if (n.subnets) allowed.push(...n.subnets.split(','));
  return { hub_name: hub.name, hub_public_key: hub.public_key, endpoint, allowed_ips: [...new Set(allowed)].join(', ') };
}

async function insertClient(env, net, name, ip, pub) {
  const run = () => env.DB.prepare('INSERT INTO nodes (network_id,name,ip,public_key,is_client,created_at) VALUES (?,?,?,?,1,?)')
    .bind(net.id, name, ip, pub, now()).run();
  try {
    return await run();
  } catch (e) {
    // 旧库还没有 is_client 列：自动补上再重试（等价于执行 migrations/0002_clients.sql）
    if (/no column named is_client|no such column:? ?is_client/i.test(String(e && e.message))) {
      await env.DB.prepare('ALTER TABLE nodes ADD COLUMN is_client INTEGER NOT NULL DEFAULT 0').run().catch(() => {});
      return await run();
    }
    throw e;
  }
}

async function createClient(env, netId, body) {
  const net = await env.DB.prepare('SELECT * FROM networks WHERE id=?').bind(netId).first();
  if (!net) throw new HttpError(404, '网络不存在');
  const name = validName(body.name);
  const pub = validPubKey(body.public_key);
  const info = await clientInfo(env, net);
  for (let i = 0; i < 5; i++) {
    const ip = await allocateIp(env, net);
    if (!ip) throw new HttpError(409, '地址池已用尽');
    try {
      const r = await insertClient(env, net, name, ip, pub);
      return { id: r.meta.last_row_id, ip, ...info };
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

// 后台“公网端点”列：IPv4 / IPv6 分开显示
//   IPv4: 手动指定 > 新鲜的 STUN 端点 > 控制面看到的 IPv4；IPv6: 手动指定的 IPv6 > agent 上报的 > 控制面看到的 IPv6
function publicAddrs(n, t) {
  const ov = n.endpoint_override || '';
  const ovV6 = ov.includes(':') && !/^[^:]+:\d+$/.test(ov);
  const stun = n.stun_endpoint && n.stun_at && t - n.stun_at < STUN_FRESH ? n.stun_endpoint : '';
  const seen = n.last_ip || '';
  const ipv4 = (ovV6 ? '' : ov) || stun || (seen && !seen.includes(':') ? seen : '');
  const ipv6 = (ovV6 ? ov : '') || n.ipv6 || (seen.includes(':') ? seen : '');
  return { ipv4, ipv6 };
}

function publicNode(n, t) {
  return {
    id: n.id,
    network_id: n.network_id,
    name: n.name,
    ip: n.ip,
    is_hub: !!n.is_hub,
    is_client: !!n.is_client,
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
    ...publicAddrs(n, t),
    paths: parsePaths(n.paths),
    created_at: n.created_at,
  };
}

// 节点的公网 IPv6：agent 上报的 > 控制面看到的（节点是经 IPv6 连上来的）
const v6Of = (n) => n.ipv6 || (n.last_ip && n.last_ip.includes(':') ? n.last_ip : '');

// 分别给出一个节点的 IPv4 / IPv6 端点（不含手动指定；IPv6 没有 NAT，端口就是监听端口）
function endpointsFor(p, t) {
  const stun = p.stun_endpoint && p.stun_at && t - p.stun_at < STUN_FRESH ? p.stun_endpoint : '';
  const seen4 = p.last_ip && !p.last_ip.includes(':') ? `${p.last_ip}:${p.listen_port}` : '';
  const v6 = v6Of(p);
  return { v4: stun || seen4, v6: v6 ? `[${v6}]:${p.listen_port}` : '' };
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
//   peer: id  hub  online  nat  [ep6 ep4]
// mesh 模式下 agent 会先尝试直连，打不通时把该对端经由 Hub 中转。
// IPv6 优先: 请求方带 X-Meshlink-Path（agent 装了路径管理器）且双方都有公网 IPv6 时，Endpoint 先给 IPv6，
// 同时在 peer 元信息里附上 ep6/ep4，路径管理器在 IPv6 握手不成功时改试 IPv4，两个都不通才走 Hub 中转。
// 没有路径管理器的 agent 保持原来的 IPv4 优先，不会因为 IPv6 被拦而断连。
function buildConfig(self, net, allPeers, t, opts = {}) {
  let peers = allPeers;
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

  const clients = peers.filter((p) => p.is_client);
  peers = peers.filter((p) => !p.is_client);
  const hubs = peers.filter((p) => p.is_hub);
  const spoke = net.mode === 'hub' && !self.is_hub;
  const list = spoke ? hubs : peers;
  const primaryHub = hubs[0];
  // 客户端（手机/电脑）只连主 Hub：主 Hub 把它们当对端；其余节点把它们的地址挂在主 Hub 上
  const iAmPrimary = !!self.is_hub && hubs.every((h) => h.id > self.id);
  const clientIps = clients.map((c) => `${c.ip}/32`);
  const selfHasV6 = !!v6Of(self);

  for (const p of list) {
    const allowed = [`${p.ip}/32`];
    if (p.subnets) allowed.push(...p.subnets.split(','));
    if (p === primaryHub && !iAmPrimary) allowed.push(...clientIps);
    if (spoke && p === primaryHub) {
      // 中心辐射模式: 其余节点（及其内网网段）的流量经主 Hub 中转
      allowed.push(netCidr);
      for (const o of peers) if (o !== p && o.subnets) allowed.push(...o.subnets.split(','));
    }
    let ep = endpointFor(p, t);
    let dual = '';
    if (opts.pathCapable && selfHasV6 && !p.endpoint_override) {
      const e = endpointsFor(p, t);
      if (e.v6) {
        ep = e.v6;                                   // 双方都有 IPv6: 先走 IPv6
        if (e.v4) dual = ` ep6=${e.v6} ep4=${e.v4}`; // 有 IPv4 才能兜底
      }
    }
    L.push(
      '', '[Peer]', `# ${p.name}`,
      `# meshlink peer id=${p.id} hub=${p.is_hub ? 1 : 0} online=${isOnline(p, t) ? 1 : 0} nat=${NAT_TYPES.has(p.nat_type) ? p.nat_type : 'unknown'}${dual}`,
      `PublicKey = ${p.public_key}`, `AllowedIPs = ${[...new Set(allowed)].join(', ')}`
    );
    if (ep) L.push(`Endpoint = ${ep}`);
    L.push('PersistentKeepalive = 25');
  }
  if (iAmPrimary) {
    for (const c of clients) {
      L.push('', '[Peer]', `# ${c.name} (client)`, `PublicKey = ${c.public_key}`, `AllowedIPs = ${c.ip}/32`);
    }
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
    const v6 = normIpv6(request.headers.get('X-Meshlink-IPv6'));
    if (ip && (ip !== node.last_ip || v6 !== (node.ipv6 || '') || t - (node.last_seen || 0) >= WRITE_THROTTLE)) {
      const upd = () => env.DB.prepare('UPDATE nodes SET last_ip=?, last_seen=?, ipv6=? WHERE id=?').bind(ip, t, v6 || null, node.id).run();
      try {
        await upd();
      } catch (e) {
        if (!/no such column:? ?ipv6|no column named ipv6/i.test(String(e && e.message))) throw e;
        // 旧库还没有 ipv6 列：自动补上再重试（等价于执行 migrations/0003_ipv6.sql）；补不上就退回只写 IPv4
        try { await env.DB.prepare('ALTER TABLE nodes ADD COLUMN ipv6 TEXT').run(); await upd(); }
        catch { await env.DB.prepare('UPDATE nodes SET last_ip=?, last_seen=? WHERE id=?').bind(ip, t, node.id).run(); }
      }
      node.last_ip = ip;
      node.ipv6 = v6;
    }

    const { results: peers } = await env.DB.prepare(
      'SELECT * FROM nodes WHERE network_id=? AND id!=? AND enabled=1 AND public_key IS NOT NULL ORDER BY id'
    ).bind(node.network_id, node.id).all();
    return textResp(buildConfig(node, node, peers, t, { pathCapable: request.headers.get('X-Meshlink-Path') === '1' }));
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

  // 控制台自定义文案（副标题）。settings 表按需自动创建，旧库无需迁移
  if (path === '/settings' && (method === 'GET' || method === 'PUT')) {
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
    if (method === 'PUT') {
      const b = await readJson(request);
      const subtitle = String(b.subtitle ?? '').trim();
      if (subtitle.length > 100) throw new HttpError(400, '内容不能超过 100 个字符');
      await env.DB.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
        .bind('subtitle', subtitle).run();
    }
    const row = await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind('subtitle').first();
    return jsonResp({ subtitle: row ? row.value : null });   // null = 还没自定义过，前端用默认文案
  }

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

  if ((m = path.match(/^\/networks\/(\d+)\/clients$/)) && method === 'POST') {
    return jsonResp(await createClient(env, Number(m[1]), await readJson(request)), 201);
  }

  if ((m = path.match(/^\/nodes\/(\d+)\/client$/)) && method === 'PUT') {
    const n = await env.DB.prepare('SELECT * FROM nodes WHERE id=?').bind(Number(m[1])).first();
    if (!n || !n.is_client) throw new HttpError(404, '客户端设备不存在');
    const net = await env.DB.prepare('SELECT * FROM networks WHERE id=?').bind(n.network_id).first();
    const pub = validPubKey((await readJson(request)).public_key);
    const info = await clientInfo(env, net);
    await env.DB.prepare('UPDATE nodes SET public_key=? WHERE id=?').bind(pub, n.id).run();
    return jsonResp({ id: n.id, ip: n.ip, ...info });
  }

  if ((m = path.match(/^\/nodes\/(\d+)$/))) {
    const id = Number(m[1]);
    if (method === 'PUT') {
      const b = await readJson(request);
      const f = parseNodeFields(b);
      if (b.ip !== undefined && String(b.ip).trim()) {
        const cur = await env.DB.prepare('SELECT network_id FROM nodes WHERE id=?').bind(id).first();
        if (!cur) throw new HttpError(404, '节点不存在');
        const net = await env.DB.prepare('SELECT * FROM networks WHERE id=?').bind(cur.network_id).first();
        f.ip = validNodeIp(net, b.ip);
      }
      const keys = Object.keys(f); // 键名全部来自 parseNodeFields 白名单（ip 经 validNodeIp 校验）
      if (!keys.length) throw new HttpError(400, '没有可更新的字段');
      try {
        const r = await env.DB.prepare(`UPDATE nodes SET ${keys.map((k) => k + '=?').join(', ')} WHERE id=?`)
          .bind(...keys.map((k) => f[k]), id).run();
        if (!r.meta.changes) throw new HttpError(404, '节点不存在');
      } catch (e) {
        if (isUnique(e)) throw new HttpError(409, /nodes\.name/.test(String(e.message)) ? '该网络下已有同名节点' : '该虚拟 IP 已被其他节点占用');
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
      const msg = String((e && e.message) || e);
      let hint = 'internal error';
      if (!env.DB || /reading 'prepare'/.test(msg)) {
        hint = '未检测到 D1 绑定 DB：请在 Pages 项目 Settings → Bindings 给 Production 和 Preview 都添加变量名为 DB 的 D1 绑定，然后重新部署';
      } else if (/no such table/i.test(msg)) {
        hint = '数据库未初始化（线上库没有表）：请对 --remote 执行 schema.sql，并确认绑定的是同一个 D1 数据库';
      } else if (/no such column/i.test(msg)) {
        hint = '数据库结构过旧，请执行 migrations/ 目录里的 SQL（0001、0002）';
      }
      return jsonResp({ error: hint }, 500);
    }
  },
};
