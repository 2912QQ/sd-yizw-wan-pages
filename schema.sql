-- MeshLink D1 schema
CREATE TABLE IF NOT EXISTS networks (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL UNIQUE,
  cidr       TEXT NOT NULL,
  mode       TEXT NOT NULL DEFAULT 'mesh',      -- mesh = 全互联, hub = 中心辐射
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id        INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  ip                TEXT NOT NULL,
  public_key        TEXT,
  secret_hash       TEXT,                        -- SHA-256(node secret)，明文只在注册时返回一次
  enroll_token      TEXT,                        -- 一次性安装令牌，注册成功后清空
  is_hub            INTEGER NOT NULL DEFAULT 0,
  is_client         INTEGER NOT NULL DEFAULT 0,    -- 1 = 手机/电脑等客户端设备（官方 WireGuard App，不跑 agent）
  subnets           TEXT NOT NULL DEFAULT '',    -- 该节点后面的内网网段，逗号分隔
  endpoint_override TEXT NOT NULL DEFAULT '',    -- 手动指定对外地址 host[:port]
  listen_port       INTEGER NOT NULL DEFAULT 51820,
  enabled           INTEGER NOT NULL DEFAULT 1,
  last_ip           TEXT,
  ipv6              TEXT,                        -- agent 上报的本机公网 IPv6（仅展示）
  last_seen         INTEGER,
  stun_endpoint     TEXT,                        -- agent 经 STUN 探测到的公网映射端点 ip:port
  stun_at           INTEGER,                     -- 上次上报 STUN 结果的时间
  nat_type          TEXT,                        -- public | cone | symmetric | unknown
  alive             TEXT,                        -- agent 上报的“有新鲜握手的对端 ID”，用来判断 agent 没同步但隧道还活着的节点
  paths             TEXT,                        -- 到各对端的路径状态 "对端ID:d|p|r,..."（d 直连 / p 尝试中 / r 中转）
  created_at        INTEGER NOT NULL,
  UNIQUE (network_id, ip),
  UNIQUE (network_id, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_token  ON nodes(enroll_token) WHERE enroll_token IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_secret ON nodes(secret_hash)  WHERE secret_hash  IS NOT NULL;

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip, ts);

-- 控制台自定义文案（控制面也会按需自动创建）
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
