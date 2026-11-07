-- 升级已有数据库（后台显示公网 IP 的运营商 / 归属地缓存）
-- 执行: npx wrangler d1 execute meshlink --remote --file=migrations/0005_ip_info.sql
-- 不执行也行：管理后台第一次查询归属地时控制面会自动建表。新部署直接用 schema.sql。
CREATE TABLE IF NOT EXISTS ip_info (
  ip   TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  ts   INTEGER NOT NULL
);
