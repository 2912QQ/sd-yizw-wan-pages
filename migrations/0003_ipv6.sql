-- 升级已有数据库（后台“公网端点”显示 IPv6）
-- 执行: npx wrangler d1 execute meshlink --remote --file=migrations/0003_ipv6.sql
-- 不执行也行：节点第一次上报 IPv6 时控制面会自动补上这一列。新部署直接用 schema.sql。
ALTER TABLE nodes ADD COLUMN ipv6 TEXT;
