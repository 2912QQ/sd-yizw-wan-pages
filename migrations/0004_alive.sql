-- 升级已有数据库（后台把“agent 没同步控制面、但隧道还活着”的节点显示为在线）
-- 执行: npx wrangler d1 execute meshlink --remote --file=migrations/0004_alive.sql
-- 不执行也行：节点第一次上报时控制面会自动补上这一列。新部署直接用 schema.sql。
ALTER TABLE nodes ADD COLUMN alive TEXT;
