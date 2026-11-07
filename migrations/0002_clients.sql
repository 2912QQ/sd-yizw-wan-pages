-- 升级已有数据库（支持手机/电脑等客户端设备）
-- 执行: npx wrangler d1 execute meshlink --remote --file=migrations/0002_clients.sql
-- 不执行也行：第一次添加客户端设备时控制面会自动补上这一列。新部署直接用 schema.sql。
ALTER TABLE nodes ADD COLUMN is_client INTEGER NOT NULL DEFAULT 0;
