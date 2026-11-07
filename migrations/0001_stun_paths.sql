-- 升级已有数据库（v1 -> v2：STUN 端点 + 路径状态）
-- 执行: npx wrangler d1 execute meshlink --remote --file=migrations/0001_stun_paths.sql
-- 新部署直接用 schema.sql 即可，不需要这个文件。
ALTER TABLE nodes ADD COLUMN stun_endpoint TEXT;
ALTER TABLE nodes ADD COLUMN stun_at INTEGER;
ALTER TABLE nodes ADD COLUMN nat_type TEXT;
ALTER TABLE nodes ADD COLUMN paths TEXT;
