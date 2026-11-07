-- 出口节点：该节点使用的出口节点 ID（0 = 不使用）。不执行也会在第一次设置出口时自动补列。
ALTER TABLE nodes ADD COLUMN exit_via INTEGER NOT NULL DEFAULT 0;
