"""防火牆規則快照：偵測「規則被改了」這件事本身

Revision ID: 0118_fw_rule_snapshots
Revises: 0117_scan_agent_auto_create_ips
Create Date: 2026-08-15

我們同步了三家防火牆的規則，但一直只是「存起來給人看」——沒有任何東西在看它們。
半夜多出一條放行規則，是防火牆被入侵或內部人員留後門的經典徵兆，而現況是被覆寫掉、
無聲無息（pfSense 的 rules JSONB 每輪 sync 直接覆寫，連歷史都沒有）。

作法：每輪 sync 把正規化後的規則清單做雜湊，**跟上一份不同才插一列**（含 diff）。
一列＝一次變更事件；沒變就一列都不多，成本趨近於零。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0118_fw_rule_snapshots"
down_revision = "0117_scan_agent_auto_create_ips"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fw_rule_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        # 三張防火牆表各自獨立，這裡用 (source_type, instance_id) 多型指涉；
        # 不設 FK —— 實例刪除後歷史要留著（instance_name 供事後顯示）
        sa.Column("source_type", sa.String(16), nullable=False),
        sa.Column("instance_id", UUID(as_uuid=True), nullable=False),
        sa.Column("instance_name", sa.String(255), nullable=False),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("rules_hash", sa.String(64), nullable=False),
        sa.Column("rule_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rules", JSONB(), nullable=False),
        # 與上一份的差異（第一份 baseline 為 NULL）
        sa.Column("diff", JSONB(), nullable=True),
    )
    op.create_index("ix_fw_rule_snapshots_instance", "fw_rule_snapshots",
                    ["source_type", "instance_id", "taken_at"])


def downgrade() -> None:
    op.drop_index("ix_fw_rule_snapshots_instance", table_name="fw_rule_snapshots")
    op.drop_table("fw_rule_snapshots")
