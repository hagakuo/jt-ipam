"""wazuh_agents.sca_checked_at：SCA 最後一次查詢的時間（有沒有結果都記）

SCA 以前每一輪同步對每個代理各打一次 API。Wazuh API 預設每分鐘只收 300 個請求，
3 萬個代理光一輪就要 100 分鐘以上，被限流的請求還被當成「沒有 SCA」安靜略過。
改成每個代理隔一段時間才查一次、每輪有上限、最久沒查的先查 —— 需要一個「查過了」的時間，
`sca_scanned_at` 只在有結果時才寫（沒跑過 SCA 的代理要維持空白），不能拿來用。

Revision ID: 0168_wazuh_sca_checked_at
Revises: 0167_fk_indexes
Create Date: 2026-09-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0168_wazuh_sca_checked_at"
down_revision: str | None = "0167_fk_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("wazuh_agents", sa.Column("sca_checked_at", sa.DateTime(timezone=True)))
    # 既有的查詢結果算「查過了」，升級後不必一口氣全部重查
    op.execute("UPDATE wazuh_agents SET sca_checked_at = sca_scanned_at WHERE sca_scanned_at IS NOT NULL")


def downgrade() -> None:
    op.drop_column("wazuh_agents", "sca_checked_at")
