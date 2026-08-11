"""scan_agents.is_local + 把未指派的子網路交給本機代理

Revision ID: 0114_scan_agent_is_local
Revises: 0113_sftp_enabled
Create Date: 2026-08-10

掃描一律要有代理。子網路的「掃描代理」留白（`scan_agent_id` 為 NULL）本來寫著
「本機直接掃描（jt-ipam 主機）」，但那條路徑**沒有任何東西會去啟動它** —— 沒有排程、
UI 也沒有觸發按鈕。於是客戶開了掃描、等著看上線狀態，卻永遠等不到（實際回報）。

安裝腳本現在會在 jt-ipam 主機上順便裝一個代理並標記 `is_local`。這支 migration 負責
把既有「已啟用掃描但沒有指派代理」的子網路接到那個代理上 —— 升級後就會真的開始掃。
本機代理還不存在時（例如先升 DB 再跑安裝腳本）什麼都不做，安裝腳本建立代理後會再接手。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0114_scan_agent_is_local"
down_revision = "0113_sftp_enabled"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_agents",
        sa.Column("is_local", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    # 已啟用掃描、卻沒有指派代理的子網路 → 指向本機代理（若已經有一個）
    op.execute(
        """
        UPDATE subnets SET scan_agent_id = (
            SELECT id FROM scan_agents WHERE is_local AND enabled ORDER BY created_at LIMIT 1
        )
        WHERE scan_enabled AND scan_agent_id IS NULL
          AND EXISTS (SELECT 1 FROM scan_agents WHERE is_local AND enabled)
        """
    )


def downgrade() -> None:
    # 只還原欄位；指派過的子網路留著 —— 把它們改回 NULL 等於再把掃描關掉一次
    op.drop_column("scan_agents", "is_local")
