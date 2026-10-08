"""規則異動的「認領」：合規證據鏈（誰確認了這筆變更、為什麼）

Revision ID: 0119_fw_ack
Revises: 0118_fw_rule_snapshots
Create Date: 2026-08-15

異動偵測只「通知」；認領讓 admin 把異動標記為「已知變更＋說明」。沒被認領的
異動累積起來，就是稽核要的證據鏈：「本月 12 筆防火牆變更，2 筆無人說明」。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0119_fw_ack"
down_revision = "0118_fw_rule_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("fw_rule_snapshots", sa.Column("ack_by", UUID(as_uuid=True), nullable=True))
    op.add_column("fw_rule_snapshots", sa.Column("ack_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("fw_rule_snapshots", sa.Column("ack_note", sa.Text(), nullable=True))


def downgrade() -> None:
    for c in ("ack_note", "ack_at", "ack_by"):
        op.drop_column("fw_rule_snapshots", c)
