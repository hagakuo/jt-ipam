"""OCS 裝置明細卡片欄位：ip_addresses.ocs_id / ocs_tag / ocs_agent / ocs_notes。

OCS 的比對是走 MAC → IP，原本只落 OS／序號／型號。裝置明細卡片還要能：
- 深連結到 OCS 主控台該電腦頁（需要 systemid → ocs_id）。
- 顯示資產標籤（TAG，來自 OCS accountinfo）。
- 顯示 OCS 代理版本（hardware.USERAGENT）。
- 顯示最新幾筆備註（itmgmt_comments）。

Revision ID: 0142_ocs_id
Revises: 0141_ocs_os
Create Date: 2026-09-19
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0142_ocs_id"
down_revision: str | None = "0141_ocs_os"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ip_addresses", sa.Column("ocs_id", sa.BigInteger()))
    op.add_column("ip_addresses", sa.Column("ocs_tag", sa.String(128)))
    op.add_column("ip_addresses", sa.Column("ocs_agent", sa.String(128)))
    op.add_column("ip_addresses", sa.Column("ocs_notes", JSONB()))


def downgrade() -> None:
    op.drop_column("ip_addresses", "ocs_notes")
    op.drop_column("ip_addresses", "ocs_agent")
    op.drop_column("ip_addresses", "ocs_tag")
    op.drop_column("ip_addresses", "ocs_id")
