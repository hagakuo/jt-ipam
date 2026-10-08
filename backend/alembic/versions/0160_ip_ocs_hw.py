"""ip_addresses.ocs_hw：OCS 回報的硬體摘要（系統／主機板／BIOS／CPU／記憶體／磁碟／顯示卡）。

使用者回報（2026-09-27）：OCS 卡片的製造商／型號讀的是裝置本身的欄位，Windows 筆電顯示成
LibreNMS 建立時填的「windows／Intel x64」；Supermicro 主機的序號是出廠佔位、主機板型號沒顯示；
也要列出主要零件。卡片改顯示 OCS 自己的資料，存在對到的 IP 上（與 ocs_notes 等欄位同一處）。
下一輪 OCS 同步就會填上，不必回填。

Revision ID: 0160_ip_ocs_hw
Revises: 0159_ip_range_source_origin
Create Date: 2026-09-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0160_ip_ocs_hw"
down_revision: str | None = "0159_ip_range_source_origin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ip_addresses", sa.Column("ocs_hw", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("ip_addresses", "ocs_hw")
