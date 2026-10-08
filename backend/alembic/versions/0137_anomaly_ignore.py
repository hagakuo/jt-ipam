"""逐 IP 的異常忽略清單。

由來：新增「一個 IP 頻繁更換 MAC」這條規則之後，Windows 11 / macOS / iOS / Android
的位址隨機化會讓一大批正常裝置每天都被報一次。沒有忽略機制的話，使用者只能整條規則
關掉 —— 那等於連真正的 IP 搶用、DHCP 池異常也一起看不到。

做成**逐類別的清單**而不是單一布林值：同樣的需求馬上會出現在別類（測試網段的機器
本來就會失聯、DMZ 主機本來就對外開埠），一個 JSONB 陣列一次解決。

Revision ID: 0137_anomaly_ignore
Revises: 0136_jump_hosts
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0137_anomaly_ignore"
down_revision = "0136_jump_hosts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ip_addresses",
        sa.Column("anomaly_ignore", JSONB(), nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("ip_addresses", "anomaly_ignore")
