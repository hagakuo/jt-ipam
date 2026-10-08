"""ip_addresses.device_kind / device_model / device_identified_at：掃描代理判讀出的設備類型

掃描代理的定期 OS 偵測以前只送回一行 OS 文字。代理 1.14.0 起連同 nmap 的結構化結果（服務
banner、網頁標題、憑證）一起送，伺服器用 IP 探測同一套判讀（含 Recog 指紋庫）推出設備類型
（攝影機、印表機、NAS…）與廠牌型號 —— 清單與拓樸據此顯示圖示，異常偵測據此發現「類型突變」。

Revision ID: 0169_ip_device_kind
Revises: 0168_wazuh_sca_checked_at
Create Date: 2026-10-01
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0169_ip_device_kind"
down_revision: str | None = "0168_wazuh_sca_checked_at"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ip_addresses", sa.Column("device_kind", sa.String(24)))
    op.add_column("ip_addresses", sa.Column("device_model", sa.String(120)))
    op.add_column("ip_addresses", sa.Column("device_identified_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("ip_addresses", "device_identified_at")
    op.drop_column("ip_addresses", "device_model")
    op.drop_column("ip_addresses", "device_kind")
