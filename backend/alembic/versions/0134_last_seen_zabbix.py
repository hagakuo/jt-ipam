"""Zabbix 也能作為上線判定的依據：`ip_addresses.last_seen_zabbix`。

Zabbix 的可用性由 Zabbix server 自己輪詢維護（與 LibreNMS／Wazuh 同一層），本來就
符合「會過期的存活證據」，但同步只把可用性寫進 `zabbix_hosts` 鏡像表，**從來沒有寫回
IP**，所以上線判定根本拿不到它 —— 使用者問「我們不是有支援 Zabbix 嗎？探測／監控
不支援它?」時才發現。

只有在 Zabbix 說 `up` 時才蓋時間：`down` 是「不活著」的證據、`unknown` 是沒有證據，
兩者都不該被寫成「看到過」。

Revision ID: 0134_last_seen_zabbix
Revises: 0133_arp_seen_per_source
Create Date: 2026-09-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0134_last_seen_zabbix"
down_revision: str | None = "0133_arp_seen_per_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ip_addresses",
        sa.Column("last_seen_zabbix", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ip_addresses", "last_seen_zabbix")
