"""ARP 證據改為**逐來源**記錄時間，並讓 Wazuh 也能作為上線判定的依據。

由來（使用者回報 2026-09-01）：設定頁的「採信哪些證據」只有一個籠統的「ARP 記錄」，
但實際上 OPNsense / pfSense / FortiGate 的 ARP 同步是寫進 `last_seen_scanner`
（＝掃描代理探測），也就是**被動學到的 ARP 被當成主動探測的證據在用**，而那個來源
預設勾選。要能逐來源選擇，就得逐來源留時間。

`arp_seen` 形狀：`{"opnsense": "2026-09-01T10:00:00+00:00", "librenms": "…"}`。
舊的 `last_seen_arp` 欄位保留不動（LibreNMS 仍寫它，畫面與既有查詢照舊）。

Revision ID: 0133_arp_seen_per_source
Revises: 0132_paloalto
Create Date: 2026-09-01
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0133_arp_seen_per_source"
down_revision: str | None = "0132_paloalto"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ip_addresses",
        sa.Column("arp_seen", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
    )
    # Wazuh agent 的 keep-alive：manager 端維護、會過期，是貨真價實的存活證據，
    # 但先前完全沒進上線判定（使用者回報：「wazuh agent 判定上線 請加入」）。
    op.add_column(
        "ip_addresses",
        sa.Column("last_seen_wazuh", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ip_addresses", "last_seen_wazuh")
    op.drop_column("ip_addresses", "arp_seen")
