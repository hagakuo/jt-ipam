"""把 ARP 證據與 LibreNMS 裝置狀態分開存

Revision ID: 0124_last_seen_arp
Revises: 0123_zabbix
Create Date: 2026-08-25

原本 ARP 看到某個 IP 也是蓋 `last_seen_librenms`，與「LibreNMS 裝置本身回報上線」
混在同一個欄位，事後分不出來。這很要命，因為兩者的可信度差很多：

- 裝置狀態：LibreNMS 自己在輪詢，有時間概念
- ARP：LibreNMS 的 ARP API **完全不回時間欄位**，我們只能因為「這筆還在清單裡」
  就蓋上同步當下的時間。來源設備（例如 AP）的 ARP 快取不老化，那個 IP 就永遠是「剛看到」

分成兩個欄位之後，`effective_status` 才能把「只有 ARP 撐著」標成獨立等級。
既有值先照抄過去（有 ARP 記錄的才抄），避免升級後整批 IP 瞬間掉成未知。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0124_last_seen_arp"
down_revision = "0123_zabbix"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ip_addresses",
                  sa.Column("last_seen_arp", sa.DateTime(timezone=True), nullable=True))
    # 既有資料的還原：ARP 同步是整批用同一個 `now` 蓋的，所以「last_seen_librenms
    # 恰好等於該 IP 的 ARP last_seen_at」就是它其實由 ARP 蓋出來的指紋（裝置狀態那條
    # 路徑是逐台各自取時間，不會分毫不差）。這種就把值搬到 last_seen_arp 並清掉
    # last_seen_librenms —— 否則升級後那些 IP 會繼續看起來像「LibreNMS 裝置說它活著」。
    op.execute("""
        UPDATE ip_addresses ia
           SET last_seen_arp = sub.last_seen_at,
               last_seen_librenms = CASE
                   WHEN ia.last_seen_librenms = sub.last_seen_at THEN NULL
                   ELSE ia.last_seen_librenms
               END
          FROM (SELECT ip, max(last_seen_at) AS last_seen_at
                  FROM arp_entries GROUP BY ip) sub
         WHERE host(ia.ip) = host(sub.ip)
    """)


def downgrade() -> None:
    op.drop_column("ip_addresses", "last_seen_arp")
