"""MAC 歷程的查詢索引（2026-10-01）。

MAC 歷程以一個 MAC 精確比對各處的資料。MACADDR 欄位本來就有索引（ip_addresses、arp_entries、
fdb_entries）；這裡補上：

- ip_change_log 的舊值／新值：只建 `field='mac'` 的部分運算式索引（大站台的異動記錄是幾百萬筆，
  全表掃描每查一次就要幾秒）。手動輸入的寫法不一（大寫、破折號、Cisco 的點號），所以比對的是
  「去掉分隔符號、轉小寫」後的 12 碼。
- dhcp_reservations.mac、device_ports.mac_address：同一個運算式（各來源寫法不同）。
- vm_interfaces.mac：MACADDR，一般索引。

運算式要與 services/mac_history._hex_of 一字不差，PostgreSQL 才會用到。

Revision ID: 0172_mac_history_indexes
Revises: 0171_paloalto_sync_vpn
"""
from __future__ import annotations

from alembic import op

revision = "0172_mac_history_indexes"
down_revision = "0171_paloalto_sync_vpn"
branch_labels = None
depends_on = None

_HEX = "regexp_replace(lower({col}), '[^0-9a-f]', '', 'g')"


def upgrade() -> None:
    op.execute(f"CREATE INDEX IF NOT EXISTS ix_ip_change_log_mac_old ON ip_change_log "
               f"(({_HEX.format(col='old_value')})) WHERE field = 'mac'")
    op.execute(f"CREATE INDEX IF NOT EXISTS ix_ip_change_log_mac_new ON ip_change_log "
               f"(({_HEX.format(col='new_value')})) WHERE field = 'mac'")
    op.execute(f"CREATE INDEX IF NOT EXISTS ix_dhcp_reservations_mac_hex ON dhcp_reservations "
               f"(({_HEX.format(col='mac')}))")
    op.execute(f"CREATE INDEX IF NOT EXISTS ix_device_ports_mac_hex ON device_ports "
               f"(({_HEX.format(col='mac_address')}))")
    op.execute("CREATE INDEX IF NOT EXISTS ix_vm_interfaces_mac ON vm_interfaces (mac)")


def downgrade() -> None:
    for name in ("ix_vm_interfaces_mac", "ix_device_ports_mac_hex", "ix_dhcp_reservations_mac_hex",
                 "ix_ip_change_log_mac_new", "ix_ip_change_log_mac_old"):
        op.execute(f"DROP INDEX IF EXISTS {name}")
