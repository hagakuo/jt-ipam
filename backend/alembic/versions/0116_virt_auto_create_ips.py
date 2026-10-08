"""Proxmox / VMware：是否信任虛擬化回報的 IP 而自動建立 IPAM 紀錄

Revision ID: 0116_virt_auto_create_ips
Revises: 0115_fw_auto_create_ips
Create Date: 2026-08-12

把三類整合的行為統一成同一個模型（「要不要建」是設定，不是各寫各的）：

- OPNsense / pfSense：0115 已加，預設關
- **Proxmox：原本『無條件自動建立』且沒有開關** → 改為由這個開關決定，**預設關**
- **VMware / ESXi：原本完全不建** → 開啟後可建

⚠️ **Proxmox 是行為變更**：升級後，原本會自動出現的 VM IP 不再自動建立，要在
「整合 Proxmox VE」把這個開關打開才會恢復。這是刻意的 —— 自動收錄會讓那些位址
不再出現在「未授權 IP」異常偵測裡（該偵測的判定是「ARP 看得到、IPAM 沒有」），
預設就該是使用者明示同意才開。CHANGELOG 已把這點列為變更項目。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0116_virt_auto_create_ips"
down_revision = "0115_fw_auto_create_ips"
branch_labels = None
depends_on = None

_TABLES = ("proxmox_instances", "esxi_instances")

# VMware 自動建立的紀錄要標成 'vmware'（原本清單裡沒有這個來源）
_OLD = ("discovery_source IN ('manual','scanner','librenms','dns','proxmox','opnsense',"
        "'phpipam','pfsense')")
_NEW = ("discovery_source IN ('manual','scanner','librenms','dns','proxmox','opnsense',"
        "'phpipam','pfsense','vmware')")
_NAMES = (
    "ip_discovery_source_valid",
    "ck_ip_addresses_ip_discovery_source_valid",
    "ck_ip_addresses_ck_ip_addresses_ip_discovery_source_valid",
)
_CANON = "ck_ip_addresses_ip_discovery_source_valid"


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table,
            sa.Column("auto_create_ips", sa.Boolean(), nullable=False,
                      server_default=sa.text("false")),
        )
    for n in _NAMES:
        op.execute(f'ALTER TABLE ip_addresses DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE ip_addresses ADD CONSTRAINT "{_CANON}" CHECK ({_NEW})')


def downgrade() -> None:
    op.execute("UPDATE ip_addresses SET discovery_source='manual' WHERE discovery_source='vmware'")
    for n in _NAMES:
        op.execute(f'ALTER TABLE ip_addresses DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE ip_addresses ADD CONSTRAINT "{_CANON}" CHECK ({_OLD})')
    for table in _TABLES:
        op.drop_column(table, "auto_create_ips")
