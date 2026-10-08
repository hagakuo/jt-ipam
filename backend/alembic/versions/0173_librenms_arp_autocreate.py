"""LibreNMS：依 ARP 表自動建立 IP（GitHub #48，2026-10-01）。

- librenms_instances 加三個欄位：auto_create_from_arp（預設關）、arp_create_require_fdb（預設開）、
  arp_create_skip_dhcp（預設開）。既有站台升級後行為不變：沒有人打開就什麼都不會建。
- ip_addresses.discovery_source 加 'librenms_arp'：跟「裝置主 IP 自動建立」的 'librenms' 分開，
  畫面上才能標成「自動收錄、未經登記」。

Revision ID: 0173_librenms_arp_autocreate
Revises: 0172_mac_history_indexes
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0173_librenms_arp_autocreate"
down_revision = "0172_mac_history_indexes"
branch_labels = None
depends_on = None

_OLD = ("discovery_source IN ('manual','scanner','librenms','dns','proxmox','opnsense',"
        "'phpipam','pfsense','vmware')")
_NEW = ("discovery_source IN ('manual','scanner','librenms','dns','proxmox','opnsense',"
        "'phpipam','pfsense','vmware','librenms_arp')")
_NAMES = (
    "ip_discovery_source_valid",
    "ck_ip_addresses_ip_discovery_source_valid",
    "ck_ip_addresses_ck_ip_addresses_ip_discovery_source_valid",
)
_CANON = "ck_ip_addresses_ip_discovery_source_valid"


def upgrade() -> None:
    op.add_column("librenms_instances", sa.Column(
        "auto_create_from_arp", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("librenms_instances", sa.Column(
        "arp_create_require_fdb", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("librenms_instances", sa.Column(
        "arp_create_skip_dhcp", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    for n in _NAMES:
        op.execute(f'ALTER TABLE ip_addresses DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE ip_addresses ADD CONSTRAINT "{_CANON}" CHECK ({_NEW})')


def downgrade() -> None:
    op.execute("UPDATE ip_addresses SET discovery_source='librenms' WHERE discovery_source='librenms_arp'")
    for n in _NAMES:
        op.execute(f'ALTER TABLE ip_addresses DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE ip_addresses ADD CONSTRAINT "{_CANON}" CHECK ({_OLD})')
    for col in ("arp_create_skip_dhcp", "arp_create_require_fdb", "auto_create_from_arp"):
        op.drop_column("librenms_instances", col)
