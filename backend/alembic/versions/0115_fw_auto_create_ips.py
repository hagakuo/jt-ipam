"""OPNsense / pfSense：DHCP 有、IPAM 沒有的 IP 可選擇自動建立

Revision ID: 0115_fw_auto_create_ips
Revises: 0114_scan_agent_is_local
Create Date: 2026-08-12

防火牆的 DHCP／ARP 同步原本只「標記既有的 IP」，對不到就把整筆資料丟掉，畫面上完全
不會說（客戶自己讀原始碼才查出來）。現在可以選擇自動建立。

**預設關閉，而且必須是關閉的**：DHCP 拿得到位址的機器不等於該進 IPAM 的機器 ——
有人私接一台筆電、拿到租約，開了這個選項就會被自動收錄成正式紀錄，而且從此
**不再出現在「未授權 IP」異常偵測裡**（那道偵測的判定正是「ARP 看得到、IPAM 沒有」）。
自動建立的紀錄以 discovery_source 標成 opnsense/pfsense，清單上另有醒目標記。

順帶放寬 discovery_source 的 CHECK：原本沒有 'pfsense'。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0115_fw_auto_create_ips"
down_revision = "0114_scan_agent_is_local"
branch_labels = None
depends_on = None

_OLD = "discovery_source IN ('manual','scanner','librenms','dns','proxmox','opnsense','phpipam')"
_NEW = ("discovery_source IN ('manual','scanner','librenms','dns','proxmox','opnsense',"
        "'phpipam','pfsense')")
# 此約束在歷史 migration 裡被命名慣例首碼過（見 0074），用 IF EXISTS 掃掉所有可能名稱再重建
_NAMES = (
    "ip_discovery_source_valid",
    "ck_ip_addresses_ip_discovery_source_valid",
    "ck_ip_addresses_ck_ip_addresses_ip_discovery_source_valid",
)
_CANON = "ck_ip_addresses_ip_discovery_source_valid"


def upgrade() -> None:
    for table in ("opnsense_firewalls", "pfsense_firewalls"):
        op.add_column(
            table,
            sa.Column("auto_create_ips", sa.Boolean(), nullable=False,
                      server_default=sa.text("false")),
        )
    for n in _NAMES:
        op.execute(f'ALTER TABLE ip_addresses DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE ip_addresses ADD CONSTRAINT "{_CANON}" CHECK ({_NEW})')


def downgrade() -> None:
    # 先把 pfsense 來源改回 manual，否則舊的 CHECK 會建不回去
    op.execute("UPDATE ip_addresses SET discovery_source='manual' WHERE discovery_source='pfsense'")
    for n in _NAMES:
        op.execute(f'ALTER TABLE ip_addresses DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE ip_addresses ADD CONSTRAINT "{_CANON}" CHECK ({_OLD})')
    for table in ("opnsense_firewalls", "pfsense_firewalls"):
        op.drop_column(table, "auto_create_ips")
