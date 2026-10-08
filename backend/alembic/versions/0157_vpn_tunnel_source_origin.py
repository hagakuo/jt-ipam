"""vpn_tunnels.source_origin：同步建立的通道記下是哪一台實例建的。

以前以「防火牆名稱/」前綴認定歸屬：防火牆改名後，舊名字的通道再也不會被清（孤兒），
刪掉防火牆也不會清（2026-09-26 稽核）。既有的同步通道依目前的防火牆名稱前綴回填；
對不上任何現有防火牆名稱的（改名前建的）維持 NULL，與手動建立的一樣不會被自動刪除。

Revision ID: 0157_vpn_tunnel_source_origin
Revises: 0156_dhcp_lease_sightings
Create Date: 2026-09-26
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0157_vpn_tunnel_source_origin"
down_revision: str | None = "0156_dhcp_lease_sightings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vpn_tunnels", sa.Column("source_origin", sa.String(64), nullable=True))
    op.create_index("ix_vpn_tunnels_source_origin", "vpn_tunnels", ["source_origin"])
    # 前綴比對用 starts_with（不是 LIKE：防火牆名稱裡的 _ 與 % 不可以當萬用字元）
    op.execute("""
        UPDATE vpn_tunnels t SET source_origin = 'opnsense:' || f.id
        FROM opnsense_firewalls f
        WHERE t.source_origin IS NULL
          AND (starts_with(t.name, f.name || '/wg/') OR starts_with(t.name, f.name || '/ipsec/'))
    """)
    op.execute("""
        UPDATE vpn_tunnels t SET source_origin = 'fortigate:' || f.id
        FROM fortigate_firewalls f
        WHERE t.source_origin IS NULL AND starts_with(t.name, f.name || '/ipsec/')
    """)
    op.execute("""
        UPDATE vpn_tunnels t SET source_origin = 'mikrotik:' || r.id
        FROM mikrotik_routers r
        WHERE t.source_origin IS NULL AND starts_with(t.name, r.name || '/wireguard/')
    """)


def downgrade() -> None:
    op.drop_index("ix_vpn_tunnels_source_origin", table_name="vpn_tunnels")
    op.drop_column("vpn_tunnels", "source_origin")
