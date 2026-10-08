"""MikroTik 第二階段：路由器對應的裝置、FDB、鄰居

- `mikrotik_routers.device_id`：這台路由器＝哪一台 jt-ipam 裝置。介面、FDB、鄰居都要落在某台裝置上；
  沒有指定時同步會用 API 位址對到的 IP 所屬裝置自動帶入。
- `fdb_entries.switch_device_id`／`mikrotik_router_id`：FDB 原本只有 LibreNMS 一個來源，
  `device_id` 指的是 LibreNMS 的裝置。MikroTik 的 bridge host 表直接記 jt-ipam 裝置，
  拓樸的 FDB 推導兩種一起用；刪路由器時它的 FDB 跟著刪。
- `mikrotik_neighbors`：`/ip/neighbor`（MNDP／CDP／LLDP）—— 對方自己宣告的「我是誰、接在你哪個埠」。

Revision ID: 0170_mikrotik_phase2
Revises: 0169_ip_device_kind
Create Date: 2026-10-01
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0170_mikrotik_phase2"
down_revision: str | None = "0169_ip_device_kind"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("mikrotik_routers", sa.Column(
        "device_id", UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True))
    op.create_index("ix_mikrotik_routers_device_id", "mikrotik_routers", ["device_id"])

    op.add_column("fdb_entries", sa.Column(
        "switch_device_id", UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=True))
    op.add_column("fdb_entries", sa.Column(
        "mikrotik_router_id", UUID(as_uuid=True), sa.ForeignKey("mikrotik_routers.id", ondelete="CASCADE"),
        nullable=True))
    op.create_index("ix_fdb_entries_switch_device_id", "fdb_entries", ["switch_device_id"])
    op.create_index("ix_fdb_entries_mikrotik_router_id", "fdb_entries", ["mikrotik_router_id"])

    op.create_table(
        "mikrotik_neighbors",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("router_id", UUID(as_uuid=True), sa.ForeignKey("mikrotik_routers.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("interface", sa.String(128), nullable=False),
        sa.Column("address", sa.String(64)),
        sa.Column("mac", sa.String(32)),
        sa.Column("identity", sa.String(255)),
        sa.Column("platform", sa.String(128)),
        sa.Column("board", sa.String(128)),
        sa.Column("version", sa.String(128)),
        sa.Column("remote_interface", sa.String(128)),
        sa.Column("discovered_by", sa.String(32)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("router_id", "interface", "mac", "identity", name="mikrotik_neighbor_unique"),
    )


def downgrade() -> None:
    op.drop_table("mikrotik_neighbors")
    op.drop_index("ix_fdb_entries_mikrotik_router_id", table_name="fdb_entries")
    op.drop_index("ix_fdb_entries_switch_device_id", table_name="fdb_entries")
    op.drop_column("fdb_entries", "mikrotik_router_id")
    op.drop_column("fdb_entries", "switch_device_id")
    op.drop_index("ix_mikrotik_routers_device_id", table_name="mikrotik_routers")
    op.drop_column("mikrotik_routers", "device_id")
