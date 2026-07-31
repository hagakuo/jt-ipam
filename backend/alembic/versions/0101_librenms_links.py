"""librenms_links：LLDP / CDP 鄰居連線 + librenms_instances.sync_links 開關

LibreNMS 的 `links` 表（xdp discovery 產出）鏡像進來。與 FDB/ARP 推導不同，
這是對端自己宣告的鄰接關係，交換器之間的 trunk 也畫得出來。

remote_* 可為空：對端不一定也被 LibreNMS 監控，那時只有 LLDP 通報的字串。
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0101_librenms_links"
down_revision = "0100_fortigate"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "librenms_instances",
        sa.Column("sync_links", sa.Boolean(), nullable=False, server_default=sa.true()),
    )

    op.create_table(
        "librenms_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("legacy_link_id", sa.BigInteger(), nullable=False),
        sa.Column("protocol", sa.String(length=16)),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("local_device_id", sa.BigInteger()),
        sa.Column("local_port_id", sa.BigInteger()),
        sa.Column("local_port_name", sa.Text()),
        sa.Column("remote_device_id", sa.BigInteger()),
        sa.Column("remote_port_id", sa.BigInteger()),
        sa.Column("remote_hostname", sa.Text()),
        sa.Column("remote_port", sa.Text()),
        sa.Column("remote_platform", sa.Text()),
        sa.Column("remote_version", sa.Text()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["instance_id"], ["librenms_instances.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("instance_id", "legacy_link_id", name="librenms_link_unique"),
    )
    op.create_index("ix_librenms_links_instance_id", "librenms_links", ["instance_id"])
    op.create_index("ix_librenms_links_local_device_id", "librenms_links", ["local_device_id"])
    op.create_index("ix_librenms_links_remote_device_id", "librenms_links", ["remote_device_id"])


def downgrade() -> None:
    op.drop_index("ix_librenms_links_remote_device_id", table_name="librenms_links")
    op.drop_index("ix_librenms_links_local_device_id", table_name="librenms_links")
    op.drop_index("ix_librenms_links_instance_id", table_name="librenms_links")
    op.drop_table("librenms_links")
    op.drop_column("librenms_instances", "sync_links")
