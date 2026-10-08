"""DHCP 租約的逐來源目擊表（dhcp_lease_sightings）。

`ip_addresses.in_dhcp_lease` 是六個 DHCP 來源共用的一個布林，清除各寫各的 —— 沒設關聯子網路
就永遠不清、Palo Alto 從來不清、有設範圍時會清掉別的來源還發著的租約（2026-09-26 稽核）。
改成逐來源記錄、旗標由這張表推導（比照 dhcp_reservations）。
目前是 True 的旗標搬進來當 `legacy`：真實同步看到就被認領，沒人認領的在寬限期後清掉。
last_seen_at 設為遷移當下，寬限期從升級那一刻開始算。

Revision ID: 0156_dhcp_lease_sightings
Revises: 0155_hostname_reports
Create Date: 2026-09-26
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0156_dhcp_lease_sightings"
down_revision: str | None = "0155_hostname_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dhcp_lease_sightings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("ip_address_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_type", sa.String(24), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("ip_address_id", "source_type", "source_id",
                            name="uq_dhcp_lease_sightings_ip_source"),
    )
    op.create_index("ix_dhcp_lease_sightings_ip_address_id", "dhcp_lease_sightings", ["ip_address_id"])
    op.create_index("ix_dhcp_lease_sightings_source", "dhcp_lease_sightings", ["source_type", "source_id"])
    op.execute("""
        INSERT INTO dhcp_lease_sightings (ip_address_id, source_type, source_id)
        SELECT id, 'legacy', '00000000-0000-0000-0000-000000000000'::uuid
        FROM ip_addresses WHERE in_dhcp_lease IS TRUE
    """)


def downgrade() -> None:
    op.drop_index("ix_dhcp_lease_sightings_source", table_name="dhcp_lease_sightings")
    op.drop_index("ix_dhcp_lease_sightings_ip_address_id", table_name="dhcp_lease_sightings")
    op.drop_table("dhcp_lease_sightings")
