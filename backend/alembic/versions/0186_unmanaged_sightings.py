"""unmanaged_sightings：沒有納管、但看得到在用的位址（2026-10-06）

掃描代理的自動收錄關閉時，掃到 IPAM 裡沒有的活位址以前直接丟掉，指示計上跟閒置一樣。現在只記「看到過」，
不建 IP 記錄。30 天沒再看到就清掉。

Revision ID: 0186_unmanaged_sightings
Revises: 0185_device_workstation_type
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0186_unmanaged_sightings"
down_revision: str | None = "0185_device_workstation_type"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "unmanaged_sightings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("subnet_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("mac", sa.String(length=17), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("subnet_id", "ip", "source", name="uq_unmanaged_sighting"),
    )
    op.create_index("ix_unmanaged_sightings_last_seen", "unmanaged_sightings", ["last_seen_at"])


def downgrade() -> None:
    op.drop_index("ix_unmanaged_sightings_last_seen", table_name="unmanaged_sightings")
    op.drop_table("unmanaged_sightings")
