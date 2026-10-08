"""OCS 也可以「限定子網路範圍」（比照 Wazuh 等整合）。

重疊網段時只跟這些子網路裡的 IP 比對 MAC；「未裝 Agent 的 IP」也只列這些子網路。
空（NULL 或空陣列）＝全域，既有的 OCS 設定行為不變。

Revision ID: 0153_ocs_scope_subnets
Revises: 0152_arp_evidence_subnet
Create Date: 2026-09-25
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0153_ocs_scope_subnets"
down_revision: str | None = "0152_arp_evidence_subnet"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ocs_servers", sa.Column("scope_subnet_ids", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("ocs_servers", "scope_subnet_ids")
