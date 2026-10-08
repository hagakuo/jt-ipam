"""主機名稱的逐來源實例目擊表（ip_hostname_reports）。

上游不再回報的主機名稱從來不會被清掉（2026-09-26 稽核：16 個來源無一例外）。要安全地清，
必須知道每個名稱是**哪一台實例**回報的 —— 觀測表一個來源只有一筆、多台共用。
既有的非手動觀測搬進來當 `legacy`：真實同步看到就被認領，沒人認領的在寬限期後清掉。
last_seen_at 設為遷移當下，寬限期從升級那一刻開始算，不會一升級就把舊資料清光。

Revision ID: 0155_hostname_reports
Revises: 0154_vnc_cred_username
Create Date: 2026-09-26
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0155_hostname_reports"
down_revision: str | None = "0154_vnc_cred_username"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ip_hostname_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("ip_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("origin", sa.String(96), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("ip_id", "source", "origin", name="uq_ip_hostname_reports_ip_source_origin"),
    )
    op.create_index("ix_ip_hostname_reports_ip_id", "ip_hostname_reports", ["ip_id"])
    op.create_index("ix_ip_hostname_reports_source_origin", "ip_hostname_reports", ["source", "origin"])
    op.execute("""
        INSERT INTO ip_hostname_reports (ip_id, source, origin, hostname, first_seen_at, last_seen_at)
        SELECT ip_id, source, 'legacy', hostname, observed_at, now()
        FROM ip_hostname_observations WHERE source <> 'manual'
    """)


def downgrade() -> None:
    op.drop_index("ix_ip_hostname_reports_source_origin", table_name="ip_hostname_reports")
    op.drop_index("ix_ip_hostname_reports_ip_id", table_name="ip_hostname_reports")
    op.drop_table("ip_hostname_reports")
