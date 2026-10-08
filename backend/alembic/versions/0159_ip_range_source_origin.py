"""ip_ranges.source_origin：由偵測到的 DHCP 發放範圍自動建立的位址範圍（集區）。

使用者要求（2026-09-27）：子網路偵測到 DHCP 發放範圍時，「位址範圍（集區）」要自動加上對應的。
自動建立的記下來源（`<來源>:<實例 id>`），跟著上游走；手動建立的維持 NULL、一律不動。
第一次建立由 jt-ipam-sync 的下一輪完成（services/ip_ranges.sync_auto_dhcp_ranges）。

Revision ID: 0159_ip_range_source_origin
Revises: 0158_console_engine_guacd
Create Date: 2026-09-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0159_ip_range_source_origin"
down_revision: str | None = "0158_console_engine_guacd"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ip_ranges", sa.Column("source_origin", sa.String(64), nullable=True))
    op.create_index("ix_ip_ranges_source_origin", "ip_ranges", ["source_origin"])


def downgrade() -> None:
    op.execute("DELETE FROM ip_ranges WHERE source_origin IS NOT NULL")
    op.drop_index("ix_ip_ranges_source_origin", table_name="ip_ranges")
    op.drop_column("ip_ranges", "source_origin")
