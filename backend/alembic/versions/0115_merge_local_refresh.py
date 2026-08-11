"""merge the NKUST refresh-token branch with the upstream chain

Revision ID: 0115_merge_local_refresh
Revises: 0102_merge_local_refresh, 0114_scan_agent_is_local
Create Date: 2026-08-11
"""

from __future__ import annotations

revision: str = "0115_merge_local_refresh"
down_revision: tuple[str, str] = (
    "0102_merge_local_refresh",
    "0114_scan_agent_is_local",
)
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
