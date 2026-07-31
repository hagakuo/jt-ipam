"""merge local refresh-token branch with the current upstream chain

Revision ID: 0102_merge_local_refresh
Revises: 0089_merge_refresh_pfsense, 0101_librenms_links
Create Date: 2026-07-31
"""

from __future__ import annotations

revision: str = "0102_merge_local_refresh"
down_revision: tuple[str, str] = (
    "0089_merge_refresh_pfsense",
    "0101_librenms_links",
)
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
