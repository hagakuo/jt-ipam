"""merge local refresh-token revocation with upstream pfSense migrations

Revision ID: 0089_merge_refresh_pfsense
Revises: 0086_refresh_token_revocation, 0088_pfsense_rules_dsv
Create Date: 2026-06-27
"""

from __future__ import annotations

revision: str = "0089_merge_refresh_pfsense"
down_revision: tuple[str, str] = (
    "0086_refresh_token_revocation",
    "0088_pfsense_rules_dsv",
)
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
