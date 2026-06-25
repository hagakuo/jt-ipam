"""refresh token revocation timestamp

Revision ID: 0086_refresh_token_revocation
Revises: 0085_vm_unique_by_vmid
Create Date: 2026-06-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0086_refresh_token_revocation"
down_revision: str | None = "0085_vm_unique_by_vmid"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("refresh_token_revoked_after", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "refresh_token_revoked_after")
