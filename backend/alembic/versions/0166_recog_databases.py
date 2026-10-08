"""recog_databases：Recog 指紋資料庫（選用；探測用來認出產品、OS、設備類型）

Revision ID: 0166_recog_databases
Revises: 0165_standalone_dhcp
Create Date: 2026-09-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0166_recog_databases"
down_revision: str | None = "0165_standalone_dhcp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recog_databases",
        sa.Column("key", sa.String(96), primary_key=True),
        sa.Column("filename", sa.String(128), nullable=False),
        sa.Column("release", sa.String(32), nullable=False),
        sa.Column("translator_version", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(32)),
        sa.Column("database_type", sa.String(32)),
        sa.Column("preference", sa.Float()),
        sa.Column("fingerprints", postgresql.JSONB(), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("skipped", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("recog_databases")
