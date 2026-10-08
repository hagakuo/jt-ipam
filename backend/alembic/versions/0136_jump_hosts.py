"""跳板主機（issue #24 階段一）：`jump_hosts` ＋ 子網路／IP 上的連線出口欄位。

規格見 `docs/SPEC_CONSOLE_RELAY_zh-TW.md` §3。指派解析順序是
**IP 覆寫 > 子網路 > 直連**，所以兩張表都要有欄位，且都可為空。

Revision ID: 0136_jump_hosts
Revises: 0135_mikrotik
Create Date: 2026-09-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0136_jump_hosts"
down_revision: str | None = "0135_mikrotik"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jump_hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default=sa.text("22")),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("auth_kind", sa.String(16), nullable=False, server_default="key"),
        # AES-GCM；金鑰與密碼二擇一，兩組都可為空（尚未設定時）
        sa.Column("private_key_enc", postgresql.BYTEA(), nullable=True),
        sa.Column("private_key_nonce", postgresql.BYTEA(), nullable=True),
        sa.Column("password_enc", postgresql.BYTEA(), nullable=True),
        sa.Column("password_nonce", postgresql.BYTEA(), nullable=True),
        # 空值＝尚未信任：連線前會取回指紋要求人工確認，不會靜靜接受任何 host key
        sa.Column("host_key_fingerprint", sa.String(128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("max_sessions", sa.Integer(), nullable=False, server_default=sa.text("10")),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("last_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint("auth_kind IN ('key','password')", name="jump_hosts_auth_kind_valid"),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="jump_hosts_port_valid"),
        sa.CheckConstraint("max_sessions BETWEEN 1 AND 200", name="jump_hosts_max_sessions_valid"),
    )

    # 指派：IP 覆寫所屬子網路；兩者都空＝直連。
    # ondelete=SET NULL：刪掉跳板不應該連帶刪掉子網路或 IP —— 只是回到直連。
    for table in ("subnets", "ip_addresses"):
        op.add_column(table, sa.Column("jump_host_id", postgresql.UUID(as_uuid=True),
                                       nullable=True))
        op.create_foreign_key(
            f"fk_{table}_jump_host", table, "jump_hosts",
            ["jump_host_id"], ["id"], ondelete="SET NULL",
        )
        op.create_index(f"ix_{table}_jump_host_id", table, ["jump_host_id"])


def downgrade() -> None:
    for table in ("subnets", "ip_addresses"):
        op.drop_index(f"ix_{table}_jump_host_id", table_name=table)
        op.drop_constraint(f"fk_{table}_jump_host", table, type_="foreignkey")
        op.drop_column(table, "jump_host_id")
    op.drop_table("jump_hosts")
