"""RustDesk：從 hbbs 刪除舊註冊（2026-10-05）

hbbs 永遠留著每一個註冊過的 ID（重灌、換電腦、測試機都會留下一筆），裝置清單越來越長。開源版沒有管理 API，
所以由 RustDesk 主機上的專用代理代為刪除：管理員在 jt-ipam 選好要刪的 ID，代理下次輪詢取走，刪之前再查一次
線上狀態（上線中的不刪），只刪 hbbs 資料庫 peer 表裡那一列。

兩邊都同意才會動到 RustDesk 的資料：
- rustdesk_servers.allow_peer_delete：網頁上的開關，預設關
- RustDesk 主機的管理員以 --allow-delete 重新執行安裝指令，代理才有寫入權限（沒有的話 hbbs 的目錄維持唯讀掛載）

- rustdesk_peer_deletes：請求與結果（pending／deleted／skipped_online／not_found／failed／cancelled）。
  同一個 ID 同時只有一筆等待中的請求；超過一天沒被代理取走的算失敗（逾時）

Revision ID: 0182_rustdesk_peer_delete
Revises: 0181_rustdesk_key_check
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0182_rustdesk_peer_delete"
down_revision: str | None = "0181_rustdesk_key_check"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("rustdesk_servers", sa.Column("allow_peer_delete", sa.Boolean(), nullable=False,
                                                server_default=sa.false()))
    op.create_table(
        "rustdesk_peer_deletes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("server_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("rustdesk_servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rustdesk_id", sa.String(100), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("detail", sa.String(500)),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('pending', 'deleted', 'skipped_online', 'not_found', 'failed', 'cancelled')",
            name="ck_rustdesk_peer_deletes_status"),
    )
    op.create_index("ix_rustdesk_peer_deletes_server_time", "rustdesk_peer_deletes", ["server_id", "requested_at"])
    op.create_index("uq_rustdesk_peer_deletes_pending", "rustdesk_peer_deletes", ["server_id", "rustdesk_id"],
                    unique=True, postgresql_where=sa.text("status = 'pending'"))
    op.create_index("ix_rustdesk_peer_deletes_requested_by", "rustdesk_peer_deletes", ["requested_by"],
                    postgresql_where=sa.text("requested_by IS NOT NULL"))


def downgrade() -> None:
    op.drop_table("rustdesk_peer_deletes")
    op.drop_column("rustdesk_servers", "allow_peer_delete")
