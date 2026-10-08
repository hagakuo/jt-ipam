"""rustdesk_servers：相容 RustDesk 的網頁連線也可以傳檔案（2026-10-05）

檔案傳輸是另外一條連線（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 附錄 J），沿用網頁連線的票證與中繼，後端照舊只轉送密文。

- web_file_transfer：「允許網頁檔案傳輸」，網頁上的開關，預設關（升級後不會自己打開；還要 web_enabled 開著）
- web_file_max_file_mb：上傳的單檔上限（MB），預設 2048（2 GB）
- web_file_max_total_mb：單次上傳的總量上限（MB），預設 10240
  兩個上限由瀏覽器照著擋（後端看不到檔案內容）

Revision ID: 0183_rustdesk_web_files
Revises: 0182_rustdesk_peer_delete
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0183_rustdesk_web_files"
down_revision: str | None = "0182_rustdesk_peer_delete"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("rustdesk_servers", sa.Column("web_file_transfer", sa.Boolean(), nullable=False,
                                                server_default=sa.false()))
    op.add_column("rustdesk_servers", sa.Column("web_file_max_file_mb", sa.Integer(), nullable=False,
                                                server_default="2048"))
    op.add_column("rustdesk_servers", sa.Column("web_file_max_total_mb", sa.Integer(), nullable=False,
                                                server_default="10240"))
    op.create_check_constraint("ck_rustdesk_servers_web_file_limits", "rustdesk_servers",
                               "web_file_max_file_mb BETWEEN 1 AND 1048576 "
                               "AND web_file_max_total_mb BETWEEN 1 AND 1048576")


def downgrade() -> None:
    op.drop_constraint("ck_rustdesk_servers_web_file_limits", "rustdesk_servers", type_="check")
    op.drop_column("rustdesk_servers", "web_file_max_total_mb")
    op.drop_column("rustdesk_servers", "web_file_max_file_mb")
    op.drop_column("rustdesk_servers", "web_file_transfer")
