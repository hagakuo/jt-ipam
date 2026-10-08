"""ip rustdesk_enabled：「以 RustDesk 連線」按鈕的逐 IP 開關（2026-10-04）

比照 SSH／RDP／VNC：IP 編輯裡勾了「啟用 RustDesk 連線」，詳細資料頁才出現 RustDesk 按鈕（使用者要求）。
預設關閉：升級後原本看得到的 RustDesk 按鈕會先消失，要逐台開啟。RustDesk ID 照樣顯示。

Revision ID: 0179_ip_rustdesk_enabled
Revises: 0178_rustdesk_reports
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0179_ip_rustdesk_enabled"
down_revision: str | None = "0178_rustdesk_reports"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "ip_addresses",
        sa.Column("rustdesk_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("ip_addresses", "rustdesk_enabled")
