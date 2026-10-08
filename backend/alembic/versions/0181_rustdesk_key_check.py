"""rustdesk_peers：客戶端的 Key 設錯（2026-10-05）

RustDesk 客戶端的 Key 設錯時照樣能註冊、回報，同一區網的直接連線也正常，只有走中繼時被 hbbr 拒絕；
網頁連線一定走中繼，看起來就像網頁連線壞了。RustDesk 代理 1.1.0 讀 hbbr／hbbs 的日誌，
把「哪個 IP 被拒、哪個 IP 通過」送上來，同一台伺服器上只有一個裝置在那個 IP 時記在它身上。

- key_fail_at：最後一次因為 Key 被拒的時間
- key_fail_scope：relay＝中繼拒絕（被連線那一端）、hbbs＝hbbs 拒絕主動連線（發起那一端）
- key_fail_count：上次通過之後被拒的次數
- key_ok_at：最後一次通過中繼的時間（比 key_fail_at 新＝已經改好）

Revision ID: 0181_rustdesk_key_check
Revises: 0180_rustdesk_web
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0181_rustdesk_key_check"
down_revision: str | None = "0180_rustdesk_web"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("rustdesk_peers", sa.Column("key_fail_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_peers", sa.Column("key_fail_scope", sa.String(8)))
    op.add_column("rustdesk_peers", sa.Column("key_fail_count", sa.Integer()))
    op.add_column("rustdesk_peers", sa.Column("key_ok_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("rustdesk_peers", "key_ok_at")
    op.drop_column("rustdesk_peers", "key_fail_count")
    op.drop_column("rustdesk_peers", "key_fail_scope")
    op.drop_column("rustdesk_peers", "key_fail_at")
