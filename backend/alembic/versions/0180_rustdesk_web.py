"""rustdesk_servers：相容 RustDesk 的網頁連線設定（2026-10-04）

在瀏覽器裡直接操作已對應到 IP 記錄的 RustDesk 裝置（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md 第 14 節）。
後端負責連 hbbs 做會合、連 hbbr 做中繼，只轉送密文；加解密與登入都在瀏覽器。

- web_enabled：是否開放網頁連線，網頁上的開關，預設關（升級後不會自己打開）
- hbbs_host：後端連 hbbs 用的位址（可帶 :埠）；空白＝用代理回報的來源位址 agent_source_ip
- relay_host：後端連 hbbr 用的位址（可帶 :埠）；空白＝hbbs 的主機＋中繼預設埠
- transport：後端連 hbbs／hbbr 用 tcp（21116／21117，預設）或 ws（21118／21119）

Revision ID: 0180_rustdesk_web
Revises: 0179_ip_rustdesk_enabled
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0180_rustdesk_web"
down_revision: str | None = "0179_ip_rustdesk_enabled"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("rustdesk_servers", sa.Column("web_enabled", sa.Boolean(), nullable=False,
                                                server_default=sa.text("false")))
    op.add_column("rustdesk_servers", sa.Column("hbbs_host", sa.String(255)))
    op.add_column("rustdesk_servers", sa.Column("relay_host", sa.String(255)))
    op.add_column("rustdesk_servers", sa.Column("transport", sa.String(8), nullable=False,
                                                server_default="tcp"))
    op.create_check_constraint("ck_rustdesk_servers_transport", "rustdesk_servers",
                               "transport IN ('tcp', 'ws')")


def downgrade() -> None:
    op.drop_constraint("ck_rustdesk_servers_transport", "rustdesk_servers", type_="check")
    op.drop_column("rustdesk_servers", "transport")
    op.drop_column("rustdesk_servers", "relay_host")
    op.drop_column("rustdesk_servers", "hbbs_host")
    op.drop_column("rustdesk_servers", "web_enabled")
