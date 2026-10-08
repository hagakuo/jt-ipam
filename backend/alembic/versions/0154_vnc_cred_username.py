"""VNC 已存帳密的帳號欄：舊資料的固定佔位值「vnc」清成空白。

VNC 以前只有密碼，金庫的 username 欄必填，前端就塞了固定值 "vnc"（不用於認證）。
2026-09-25 起 guacd 引擎支援「帳號＋密碼」的 VNC 認證（macOS 螢幕共享、UltraVNC MS 登入、
VeNCrypt），帳號欄開始有意義 —— 佔位值不清掉的話，會被當成帳號「vnc」送去認證。
舊表單沒有帳號欄，不可能有人真的把 VNC 帳號設成 vnc，所以可以安全地全部清掉。

Revision ID: 0154_vnc_cred_username
Revises: 0153_ocs_scope_subnets
Create Date: 2026-09-25
"""
from __future__ import annotations

from alembic import op

revision: str = "0154_vnc_cred_username"
down_revision: str | None = "0153_ocs_scope_subnets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE ssh_credentials SET username = '' WHERE protocol = 'vnc' AND username = 'vnc'")


def downgrade() -> None:
    op.execute("UPDATE ssh_credentials SET username = 'vnc' WHERE protocol = 'vnc' AND username = ''")
