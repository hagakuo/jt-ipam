"""email 允許重複：同一個人同時有本機帳號與 LDAP/SSO 帳號是常態

Revision ID: 0120_users_email_not_unique
Revises: 0119_fw_ack
Create Date: 2026-08-19

`users.email` 原本是唯一鍵，但真實情境裡同一個人常常同時擁有本機帳號與 LDAP／SSO
帳號，兩邊 email 相同。唯一鍵讓 LDAP 自動建帳號在 commit 時撞 unique，整個登入回
500（帳密其實驗過了），且該帳號永遠建不起來。email 只是聯絡資訊、不是身分識別 ——
身分識別是 username（仍為唯一）。改成一般索引：查詢一樣快，但不再擋重複。

⚠️ 一起改的還有 `services/auth.py` 兩處登入查詢：以 email 登入時必須依領域限縮，
且不可用 `scalar_one_or_none()`，否則重複 email 會換成 MultipleResultsFound 的 500。
"""
from __future__ import annotations

from alembic import op

revision = "0120_users_email_not_unique"
down_revision = "0119_fw_ack"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_users_email", table_name="users")
    op.create_index("ix_users_email", "users", ["email"], unique=False)


def downgrade() -> None:
    # 還原唯一鍵；若此時已存在重複 email，這步會失敗 —— 這是預期行為
    # （資料已經不符合舊約束，必須由管理者先決定要保留哪一筆）
    op.drop_index("ix_users_email", table_name="users")
    op.create_index("ix_users_email", "users", ["email"], unique=True)
