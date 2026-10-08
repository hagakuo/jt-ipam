"""ユーザー設定の locale に ja-JP を許可する。

`user_preferences.locale` には CHECK 制約があり、'zh-TW' と 'en-US' しか受け付け
なかった。UI に日本語を追加しただけでは、利用者が日本語を選んだ瞬間に保存が
IntegrityError で落ちる —— 画面には「保存に失敗しました」としか出ないため、
原因が制約だとは分からない。

制約名はカタログから引いて落とす。0001 が付けた名前（ck_user_preferences_locale_valid）に
命名規約の接頭辞がもう一度付き、実際の環境では二重（ck_user_preferences_ck_user_preferences_
locale_valid）になっている。名前を直書きすると、どちらの環境かで必ず片方が壊れる。

Revision ID: 0139_locale_ja
Revises: 0138_drop_wazuh_cve
"""
from __future__ import annotations

from alembic import op

revision = "0139_locale_ja"
down_revision = "0138_drop_wazuh_cve"
branch_labels = None
depends_on = None

# `%` は使わない。alembic の op.execute は文字列をそのまま通すが、ドライバによっては
# パラメータ記号として解釈され、構文エラーになる（実際にそれで落ちた）。
_DROP_BY_DEFINITION = """
DO $$
DECLARE c text;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'user_preferences'::regclass
      AND contype = 'c'
      AND position('locale' in pg_get_constraintdef(oid)) > 0
  LOOP
    EXECUTE 'ALTER TABLE user_preferences DROP CONSTRAINT ' || quote_ident(c);
  END LOOP;
END $$;
"""


def upgrade() -> None:
    op.execute(_DROP_BY_DEFINITION)
    op.execute(
        "ALTER TABLE user_preferences ADD CONSTRAINT ck_user_preferences_locale_valid "
        "CHECK (locale IN ('zh-TW','en-US','ja-JP'))"
    )


def downgrade() -> None:
    # 日本語を選んでいた利用者は、戻す前に既定へ寄せる（そうしないと制約を作れない）。
    op.execute("UPDATE user_preferences SET locale = 'en-US' WHERE locale = 'ja-JP'")
    op.execute(_DROP_BY_DEFINITION)
    op.execute(
        "ALTER TABLE user_preferences ADD CONSTRAINT ck_user_preferences_locale_valid "
        "CHECK (locale IN ('zh-TW','en-US'))"
    )
