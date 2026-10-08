"""稽核記錄改成真正的「只能新增」：拿掉外鍵、資料庫層拒絕 UPDATE / DELETE。

2026-09-23 prod：刪除一個帳號，稽核鏈就斷了。`audit_logs.actor_user_id` 的外鍵是
`ON DELETE SET NULL`，刪帳號時資料庫自動把這個人的稽核記錄 actor 清成 NULL ——
內容一變，雜湊重算不回來，驗證就報「中斷」。換回原本的帳號 ID 後雜湊完全吻合，
證明不是有人竄改，是外鍵做的。一條被正常操作就能弄斷的稽核鏈沒有證明力。

1. **拿掉外鍵**。稽核記錄保留當時的帳號 UUID（刪帳號時的那筆稽核另外記著帳號名稱），
   不需要參照完整性；需要的是「寫了就不再變」。
2. **觸發器拒絕 UPDATE / DELETE**。程式錯誤、串連、匯入、誤操作都改不動。
   有資料表擁有者權限的人仍然可以停用觸發器 —— 那一層由雜湊鏈與外部錨定
   （`audit-anchors.jsonl`）負責抓，這裡擋的是「不小心」與「應用程式層的任何路徑」。
   TRUNCATE 刻意不擋：測試每次都要清空全部資料表。

Revision ID: 0149_audit_logs_append_only
Revises: 0148_shelf_stack_and_top
Create Date: 2026-09-23
"""
from __future__ import annotations

from alembic import op

revision: str = "0149_audit_logs_append_only"
down_revision: str | None = "0148_shelf_stack_and_top"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS fk_audit_logs_actor_user_id_users")
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs is append-only: % is not allowed (id=%)', TG_OP, OLD.id
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$
    """)
    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
    op.execute("""
        CREATE TRIGGER audit_logs_append_only
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_logs_append_only()")
    # 不把外鍵加回去：它正是讓稽核鏈斷掉的原因。降版只移除保護，不重新引入缺陷。
