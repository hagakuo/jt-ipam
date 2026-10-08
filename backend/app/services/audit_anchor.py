"""稽核鏈的定期驗證與外部錨定。

雜湊鏈本身能證明的事有限，而**它證明不了的那件事**正是這個模組存在的理由：

- 中間任何一筆被改或被刪 → 後面每一筆的 prev_hash 都對不上，`verify_chain` 抓得到
- **從尾端整段截斷 → 鏈仍然完整**，因為被刪掉的是「還沒有人引用過」的最後幾筆

要偵測尾端截斷，唯一的辦法是把「當時最新的雜湊與筆數」記到**資料庫外面**。
之後只要那個被錨定的位置在資料庫裡消失或雜湊變了，就代表有人動過尾端。

錨定檔刻意用純文字逐行附加：它要能被備份、被複製到別台、被人眼閱讀，
而且即使 jt-ipam 整個掛掉也還讀得到。同一份內容也寫進系統日誌（journald），
這樣就算檔案被刪，日誌收集端仍留有副本。
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import verify_chain

log = logging.getLogger("jt_ipam.audit_anchor")

# 錨定檔預設放在資料目錄；權限 0600（內容不敏感，但不該被隨意改）
DEFAULT_ANCHOR_PATH = "/var/lib/jt-ipam/audit-anchors.jsonl"


def anchor_path() -> Path:
    return Path(os.environ.get("JT_IPAM_AUDIT_ANCHOR_FILE", DEFAULT_ANCHOR_PATH))


def baseline_id() -> int | None:
    """驗證起點（`JT_IPAM_AUDIT_CHAIN_BASELINE_ID`），沒設就是從頭驗。

    存在的理由很具體：0.5.204 之前 `append_audit` 只 add 不 flush，同一交易連寫多筆
    （批次刪除）時每一筆都接到同一個前置雜湊 —— 那是**寫入端的 bug 留下的舊斷點**，
    不是有人動過資料。舊段落已無法補回正確雜湊（要補就得改寫既有記錄，那本身
    才是竄改），所以只能明確劃一條線：從這個 id 之後開始驗。

    設了之後每輪都會記一行 WARNING 說明「這條線之前沒有被驗證」——
    這種折衷可以接受，但不可以安靜。
    """
    raw = os.environ.get("JT_IPAM_AUDIT_CHAIN_BASELINE_ID", "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        log.warning("JT_IPAM_AUDIT_CHAIN_BASELINE_ID=%r 不是整數，忽略", raw)
        return None
    return value if value > 0 else None


def read_last_anchor(path: Path | None = None) -> dict[str, Any] | None:
    """讀最後一筆錨定。檔案不存在／損壞都回 None（視為尚未錨定，不是錯誤）。"""
    p = path or anchor_path()
    try:
        if not p.exists():
            return None
        last = None
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except ValueError:
                continue        # 壞掉的行略過，不讓它擋住後面的好行
        return last
    except OSError:
        return None


def append_anchor(rec: dict[str, Any], path: Path | None = None) -> None:
    p = path or anchor_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    with contextlib.suppress(OSError):   # 某些檔案系統 chmod 會失敗，不該讓錨定本身失敗
        p.chmod(0o600)
    # 同一份寫進系統日誌：錨定檔被刪時，日誌收集端仍有副本
    log.info("audit anchor %s", json.dumps(rec, ensure_ascii=False, sort_keys=True))


# 站內通知去重：斷鏈不會自己好，每 5 分鐘發一次等於每天每位管理員 288 則 ——
# 洗版的告警和沒有告警一樣沒用。比照憑證告警的作法，同一種失敗一段時間內只發一次。
NOTIFY_DEDUP_HOURS = 12
_NOTIFY_TITLE = "稽核鏈驗證失敗"
_NOTIFY_KEY = "notif.audit_chain_broken"


async def notify_chain_failure(
    session: AsyncSession, result: dict[str, Any], *, dedup_hours: int = NOTIFY_DEDUP_HOURS,
) -> int:
    """把驗證失敗發給所有管理員；回傳實際發出的則數（去重後可能是 0）。"""
    from datetime import timedelta

    from sqlalchemy import select

    from app.models.notification import Notification
    from app.models.user import User
    from app.services.notification import push_notification

    since = datetime.now(UTC) - timedelta(hours=dedup_hours)
    recent = (await session.execute(
        select(Notification.id).where(
            Notification.object_type == "audit",
            # 去重要看穩定的識別碼，不要看顯示文字：標題一旦改寫（例如翻譯或潤稿），
            # 舊列就比對不到，症狀是「同一件事開始每次都通知」——不會有任何錯誤。
            # 舊列沒有 title_key，所以兩個都收，升級當下不會冒出一則重複通知。
            or_(Notification.title_key == _NOTIFY_KEY,
                Notification.title == _NOTIFY_TITLE),
            Notification.created_at >= since,
        ).limit(1))).scalars().first()
    if recent is not None:
        return 0

    # 通知發送設定裡可以關掉（`audit.chain_broken`）。原本是直接推 ——
    # 使用者收得到卻沒有任何地方管得到它。預設仍是站內＋Email 都開：這是資安事件。
    from app.services.system_config import get_notification_matrix
    ch = (await get_notification_matrix(session)).get(
        "audit.chain_broken", {"in_app": True, "email": True})
    if not (ch.get("in_app") or ch.get("email")):
        return 0

    admins = (await session.execute(
        select(User).where(User.is_admin.is_(True), User.is_active.is_(True))
    )).scalars().all()
    detail = str(result.get("detail") or result.get("reason") or "unknown")
    if ch.get("in_app"):
        for admin in admins:
            await push_notification(
                session, user_id=admin.id, severity="error",
                title=_NOTIFY_TITLE, body=detail,
                link="/audit", object_type="audit", object_id=None,
                title_key=_NOTIFY_KEY, body_key="notif.audit_chain_broken_body",
                params={"detail": detail},
            )
    if ch.get("email"):
        from app.services.notification import email_users
        await email_users(session, [a.email for a in admins],
                          f"[jt-ipam] {_NOTIFY_TITLE}", detail)
    return len(admins)


async def verify_and_anchor(
    session: AsyncSession, *, path: Path | None = None,
) -> dict[str, Any]:
    """驗證鏈（自上次錨定起）並寫入新的錨定點。

    回傳 `{"ok": bool, "reason": str|None, ...}`；`ok=False` 時呼叫端應發告警。
    **不自行 commit**：由呼叫端決定交易邊界。
    """
    from app.models.audit import AuditLog

    total = int(await session.scalar(select(func.count()).select_from(AuditLog)) or 0)
    latest = (await session.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1))).scalars().first()

    prev = read_last_anchor(path)
    result: dict[str, Any] = {"ok": True, "reason": None, "count": total,
                              "anchored_from": prev.get("audit_id") if prev else None}

    if prev:
        anchored_id = int(prev.get("audit_id") or 0)
        # 錨定檔存的是 hex（純文字要能被人眼閱讀／被別的工具比對），DB 欄位是 bytes
        anchored_hex = str(prev.get("this_hash") or "")
        try:
            anchored_hash = bytes.fromhex(anchored_hex) if anchored_hex else b""
        except ValueError:
            anchored_hash = b""
        row = (await session.execute(
            select(AuditLog).where(AuditLog.id == anchored_id))).scalars().first()
        # 尾端截斷的證據：上次錨定的那一筆不見了，或它的雜湊被換過
        if row is None:
            result.update(ok=False, reason="anchored_row_missing",
                          detail=f"上次錨定的稽核記錄 id={anchored_id} 已不存在（疑似尾端截斷或整段刪除）")
            return result
        if anchored_hash and row.this_hash != anchored_hash:
            result.update(ok=False, reason="anchored_hash_changed",
                          detail=f"稽核記錄 id={anchored_id} 的雜湊與錨定值不符（內容被改過）")
            return result
        if total < int(prev.get("count") or 0):
            result.update(ok=False, reason="count_shrank",
                          detail=f"稽核記錄總數從 {prev.get('count')} 減為 {total}（有記錄被刪）")
            return result
        ok, bad = await verify_chain(
            session, after_id=anchored_id,
            expected_prev=anchored_hash or None)
    else:
        base = baseline_id()
        if base is None:
            ok, bad = await verify_chain(session)  # 首次：整條驗一次
        else:
            # 首次且有基準線：從基準線之後開始驗，並且每輪都講清楚沒驗到哪一段
            row = (await session.execute(
                select(AuditLog).where(AuditLog.id == base))).scalars().first()
            if row is None:
                result.update(ok=False, reason="baseline_row_missing",
                              detail=f"設定的稽核鏈基準線 id={base} 不存在")
                return result
            log.warning("audit chain verified from baseline id=%s "
                        "(records at or before it are NOT verified)", base)
            result["baseline_id"] = base
            ok, bad = await verify_chain(session, after_id=base,
                                         expected_prev=row.this_hash)

    if not ok:
        result.update(ok=False, reason="chain_broken",
                      detail=f"雜湊鏈在 audit id={bad} 中斷")
        return result

    if latest is not None:
        rec = {
            "at": datetime.now(UTC).isoformat(),
            "audit_id": latest.id,
            "this_hash": latest.this_hash.hex(),
            "count": total,
        }
        if result.get("baseline_id"):
            rec["baseline_id"] = result["baseline_id"]
        append_anchor(rec, path)
        result["anchored_to"] = latest.id
    return result
