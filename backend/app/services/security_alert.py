"""資安面的通知：管理員權限變更、疑似暴力破解。

兩者性質完全不同，判準也不同：

- **權限變更**低頻、高影響 —— 每一次都值得說，預設連 Email 都開。多一個管理員是
  整個系統最重要的事實變化之一，事後才從稽核翻出來就太慢了。
- **帳號鎖定**高頻（有人打錯五次密碼就會發生）—— 每次都通知的話第一週就被關掉。
  只有**暴力破解的形狀**才吵人：多個帳號同時被鎖。單一使用者忘記密碼不是資安事件。
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import append_audit
from app.services.health_alert import _notify
from app.services.state_alert import observe

EVENT_PRIVILEGE = "security.privilege_changed"
EVENT_BRUTE = "security.brute_force"


async def notify_privilege_change(
    session: AsyncSession, *, actor: str, target: str, change: str,
) -> None:
    """管理權限被授予或收回。

    這裡不做狀態轉換判斷 —— 權限變更是**事件**不是狀態：每一次都是獨立的一件事，
    而且不會「持續發生」。
    """
    await _notify(
        session, event=EVENT_PRIVILEGE,
        title=f"管理權限變更：{target}",
        body=f"{change}（操作者：{actor}）。若不是預期中的異動，請立刻檢查稽核記錄。",
        link="/users", severity="error")


async def audit_lockout(
    session: AsyncSession, *, user: Any, actor_ip: str | None, until: datetime,
) -> None:
    """帳號被鎖定時留一筆稽核。

    這是原本完全沒有的：`auth.py` 只把 `locked_until` 寫進去就 commit，
    於是「這個帳號什麼時候被鎖過、從哪個位址打的」事後完全查不到。
    """
    await append_audit(
        session,
        actor_user_id=None,          # 鎖定是系統的動作，不是某個登入者做的
        actor_ip=actor_ip, actor_user_agent=None,
        object_type="auth", object_id=str(user.id), action="account_locked",
        diff={"username": user.username,
              "failed_login_count": int(getattr(user, "failed_login_count", 0) or 0),
              "locked_until": until.isoformat()},
        request_id=None,
    )


async def check_lockouts(
    session: AsyncSession, locked_users: list[Any], *,
    now: datetime | None = None, min_accounts: int = 3,
) -> int:
    """目前**仍在鎖定中**的帳號數達到門檻 → 通知一次。

    只看還鎖著的：鎖定期已過的帳號不算，否則昨天的事今天還在報。
    """
    now = now or datetime.now(UTC)
    active = []
    for u in locked_users:
        until = getattr(u, "locked_until", None)
        if until is None:
            continue
        if until.tzinfo is None:
            until = until.replace(tzinfo=UTC)
        if until > now:
            active.append(u)

    change = await observe(session, key="security:brute_force",
                           failing=len(active) >= min_accounts, threshold=1)
    if change != "down":
        return 0
    names = "、".join(sorted(str(u.username) for u in active)[:10])
    await _notify(
        session, event=EVENT_BRUTE,
        title=f"疑似暴力破解：{len(active)} 個帳號同時處於鎖定中",
        body=(f"帳號：{names}。單一使用者忘記密碼不會造成這種形狀 —— "
              f"請檢查登入來源位址與稽核記錄。"),
        link="/audit", severity="error")
    return 1
