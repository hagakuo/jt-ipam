"""資安面的兩類通知：管理員權限變更、帳號鎖定。

兩者的性質完全不同，所以判準也不同：

- **權限變更**是低頻、高影響 —— 每一次都值得說，而且預設連 Email 都開。
  多一個管理員是整個系統最重要的事實變化之一，事後才從稽核記錄翻出來就太慢了。
- **帳號鎖定**是高頻事件（有人打錯五次密碼就會發生）—— 每次都通知的話，
  第一週就會被關掉。只有「**暴力破解的形狀**」才值得吵人：同一帳號短時間內
  反覆被鎖，或多個帳號同時被鎖。單一使用者忘記密碼不是。

另外補一個原本就缺的洞：**帳號被鎖定的當下連稽核記錄都沒有** ——
「這個帳號什麼時候被鎖過」現在完全查不到。不管要不要通知，那件事本身就該補。
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta


def test_the_events_are_in_the_matrix():
    from app.services.system_config import NOTIFY_EVENTS

    keys = {k: (ia, em) for k, ia, em in NOTIFY_EVENTS}
    assert "security.privilege_changed" in keys
    assert keys["security.privilege_changed"][1] is True, "權限變更預設要連 Email 都開"
    assert "security.brute_force" in keys


async def test_privilege_change_notifies(db_session, admin_user):
    from app.models.notification import Notification
    from app.services.security_alert import notify_privilege_change
    from sqlalchemy import func, select

    n0 = (await db_session.execute(
        select(func.count()).select_from(Notification))).scalar_one()
    await notify_privilege_change(
        db_session, actor="alice", target="bob", change="granted admin")
    assert (await db_session.execute(
        select(func.count()).select_from(Notification))).scalar_one() > n0


async def test_single_lockout_is_not_an_alert(db_session, admin_user):
    """一個人忘記密碼被鎖 —— 不是資安事件，不要吵人。"""
    from app.services.security_alert import check_lockouts

    class _U:
        def __init__(self, name, until, fails=5):
            self.id = f"1111{name}"
            self.username = name
            self.locked_until = until
            self.failed_login_count = fails

    now = datetime.now(UTC)
    locked = [_U("alice", now + timedelta(minutes=10))]
    assert await check_lockouts(db_session, locked, now=now) == 0


async def test_several_accounts_locked_at_once_is_an_alert(db_session, admin_user):
    """多個帳號同時被鎖＝有人在掃 —— 那是暴力破解的形狀。"""
    from app.services.security_alert import check_lockouts

    class _U:
        def __init__(self, name):
            self.id = f"2222{name}"
            self.username = name
            self.locked_until = datetime.now(UTC) + timedelta(minutes=10)
            self.failed_login_count = 5

    now = datetime.now(UTC)
    many = [_U("a"), _U("b"), _U("c")]
    assert await check_lockouts(db_session, many, now=now, min_accounts=3) == 1
    # 同一批還鎖著時不要每輪再講一次
    assert await check_lockouts(db_session, many, now=now, min_accounts=3) == 0


async def test_expired_locks_do_not_count(db_session, admin_user):
    """鎖定期已過的帳號不算 —— 否則昨天的事今天還在報。"""
    from app.services.security_alert import check_lockouts

    class _U:
        def __init__(self, name):
            self.id = f"3333{name}"
            self.username = name
            self.locked_until = datetime.now(UTC) - timedelta(hours=2)
            self.failed_login_count = 5

    now = datetime.now(UTC)
    assert await check_lockouts(db_session, [_U("a"), _U("b"), _U("c")],
                                now=now, min_accounts=3) == 0


async def test_lockout_is_audited(db_session):
    """帳號被鎖要留稽核 —— 這是原本完全沒有的。"""
    from app.models.audit import AuditLog
    from app.services.security_alert import audit_lockout
    from sqlalchemy import select

    class _U:
        id = "44444444-4444-4444-4444-444444444444"
        username = "carol"
        failed_login_count = 5

    await audit_lockout(db_session, user=_U(), actor_ip="198.51.100.7",
                        until=datetime.now(UTC) + timedelta(minutes=15))
    await db_session.flush()
    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "account_locked"))).scalars().all()
    assert len(rows) == 1
    assert "carol" in str(rows[0].diff)
