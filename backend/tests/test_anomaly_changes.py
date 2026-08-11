"""變更行為分析：從稽核記錄找出值得看一眼的操作。

稽核記錄平常沒有人會去翻（線上 90 天有 3,262 筆），但裡面藏著三件事是出了問題才會回頭
找、而那時候已經太晚：

1. **短時間內大量刪除** —— 誤操作或惡意，兩者都要立刻知道
2. **集中的登入失敗** —— 同一個來源反覆嘗試
3. **權限與憑證的變更** —— 授權、建帳號、發 API token，這幾件事一旦發生就該被看見

刻意**不做**「非上班時段的變更」：那需要一個可靠的時區與工時設定，猜錯就會把正常的白天
工作標成可疑 —— 一條會誤報的規則比沒有規則更糟，因為它會訓練人忽略整個清單。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.audit import AuditLog
from app.services.anomaly import detect_suspicious_changes

NOW = datetime.now(UTC)


async def _log(db_session, *, action, object_type="ip_address", actor=None,
               ip="203.0.113.5", when=None, n=1):
    for i in range(n):
        db_session.add(AuditLog(
            ts=(when or NOW) - timedelta(seconds=i),
            actor_user_id=actor, actor_ip=ip, object_type=object_type,
            action=action, object_id=uuid.uuid4(),
            prev_hash=b"\x00" * 32, this_hash=uuid.uuid4().bytes * 2,
        ))
    await db_session.flush()


@pytest.mark.anyio
async def test_bulk_delete_is_reported(db_session, admin_user):
    await _log(db_session, action="delete", actor=admin_user.id, n=40)
    await db_session.commit()

    out = await detect_suspicious_changes(db_session)
    hits = [x for x in out if x["kind"] == "bulk_delete"]
    assert hits, "短時間內刪掉 40 筆要報"
    assert hits[0]["count"] >= 40


@pytest.mark.anyio
async def test_a_few_deletes_are_normal(db_session, admin_user):
    """日常清理不該被標成可疑 —— 會誤報的規則會讓人忽略整個清單。"""
    await _log(db_session, action="delete", actor=admin_user.id, n=3)
    await db_session.commit()

    out = await detect_suspicious_changes(db_session)
    assert not [x for x in out if x["kind"] == "bulk_delete"]


@pytest.mark.anyio
async def test_repeated_login_failures_from_one_source(db_session):
    await _log(db_session, action="login_failed", object_type="user",
               ip="203.0.113.66", n=12)
    await db_session.commit()

    out = await detect_suspicious_changes(db_session)
    hits = [x for x in out if x["kind"] == "login_failures"]
    assert hits
    assert hits[0]["actor_ip"] == "203.0.113.66"


@pytest.mark.anyio
async def test_permission_grant_is_always_surfaced(db_session, admin_user):
    """授權只要發生就該被看見 —— 這種事不需要「量大」才值得注意。"""
    await _log(db_session, action="create", object_type="permission",
               actor=admin_user.id, n=1)
    await db_session.commit()

    out = await detect_suspicious_changes(db_session)
    hits = [x for x in out if x["kind"] == "privilege_change"]
    assert hits and hits[0]["object_type"] == "permission"


@pytest.mark.anyio
async def test_old_events_are_ignored(db_session, admin_user):
    """只看最近的變更 —— 否則清單會永遠掛著半年前處理完的事。"""
    await _log(db_session, action="delete", actor=admin_user.id,
               when=NOW - timedelta(days=40), n=50)
    await db_session.commit()

    out = await detect_suspicious_changes(db_session)
    assert not [x for x in out if x["kind"] == "bulk_delete"]


@pytest.mark.anyio
async def test_system_deletes_are_not_flagged(db_session):
    """沒有操作者的刪除是系統同步做的（整合刪掉重建），不是可疑行為。

    實機資料才看得出來：某次同步在 19 分鐘內刪了 967 筆，全部沒有 actor。
    把這種也報出來，清單第一名永遠是例行作業，真正的人為誤刪反而被埋掉。
    """
    await _log(db_session, action="delete", actor=None, n=60)
    await db_session.commit()

    out = await detect_suspicious_changes(db_session)
    assert not [x for x in out if x["kind"] == "bulk_delete"]
