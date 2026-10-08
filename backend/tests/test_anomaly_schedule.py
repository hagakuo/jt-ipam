"""異常偵測的排程執行。

為什麼要有：偵測邏輯早就寫好了（`run_detection`），但只能靠人按「執行掃描」。
IP 衝突、非法 DHCP、對外曝險這些事情不會挑上班時間發生，沒有排程就等於
「有人記得去按」才會發現。

這裡守三件事：
1. **排程判斷共用同一份實作** —— 巡檢已經有一套（每天／每週某幾天／每月某一天，
   含月底夾邊界）。再寫第二套的話，之後只會有一套被修到。
2. **不會洗版** —— 偵測結果是「目前的狀態」，不是事件流。同一個沒處理的 IP 衝突，
   排程每天跑就會每天通知一次、永遠不停，最後的下場是整類通知被使用者忽略。
   只有「與上次相比是新的」才通知。
3. **開關預設是關的** —— 排程會發通知給所有管理員，升級不該自己開始發信。
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

TPE = timezone(timedelta(hours=8))


def test_schedule_logic_is_shared_with_the_audit_schedule():
    """兩邊必須是同一個函式物件 —— 有兩份實作時，被修到的永遠只有一份。"""
    from app.services.ai_audit import due as audit_due
    from app.services.schedule import due as shared_due

    assert audit_due is shared_due


def test_defaults_are_off():
    """升級不會讓任何站台突然開始每天發通知。"""
    from app.services.system_config import AnomalyConfig

    cfg = AnomalyConfig()
    assert cfg.schedule_enabled is False


async def test_schedule_round_trips(db_session):
    from app.services.system_config import get_anomaly_config, set_anomaly_config

    await set_anomaly_config(db_session, schedule_enabled=True, times=["02:15", "14:00"],
                             frequency="weekly", weekdays=[1, 4])
    await db_session.commit()
    cfg = await get_anomaly_config(db_session)
    assert cfg.schedule_enabled is True
    assert cfg.times == ["02:15", "14:00"]
    assert cfg.frequency == "weekly"
    assert cfg.weekdays == [1, 4]


async def test_last_run_round_trips(db_session):
    from app.services.system_config import get_anomaly_last_run, set_anomaly_last_run

    assert await get_anomaly_last_run(db_session) is None
    at = datetime(2026, 9, 8, 2, 15, tzinfo=UTC)
    await set_anomaly_last_run(db_session, at=at)
    await db_session.commit()
    assert await get_anomaly_last_run(db_session) == at


async def test_only_new_findings_notify(db_session, admin_user):
    """同一批發現跑第二次不再通知；出現新的一筆才會再響。"""
    from app.models.notification import Notification
    from app.services.anomaly import notify_new_findings
    from sqlalchemy import func, select

    async def count() -> int:
        return (await db_session.execute(
            select(func.count()).select_from(Notification))).scalar_one()

    first = {"ip_conflicts": [{"ip": "198.51.100.10", "count": 2}]}
    sent = await notify_new_findings(db_session, first)
    await db_session.commit()
    assert sent == 1, "第一次看到就要通知"
    after_first = await count()
    assert after_first >= 1

    # 完全一樣的狀態：不該再發
    sent = await notify_new_findings(db_session, first)
    await db_session.commit()
    assert sent == 0, "同一件事重複通知＝排程開兩天就沒人看通知了"
    assert await count() == after_first

    # 多了一筆新的 → 要通知
    second = {"ip_conflicts": [{"ip": "198.51.100.10", "count": 2},
                               {"ip": "198.51.100.11", "count": 3}]}
    sent = await notify_new_findings(db_session, second)
    await db_session.commit()
    assert sent == 1, "出現新的異常就必須說"
    assert await count() > after_first


async def test_resolved_findings_do_not_notify(db_session, admin_user):
    """異常消失不是新事件 —— 不該因為「少了一筆」而發通知。"""
    from app.services.anomaly import notify_new_findings

    both = {"ip_conflicts": [{"ip": "198.51.100.10"}, {"ip": "198.51.100.11"}]}
    await notify_new_findings(db_session, both)
    await db_session.commit()
    sent = await notify_new_findings(db_session, {"ip_conflicts": [{"ip": "198.51.100.10"}]})
    await db_session.commit()
    assert sent == 0


@pytest.mark.parametrize(("last", "now", "expected"), [
    # 排 03:30；上次是前一天 03:31，現在是今天 04:00 → 已越過今天的 03:30
    (datetime(2026, 9, 7, 3, 31, tzinfo=TPE), datetime(2026, 9, 8, 4, 0, tzinfo=TPE), True),
    # 同一天 03:31 跑過，現在 04:00 → 還沒到下一個時刻
    (datetime(2026, 9, 8, 3, 31, tzinfo=TPE), datetime(2026, 9, 8, 4, 0, tzinfo=TPE), False),
])
def test_due_uses_wall_clock_times(last, now, expected):
    from app.services.schedule import due

    assert due(last, ["03:30"], now) is expected


# ── 分鐘等級：每隔 N 分鐘 ──────────────────────────────────────────────────
# 「每天幾點」對 IP 衝突、非法 DHCP 這種事情太慢：那是營運監控，不是月報。
# 所以另外給一個間隔模式。刻意與「幾點幾分」並存而不是取代 ——
# 巡檢那種會打 LLM 的工作仍然要固定時刻，否則會跟著執行時間往後漂。

def test_interval_is_due_after_the_gap():
    from app.services.schedule import due

    now = datetime(2026, 9, 8, 10, 30, tzinfo=TPE)
    assert due(now - timedelta(minutes=16), [], now,
               frequency="interval", interval_minutes=15) is True
    assert due(now - timedelta(minutes=14), [], now,
               frequency="interval", interval_minutes=15) is False


def test_interval_ignores_the_time_list():
    """間隔模式不看時刻清單 —— 兩者混在一起判斷會變成沒人講得清楚的行為。"""
    from app.services.schedule import due

    now = datetime(2026, 9, 8, 10, 30, tzinfo=TPE)
    assert due(now - timedelta(hours=3), ["03:30"], now,
               frequency="interval", interval_minutes=60) is True


def test_interval_runs_immediately_when_never_run():
    from app.services.schedule import due

    assert due(None, [], frequency="interval", interval_minutes=60) is True


async def test_interval_config_round_trips(db_session):
    from app.services.system_config import get_anomaly_config, set_anomaly_config

    await set_anomaly_config(db_session, frequency="interval", interval_minutes=15)
    await db_session.commit()
    cfg = await get_anomaly_config(db_session)
    assert cfg.frequency == "interval"
    assert cfg.interval_minutes == 15


async def test_interval_below_the_timer_period_is_clamped(db_session):
    """排程是靠 5 分鐘一輪的 timer 觸發的，設 1 分鐘做不到 ——
    夾到實際辦得到的下限，而不是讓使用者以為設定了卻沒有生效。"""
    from app.services.system_config import get_anomaly_config, set_anomaly_config

    await set_anomaly_config(db_session, frequency="interval", interval_minutes=1)
    await db_session.commit()
    cfg = await get_anomaly_config(db_session)
    assert cfg.interval_minutes == 5


async def test_schedule_endpoint_round_trips(client, db_session, auth_headers):
    """設定頁存得下去、讀得回來 —— 而且非管理員碰不到。"""
    r = await client.get("/api/v1/anomalies/schedule", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["schedule_enabled"] is False        # 預設關閉

    r = await client.put("/api/v1/anomalies/schedule", headers=auth_headers, json={
        "schedule_enabled": True, "frequency": "interval", "interval_minutes": 15,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schedule_enabled"] is True
    assert body["frequency"] == "interval"
    assert body["interval_minutes"] == 15

    again = (await client.get("/api/v1/anomalies/schedule", headers=auth_headers)).json()
    assert again["interval_minutes"] == 15


async def test_schedule_endpoint_requires_admin(client, db_session):
    """排程會發通知給所有管理員，不是一般使用者可以動的東西。"""
    r = await client.get("/api/v1/anomalies/schedule")
    assert r.status_code in (401, 403)
