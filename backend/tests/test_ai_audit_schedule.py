"""巡檢排程：每天／每週某幾天／每月某一天。

原本只有「每天的哪幾個時刻」。這裡把排程拆成兩個維度 ——「**哪幾天**」×「**幾點**」，
時刻沿用既有的 ai_audit_times，日期由 frequency 決定。

守的重點是**不會安靜地不跑**。這類排程最典型的壞法不是報錯，而是條件永遠不成立：
設每月 31 號，遇到只有 30 天的月份就整月沒動靜，而畫面上一切正常。
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.services import ai_audit as aa

TPE = timezone(timedelta(hours=8))


def _at(month: int, day: int, hh: int, mm: int = 0) -> datetime:
    return datetime(2026, month, day, hh, mm, tzinfo=TPE)


# 2026-08-03 是星期一 → 8/3 Mon, 8/4 Tue, 8/8 Sat, 8/9 Sun
MON, TUE, SAT, SUN = 3, 4, 8, 9


@pytest.mark.parametrize(("last", "now", "weekdays", "expected"), [
    # 週一排程，今天就是週一而且 03:30 已過 → 該跑
    (_at(8, 1, 3, 30), _at(8, MON, 14, 0), [1], True),
    # 同一個週一已經跑過 → 不再跑
    (_at(8, MON, 3, 31), _at(8, MON, 14, 0), [1], False),
    # 今天是週二、排程只設週一 → 不跑（但上週一那次已經跑過了）
    (_at(8, MON, 3, 31), _at(8, TUE, 14, 0), [1], False),
    # 今天是週二、排程只設週一，而上次是更早以前 → 要補跑昨天那一次
    (_at(7, 28, 3, 31), _at(8, TUE, 14, 0), [1], True),
    # 多選：週六與週日
    (_at(8, MON, 3, 31), _at(8, SAT, 4, 0), [6, 7], True),
    (_at(8, SAT, 4, 0), _at(8, SUN, 2, 0), [6, 7], False),   # 週日 03:30 還沒到
    (_at(8, SAT, 4, 0), _at(8, SUN, 4, 0), [6, 7], True),
])
def test_weekly(last, now, weekdays, expected) -> None:
    assert aa.due(last, ["03:30"], now,
                  frequency="weekly", weekdays=weekdays) is expected


@pytest.mark.parametrize(("last", "now", "day", "expected"), [
    # 每月 15 號，今天 15 號且時刻已過 → 該跑
    (_at(7, 15, 3, 31), _at(8, 15, 9, 0), 15, True),
    (_at(8, 15, 3, 31), _at(8, 15, 9, 0), 15, False),
    # 今天 16 號、這個月 15 號那次已經跑過 → 不跑
    (_at(8, 15, 3, 31), _at(8, 16, 9, 0), 15, False),
    # 今天 16 號但這個月 15 號沒跑到（服務停機）→ 補跑
    (_at(7, 15, 3, 31), _at(8, 16, 9, 0), 15, True),
    # 今天 14 號 → 這個月還沒到，上個月那次已跑過 → 不跑
    (_at(7, 15, 3, 31), _at(8, 14, 9, 0), 15, False),
])
def test_monthly(last, now, day, expected) -> None:
    assert aa.due(last, ["03:30"], now,
                  frequency="monthly", month_day=day) is expected


def test_monthly_31_still_runs_in_a_short_month() -> None:
    """設每月 31 號，遇到 30 天的月份要落在該月最後一天 —— 不能整月安靜地不跑。

    這是這類排程最常見的壞法：條件永遠不成立，沒有錯誤、沒有紀錄，看起來就像功能沒開。
    """
    # 2026-06 只有 30 天；6/30 03:30 已過，上次是 5 月那輪
    assert aa.due(_at(5, 31, 3, 31), ["03:30"], _at(6, 30, 9, 0),
                  frequency="monthly", month_day=31) is True


def test_monthly_31_in_february() -> None:
    """2 月只有 28 天（2026 非閏年）→ 2/28 就是那一輪。"""
    assert aa.due(_at(1, 31, 3, 31), ["03:30"], _at(2, 28, 9, 0),
                  frequency="monthly", month_day=31) is True


def test_weekly_with_no_weekday_selected_never_runs() -> None:
    """一天都沒選＝沒有排程，不能退化成「每天都跑」。"""
    assert aa.due(_at(8, 1, 3, 30), ["03:30"], _at(8, MON, 14, 0),
                  frequency="weekly", weekdays=[]) is False


def test_daily_is_unchanged_and_is_the_default() -> None:
    """既有安裝沒有 frequency 設定 → 必須維持原本的每天行為（升級不改變既有排程）。"""
    assert aa.due(_at(8, 1, 3, 30), ["03:30"], _at(8, 2, 14, 0)) is True
    assert aa.due(_at(8, 1, 3, 30), ["03:30"], _at(8, 2, 14, 0),
                  frequency="daily") is True


def test_never_run_before_still_runs_once_whatever_the_frequency() -> None:
    """剛打開開關就要跑一次 —— 否則設每月 1 號的人會以為功能壞了。"""
    for freq, kw in (("daily", {}), ("weekly", {"weekdays": [1]}),
                     ("monthly", {"month_day": 15})):
        assert aa.due(None, ["03:30"], _at(8, TUE, 14, 0),
                      frequency=freq, **kw) is True


def test_last_run_in_utc_is_converted_for_weekly_too() -> None:
    """last_run 由 DB 讀出是 UTC；跨時區比較會差 8 小時，週排程一樣要換算。"""
    # 台北 8/3(一) 04:00 跑過 ＝ UTC 8/2 20:00
    last_utc = datetime(2026, 8, 2, 20, 0, tzinfo=UTC)
    assert aa.due(last_utc, ["03:30"], _at(8, MON, 14, 0),
                  frequency="weekly", weekdays=[1]) is False
