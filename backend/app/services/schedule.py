"""排程時刻判斷：「哪幾天」×「幾點」。

這一段原本長在 `ai_audit.py` 裡，只有巡檢在用。異常偵測也要排程之後就搬到這裡 ——
同一段邏輯留兩份實作的下場，是之後只有一份會被修到（月底夾邊界這種細節尤其危險：
兩邊行為不一致時，畫面上看不出任何差別）。

用「幾點幾分」而不是「每 N 小時」：間隔式排程會跟著每次的執行時間往後漂，
跑幾天之後就沒人說得準它半夜還是上班時間在動。
"""
from __future__ import annotations

import calendar
from datetime import datetime, timedelta


def _local_now() -> datetime:
    """伺服器本地時間。排程時刻是使用者用牆上時鐘設的，不是 UTC。"""
    return datetime.now().astimezone()


# 間隔模式的下限：排程是由 `jt-ipam-sync.timer`（約 5 分鐘一輪）觸發的，
# 設得比它還密只是讓使用者以為有效。夾到辦得到的下限，不要假裝支援。
MIN_INTERVAL_MINUTES = 5


def due(
    last_run: datetime | None, times: list[str], now: datetime | None = None,
    *, frequency: str = "daily", weekdays: list[int] | None = None,
    month_day: int | None = None, interval_minutes: int | None = None,
) -> bool:
    """排程判斷：自上次執行後，是否已經越過任何一個排定時刻。

    排程拆成兩個維度 ——「**哪幾天**」×「**幾點**」：
    - `frequency="daily"`：每天（既有行為，也是預設，升級不會改變既有安裝的排程）
    - `frequency="weekly"` + `weekdays`：每週的指定幾天（1=週一 … 7=週日，可多選）
    - `frequency="monthly"` + `month_day`：每月的指定某一天（1–31）
    - `frequency="interval"` + `interval_minutes`：每隔 N 分鐘（下限 5 分鐘＝timer 的週期）

    用「幾點幾分」而不是「每 N 小時」：間隔式排程會跟著每次的執行時間往後漂，
    跑了幾天之後就沒人說得準它半夜還是上班時間在打 LLM。

    `last_run` 為 None（剛啟用、還沒跑過）→ 下一輪就跑一次，之後才照時刻走。這是刻意的：
    打開開關卻要等到下個月 1 號才有任何動靜，看起來就像功能壞了。
    """
    if frequency == "interval":
        # 「每隔 N 分鐘」：給營運監控用（IP 衝突、非法 DHCP 這類事情等不到隔天）。
        # 這個模式**不看時刻清單** —— 兩種語意混在一起判斷，沒有人講得清楚它何時會跑。
        # 間隔式排程會跟著執行時間往後漂，對固定時刻的工作是缺點；對「每隔一段時間
        # 檢查一次」正好是要的行為。
        gap = max(int(interval_minutes or MIN_INTERVAL_MINUTES), MIN_INTERVAL_MINUTES)
        if last_run is None:
            return True
        now = now or _local_now()
        return last_run.astimezone(now.tzinfo) <= now - timedelta(minutes=gap)

    times = [t for t in times if _parse_hhmm(t) is not None]
    if not times:
        return False
    if frequency == "weekly" and not weekdays:
        return False          # 一天都沒選＝沒有排程，不能退化成每天都跑
    if last_run is None:
        return True
    now = now or _local_now()
    prev = _previous_occurrence(times, now, frequency=frequency,
                                weekdays=weekdays, month_day=month_day)
    if prev is None:
        return False
    return last_run.astimezone(now.tzinfo) < prev


def _parse_hhmm(text: str) -> tuple[int, int] | None:
    hh, _, mm = str(text).partition(":")
    try:
        h, m = int(hh), int(mm)
    except ValueError:
        return None
    return (h, m) if 0 <= h <= 23 and 0 <= m <= 59 else None


def _runs_on(day: datetime, frequency: str, weekdays: list[int] | None,
             month_day: int | None) -> bool:
    """這一天是不是排程日。"""
    if frequency == "weekly":
        return day.isoweekday() in set(weekdays or ())
    if frequency == "monthly":
        return day.day == _month_day_for(day, month_day)
    return True


def _month_day_for(day: datetime, month_day: int | None) -> int:
    """把「每月第幾天」夾到該月實際存在的日子。

    設 31 號卻遇到只有 30 天的月份時，落在該月最後一天，而不是整個月都不跑 ——
    後者是這類排程最典型的壞法：條件永遠不成立，沒有錯誤也沒有紀錄，
    看起來就只是「功能沒在動」。2 月同理。
    """
    d = int(month_day or 1)
    last = calendar.monthrange(day.year, day.month)[1]
    return max(1, min(d, last))


def _previous_occurrence(
    times: list[str], now: datetime, *, frequency: str = "daily",
    weekdays: list[int] | None = None, month_day: int | None = None,
) -> datetime | None:
    """最近一個「已經過去」的排定時刻；找不到（例如剛設定完）回 None。

    往回走日曆而不是只看昨天：週排程與月排程的上一次可能在好幾天前，
    只退一天會把「服務停了幾天沒跑到」的那一輪漏掉。
    """
    hms = [hm for hm in (_parse_hhmm(t) for t in times) if hm is not None]
    if not hms:
        return None
    # 往回找 400 天足以涵蓋任何月排程（最長間隔約 31 天）
    for back in range(400):
        day = now - timedelta(days=back)
        if not _runs_on(day, frequency, weekdays, month_day):
            continue
        slots = [day.replace(hour=h, minute=m, second=0, microsecond=0) for h, m in hms]
        passed = [t for t in slots if t <= now]
        if passed:
            return max(passed)
    return None
