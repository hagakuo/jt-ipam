"""防火牆給的逐來源觀測時間（`ip_addresses.arp_seen`）。

## 為什麼有這個檔案

在這之前，OPNsense／pfSense／FortiGate／Palo Alto 同步回來的 ARP 表、DHCP 租約與
VPN 連線，**全部**都寫進 `ip_addresses.last_seen_scanner`。結果有兩個：

1. 畫面上出現「上線 (scanner)」，但那台站台根本沒有裝掃描代理 —— 來源是騙人的。
2. 管理員沒辦法只採信其中一部分。三種證據的可信度差很多（ARP 表按逾時淘汰、
   VPN 連線是此刻連著、DHCP 租約可能是三天前拿的），混在同一個欄位就分不開。

所以改成逐來源記時間，鍵是證據契約裡登記的名字（`arp:opnsense`、`vpn:pfsense`、
`lease:fortigate`…），能不能拿來宣稱上線由 `services/evidence.py` 決定。

## 兩個實作上的坑

- **JSONB 就地改不會被存下來**：SQLAlchemy 預設不追蹤 dict 內容變動，
  `ipa.arp_seen["x"] = ...` 會安靜地不寫回資料庫。這裡一律建新 dict 再指派。
- **靜態／永久 ARP 項目不會淘汰**：那種項目留在表裡跟機器活不活著無關，
  拿它宣稱上線就是重演「關機數週卻全綠」那個事故。所以 `permanent=True` 直接不記。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.services.evidence import is_aging


def seen_from_remaining(
    remaining: object, max_age: float, *, now: datetime | None = None,
) -> datetime | None:
    """由「剩餘秒數」推回**實際被更新的時間**。

    這是「防火牆的 ARP 表可不可以當上線證據」的關鍵：條目還在表裡，不代表剛剛才看到 ——
    OPNsense 的 `expires` 從 1200 秒（FreeBSD 的 max_age，實機驗證過）往下數，一筆
    `expires=343` 的條目其實是 **14 分鐘前**更新的。一律蓋上同步當下的時間，等於把
    「快過期了」講成「剛剛才看到」，那正是我們批評 LibreNMS ARP 的那個毛病。

    回 None＝這筆給不出時間（不合理的數值），由呼叫端決定要不要退回同步當下時間。
    """
    try:
        rem = float(remaining)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if rem < 0 or max_age <= 0 or rem > max_age:
        return None
    now = now or datetime.now(UTC)
    return now - timedelta(seconds=max_age - rem)


def seen_from_age(age: object, *, now: datetime | None = None) -> datetime | None:
    """由「已經過幾秒」推回實際被更新的時間（FortiOS 的 ARP 給的是這種）。"""
    try:
        secs = float(age)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if secs < 0 or secs > 86400:      # 超過一天的「年齡」不合理，寧可不用
        return None
    return (now or datetime.now(UTC)) - timedelta(seconds=secs)


def stamp(
    ipa: Any, source: str, when: datetime | None = None, *, permanent: bool = False,
) -> None:
    """把 `source` 的觀測時間記到這筆 IP 上。

    `source` 用完整的契約名稱（如 `arp:opnsense`）。`permanent=True`（靜態 ARP 項目）
    一律略過 —— 那種項目不會因為機器關機而消失。
    """
    if permanent or not source:
        return
    now = datetime.now(UTC)
    # 不接受未來的時間：下面取較新的，上游時鐘跑快的值會永遠贏
    ts = min((when or now).astimezone(UTC), now)
    current = dict(getattr(ipa, "arp_seen", None) or {})
    # 取較新的：同廠牌的多台實例共用同一個鍵，同一台也可能有好幾筆項目。以前後寫的蓋掉先寫的，
    # 剩餘時間較短（推回較舊）的那台會把剛看到的時間往回改（2026-09-26 稽核）
    prev = _parse(current.get(source))
    if prev is not None and prev >= ts:
        return
    current[source] = ts.isoformat()
    ipa.arp_seen = current      # 指派而非就地改：JSONB 才會被寫回


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def newest(
    ipa: Any, sources: set[str] | frozenset[str] | None = None,
) -> tuple[datetime | None, str | None]:
    """在被採信的來源之中，最近一次觀測的時間與來源名稱。

    `sources=None`＝不過濾（用於「這筆 IP 有哪些證據」的顯示）。
    """
    best_ts: datetime | None = None
    best_src: str | None = None
    for key, raw in (getattr(ipa, "arp_seen", None) or {}).items():
        if sources is not None and key not in sources:
            continue
        ts = _parse(raw)
        if ts is None:
            continue
        if best_ts is None or ts > best_ts:
            best_ts, best_src = ts, key
    return best_ts, best_src


def newest_aging(
    ipa: Any, sources: set[str] | frozenset[str],
) -> tuple[datetime | None, str | None]:
    """同上，但只看**會過期**的來源 —— 只有那些能宣稱「現在上線」。"""
    return newest(ipa, {s for s in sources if is_aging(s)})
