"""對外開放服務「新增」併進既有的對外曝險那一類。

為什麼不另開一個事件：異常偵測已經有「對外曝險」，而對外開放服務清單看的是同一件事
的另一面（清單 vs 問題）。兩個都發通知的話，同一個新開的埠會收到兩則 ——
使用者要管兩個開關，而且會開始懷疑哪一個才是真的。

**第一次執行必須是安靜的**：沒有基準時，站上每一個既有的對外服務都會是「新增」，
那會在第一次啟用的當下送出幾十則通知，然後這個功能就被關掉了。
"""
from __future__ import annotations


class _Surface:
    """假的對外開放服務清單。"""

    def __init__(self, items):
        self.items = items

    async def __call__(self, session):
        return self.items


async def test_first_run_records_a_baseline_and_says_nothing(db_session):
    from app.services.anomaly import detect_new_exposure

    items = [{"ip": "198.51.100.7", "port": 443, "proto": "tcp"},
             {"ip": "198.51.100.8", "port": 22, "proto": "tcp"}]
    out = await detect_new_exposure(db_session, surface=_Surface(items))
    assert out == [], "第一次只建立基準，不能把既有的全部報成新增"


async def test_a_newly_opened_service_is_reported(db_session):
    from app.services.anomaly import detect_new_exposure

    base = [{"ip": "198.51.100.7", "port": 443, "proto": "tcp"}]
    await detect_new_exposure(db_session, surface=_Surface(base))

    more = [*base, {"ip": "198.51.100.9", "port": 3389, "proto": "tcp"}]
    out = await detect_new_exposure(db_session, surface=_Surface(more))
    assert len(out) == 1
    assert out[0]["ip"] == "198.51.100.9"
    assert out[0]["kind"] == "exposed_new"
    # 再跑一次就不是新的了
    assert await detect_new_exposure(db_session, surface=_Surface(more)) == []


async def test_a_service_that_closes_is_not_reported(db_session):
    """關掉一個對外服務是好事，不是異常。"""
    from app.services.anomaly import detect_new_exposure

    both = [{"ip": "198.51.100.7", "port": 443, "proto": "tcp"},
            {"ip": "198.51.100.8", "port": 22, "proto": "tcp"}]
    await detect_new_exposure(db_session, surface=_Surface(both))
    out = await detect_new_exposure(db_session, surface=_Surface(both[:1]))
    assert out == []


async def test_it_reappears_as_new_after_being_closed(db_session):
    """關掉之後又被打開，那是新的一次曝險，要再報一次。"""
    from app.services.anomaly import detect_new_exposure

    both = [{"ip": "198.51.100.7", "port": 443, "proto": "tcp"},
            {"ip": "198.51.100.8", "port": 22, "proto": "tcp"}]
    await detect_new_exposure(db_session, surface=_Surface(both))
    await detect_new_exposure(db_session, surface=_Surface(both[:1]))
    out = await detect_new_exposure(db_session, surface=_Surface(both))
    assert len(out) == 1 and out[0]["ip"] == "198.51.100.8"
