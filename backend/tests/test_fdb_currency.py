"""FDB：分清楚「目前有效」與「歷史紀錄」。

外部 review 指出、實際查證屬實的三件事：

1. `derive_switch_ports` 讀**全部**歷史 FDB，只過濾 `port_name IS NOT NULL` ——
   半年前只出現過一次的埠，和今天的埠有同等發言權。於是 IP 的「交換器位置」
   可能指向一個早就搬走的舊埠，而畫面上看起來完全正常。
2. 同步把 `first_seen_at` / `last_seen_at` 都蓋成 jt-ipam 的同步時間，
   **丟掉 LibreNMS 自己的 `created_at` / `updated_at`**。實機上那兩個欄位是有值的
   （實測某筆 created 2021-11-18、updated 今天），丟掉等於把「這個 MAC 在這個埠
   已經待了幾年」這個資訊變成「今天才第一次看到」。
3. 沒有 `prune_stale_fdb()`：ARP 有回收、FDB 沒有，只會無限累積。

歷史要留（那正是這張表的價值），但**推導目前位置時只能採用近期仍在的條目**。
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models.librenms import FDBEntry


def test_sync_prefers_the_upstream_timestamps():
    """LibreNMS 給了 created_at / updated_at 就要用它的，不要蓋成同步當下時間。"""
    from app.services.librenms import _fdb_times

    row = {"created_at": "2021-11-18T00:00:40.000000Z",
           "updated_at": "2026-09-08T00:02:50.000000Z"}
    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    first, last = _fdb_times(row, now)
    assert first.year == 2021, "首見時間應沿用上游，否則多年前的條目會顯示成今天才出現"
    assert last.day == 8 and last.month == 9


def test_sync_falls_back_to_now_when_upstream_has_no_times():
    from app.services.librenms import _fdb_times

    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    first, last = _fdb_times({}, now)
    assert first == now and last == now


def test_sync_ignores_unparsable_timestamps():
    """上游給的東西不能直接信 —— 壞掉的字串不該讓整批同步爆掉。"""
    from app.services.librenms import _fdb_times

    now = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
    first, last = _fdb_times({"created_at": "not-a-date", "updated_at": None}, now)
    assert first == now and last == now


async def test_stale_entries_do_not_decide_the_current_port(db_session):
    """舊埠留在歷史裡，但不參與「目前位置」的判斷。"""
    from app.services.librenms import current_fdb_cutoff, is_current

    now = datetime.now(UTC)
    fresh = FDBEntry(mac="00005e005301", port_name="Gi1/0/1",
                     first_seen_at=now - timedelta(days=400), last_seen_at=now)
    stale = FDBEntry(mac="00005e005301", port_name="Gi1/0/9",
                     first_seen_at=now - timedelta(days=400),
                     last_seen_at=now - timedelta(days=30))
    cutoff = current_fdb_cutoff(now=now, max_age_hours=24)
    assert is_current(fresh, cutoff) is True
    assert is_current(stale, cutoff) is False


async def test_prune_removes_only_what_is_past_retention(db_session):
    from app.services.librenms import prune_stale_fdb

    now = datetime.now(UTC)
    keep = FDBEntry(mac="00005e005302", port_name="Gi1/0/2",
                    first_seen_at=now, last_seen_at=now - timedelta(days=100))
    drop = FDBEntry(mac="00005e005303", port_name="Gi1/0/3",
                    first_seen_at=now, last_seen_at=now - timedelta(days=400))
    db_session.add_all([keep, drop])
    await db_session.flush()

    removed = await prune_stale_fdb(db_session, max_age_days=365)
    assert removed == 1, "只該刪掉超過保留期限的那一筆"
    left = await db_session.get(FDBEntry, keep.id)
    assert left is not None
    assert await db_session.get(FDBEntry, drop.id) is None


async def test_prune_can_be_switched_off(db_session):
    """0 = 永久保留。FDB 是查案用的歷史，不該逼人一定要刪。"""
    from app.services.librenms import prune_stale_fdb

    now = datetime.now(UTC)
    db_session.add(FDBEntry(mac="00005e005304", port_name="Gi1/0/4",
                            first_seen_at=now, last_seen_at=now - timedelta(days=999)))
    await db_session.flush()
    assert await prune_stale_fdb(db_session, max_age_days=0) == 0
