"""系統自我診斷（2026-09-05 客戶回報後新增）。

客戶的症狀是：儀表板顯示 55 台裝置，點進裝置清單卻是 Internal Server Error 加空白。
成因是資料庫結構落後於程式 —— 而這件事**系統啟動時就查得出來**，卻沒有任何地方講。

這一組測試守的是「查得出來就要講出來」，以及診斷本身不可以把服務弄掛。
"""

from __future__ import annotations

from typing import Any

import pytest
from app.services import self_check


@pytest.mark.anyio
async def test_schema_state_reports_head_and_current(db_session: Any) -> None:
    state = await self_check.schema_state(db_session)
    assert state["error"] is None, state["error"]
    assert state["head"], "讀不到程式端的 migration head"
    assert state["behind"] is False, f"測試庫落後：{state}"


@pytest.mark.anyio
async def test_schema_state_detects_drift(db_session: Any, monkeypatch: Any) -> None:
    """資料庫停在舊版時要判定為落後 —— 這正是客戶那台的狀況。"""
    monkeypatch.setattr(self_check, "_alembic_heads", lambda: {"9999_not_applied"})
    state = await self_check.schema_state(db_session)
    assert state["behind"] is True
    assert state["head"] == "9999_not_applied"


@pytest.mark.anyio
async def test_unreadable_schema_is_not_reported_as_behind(
    db_session: Any, monkeypatch: Any,
) -> None:
    """讀不出來 ≠ 落後。不確定就不要嚇人，但要把原因帶出來。"""
    def boom() -> set[str]:
        raise RuntimeError("no scripts here")

    monkeypatch.setattr(self_check, "_alembic_heads", boom)
    state = await self_check.schema_state(db_session)
    assert state["behind"] is False
    assert "no scripts here" in (state["error"] or "")


@pytest.mark.anyio
async def test_every_failing_check_says_how_to_fix_it(db_session: Any) -> None:
    """只說「壞了」等於沒說 —— 非 ok 的項目一定要附可執行的下一步。"""
    rep = await self_check.run_checks(db_session)
    assert rep.checks, "一項檢查都沒有"
    for c in rep.checks:
        if c.status != "ok":
            assert c.fix or c.detail, f"{c.key} 沒說要怎麼處理"


@pytest.mark.anyio
async def test_a_broken_check_does_not_break_the_report(
    db_session: Any, monkeypatch: Any,
) -> None:
    """診斷本身出錯時，其他項目仍要跑完 —— 一份報告不該因為一項壞掉就整份消失。"""
    def boom(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("disk check exploded")

    monkeypatch.setattr(self_check.shutil, "disk_usage", boom)
    rep = await self_check.run_checks(db_session)
    keys = {c.key for c in rep.checks}
    assert "schema" in keys
    assert "disk" in keys
    disk = next(c for c in rep.checks if c.key == "disk")
    assert disk.status == "warn"
    assert "disk check exploded" in disk.detail


@pytest.mark.anyio
async def test_text_report_is_pasteable_and_names_the_cli(db_session: Any) -> None:
    """下載的記錄檔要能直接貼進工單，並講明哪些檢查後端看不到。"""
    text = (await self_check.run_checks(db_session)).as_text()
    assert "jt-ipam self-check" in text
    assert "jt-ipam.sh doctor" in text, "沒有指出系統層檢查要用 CLI"
    assert any(mark in text for mark in ("[ OK ]", "[WARN]", "[FAIL]"))


@pytest.mark.anyio
async def test_data_health_names_the_row_and_the_reason(db_session: Any) -> None:
    """客戶那一類故障：一列資料讓整個清單頁 500，而畫面上看不出是哪一筆。

    健檢要直接講出「哪一張表、哪一筆、哪個欄位、實際值是什麼」——
    只說「有資料有問題」的話，還是得有人去翻資料庫，那就等於沒把診斷做完。
    """
    from sqlalchemy import text as sa_text

    await db_session.execute(sa_text(
        "INSERT INTO devices (id, name, type, u_position)"
        " VALUES (gen_random_uuid(), 'rack-sync-device', 'server', 250)"))
    await db_session.flush()

    # 讀取用 schema 已放寬長度，但 u_position 的範圍仍會擋（資料庫沒有這個約束）
    from app.schemas.device import DeviceRead
    if "u_position" in DeviceRead.model_fields and \
            DeviceRead.model_fields["u_position"].metadata:
        rows = await self_check.data_health(db_session)
        devices = [r for r in rows if r["table"] == "裝置"]
        assert devices
        assert devices[0]["bad_count"] >= 1
        assert "u_position" in devices[0]["bad"][0]["why"]
        assert "250" in devices[0]["bad"][0]["why"], "沒有帶出實際值"


@pytest.mark.anyio
async def test_long_integration_values_no_longer_break_the_device_list(
    db_session: Any,
) -> None:
    """整合寫進來的長字串（資料庫是 text）不可以讓清單讀不出來。

    這正是客戶踩到的：LibreNMS／Proxmox 給的 vendor／model 可以超過表單的 64 字上限，
    而讀取用的 schema 以前照樣拿寫入限制去驗 —— 一列不合規就整頁 500。
    """
    from app.models.device import Device
    from app.schemas.device import DeviceRead
    from sqlalchemy import select

    dev = Device(name="sw-from-librenms", type="switch", vendor="X" * 200, model="Y" * 200)
    db_session.add(dev)
    await db_session.flush()
    row = (await db_session.execute(
        select(Device).where(Device.id == dev.id))).scalars().one()
    out = DeviceRead.model_validate(row)          # 不可以丟例外
    assert out.vendor is not None
    assert len(out.vendor) == 200
