"""LibreNMS LLDP / CDP 鄰居同步（`links`）。

⚠️ 開發時**沒有實機資料可驗**：prod 的 LibreNMS（mon5，82 台裝置）links 表是空的
——`/api/v0/resources/links` 回 404 `{"message":"Links do not exist"}`。端點路徑本身
已對實機確認正確（LibreNMS 認得該路由、回的是語意錯誤而非路由 404）。
所以測試重點放在：**容錯解析**、**空來源不能當成失敗**、以及鏡像/清除語意。
"""

from __future__ import annotations

import uuid

import pytest
from app.models.librenms import LibreNMSInstance, LibreNMSLink
from app.services import librenms as lnms
from sqlalchemy import func, select


async def _mk_instance(session, name="lnms-links") -> LibreNMSInstance:
    inst = LibreNMSInstance(
        name=f"{name}-{uuid.uuid4().hex[:6]}",
        api_url="http://192.0.2.60",
        api_token_enc=b"x", api_token_nonce=b"x",
        enabled=True, sync_links=True,
    )
    session.add(inst)
    await session.flush()
    return inst


def _patch(monkeypatch, payload, *, raise_exc: Exception | None = None):
    async def fake(_inst, path, *, timeout=30.0):
        if raise_exc is not None:
            raise raise_exc
        return payload
    monkeypatch.setattr(lnms, "_api_get", fake)


@pytest.mark.anyio
async def test_empty_source_is_not_an_error(db_session, monkeypatch) -> None:
    """LibreNMS 沒有任何鄰居時回 404 "Links do not exist" —— 那是正常狀態，不是錯誤。

    這是實機實際觀察到的行為。若當成錯誤往上拋，整輪 LibreNMS sync 會被一個
    「本來就沒開 LLDP」的環境弄掛。
    """
    inst = await _mk_instance(db_session)
    _patch(monkeypatch, None, raise_exc=lnms.LibreNMSError(
        'LibreNMS /api/v0/resources/links: 404 {"status":"error","message":"Links do not exist"}'
    ))
    seen, upserted, pruned = await lnms.sync_links(db_session, inst)
    assert (seen, upserted, pruned) == (0, 0, 0)


@pytest.mark.anyio
async def test_other_errors_still_propagate(db_session, monkeypatch) -> None:
    """只有「沒資料」才吞掉；認證失敗之類仍要冒出來，否則問題會被藏住。"""
    inst = await _mk_instance(db_session)
    _patch(monkeypatch, None, raise_exc=lnms.LibreNMSError("LibreNMS /api/v0/resources/links: 401 unauthorized"))
    with pytest.raises(lnms.LibreNMSError):
        await lnms.sync_links(db_session, inst)


@pytest.mark.anyio
async def test_mirrors_links_and_tolerates_missing_fields(db_session, monkeypatch) -> None:
    inst = await _mk_instance(db_session)
    _patch(monkeypatch, {"links": [
        {   # 兩端都被監控的完整鄰居
            "id": 11, "protocol": "lldp", "active": 1,
            "local_device_id": 5, "local_port_id": 501, "local_port": "Gi1/0/1",
            "remote_device_id": 7, "remote_port_id": 702,
            "remote_hostname": "core-sw-01", "remote_port": "Gi1/0/24",
            "remote_platform": "Cisco C9300", "remote_version": "17.3",
        },
        {   # 對端未納管：只有 LLDP 通報字串，remote_device_id=0
            "id": 12, "protocol": "cdp",
            "local_device_id": 5, "local_port": "Gi1/0/2",
            "remote_device_id": 0, "remote_hostname": "unmanaged-ap",
        },
        {"protocol": "lldp"},          # 沒有 id → 略過，不能炸
        "not-a-dict",                  # 型別不對 → 略過
    ]})
    seen, upserted, _pruned = await lnms.sync_links(db_session, inst)
    assert (seen, upserted) == (2, 2)

    rows = {r.legacy_link_id: r for r in (await db_session.execute(
        select(LibreNMSLink).where(LibreNMSLink.instance_id == inst.id)
    )).scalars().all()}
    assert set(rows) == {11, 12}
    assert rows[11].remote_hostname == "core-sw-01"
    assert rows[11].local_port_name == "Gi1/0/1"
    assert rows[11].remote_device_id == 7
    # LibreNMS 用 0 表示「沒有對應的裝置」→ 要存成 None，不是 0
    assert rows[12].remote_device_id is None
    assert rows[12].remote_hostname == "unmanaged-ap"
    assert rows[12].remote_port is None


@pytest.mark.anyio
async def test_stale_links_are_pruned(db_session, monkeypatch) -> None:
    """拔線／對端下線後該關係就不該留著（避免拓樸畫出已不存在的連線）。"""
    inst = await _mk_instance(db_session)
    _patch(monkeypatch, {"links": [
        {"id": 21, "local_device_id": 1, "remote_hostname": "a"},
        {"id": 22, "local_device_id": 1, "remote_hostname": "b"},
    ]})
    await lnms.sync_links(db_session, inst)
    assert int(await db_session.scalar(
        select(func.count()).select_from(LibreNMSLink).where(LibreNMSLink.instance_id == inst.id)
    ) or 0) == 2

    _patch(monkeypatch, {"links": [{"id": 21, "local_device_id": 1, "remote_hostname": "a"}]})
    seen, upserted, pruned = await lnms.sync_links(db_session, inst)
    assert (seen, upserted, pruned) == (1, 1, 1)
    left = (await db_session.execute(
        select(LibreNMSLink.legacy_link_id).where(LibreNMSLink.instance_id == inst.id)
    )).scalars().all()
    assert list(left) == [21]


@pytest.mark.anyio
async def test_toggle_off_skips(db_session, monkeypatch) -> None:
    inst = await _mk_instance(db_session)
    inst.sync_links = False
    called = {"n": 0}

    async def fake(_i, _p, *, timeout=30.0):
        called["n"] += 1
        return {"links": []}
    monkeypatch.setattr(lnms, "_api_get", fake)
    assert await lnms.sync_links(db_session, inst) == (0, 0, 0)
    assert called["n"] == 0, "關掉開關還是打了 API"
