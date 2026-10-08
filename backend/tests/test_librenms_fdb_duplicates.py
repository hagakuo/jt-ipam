"""issue #43：LibreNMS 同步 FDB 撞 `fdb_entry_unique`，作業卡在「執行中」。

兩個原因：
1. 同一次回應裡同一個「MAC＋裝置＋埠＋VLAN」出現兩次（LibreNMS 的 FDB 以內部 VLAN row id 記，
   換算成 VLAN 號後可能重疊）。正式環境的 session 是 autoflush=False，第二筆查不到第一筆還沒寫入
   的新增 → 新增兩次 → 唯一鍵衝突。測試一定要比照 autoflush=False，否則測不出來。
2. 作業失敗後 session 處在「交易已失敗」狀態，沒有先還原就寫最終狀態 → 寫入也失敗 →
   作業永遠停在 running（見 test_background_task_final_state.py）。
"""
from __future__ import annotations

import uuid

import pytest
from app.models.librenms import FDBEntry, LibreNMSDevice, LibreNMSInstance
from app.services import librenms as lnms
from sqlalchemy import func, select


async def _setup(session):
    inst = LibreNMSInstance(name=f"lnms-fdb-{uuid.uuid4().hex[:6]}", api_url="http://192.0.2.61",
                            api_token_enc=b"x", api_token_nonce=b"x", enabled=True, sync_fdb=True)
    session.add(inst)
    await session.flush()
    dev = LibreNMSDevice(instance_id=inst.id, legacy_device_id=7, hostname="sw-e2e")
    session.add(dev)
    await session.flush()
    return inst, dev


def _patch(monkeypatch, fdb_rows):
    async def fake(_inst, path, *, timeout=30.0):
        if path.endswith("/resources/vlans"):
            # 兩個不同的內部 row id 都對到 VLAN 2 —— 重複就是這樣來的
            return {"vlans": [{"vlan_id": 11, "vlan_vlan": 2}, {"vlan_id": 12, "vlan_vlan": 2}]}
        if "/ports" in path:
            return {"ports": [{"port_id": 1, "ifName": "ge-0/1/0.0"}]}
        if path.endswith("/fdb"):
            return {"ports_fdb": fdb_rows}
        raise AssertionError(path)
    monkeypatch.setattr(lnms, "_api_get", fake)


@pytest.mark.anyio
async def test_duplicate_rows_in_one_response_do_not_collide(db_session, monkeypatch) -> None:
    db_session.autoflush = False          # 比照正式環境
    inst, dev = await _setup(db_session)
    _patch(monkeypatch, [
        {"mac_address": "00005E005321", "vlan_id": 11, "port_id": 1,
         "created_at": "2026-09-20T01:04:14Z", "updated_at": "2026-09-21T18:07:31Z"},
        {"mac_address": "00005e005321", "vlan_id": 12, "port_id": 1,
         "created_at": "2026-09-19T00:00:00Z", "updated_at": "2026-09-22T00:00:00Z"},
        # 埠名稱對不到（NULL）的也不可以每次同步都多一筆
        {"mac_address": "00005e005322", "vlan_id": 11, "port_id": 99},
        {"mac_address": "00005e005322", "vlan_id": 11, "port_id": 99},
    ])
    await lnms.sync_fdb(db_session, inst)
    await db_session.commit()
    rows = (await db_session.execute(select(FDBEntry).where(FDBEntry.device_id == dev.id)
                                     .order_by(FDBEntry.mac))).scalars().all()
    assert [(r.mac, r.port_name, r.vlan_id_num) for r in rows] == [
        ("00:00:5e:00:53:21", "ge-0/1/0.0", 2), ("00:00:5e:00:53:22", None, 2)]
    # 兩筆合併：首見取較早、末見取較晚
    first = rows[0]
    assert first.first_seen_at.isoformat().startswith("2026-09-19")
    assert first.last_seen_at.isoformat().startswith("2026-09-22")

    # 第二次同步（同樣的資料）不會新增、也不會撞鍵
    await lnms.sync_fdb(db_session, inst)
    await db_session.commit()
    n = (await db_session.execute(select(func.count()).select_from(FDBEntry)
                                  .where(FDBEntry.device_id == dev.id))).scalar()
    assert n == 2
