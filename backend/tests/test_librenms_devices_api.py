"""`GET /api/v1/librenms/devices`：裝置帶主要 IP 時不可以 500（2026-09-30 大量資料測試抓到）。

INET 欄位讀回來是 `IPv4Address` 物件，回應模型的 `primary_ip: str` 不接受 —— 只要有任何一台
LibreNMS 裝置有主要 IP，整支 API 就 500。前端沒用到這支，所以一直沒人發現（外部 API 才會打）。
"""
from __future__ import annotations

import uuid

from app.models.librenms import LibreNMSDevice, LibreNMSInstance


async def test_devices_with_a_primary_ip_serialise(client, auth_headers, db_session) -> None:
    inst = LibreNMSInstance(name=f"l-{uuid.uuid4().hex[:6]}", api_url="https://librenms.example",
                            api_token_enc=b"x", api_token_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    db_session.add_all([
        LibreNMSDevice(instance_id=inst.id, legacy_device_id=1, hostname="sw1", primary_ip="192.0.2.1"),
        LibreNMSDevice(instance_id=inst.id, legacy_device_id=2, hostname="sw2", primary_ip="2001:db8::2"),
        LibreNMSDevice(instance_id=inst.id, legacy_device_id=3, hostname="sw3"),
    ])
    await db_session.commit()
    r = await client.get("/api/v1/librenms/devices", headers=auth_headers)
    assert r.status_code == 200, r.text[:300]
    got = {d["hostname"]: d["primary_ip"] for d in r.json()["items"]}
    assert got == {"sw1": "192.0.2.1", "sw2": "2001:db8::2", "sw3": None}
