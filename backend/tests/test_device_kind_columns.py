"""「設備類型」欄位要在每一張以 IP 記錄為列的表格都選得到（使用者 2026-10-04：「我們因為有了設備類型欄位，
所以很多相關頁面的欄位也要有此欄位可以選」）。

畫面要用到 `device_kind`（圖示＋名稱）與 `device_model`（滑過顯示型號），所以這些清單的每一列都要帶。
大站台一頁就是幾萬列：一律在原本的查詢裡多選兩欄，不可以逐列再查。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import agent_scope


@pytest.fixture(autouse=True)
def _fresh_cache():
    agent_scope._CACHE.clear()
    yield
    agent_scope._CACHE.clear()


async def _subnet(db, cidr: str) -> Subnet:
    sec = Section(name=f"dk-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr, scan_enabled=True, anomaly_enabled=True)
    db.add(sub)
    await db.flush()
    return sub


async def test_connection_targets_carry_device_kind(client, auth_headers, db_session) -> None:
    sub = await _subnet(db_session, "198.51.100.0/24")
    db_session.add(IPAddress(subnet_id=sub.id, ip="198.51.100.21", hostname="nas-21", ssh_enabled=True,
                             device_kind="storage", device_model="Synology DS920+"))
    await db_session.commit()
    r = await client.get("/api/v1/addresses/connections/targets", headers=auth_headers)
    assert r.status_code == 200, r.text
    row = next(x for x in r.json() if x["ip"].split("/")[0] == "198.51.100.21")
    assert (row["device_kind"], row["device_model"]) == ("storage", "Synology DS920+")


@pytest.fixture
async def kinds(db_session):
    """有主機名稱、沒有任何代理的 IP：三種設備類型＋一台沒判讀出類型的。"""
    sub = await _subnet(db_session, "203.0.113.0/24")
    now = datetime.now(UTC)
    for i, (kind, model) in enumerate((("switch", "Cisco C9300"), ("printer", "HP LaserJet M404"),
                                       (None, None), ("camera", None)), start=1):
        db_session.add(IPAddress(subnet_id=sub.id, ip=f"203.0.113.{i}", hostname=f"dk-{i}", device_kind=kind,
                                 device_model=model, last_seen_scanner=now))
    await db_session.commit()
    return sub


@pytest.mark.parametrize("path", ["/api/v1/wazuh/missing-agents", "/api/v1/ocs/missing-agents"])
async def test_missing_agent_pages_carry_device_kind_and_sort_by_it(client, auth_headers, kinds, path) -> None:
    params = {"page": 1, "page_size": 50, "subnet_id": str(kinds.id)}
    r = await client.get(path, headers=auth_headers, params=params)
    assert r.status_code == 200, r.text
    by_ip = {x["ip"]: x for x in r.json()["items"]}
    assert by_ip["203.0.113.2"]["device_kind"] == "printer"
    assert by_ip["203.0.113.2"]["device_model"] == "HP LaserJet M404"
    assert by_ip["203.0.113.3"]["device_kind"] is None

    async def order(direction: str) -> list[str | None]:
        rr = await client.get(path, headers=auth_headers,
                              params={**params, "sort": "device_kind", "order": direction})
        assert rr.status_code == 200, rr.text
        return [x["device_kind"] for x in rr.json()["items"]]

    assert await order("asc") == ["camera", "printer", "switch", None], "沒有類型的排最後"
    assert await order("desc") == ["switch", "printer", "camera", None], "降冪也是沒有類型的排最後"

    # 不分頁的完整清單（舊用法、AI 工具）也要帶
    full = await client.get(path, headers=auth_headers)
    assert full.status_code == 200, full.text
    row = next(x for x in full.json() if x["ip"] == "203.0.113.1")
    assert row["device_kind"] == "switch" and row["device_model"] == "Cisco C9300"


async def test_anomaly_rows_get_the_records_device_kind(db_session) -> None:
    from app.services.anomaly import attach_liveness

    sub = await _subnet(db_session, "192.0.2.0/24")
    ip = IPAddress(subnet_id=sub.id, ip="192.0.2.30", device_kind="wireless_ap", device_model="UniFi U6-Pro")
    db_session.add(ip)
    await db_session.commit()
    out = await attach_liveness(db_session, {
        "ghost_ips": [{"ip": "192.0.2.30", "ip_address_id": str(ip.id)}],
        "ip_conflicts": [{"ip": "192.0.2.30"}],
        "unauthorized_ips": [{"ip": "192.0.2.99"}],
        "identity_changes": [{"ip": "192.0.2.30", "ip_id": str(ip.id), "device_model": "U6-Pro (rev 2)"}],
    })
    assert out["ghost_ips"][0]["device_kind"] == "wireless_ap"
    assert out["ghost_ips"][0]["device_model"] == "UniFi U6-Pro"
    assert out["ip_conflicts"][0]["device_kind"] == "wireless_ap", "只有 IP 文字的列也對得到"
    assert out["unauthorized_ips"][0].get("device_kind") is None, "IPAM 沒有記錄的位址沒有類型"
    assert out["identity_changes"][0]["device_model"] == "U6-Pro (rev 2)", "列自己帶的型號不可以被蓋掉"
    assert out["identity_changes"][0]["device_kind"] == "wireless_ap"


async def test_attack_surface_identity_carries_device_kind(db_session) -> None:
    from app.models.nat import NATTranslation
    from app.services.fw_lookup import attack_surface

    sub = await _subnet(db_session, "198.51.100.0/24")
    cam = IPAddress(subnet_id=sub.id, ip="198.51.100.80", hostname="cam-80", device_kind="camera",
                    device_model="Hikvision DS-2CD2043")
    db_session.add(cam)
    await db_session.flush()
    db_session.add(NATTranslation(name="cam-forward", type="port_forward", dst_ip_id=cam.id, dst_port=554,
                                  protocol="tcp", src_interface="wan", disabled=False, source_origin="manual"))
    await db_session.commit()
    items = await attack_surface(db_session)
    ident = next(i["identity"] for i in items if i.get("name") == "cam-forward")
    assert (ident["device_kind"], ident["device_model"]) == ("camera", "Hikvision DS-2CD2043")
