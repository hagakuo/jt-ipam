"""依網卡 MAC 把 IP 掛回所屬裝置 —— 十條「不猜」的規則。

由來：一台多網卡機器的第二個 IP 常常沒有 `device_id`（既有的 LibreNMS 同步只掛主要
IP），於是裝置頁的 IP 清單不完整，AI 巡檢還會把它報成「重複的 IP 紀錄」。而那個 MAC
就寫在該裝置的連接埠上 —— 系統手上早就有答案，只是沒去用。

**前提（已對實機查證）**：`device_ports.mac_address` 存的是埠自身的硬體位址
（LibreNMS 寫 `ifPhysAddress`、Proxmox 寫網卡設定），不是該埠學習到的 MAC。若是後者，
這套比對會把主機的 IP 掛到交換器上，整個方向就反了。

**寧可不掛也不要掛錯**：沒有關聯，使用者會去查；掛錯了，不會有人發現。
"""
from __future__ import annotations

import uuid

import pytest
from app.services import ip_device_link as link


async def _base(db_session, *, archived=False, ip_customer=None, dev_customer=None,
                hostname=None, port_mac="02:00:00:00:00:02", ip_mac="02:00:00:00:00:02"):
    from app.models.address import IPAddress
    from app.models.device import Device
    from app.models.physical import DevicePort
    from app.models.section import Section
    from app.models.subnet import Subnet
    from datetime import UTC, datetime

    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24",
                 archived_at=datetime.now(UTC) if archived else None)
    dev = Device(name=hostname or f"srv-{uuid.uuid4().hex[:6]}", type="server",
                 customer_id=dev_customer)
    db_session.add_all([sub, dev])
    await db_session.flush()
    db_session.add(DevicePort(device_id=dev.id, name="eth1", mac_address=port_mac))
    ipa = IPAddress(subnet_id=sub.id, ip="198.51.100.11", mac=ip_mac,
                    hostname=hostname, customer_id=ip_customer)
    db_session.add(ipa)
    await db_session.flush()
    return dev, ipa, sub


async def _run(db_session, **kw):
    stats = await link.link_by_port_mac(db_session, **kw)
    await db_session.flush()
    return stats


@pytest.mark.anyio
async def test_the_happy_path_links_the_ip(db_session):
    dev, ipa, _ = await _base(db_session)
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert st.linked >= 1 and ipa.device_id == dev.id


@pytest.mark.anyio
async def test_rule1_an_existing_link_is_never_overwritten(db_session):
    from app.models.device import Device
    dev, ipa, _ = await _base(db_session)
    other = Device(name=f"other-{uuid.uuid4().hex[:6]}", type="server")
    db_session.add(other)
    await db_session.flush()
    ipa.device_id = other.id
    await db_session.flush()
    await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id == other.id


@pytest.mark.anyio
async def test_rule2_an_ambiguous_mac_is_left_alone(db_session):
    """同一個 MAC 出現在兩台裝置上就不猜（複製的 VM、共用的虛擬 MAC）。"""
    from app.models.device import Device
    from app.models.physical import DevicePort
    _dev, ipa, _ = await _base(db_session)
    other = Device(name=f"other-{uuid.uuid4().hex[:6]}", type="server")
    db_session.add(other)
    await db_session.flush()
    db_session.add(DevicePort(device_id=other.id, name="eth9",
                              mac_address="02:00:00:00:00:02"))
    await db_session.flush()
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None and st.skipped_ambiguous >= 1


@pytest.mark.anyio
async def test_rule4_an_ip_whose_device_was_edited_by_a_person_is_left_alone(db_session):
    """人手動改過（含清空）的裝置欄，自動邏輯不再插手。

    少了這條，使用者清掉一個掛錯的關聯之後，下一輪同步又會掛回去 —— 系統與人對打，
    而且人永遠贏不了。
    """
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.ip_history import log_change
    _dev, ipa, _ = await _base(db_session)
    u = User(username=f"op-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=True, is_active=True)
    db_session.add(u)
    await db_session.flush()
    await log_change(db_session, ip=ipa, event_type="edited", field="device_id",
                     old="something", new=None, source="manual", actor_user_id=u.id)
    await db_session.flush()
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None and st.skipped_manual >= 1


@pytest.mark.anyio
@pytest.mark.parametrize("mac", [
    "00:00:5e:00:01:2a",   # VRRP 虛擬 MAC —— 依定義出現在多台路由器上
    "00:00:0c:07:ac:01",   # HSRP 同理
    "00:00:00:00:00:00",   # 全零
    "ff:ff:ff:ff:ff:ff",   # 廣播
    "01:00:5e:00:00:01",   # 多播位元 —— 永遠不是網卡的單播位址
])
async def test_rule5and6_protocol_and_non_unicast_macs_are_skipped(db_session, mac):
    _dev, ipa, _ = await _base(db_session, port_mac=mac, ip_mac=mac)
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None
    assert st.skipped_invalid_mac >= 1


@pytest.mark.anyio
async def test_rule6_garbage_in_the_port_mac_column_is_not_a_match(db_session):
    """`device_ports.mac_address` 是 VARCHAR 且可手動編輯 —— 垃圾從這裡進來。

    正規化只挑十六進位字元，所以 "N/A" 會變成 "a"、"incomplete" 會變成 "cee"：
    **非空**，會被當成有效的鍵去配對。
    """
    _dev, ipa, _ = await _base(db_session, port_mac="N/A")
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None


@pytest.mark.anyio
async def test_rule7_a_contradicting_hostname_blocks_the_link(db_session):
    """MAC 與主機名稱是兩條獨立線索 —— 打架時不猜。"""
    from app.models.device import Device
    dev, ipa, _ = await _base(db_session)
    dev.name = "storage-01"
    ipa.hostname = "printer-07"
    await db_session.flush()
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None and st.skipped_hostname_mismatch >= 1


@pytest.mark.anyio
async def test_a_hostname_that_extends_the_device_name_is_still_a_match(db_session):
    """實機常見：`srv-01-storage` 是 `srv-01` 的儲存網網卡 —— 那不是矛盾。"""
    dev, ipa, _ = await _base(db_session)
    dev.name = "srv-01"
    ipa.hostname = "srv-01-storage.example.test"
    await db_session.flush()
    await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id == dev.id


@pytest.mark.anyio
async def test_rule8_a_cross_customer_link_is_skipped(db_session):
    """多單位共管：IP 屬 B 單位、裝置屬 A 單位就不掛。

    只在**兩邊都有值且不同**時才擋 —— 多單位站台初期大量物件沒填單位，嚴格比對會讓
    功能完全不動。
    """
    from app.models.customer import Customer
    a, b = Customer(name=f"A-{uuid.uuid4().hex[:4]}"), Customer(name=f"B-{uuid.uuid4().hex[:4]}")
    db_session.add_all([a, b])
    await db_session.flush()
    _dev, ipa, _ = await _base(db_session, ip_customer=b.id, dev_customer=a.id)
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None and st.skipped_customer >= 1


@pytest.mark.anyio
async def test_the_customer_can_be_inherited_from_the_subnet(db_session):
    """單位常常掛在子網路而不是逐筆 IP 上 —— 往上找才擋得到真正的跨單位。"""
    from app.models.customer import Customer
    a, b = Customer(name=f"A-{uuid.uuid4().hex[:4]}"), Customer(name=f"B-{uuid.uuid4().hex[:4]}")
    db_session.add_all([a, b])
    await db_session.flush()
    _dev, ipa, sub = await _base(db_session, dev_customer=a.id)
    sub.customer_id = b.id
    await db_session.flush()
    st = await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None and st.skipped_customer >= 1


@pytest.mark.anyio
async def test_rule9_archived_subnets_are_left_alone(db_session):
    _dev, ipa, _ = await _base(db_session, archived=True)
    await _run(db_session)
    await db_session.refresh(ipa)
    assert ipa.device_id is None


@pytest.mark.anyio
async def test_rule10_a_subnet_scope_narrows_what_is_touched(db_session):
    """比照本專案每一個整合都有的 scope_subnet_ids —— 重疊網段下要能收斂範圍。"""
    _dev, ipa, _sub = await _base(db_session)
    await _run(db_session, scope_subnet_ids=[str(uuid.uuid4())])
    await db_session.refresh(ipa)
    assert ipa.device_id is None


@pytest.mark.anyio
async def test_preview_changes_nothing_but_reports_what_would_happen(db_session):
    """開關前要能先看會動到什麼 —— 這是會改資料的作業。"""
    dev, ipa, _ = await _base(db_session)
    st = await _run(db_session, dry_run=True)
    await db_session.refresh(ipa)
    assert ipa.device_id is None
    assert st.linked >= 1
    assert any(s["device"] == dev.name for s in st.samples)


@pytest.mark.anyio
async def test_every_link_is_recorded_in_the_ip_history(db_session):
    from sqlalchemy import select
    from app.models.ip_change_log import IPChangeLog
    _dev, ipa, _ = await _base(db_session)
    await _run(db_session)
    rows = (await db_session.execute(
        select(IPChangeLog).where(IPChangeLog.ip_id == ipa.id,
                                  IPChangeLog.field == "device_id")
    )).scalars().all()
    assert len(rows) == 1 and rows[0].source == "system"


# ─────────────── 端點：設定與預覽 ───────────────
# 服務層綠不代表畫面能用 —— VMware 整合就是這樣：33 條測試全綠，但表單送出去 422，
# 因為沒有一條經過 schema。欄位契約要自己測。

@pytest.mark.anyio
async def test_the_setting_is_off_by_default(client, auth_headers):
    """升級之後不該多出一個每 5 分鐘自動改資料的作業。"""
    r = await client.get("/api/v1/system/ip-device-autolink", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False


@pytest.mark.anyio
async def test_the_form_payload_is_accepted_and_persisted(client, auth_headers):
    body = {"enabled": True, "scope_subnet_ids": [str(uuid.uuid4())]}
    r = await client.put("/api/v1/system/ip-device-autolink", json=body, headers=auth_headers)
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True
    again = await client.get("/api/v1/system/ip-device-autolink", headers=auth_headers)
    assert again.json()["scope_subnet_ids"] == body["scope_subnet_ids"]
    # 收尾：關回去，別讓其他測試在開啟狀態下跑
    await client.put("/api/v1/system/ip-device-autolink",
                     json={"enabled": False, "scope_subnet_ids": []}, headers=auth_headers)


@pytest.mark.anyio
async def test_preview_reports_counts_and_changes_nothing(client, auth_headers, db_session):
    from sqlalchemy import func, select
    from app.models.address import IPAddress
    dev, ipa, _ = await _base(db_session)
    await db_session.commit()
    before = await db_session.scalar(
        select(func.count()).select_from(IPAddress).where(IPAddress.device_id.is_(None)))
    r = await client.post("/api/v1/system/ip-device-autolink/preview", headers=auth_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["would_link"] >= 1
    assert "skipped" in body and "ambiguous_mac" in body["skipped"]
    await db_session.commit()
    after = await db_session.scalar(
        select(func.count()).select_from(IPAddress).where(IPAddress.device_id.is_(None)))
    assert after == before, "預覽不可以動到任何資料"


@pytest.mark.anyio
async def test_the_settings_endpoints_require_admin(client, db_session):
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    u = User(username=f"na-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local",
             password_hash=hash_password("TestPassword2026!"), is_admin=False, is_active=True)
    db_session.add(u)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    for call in (client.get("/api/v1/system/ip-device-autolink", headers=h),
                 client.put("/api/v1/system/ip-device-autolink", json={"enabled": True}, headers=h),
                 client.post("/api/v1/system/ip-device-autolink/preview", headers=h)):
        assert (await call).status_code == 403
