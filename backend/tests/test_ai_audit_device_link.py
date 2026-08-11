"""巡檢快照要告訴模型「這兩個 IP 是同一台機器」。

實機誤報：一台雙網卡的 NAS（eth0 / eth1）有兩個 IP，兩筆紀錄的主機名稱相同，
模型於是報了一條「重複的 IP 紀錄 —— 兩個不同的 IP 位址對應到相同的裝置名稱」。

以模型拿到的資料來說，那個推論是合理的：快照裡每筆 IP 只有 ip / hostname / state /
status，**完全沒有裝置關聯，也沒有 MAC**。可是資料庫裡明明有 —— 第二個 IP 的 MAC
就是該裝置 eth1 的 MAC。錯不在模型，在於我們把決定性的事實藏起來了。

一台機器有多個網卡、多個 IP 是正常的多重歸屬，不是衝突。
"""
from __future__ import annotations

import uuid

import pytest
from app.services import ai_audit as aa


async def _admin(db_session):
    from app.core.security import hash_password
    from app.models.user import User
    u = User(username=f"aiadm-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=True, is_active=True)
    db_session.add(u)
    await db_session.flush()
    return u


async def _fixture(db_session):
    from app.models.address import IPAddress
    from app.models.device import Device
    from app.models.physical import DevicePort
    from app.models.section import Section
    from app.models.subnet import Subnet

    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", description="測試")
    dev = Device(name=f"nas-{uuid.uuid4().hex[:6]}", type="server")
    db_session.add_all([sub, dev])
    await db_session.flush()
    db_session.add_all([
        DevicePort(device_id=dev.id, name="eth0", mac_address="00:00:5e:00:53:01"),
        DevicePort(device_id=dev.id, name="eth1", mac_address="00:00:5e:00:53:02"),
    ])
    # 第一個 IP 有 device_id；第二個沒有，只能靠 MAC 對到 eth1
    a = IPAddress(subnet_id=sub.id, ip="198.51.100.10", hostname=dev.name,
                  mac="00:00:5e:00:53:01", device_id=dev.id)
    b = IPAddress(subnet_id=sub.id, ip="198.51.100.11", hostname=dev.name,
                  mac="00:00:5e:00:53:02")
    db_session.add_all([a, b])
    await db_session.flush()
    return dev, sub


@pytest.mark.anyio
async def test_snapshot_carries_the_owning_device(db_session):
    dev, _sub = await _fixture(db_session)
    snap = await aa._collect(db_session, await _admin(db_session))
    got = {r["ip"]: r for r in snap["ips"]}
    assert got["198.51.100.10"]["device"] == dev.name


@pytest.mark.anyio
async def test_an_ip_linked_only_by_nic_mac_is_still_attributed(db_session):
    """第二張網卡的 IP 常常沒有 device_id —— 但 MAC 就在該裝置的連接埠上。

    不做這層對應的話，模型看到的仍是「兩個孤立的 IP 剛好同名」，誤報照舊。
    """
    dev, _sub = await _fixture(db_session)
    snap = await aa._collect(db_session, await _admin(db_session))
    got = {r["ip"]: r for r in snap["ips"]}
    assert got["198.51.100.11"]["device"] == dev.name


@pytest.mark.anyio
async def test_the_prompt_says_multi_homing_is_not_a_conflict(db_session):
    """光給欄位不夠 —— 還要明講「同一台機器有多個 IP 是正常的」。"""
    assert "multi-homed" in aa._PROMPT or "multiple IP addresses" in aa._PROMPT


@pytest.mark.anyio
async def test_device_names_are_not_leaked_to_users_without_access(db_session):
    """看不到那台裝置的帳號，快照裡就不該出現它的名字。"""
    dev, _sub = await _fixture(db_session)
    from app.core.security import hash_password
    from app.models.user import User
    u = User(username=f"nodev-{uuid.uuid4().hex[:6]}", email=f"{uuid.uuid4().hex[:6]}@e.test",
             password_hash=hash_password("Xx!12345678xX"), is_admin=False, is_active=True)
    db_session.add(u)
    await db_session.flush()
    snap = await aa._collect(db_session, u)
    assert all(r.get("device") != dev.name for r in snap["ips"])
