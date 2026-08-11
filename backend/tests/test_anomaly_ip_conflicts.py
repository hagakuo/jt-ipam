"""IP 衝突偵測：MAC 要帶得出廠商，以及要標出本地管理（隨機／虛擬）位址。

背景：這張表原本只列 IP 與一串裸 MAC，實務上看不懂 —— prod 上 55 筆衝突、133 個 MAC，
其中 64 個是本地管理位址（虛擬機、容器、手機 MAC 隱私隨機化），那些根本不是兩台機器
搶同一個 IP。分不出來的話整張表就只是雜訊。
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from app.models.librenms import ARPEntry
from app.models.oui import OUIVendor
from app.services.anomaly import _is_locally_administered, detect_ip_conflicts


@pytest.mark.parametrize(("mac", "expected"), [
    ("bc:24:11:c6:68:c8", False),   # Proxmox，廠商燒錄的全球唯一位址
    ("60:45:bd:fc:01:71", False),   # Microsoft
    ("34:f6:8d:1e:36:7e", False),   # Apple
    ("02:42:ac:12:00:03", True),    # Docker 容器
    ("46:f2:98:05:0e:5e", True),    # 隨機化
    ("de:4f:8b:08:31:70", True),
    ("1e:d8:38:9e:75:de", True),
    ("BC-24-11-C6-68-C8", False),   # 破折號寫法也要判對
    ("garbage", False),             # 壞資料不能炸
])
def test_locally_administered_bit(mac, expected):
    assert _is_locally_administered(mac) is expected


async def test_conflict_reports_vendor_and_local_flag(db_session):
    """一個 IP 上同時有真實 MAC 與隨機 MAC —— 兩者都要出現，且分得出來。

    這裡守的是一個實際踩過的 bug：`vendor_map()` 回的 key 是**正規化後的 6 碼前綴**
    （'BC2411'），不是完整 MAC。當初拿完整 MAC 去查，結果每一筆廠商都是空的，
    而畫面上只會顯示「未知」—— 不會報錯，也沒人會發現。
    """
    db_session.add(OUIVendor(prefix="BC2411", short_name="ProxmoxServe",
                             name="Proxmox Server Solutions GmbH", source="test"))
    now = datetime.now(UTC)
    for mac in ("bc:24:11:c6:68:c8", "46:f2:98:05:0e:5e"):
        db_session.add(ARPEntry(ip="198.51.100.7", mac=mac, last_seen_at=now))
    await db_session.flush()

    rows = await detect_ip_conflicts(db_session)
    # 服務層要回字串：asyncpg 對 INET 欄位回的是 IPv4Address 物件（已知地雷 #10）
    ips = [r["ip"] for r in rows]
    assert all(isinstance(i, str) for i in ips), f"IP 應為字串，實際: {[type(i) for i in ips]}"
    matched = [r for r in rows if r["ip"] == "198.51.100.7"]
    assert matched, f"沒偵測到衝突，實際有: {ips}"
    row = matched[0]
    assert all(isinstance(m["mac"], str) for m in row["macs"]), "MAC 也要是字串"
    by_mac = {m["mac"]: m for m in row["macs"]}
    assert len(by_mac) == 2

    real = by_mac["bc:24:11:c6:68:c8"]
    assert real["vendor"] == "ProxmoxServe", "廠商查不到就等於整欄顯示未知（曾經的 bug）"
    assert real["local"] is False

    rand = by_mac["46:f2:98:05:0e:5e"]
    assert rand["local"] is True
    assert rand["vendor"] is None, "本地管理位址沒有 OUI 登記，查不到廠商是正常的"


async def test_single_mac_is_not_a_conflict(db_session):
    now = datetime.now(UTC)
    db_session.add(ARPEntry(ip="198.51.100.8", mac="bc:24:11:00:00:01", last_seen_at=now))
    await db_session.flush()
    rows = await detect_ip_conflicts(db_session)
    assert not any(r["ip"] == "198.51.100.8" for r in rows)
