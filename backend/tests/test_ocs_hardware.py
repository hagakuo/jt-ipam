"""OCS 卡片要顯示 OCS 自己的硬體資料（2026-09-27 使用者回報）。

以前卡片的「製造商／型號／序號」讀的是裝置本身的欄位：Windows 筆電被 LibreNMS 建立時
填了「windows／Intel x64」（OS 與 CPU 架構），卡片就頂著 OCS 的名義顯示這兩個值，
OCS 裡明明是 Dell Inc.／Latitude E5270。Supermicro 主機的系統序號是出廠佔位
「0123456789」，真正的序號在主機板上；主機板型號也沒顯示。另外要列出主要零件。

資料形狀照 OCS 2.10／2.11 REST 的實際回應（序號等識別資料都換成虛構值）。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.services import ocs as svc

# Windows 代理（2.11）：筆電、記憶體一條＋一筆空插槽陣列、磁碟型號在 NAME、MODEL 是裝置路徑
WIN_LAPTOP: dict[str, Any] = {
    "hardware": {"NAME": "laptop-07", "OSNAME": "Microsoft Windows 10 Pro", "MEMORY": 16384,
                 "LASTDATE": "2026-09-26 07:27:04"},
    "bios": [{"SMANUFACTURER": "Dell Inc.", "SMODEL": "Latitude E5270", "SSN": "SN-LAPTOP-07",
              "TYPE": "LapTop", "BMANUFACTURER": "Dell Inc.", "BVERSION": "1.19.3",
              "BDATE": "20/08/2018", "MMANUFACTURER": "Dell Inc.", "MMODEL": "",
              "MSN": "/SN-LAPTOP-07/BOARD-0001/", "ASSETTAG": ""}],
    "cpus": [{"TYPE": "Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz", "MANUFACTURER": "GenuineIntel",
              "CORES": 2, "LOGICAL_CPUS": 4, "SPEED": "2501", "SOCKET": "U3E1"}],
    "memories": [
        {"CAPACITY": 16384, "CAPTION": "實體記憶體", "DESCRIPTION": "BANK 0 (No ECC)",
         "NUMSLOTS": 1, "TYPE": "Unknown", "SPEED": "2133", "SERIALNUMBER": "MEM-0001"},
        # 這一筆是「記憶體陣列」本身，不是模組
        {"CAPACITY": 0, "CAPTION": "實體記憶體陣列", "DESCRIPTION": "實體記憶體陣列",
         "NUMSLOTS": 2, "TYPE": "Empty slot", "SPEED": "", "SERIALNUMBER": "MEM-0001"},
    ],
    "storages": [{"NAME": "SAMSUNG SSD PM871b M.2 2280 256GB", "MODEL": "//./PHYSICALDRIVE0",
                  "MANUFACTURER": "(Standard disk drives)", "DESCRIPTION": "Disk drive",
                  "TYPE": "Fixed hard disk media", "DISKSIZE": 244191, "SERIALNUMBER": "DISK-0001"}],
    "videos": [{"NAME": "Intel(R) HD Graphics 520", "CHIPSET": "Intel(R) HD Graphics Family",
                "MEMORY": "1024", "RESOLUTION": "1366 x 768"}],
}

# Unix 代理（2.10）：系統序號是出廠佔位、主機板才有真值；DDR5 容量讀不到（0）；
# zram 不是實體磁碟；同一張 GPU 由 lspci 與 nvidia-smi 各報一次
LINUX_SERVER: dict[str, Any] = {
    "hardware": {"NAME": "ws-01", "OSNAME": "Linux", "MEMORY": 128564,
                 "LASTDATE": "2026-09-27 07:46:19"},
    "bios": [{"SMANUFACTURER": "Supermicro", "SMODEL": "Super Server", "SSN": "0123456789",
              "TYPE": "Desktop", "BMANUFACTURER": "American Megatrends International, LLC.",
              "BVERSION": "2.2", "BDATE": "06/12/2023", "MMANUFACTURER": "Supermicro",
              "MMODEL": "X13SAZ-F", "MSN": "BOARD-SN-0002", "ASSETTAG": "Chassis Asset Tag"}],
    "cpus": [{"TYPE": "12th Gen Intel(R) Core(TM) i5-12400", "MANUFACTURER": "Intel",
              "CORES": 6, "LOGICAL_CPUS": 12, "SPEED": "", "SOCKET": "CPU"}],
    "memories": [
        {"CAPACITY": 0, "CAPTION": f"DIMM{s}", "DESCRIPTION": "", "NUMSLOTS": i,
         "TYPE": "DDR5", "SPEED": "5600", "SERIALNUMBER": f"MEM-{i}"}
        for i, s in enumerate(("A1", "A2", "B1", "B2"))
    ],
    "storages": [
        {"NAME": "sda", "MODEL": "SSSTC ER3-CD1920A", "MANUFACTURER": "SSSTC", "TYPE": "disk",
         "DESCRIPTION": "ATA Disk", "DISKSIZE": 1920383, "SERIALNUMBER": "DISK-A"},
        {"NAME": "sdb", "MODEL": "SSSTC ER3-CD240", "MANUFACTURER": "SSSTC", "TYPE": "disk",
         "DESCRIPTION": "ATA Disk", "DISKSIZE": 240057, "SERIALNUMBER": "DISK-B"},
        {"NAME": "zram0", "MODEL": "", "MANUFACTURER": "", "TYPE": "disk",
         "DESCRIPTION": "", "DISKSIZE": 17180, "SERIALNUMBER": ""},
    ],
    "videos": [
        {"NAME": "Intel Corporation Alder Lake-S GT1 [UHD Graphics 730] ",
         "CHIPSET": "VGA compatible controller", "MEMORY": "256"},
        {"NAME": "NVIDIA Corporation AD106 [GeForce RTX 4060 Ti] ",
         "CHIPSET": "VGA compatible controller", "MEMORY": "32"},
        {"NAME": "ASPEED Technology, Inc. ASPEED Graphics Family ",
         "CHIPSET": "VGA compatible controller", "MEMORY": ""},
        {"NAME": "NVIDIA GeForce RTX 4060 Ti", "CHIPSET": "", "MEMORY": "16380"},
    ],
}


# ─────────────────── 純函式：摘要 ───────────────────

def test_windows_laptop_summary() -> None:
    hw = svc.hardware_summary(WIN_LAPTOP)
    assert hw["system"] == {"vendor": "Dell Inc.", "model": "Latitude E5270",
                            "serial": "SN-LAPTOP-07", "chassis": "LapTop"}
    # 主機板序號去掉 Dell 格式前後的斜線；沒有型號就是 None
    assert hw["board"] == {"vendor": "Dell Inc.", "model": None,
                           "serial": "SN-LAPTOP-07/BOARD-0001"}
    assert hw["bios"] == {"vendor": "Dell Inc.", "version": "1.19.3", "date": "20/08/2018"}
    assert hw["cpus"] == [{"model": "Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz",
                           "cores": 2, "threads": 4, "mhz": 2501, "count": 1}]
    # 陣列那筆不是模組；型別 Unknown 不顯示
    assert hw["memory"] == {"total_mb": 16384,
                            "modules": [{"size_mb": 16384, "type": None, "speed": 2133, "count": 1}]}
    # MODEL 是裝置路徑時，型號在 NAME
    assert hw["disks"] == [{"model": "SAMSUNG SSD PM871b M.2 2280 256GB", "size_mb": 244191}]
    assert hw["gpus"] == [{"name": "Intel(R) HD Graphics 520", "memory_mb": 1024}]


def test_linux_server_summary() -> None:
    hw = svc.hardware_summary(LINUX_SERVER)
    # 系統序號是出廠佔位 → None；卡片改顯示主機板序號
    assert hw["system"]["serial"] is None
    assert hw["system"]["model"] == "Super Server"
    assert hw["board"] == {"vendor": "Supermicro", "model": "X13SAZ-F", "serial": "BOARD-SN-0002"}
    assert hw["cpus"] == [{"model": "12th Gen Intel(R) Core(TM) i5-12400",
                           "cores": 6, "threads": 12, "mhz": None, "count": 1}]
    # 四條 DDR5 容量讀不到：數量、型別、速度照列，容量 None；總量取 hardware.MEMORY
    assert hw["memory"] == {"total_mb": 128564,
                            "modules": [{"size_mb": None, "type": "DDR5", "speed": 5600, "count": 4}]}
    # zram 不是實體磁碟
    assert [d["model"] for d in hw["disks"]] == ["SSSTC ER3-CD1920A", "SSSTC ER3-CD240"]
    # lspci 名稱取中括號裡的產品名；同一張卡兩筆合併、取實際顯示記憶體；
    # lspci 報的 BAR 大小（256／32）不是顯示記憶體，不顯示
    assert hw["gpus"] == [
        {"name": "Intel UHD Graphics 730", "memory_mb": None},
        {"name": "NVIDIA GeForce RTX 4060 Ti", "memory_mb": 16380},
        {"name": "ASPEED Graphics Family", "memory_mb": None},
    ]


def test_summary_of_an_empty_computer_is_all_none() -> None:
    hw = svc.hardware_summary({"hardware": {"NAME": "x"}})
    assert hw["system"] == {"vendor": None, "model": None, "serial": None, "chassis": None}
    assert hw["cpus"] == []
    assert hw["disks"] == []
    assert hw["gpus"] == []
    assert hw["memory"] == {"total_mb": None, "modules": []}


def test_mojibake_is_repaired_in_the_summary() -> None:
    """OCS 常把 UTF-8 當 latin-1 再存一次（實機：「實體記憶體」變成 å¯¦é«…）。"""
    comp = {"videos": [{"NAME": "顯示卡".encode().decode("latin-1"), "MEMORY": "2048"},
                       {"NAME": "Intel(R) HD Graphics 520", "MEMORY": ""}]}   # 純 ASCII 不受影響
    names = [g["name"] for g in svc.hardware_summary(comp)["gpus"]]
    assert names == ["顯示卡", "Intel(R) HD Graphics 520"]


# ─────────────────── bios_asset：寫進裝置欄位的值 ───────────────────

def test_factory_serial_placeholder_falls_back_to_the_board_serial() -> None:
    a = svc.bios_asset(LINUX_SERVER["bios"])
    assert a["serial"] == "BOARD-SN-0002"
    assert a["vendor"] == "Supermicro"
    assert a["model"] == "Super Server"


@pytest.mark.parametrize("junk", ["0123456789", "1234567890", "123456789", "Default string",
                                  "Chassis Serial Number", "System Serial Number"])
def test_more_serial_placeholders(junk: str) -> None:
    assert svc.bios_asset([{"SSN": junk}])["serial"] is None


# ─────────────────── 套用到 IP／裝置 ───────────────────

async def _mk_ip(session, ip_str: str, mac: str, *, device_id=None):
    from app.models.address import IPAddress
    from app.models.section import Section
    from app.models.subnet import Subnet
    sec = Section(name=f"t-{uuid.uuid4().hex[:6]}")
    session.add(sec)
    await session.flush()
    net = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    session.add(net)
    await session.flush()
    obj = IPAddress(subnet_id=net.id, ip=ip_str, mac=mac, device_id=device_id)
    session.add(obj)
    await session.flush()
    return obj


def _server(**kw: Any) -> Any:
    from types import SimpleNamespace
    base = {"id": uuid.uuid4(), "name": "ocs", "source_type": "rest",
            "base_url": "https://192.0.2.10", "sync_bios": True, "stale_after_days": 30}
    base.update(kw)
    return SimpleNamespace(**base)


def _with_nic(comp: dict[str, Any], mac: str) -> dict[str, Any]:
    return {**comp, "networks": [{"MACADDR": mac, "VIRTUALDEV": 0, "IPADDRESS": "198.51.100.41"}]}


NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


async def test_apply_stores_the_hardware_summary_on_the_ip(db_session) -> None:
    from app.services.arp_precedence import normalize_mac
    ip = await _mk_ip(db_session, "198.51.100.41", "aa:bb:cc:00:00:41")
    idx = {normalize_mac("aa:bb:cc:00:00:41"): [ip.id]}
    await svc._apply_computer(db_session, _server(), _with_nic(LINUX_SERVER, "aa:bb:cc:00:00:41"),
                             idx, NOW, ocs_id=53)
    await db_session.flush()
    await db_session.refresh(ip)
    assert ip.ocs_hw["board"]["model"] == "X13SAZ-F"
    assert ip.ocs_hw["memory"]["total_mb"] == 128564


async def test_os_name_as_vendor_and_cpu_arch_as_model_are_replaced(db_session) -> None:
    """LibreNMS 建立 Windows 裝置時把 OS 填進廠牌、CPU 架構填進型號 —— 那不是硬體資訊，
    OCS 有真值就換掉；使用者自己填的值照樣不動。"""
    from app.models.device import Device
    from app.services.arp_precedence import normalize_mac
    dev = Device(name="laptop-07", vendor="windows", model="Intel x64")
    other = Device(name="laptop-08", vendor="Acme", model="Custom Box")
    db_session.add_all([dev, other])
    await db_session.flush()
    ip1 = await _mk_ip(db_session, "198.51.100.41", "aa:bb:cc:00:00:41", device_id=dev.id)
    ip2 = await _mk_ip(db_session, "198.51.100.42", "aa:bb:cc:00:00:42", device_id=other.id)
    idx = {normalize_mac("aa:bb:cc:00:00:41"): [ip1.id], normalize_mac("aa:bb:cc:00:00:42"): [ip2.id]}
    await svc._apply_computer(db_session, _server(), _with_nic(WIN_LAPTOP, "aa:bb:cc:00:00:41"), idx, NOW)
    comp2 = {**_with_nic(WIN_LAPTOP, "aa:bb:cc:00:00:42")}
    comp2["networks"][0]["IPADDRESS"] = "198.51.100.42"
    await svc._apply_computer(db_session, _server(), comp2, idx, NOW)
    await db_session.flush()
    await db_session.refresh(dev)
    await db_session.refresh(other)
    assert (dev.vendor, dev.model) == ("Dell Inc.", "Latitude E5270")
    assert (other.vendor, other.model) == ("Acme", "Custom Box")


async def test_os_name_vendor_is_kept_when_ocs_has_nothing_better(db_session) -> None:
    from app.models.device import Device
    from app.services.arp_precedence import normalize_mac
    dev = Device(name="laptop-09", vendor="windows", model="AMD x64")
    db_session.add(dev)
    await db_session.flush()
    ip = await _mk_ip(db_session, "198.51.100.41", "aa:bb:cc:00:00:41", device_id=dev.id)
    idx = {normalize_mac("aa:bb:cc:00:00:41"): [ip.id]}
    comp = _with_nic({**WIN_LAPTOP, "bios": []}, "aa:bb:cc:00:00:41")
    await svc._apply_computer(db_session, _server(), comp, idx, NOW)
    await db_session.flush()
    await db_session.refresh(dev)
    assert (dev.vendor, dev.model) == ("windows", "AMD x64")


async def test_unmatched_ip_loses_the_hardware_summary_too(db_session) -> None:
    ip = await _mk_ip(db_session, "198.51.100.41", "aa:bb:cc:00:00:41")
    ip.ocs_id = 53
    ip.ocs_hw = svc.hardware_summary(LINUX_SERVER)
    await db_session.flush()
    cleared = await svc._clear_unmatched(db_session, _server(), set(), peers=1)
    await db_session.flush()
    await db_session.refresh(ip)
    assert cleared == 1
    assert ip.ocs_hw is None


# ─────────────────── 裝置明細的 OCS 卡片 ───────────────────

async def test_device_card_shows_ocs_values_not_the_device_fields(client, auth_headers, db_session) -> None:
    from app.models.device import Device
    dev = Device(name="laptop-07", vendor="windows", model="Intel x64")
    db_session.add(dev)
    await db_session.flush()
    ip = await _mk_ip(db_session, "198.51.100.41", "aa:bb:cc:00:00:41", device_id=dev.id)
    ip.ocs_id = 13
    ip.last_seen_ocs = NOW
    ip.ocs_hw = svc.hardware_summary(WIN_LAPTOP)
    await db_session.commit()

    r = await client.get(f"/api/v1/devices/{dev.id}/integrations", headers=auth_headers)
    assert r.status_code == 200, r.text
    ocs = r.json()["ocs"]
    assert (ocs["vendor"], ocs["model"], ocs["serial"]) == ("Dell Inc.", "Latitude E5270", "SN-LAPTOP-07")
    assert ocs["hw"]["cpus"][0]["threads"] == 4


async def test_device_card_uses_the_board_serial_when_the_system_one_is_a_placeholder(
        client, auth_headers, db_session) -> None:
    from app.models.device import Device
    dev = Device(name="ws-01")
    db_session.add(dev)
    await db_session.flush()
    ip = await _mk_ip(db_session, "198.51.100.41", "aa:bb:cc:00:00:41", device_id=dev.id)
    ip.ocs_id = 53
    ip.last_seen_ocs = NOW
    ip.ocs_hw = svc.hardware_summary(LINUX_SERVER)
    await db_session.commit()

    ocs = (await client.get(f"/api/v1/devices/{dev.id}/integrations", headers=auth_headers)).json()["ocs"]
    assert ocs["serial"] == "BOARD-SN-0002"
    assert ocs["serial_from_board"] is True


async def test_a_factory_placeholder_serial_already_on_the_device_is_replaced(db_session) -> None:
    """舊版同步把系統序號的出廠佔位（0123456789）存進了裝置；它也是佔位，要能被主機板序號換掉。"""
    from app.models.device import Device
    from app.services.arp_precedence import normalize_mac
    dev = Device(name="ws-01", serial="0123456789")
    db_session.add(dev)
    await db_session.flush()
    ip = await _mk_ip(db_session, "198.51.100.41", "aa:bb:cc:00:00:41", device_id=dev.id)
    idx = {normalize_mac("aa:bb:cc:00:00:41"): [ip.id]}
    await svc._apply_computer(db_session, _server(), _with_nic(LINUX_SERVER, "aa:bb:cc:00:00:41"), idx, NOW)
    await db_session.flush()
    await db_session.refresh(dev)
    assert dev.serial == "BOARD-SN-0002"


@pytest.mark.parametrize("name", ["rbd0", "rbd7", "zd0", "zd16", "drbd1", "loop3", "dm-0", "nbd0", "zram0"])
def test_virtual_block_devices_are_not_physical_disks(name: str) -> None:
    """PVE 主機上 Ceph 的 rbd、ZFS 的 zvol（zd）等是虛擬區塊裝置，OCS 代理照 lsblk 一律回報成 disk
    （2026-09-27 使用者回報：Ceph 節點的磁碟清單列出 rbd0～rbd7）。"""
    comp = {"storages": [
        {"NAME": name, "MODEL": "", "MANUFACTURER": "", "TYPE": "disk", "DISKSIZE": 8590},
        {"NAME": "sda", "MODEL": "SATA ER2-CD1920A", "MANUFACTURER": "SSSTC", "TYPE": "disk",
         "DISKSIZE": 1920383},
    ]}
    assert [d["model"] for d in svc.hardware_summary(comp)["disks"]] == ["SATA ER2-CD1920A"]


def test_a_vm_keeps_its_own_virtual_disk() -> None:
    """VM 裡的 vda／xvda 就是那台 VM 的磁碟，要留著。"""
    comp = {"storages": [{"NAME": "vda", "MODEL": "", "TYPE": "disk", "DISKSIZE": 34360}]}
    assert [d["model"] for d in svc.hardware_summary(comp)["disks"]] == ["vda"]
