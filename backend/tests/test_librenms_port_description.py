"""交換器上的 port description（`ifAlias`）要同步進 `device_ports.description`。

由來（2026-09-03 使用者回報）：LibreNMS 的埠清單上有「人資-王小明-10.0.0.5」這種現場最有用
的一欄，我們的裝置埠清單卻整排「—」。原因是 ports 只抓了 `ifName,ifType,ifPhysAddress`。

⚠️ 不能照抄 `ifAlias`：**沒設過說明的埠不會是空白**，各家塞的東西還不一樣。
三種實機樣態（都用實際 API 回應驗過）：

- Linux 主機：`ifAlias` ＝ `ifName`
- Cisco Nexus 樣態：`ifAlias` ＝ `ifName` ＝ `ifDescr`
- D-Link DGS-1510：`ifAlias` ＝ `ifDescr` ＝ 韌體樣板（`… Port 24 on Unit 1`），
  只有真的設過的那一埠不一樣

判斷寫在 `_port_descriptions`（**逐台**看，不是逐筆）。
"""

from __future__ import annotations

from app.services.librenms import _port_descriptions

# 實機取樣：D-Link DGS-1510-28X，只有 eth1/0/24 被設過說明
_DLINK_BOILER = "D-Link Corporation DGS-1510-28X HW A1 firmware 1.70.B015 Port {n} on Unit 1"
DLINK = [
    *[{"ifName": f"eth1/0/{n}", "ifAlias": _DLINK_BOILER.format(n=n),
       "ifDescr": _DLINK_BOILER.format(n=n)} for n in range(1, 24)],
    {"ifName": "eth1/0/24", "ifAlias": "上行連接專用",
     "ifDescr": _DLINK_BOILER.format(n=24)},
    # 一次性的樣板字：每台只出現一次，「重複三次」的訊號擋不住，靠等於 ifDescr 認出來
    {"ifName": "cpu0", "ifAlias": "D-Link Corporation … CPU Port Interface",
     "ifDescr": "D-Link Corporation … CPU Port Interface"},
    {"ifName": "L2VLAN 1", "ifAlias": "D-Link Corporation … L2VLAN 1",
     "ifDescr": "D-Link Corporation … L2VLAN 1"},
]


def test_only_the_port_someone_actually_described_is_taken() -> None:
    """實機驗證過的那一台：31 埠只有一筆是人寫的。"""
    out = _port_descriptions(DLINK)
    assert out == {"eth1/0/24": "上行連接專用"}, out


def test_nexus_style_where_every_field_is_the_interface_name() -> None:
    ports = [{"ifName": n, "ifAlias": n, "ifDescr": n}
             for n in ("mgmt0", "Eth1/1/1", "Eth1/1/2", "Eth1/9")]
    assert _port_descriptions(ports) == {}


def test_linux_host_where_alias_repeats_the_interface_name() -> None:
    ports = [{"ifName": n, "ifAlias": n, "ifDescr": n}
             for n in ("eno1np0", "eno2np1", "vmbr0", "vmbr10")]
    assert _port_descriptions(ports) == {}


def test_a_template_with_different_numbers_is_still_a_template() -> None:
    """`Port 1 on Unit 1` 與 `Port 2 on Unit 1` 抽掉數字後相同 → 機器產生的，不是人寫的。

    （即使某台設備的 `ifDescr` 不等於 `ifAlias`，這個訊號仍然擋得住。）
    """
    ports = [{"ifName": f"Gi1/0/{n}", "ifAlias": f"Uplink port {n} of stack member 1",
              "ifDescr": "something else"} for n in (1, 2, 3, 4)]
    assert _port_descriptions(ports) == {}


def test_real_descriptions_are_kept_even_when_they_look_alike() -> None:
    """人寫的說明彼此不同 → 全部保留（兩筆同型也還沒到「三次」的門檻）。"""
    ports = [
        {"ifName": "Gi1/0/6", "ifAlias": "人資-陳小姐-10.0.0.6", "ifDescr": "Gi1/0/6"},
        {"ifName": "Gi1/0/8", "ifAlias": "資管-葉先生-10.0.0.8", "ifDescr": "Gi1/0/8"},
        {"ifName": "Gi1/0/9", "ifAlias": "總經理室", "ifDescr": "Gi1/0/9"},
    ]
    assert _port_descriptions(ports) == {
        "Gi1/0/6": "人資-陳小姐-10.0.0.6",
        "Gi1/0/8": "資管-葉先生-10.0.0.8",
        "Gi1/0/9": "總經理室",
    }


def test_long_alias_is_bounded() -> None:
    """說明欄是 Text，但外部字串仍要設界。"""
    out = _port_descriptions([{"ifName": "Gi1/0/1", "ifAlias": "x" * 900, "ifDescr": "d"}])
    assert len(out["Gi1/0/1"]) == 500


def test_sync_only_overwrites_when_librenms_has_a_value() -> None:
    """LibreNMS 沒給說明時不可以把既有的清掉（與埠 MAC 同一條規則）。"""
    import inspect

    from app.services.librenms import sync_device_ports

    src = inspect.getsource(sync_device_ports)
    # 「沒給就不動」由 upsert 的 coalesce 保證；實際行為在 test_device_ports_reconcile 的
    # test_librenms_without_a_value_keeps_what_is_there 跑同步驗
    assert "coalesce(ins.excluded.description" in src and "coalesce(ins.excluded.mac_address" in src
    assert "ifAlias" in src, "ports 查詢沒有帶 ifAlias，說明就同步不回來"
