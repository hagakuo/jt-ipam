"""新增一個整合時，**所有跟著它走的功能都要跟上**。

由來（2026-09-02，使用者：「只要加了新的支援整合 所有功能都要跟進」）：Palo Alto 的
同步、規則異動偵測、設定頁都做好了，但一輪盤點之後還是有一串地方停在前一家：
AI 對話的工具（`list_firewalls` 少一家、沒有對應的政策／位址工具）、IP 詳細資料的
防火牆反查、稽核的目標名稱對照、未授權 DHCP 的整合主機允許清單、規則異動頁的說明文字。

這些漏掉的共同點是**不會壞、只會少**：功能看起來正常，只是少了一家，所以沒人發現。
唯一擋得住的方式就是把「一個整合要出現在哪些地方」寫成清單，讓漏掉的當場失敗。

新增整合時：把廠牌加進 `FIREWALL_VENDORS`，然後把測試點亮。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
FRONTEND = BACKEND.parent / "frontend"

#: 有「防火牆規則／位址物件」的廠牌 —— 每一家都要走完下面每一項。
FIREWALL_VENDORS = ("opnsense", "pfsense", "fortigate", "paloalto", "mikrotik")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ─────────────────── AI 對話（MCP 工具）───────────────────

def test_list_firewalls_covers_every_vendor() -> None:
    """少一家時模型會拿一份不完整的清單當成全部去回答「我們有哪些防火牆」。"""
    src = _read(BACKEND / "app" / "mcp" / "tools.py")
    body = src[src.index("async def list_firewalls"):src.index("async def list_fortigate_policies")]
    for vendor in FIREWALL_VENDORS:
        assert f'"{vendor}"' in body, f"list_firewalls 少了 {vendor}"


#: 有專屬資料表的廠牌 → 各自的唯讀工具名。後綴跟著該廠牌的用語走
#: （PAN-OS/FortiOS 叫 policy、RouterOS 叫 rule；位址物件 vs address-list）。
VENDOR_TOOL_SUFFIXES = {
    "fortigate": ("policies", "addresses"),
    "paloalto": ("policies", "addresses"),
    "mikrotik": ("rules", "address_lists"),
}


@pytest.mark.parametrize("vendor", sorted(VENDOR_TOOL_SUFFIXES))
def test_vendor_has_policy_and_address_tools(vendor: str) -> None:
    """專屬資料表的廠牌要有自己的唯讀工具，否則 AI 對話問不到它的規則。

    （OPNsense／pfSense 的規則走 `list_firewall_rules` 與別名工具，不在此列。）
    """
    from app.mcp.tools import GLOBAL_READ_TOOLS, TOOLS

    for suffix in VENDOR_TOOL_SUFFIXES[vendor]:
        name = f"list_{vendor}_{suffix}"
        assert name in TOOLS, f"AI 對話沒有 {name}"
        # 防火牆政策是全域基礎設施資料：只被指派特定物件的帳號不該問得到
        assert name in GLOBAL_READ_TOOLS, f"{name} 沒有歸進 GLOBAL_READ_TOOLS（權限會太鬆）"


# ─────────────────── 規則異動 ───────────────────

def test_rule_change_detection_covers_every_vendor() -> None:
    src = _read(BACKEND / "app" / "services" / "fw_review.py")
    for vendor in FIREWALL_VENDORS:
        assert f'source_type == "{vendor}"' in src, f"規則異動偵測少了 {vendor}"


def test_rule_change_page_text_lists_every_vendor() -> None:
    """說明文字漏掉一家，使用者會以為那家沒在被盯著（使用者實際回報過）。"""
    labels = {"opnsense": "OPNsense", "pfsense": "pfSense",
              "fortigate": "FortiGate", "paloalto": "Palo Alto",
              "mikrotik": "MikroTik"}
    missing_label = [v for v in FIREWALL_VENDORS if v not in labels]
    assert not missing_label, f"新廠牌要在這裡補上顯示名稱：{missing_label}"
    for locale in ("zh-TW", "en-US", "ja-JP"):
        hint = json.loads(_read(FRONTEND / "src" / "i18n" / f"{locale}.json"))["fw_changes"]["hint"]
        for vendor in FIREWALL_VENDORS:
            assert labels[vendor] in hint, f"{locale} 的規則異動說明少了 {labels[vendor]}"


# ─────────────────── 其餘會逐廠牌列舉的地方 ───────────────────

@pytest.mark.parametrize(
    ("path", "what"),
    [
        ("app/services/fw_lookup.py", "IP 詳細資料的防火牆反查"),
        ("app/api/v1/endpoints/nat.py", "NAT 來源標示與篩選"),
        ("app/api/v1/endpoints/system_settings.py", "整合是否存在（選單顯示用）"),
        ("app/services/system_transfer/registry.py", "系統匯出／匯入的資料表分類"),
        ("scripts/../scripts/jt-ipam-sync.py", "排程同步"),
    ],
)
def test_place_knows_every_vendor(path: str, what: str) -> None:
    root = BACKEND.parent if path.startswith("scripts") else BACKEND
    src = _read(root / path.replace("scripts/../", ""))
    for vendor in FIREWALL_VENDORS:
        assert vendor in src, f"{what}（{path}）少了 {vendor}"


#: 稽核的 object_type 不是機械式的 `<廠牌>_firewall`：MikroTik 的物件是「路由器」
#: （同一套整合也涵蓋交換器），叫它 firewall 會與畫面上的用語對不起來。
AUDIT_OBJECT_TYPE = {
    "opnsense": "opnsense_firewall", "pfsense": "pfsense_firewall",
    "fortigate": "fortigate_firewall", "paloalto": "paloalto_firewall",
    "mikrotik": "mikrotik_router",
}


def test_audit_can_name_every_integration_instance() -> None:
    """沒有對照時稽核的「目標」只會顯示截斷 UUID，多台同型整合就分不出是哪一台。"""
    src = _read(BACKEND / "app" / "api" / "v1" / "endpoints" / "audit.py")
    missing_key = [v for v in FIREWALL_VENDORS if v not in AUDIT_OBJECT_TYPE]
    assert not missing_key, f"新廠牌要在這裡寫下稽核 object_type：{missing_key}"
    for vendor in FIREWALL_VENDORS:
        key = AUDIT_OBJECT_TYPE[vendor]
        assert f'"{key}"' in src, f"稽核目標名稱對照少了 {key}"


def test_precedence_sources_have_display_names() -> None:
    """來源優先序頁沒有對照就直接印出小寫的鍵（使用者回報看到 `paloalto`／`zabbix`）。"""
    from app.services.arp_precedence import ARP_SOURCES
    from app.services.hostname import DEFAULT_ORDER

    needed = set(DEFAULT_ORDER) | set(ARP_SOURCES)
    for locale in ("zh-TW", "en-US", "ja-JP"):
        names = json.loads(
            _read(FRONTEND / "src" / "i18n" / f"{locale}.json"))["hostnameSrc"]["src"]
        missing = sorted(s for s in needed if s not in names)
        assert not missing, f"{locale} 的來源優先序少了顯示名稱：{missing}"


def test_monitoring_integrations_actually_feed_liveness() -> None:
    """**登記成「會過期」還不夠 —— 要真的有資料寫回 IP，才能列進上線判定。**

    Zabbix 踩過：契約裡登記好好的，同步卻只寫自己的鏡像表，於是判定拿不到、
    設定頁也列不出來，看起來像「不支援」（使用者發現的）。
    """
    from app.services.evidence import LIVENESS_SOURCES, aging_sources

    monitoring = {"scanner", "librenms", "wazuh", "zabbix"}
    missing = sorted(monitoring - set(LIVENESS_SOURCES))
    assert not missing, f"這些來源會過期卻沒進上線判定清單：{missing}"
    assert monitoring <= set(aging_sources())


def test_evidence_contract_knows_every_vendor() -> None:
    """防火牆給的證據要逐來源登記，否則 `is_aging` 會安靜回 False。"""
    from app.services.evidence import SOURCES

    for vendor in FIREWALL_VENDORS:
        assert vendor in SOURCES, f"證據契約少了 {vendor}"
        assert f"arp:{vendor}" in SOURCES, f"證據契約少了 arp:{vendor}"


# ─────────────────── 刻意還沒跟上的地方（要寫下來，不要靠記得）───────────────────

def test_known_vendor_limited_features_are_declared() -> None:
    """有兩個功能**刻意**只做部分廠牌 —— 把理由寫在這裡，免得下次被當成漏掉補一補。

    - **對外開放服務**（`detect_exposed_services`）目前只讀 OPNsense 的放行規則與
      各家共用的 NAT 表。FortiGate 的政策與 PAN-OS 的 App-ID 規則**不等於連接埠可達**，
      直接塞進去會製造假的曝險（與 PVE 防火牆那份規格書同一個判斷）。
    - **規則劣化偵測**（`detect_fw_rule_rot`）的「any-any 放行 / WAN 開管理埠」只做
      pfSense（資料形狀最穩定）；懸空 NAT 那一項則是各家都有（走 NAT 表）。

    真的要擴到其他廠牌時，要先想清楚「這條規則代表對外可達嗎」，而不是把欄位對一對。
    """
    src = _read(BACKEND / "app" / "services" / "anomaly.py")
    assert "OPNsenseRule" in src, "對外開放服務的規則來源改了？連帶要重新評估這個限制"
    assert "PfSenseFirewall" in src, "規則劣化偵測的來源改了？連帶要重新評估這個限制"
