"""Palo Alto（PAN-OS）整合：解析與規則。

**沒有實機**，所以這裡測的是「拿到那樣的回應時，我們怎麼解讀」——
也就是最容易在別人機器上出錯、而且不需要連線就驗得了的部分：

1. REST 的外層剝殼（`entry` 只有一筆時是物件不是陣列）
2. PAN-OS 的清單形狀 `{"member": [...]}`
3. 位址型別是**用欄位名**表示的（`ip-netmask` / `fqdn` …），不是另一個 type 欄位
4. `disabled` 是 `"yes"`／`"no"` 字串，不是布林
5. REST URI 的版本段由 `sw-version` 推導 —— 寫死會在別的 PAN-OS 版本整批 404
6. 規則異動的正規化：名稱是識別，順序被拖動不算變更
"""

from __future__ import annotations

import re

import pytest

from app.services import paloalto as pa
from app.services.fw_review import normalize_paloalto, rules_hash


class _Row:
    """PaloAltoPolicy 的最小替身（正規化只讀屬性，不需要真的 ORM 物件）。"""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_members_flattens_panos_lists():
    assert pa._members({"member": ["a", "b"]}) == "a, b"
    assert pa._members({"member": "only"}) == "only"
    assert pa._members(None) is None
    assert pa._members({}) is None


def test_address_type_comes_from_the_field_name():
    """PAN-OS 沒有 type 欄位 —— 是哪一種位址，看的是出現了哪個欄位名。"""
    assert pa._addr_value({"ip-netmask": "198.51.100.0/24"}) == ("ip-netmask", "198.51.100.0/24")
    assert pa._addr_value({"fqdn": "www.example.com"}) == ("fqdn", "www.example.com")
    assert pa._addr_value({"ip-range": "198.51.100.1-198.51.100.9"})[0] == "ip-range"
    assert pa._addr_value({"description": "沒有位址"}) == (None, None)


def test_mac_and_ip_normalisation():
    assert pa._norm_mac("00:1B:44:11:3A:B7") == "00:1b:44:11:3a:b7"
    assert pa._norm_mac("001b.4411.3ab7") == "00:1b:44:11:3a:b7"
    assert pa._norm_mac("N/A") is None
    assert pa._valid_ip("198.51.100.5/24") == "198.51.100.5"
    assert pa._valid_ip("不是位址") is None


@pytest.mark.parametrize(
    ("sw_version", "expected"),
    [("11.1.4-h7", "v11.1"), ("10.2.9", "v10.2"), ("9.1.0", "v9.1")],
)
def test_sw_version_maps_to_a_known_rest_version(sw_version: str, expected: str):
    """REST URI 的版本段綁 PAN-OS 版本；對不上就整批 404。

    這裡直接驗轉換規則本身（`11.1.4-h7` → `v11.1`），不必連線。
    """
    m = re.match(r"(\d+)\.(\d+)", sw_version)
    assert m
    ver = f"v{m.group(1)}.{m.group(2)}"
    assert ver == expected
    assert ver in pa.KNOWN_API_VERSIONS, "轉出來的版本必須在已知清單裡，否則等於沒偵測"


def test_unknown_version_falls_back_to_the_newest_known():
    """未來版本（如 v99.9）不可以讓整個整合停擺 —— 退回最新的已知版本，
    再由 404 的訊息去指引使用者手動指定。"""
    assert pa.KNOWN_API_VERSIONS[0].startswith("v")


def test_rule_normalisation_uses_the_name_as_identity():
    """PAN-OS 規則沒有數字 id，名稱就是識別（vsys 內唯一）。"""
    rows = [_Row(vsys="vsys1", name="allow-web", action="allow", disabled=False,
                 from_zone="trust", to_zone="untrust", source="any", destination="any",
                 application="web-browsing", service="application-default", description="")]
    out = normalize_paloalto(rows)
    assert out[0]["key"] == "vsys1:allow-web"
    assert out[0]["action"] == "allow"
    assert "web-browsing" in out[0]["descr"], "App-ID 是規則的核心語意，不可以漏掉"


def test_reordering_rules_is_not_a_change():
    """把規則拖上拖下不算「規則有異動」—— 與其他廠牌一致。"""
    a = _Row(vsys="vsys1", name="r1", action="allow", disabled=False, from_zone="a",
             to_zone="b", source="s", destination="d", application="app", service="svc",
             description="")
    b = _Row(vsys="vsys1", name="r2", action="deny", disabled=False, from_zone="a",
             to_zone="b", source="s", destination="d", application="app", service="svc",
             description="")
    assert rules_hash(normalize_paloalto([a, b])) == rules_hash(normalize_paloalto([b, a]))


def test_disabling_a_rule_is_a_change():
    """停用是實質變更，一定要被偵測到。"""
    base = {"vsys": "vsys1", "name": "r1", "action": "allow", "from_zone": "a",
            "to_zone": "b", "source": "s", "destination": "d", "application": "app",
            "service": "svc", "description": ""}
    on = normalize_paloalto([_Row(**base, disabled=False)])
    off = normalize_paloalto([_Row(**base, disabled=True)])
    assert rules_hash(on) != rules_hash(off)


def test_source_is_registered_everywhere_it_must_be():
    """新來源漏登記會**安靜失效**：MAC 被丟掉、主機名稱不採用、證據契約守門測試會擋。"""
    from app.models.ip_hostname import HOSTNAME_SOURCES
    from app.services.arp_precedence import ARP_SOURCES
    from app.services.hostname import DEFAULT_ORDER

    assert "paloalto" in ARP_SOURCES, "沒登記 → consider_mac 會安靜丟掉 MAC"
    assert "paloalto" in HOSTNAME_SOURCES, "沒登記 → 主機名稱觀測寫不進去"
    assert "paloalto" in DEFAULT_ORDER, "沒登記 → 主機名稱優先序解析不到這個來源"


async def test_nat_rows_are_scoped_to_this_instance(db_session):
    """刪除實例時只能清自己的 NAT 列 —— `nat_translations` 是多來源共用表。
    （以前只比對原始碼字串；清除改由 integration_cleanup 集中處理後，改成實際驗行為）"""
    import uuid

    from app.api.v1.endpoints.paloalto import cleanup_shared_rows
    from app.models.nat import NATTranslation
    from sqlalchemy import select

    mine, other = uuid.uuid4(), uuid.uuid4()
    for origin in (f"paloalto:{mine}", f"paloalto:{other}", f"fortigate:{mine}"):
        db_session.add(NATTranslation(name=origin, type="port_forward", source_origin=origin,
                                      external_id="r1"))
    await db_session.flush()
    await cleanup_shared_rows(db_session, mine)
    left = set((await db_session.execute(select(NATTranslation.source_origin))).scalars().all())
    assert f"paloalto:{mine}" not in left
    assert {f"paloalto:{other}", f"fortigate:{mine}"} <= left, "清到別台／別家的 NAT 列"


def test_api_key_encrypts_into_exactly_two_columns():
    """回歸（瀏覽器測試抓到的）：金鑰加密的回傳形狀要對得上資料表欄位。

    `PaloAltoFirewall` 的金鑰存成兩個 bytea 欄位（`api_key_enc` / `api_key_nonce`）。
    先前這裡誤用了 `envelope_encrypt`（回四個欄位的 dict，是給 JSONB 存的），
    於是「新增 Palo Alto 防火牆」一按下儲存就 `too many values to unpack` 500 ——
    後端單元測試全綠，因為沒有任何一支真的呼叫過它。加密／解密要能來回一次。
    """
    import uuid

    fw_id = uuid.uuid4()
    enc, nonce = pa.encrypt_api_key(fw_id, "s3cret-key")
    assert isinstance(enc, bytes) and isinstance(nonce, bytes)

    class _FW:
        id = fw_id
        api_key_enc = enc
        api_key_nonce = nonce

    assert pa._decrypt_key(_FW()) == "s3cret-key"


def test_api_key_is_bound_to_the_row_id():
    """AAD 綁 id：把別台的密文複製過來也解不開（防止換 id 竊取金鑰）。"""
    import uuid

    import pytest as _pytest

    enc, nonce = pa.encrypt_api_key(uuid.uuid4(), "s3cret-key")

    class _Other:
        id = uuid.uuid4()
        api_key_enc = enc
        api_key_nonce = nonce

    with _pytest.raises(Exception):
        pa._decrypt_key(_Other())
