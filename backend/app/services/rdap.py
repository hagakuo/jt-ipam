"""RDAP 線上查詢（RFC 9083）→ Subnet 匯入計畫。

為什麼是 RDAP 而不是各家自己的 API：RDAP 是註冊管理機構的標準查詢協定，回的是 JSON，
RIPE 與 TWNIC 共用同一支客戶端就夠，不必為每家寫一份解析。

**TWNIC 的位置容易誤解**：台灣的 IP 網段權威來源是 APNIC（TWNIC 是它底下的 NIR），
所以查詢入口是 `rdap.apnic.net`，APNIC 會把台灣網段自動轉到 `twnic.rdap.apnic.net`。
`rdap.twnic.net.tw` 這個看似理所當然的網址並不存在（實測連不上）。

⚠️ **RDAP 查不到 handle → 網段**。entity 查詢在 APNIC 直接回 404，就算 RIPE 回 200，
回應裡也不含 `networks`。所以這裡只做「IP / CIDR → 網段」，handle 那條路要走貼上 whois
文字（`services/ripe_twnic.py`）。不要在 UI 上放一個做不到的 handle 查詢欄位。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from app.core.safe_http import UnsafeOutboundURL, safe_request

# 每個來源的查詢入口。兩者都會視網段轉址到實際的註冊管理機構，`safe_request`
# 會在每次轉址後重新做 SSRF 檢查。
RDAP_SOURCES: dict[str, str] = {
    "ripe": "https://rdap.db.ripe.net",
    "twnic": "https://rdap.apnic.net",
}

_TIMEOUT = 20.0


class RdapError(RuntimeError):
    """查詢失敗（連不上、查無資料、對方回非預期內容）—— 屬上游問題。"""


class RdapInputError(RdapError):
    """使用者輸入不是有效的 IP / CIDR —— 屬用戶端問題，端點要回 400 而不是 502。"""


@dataclass
class RdapNetwork:
    cidrs: list[str] = field(default_factory=list)
    handle: str | None = None
    name: str | None = None
    country: str | None = None
    net_type: str | None = None
    status: list[str] = field(default_factory=list)
    remarks: list[str] = field(default_factory=list)
    entities: list[dict[str, Any]] = field(default_factory=list)
    source_url: str | None = None


def normalize_query(raw: str) -> str:
    """把使用者輸入正規化成可放進 RDAP 路徑的 IP 或 CIDR。

    同時是**輸入驗證**：只接受真的能解析成位址或網段的字串，其餘一律拒絕 ——
    這個值會被接到查詢網址裡，不能讓任意字串穿過去。
    """
    q = (raw or "").strip()
    if not q:
        raise RdapInputError("請輸入 IP 或 CIDR")
    try:
        if "/" in q:
            return str(ipaddress.ip_network(q, strict=False))
        return str(ipaddress.ip_address(q))
    except ValueError as exc:
        raise RdapInputError(f"不是有效的 IP 或 CIDR：{raw}") from exc


def _cidrs_from(d: dict[str, Any]) -> list[str]:
    """優先用 cidr0_cidrs（RDAP 的 CIDR 擴充），沒有才由起訖位址推。"""
    out: list[str] = []
    for c in d.get("cidr0_cidrs") or []:
        prefix = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if prefix is None or length is None:
            continue
        try:
            out.append(str(ipaddress.ip_network(f"{prefix}/{length}", strict=False)))
        except ValueError:
            continue
    if out:
        return out

    start, end = d.get("startAddress"), d.get("endAddress")
    if start and end:
        try:
            return [str(n) for n in ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end),
            )]
        except (ValueError, TypeError):
            return []
    return []


def _entity_name(ent: dict[str, Any]) -> str | None:
    """從 jCard（vcardArray）取顯示名稱。結構是 ['vcard', [[名稱, {}, 型別, 值], ...]]。"""
    arr = ent.get("vcardArray")
    if not isinstance(arr, list) or len(arr) < 2 or not isinstance(arr[1], list):
        return None
    for item in arr[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return str(item[3]) if item[3] else None
    return None


def parse_rdap_network(d: dict[str, Any]) -> RdapNetwork:
    """把 RDAP 的 ip network 物件轉成我們要的欄位（純函式，好測）。"""
    remarks: list[str] = []
    for r in d.get("remarks") or []:
        remarks.extend(str(x) for x in (r.get("description") or []))

    entities = []
    for e in d.get("entities") or []:
        entities.append({
            "handle": e.get("handle"),
            "roles": e.get("roles") or [],
            "name": _entity_name(e),
        })

    return RdapNetwork(
        cidrs=_cidrs_from(d),
        handle=d.get("handle"),
        name=d.get("name"),
        country=d.get("country"),
        net_type=d.get("type"),
        status=[str(s) for s in (d.get("status") or [])],
        remarks=remarks,
        entities=entities,
    )


async def lookup_ip(source: str, query: str) -> RdapNetwork:
    """向指定來源查一個 IP / CIDR 的網段登記資料。"""
    base = RDAP_SOURCES.get(source)
    if base is None:
        raise RdapInputError(f"未知的查詢來源：{source}")
    q = normalize_query(query)
    url = f"{base}/ip/{q}"
    try:
        resp = await safe_request("GET", url, timeout=_TIMEOUT,
                                  headers={"Accept": "application/rdap+json"})
    except UnsafeOutboundURL as exc:
        raise RdapError(f"查詢被安全檢查擋下：{exc}") from exc
    except Exception as exc:  # 連線失敗 / 逾時
        raise RdapError(f"連不上 {base}：{exc}") from exc

    if resp.status_code == 404:
        raise RdapError(f"{source.upper()} 查無此網段：{q}")
    if resp.status_code >= 400:
        raise RdapError(f"{source.upper()} 回應 HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise RdapError("對方回的不是 JSON（可能不是 RDAP 服務）") from exc
    if not isinstance(data, dict):
        raise RdapError("RDAP 回應格式非預期")

    net = parse_rdap_network(data)
    net.source_url = str(resp.url)
    if not net.cidrs:
        raise RdapError(f"查到資料但取不出網段（{q}）")
    return net
