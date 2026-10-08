"""「這個 IP 被哪些防火牆規則管到」—— 反向查詢。

日常維運最常問的是反向問題：不是「這條規則管誰」，而是「這台機器對外開了什麼、
誰能連它」。這裡把各家防火牆（OPNsense、pfSense、FortiGate、Palo Alto、MikroTik）的規則、NAT、
別名與位址物件做成以 IP 為中心的反查（IP 詳細資料的防火牆區塊與「調查」共用）。

比對語意（刻意保守、每筆附命中原因）：
- **明確命中**才列：規則欄位是這個 IP、或是包含它的 CIDR、或是「成員包含它的別名／位址物件」。
  FortiGate／Palo Alto 的政策以物件名稱引用（常常好幾個寫在同一欄），所以先找出涵蓋這個 IP 的物件。
- `any` 不列 —— 每條 any 規則都命中每個 IP，列了等於整頁雜訊；UI 另以一句話註明
  「來源/目的為 any 的規則也適用」。
- 全部確定性查詢；別名成員只認單一 IP 與 CIDR（URL 型別名內容不可判定，跳過）。
"""
from __future__ import annotations

import ipaddress
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


def _field_matches(field: Any, aip: Any, alias_names: set[str]) -> dict[str, Any] | None:
    """規則欄位是否明確涵蓋這個 IP。回傳命中原因；None＝不命中（含 any）。

    回傳的是**結構**（`{"code": ..., "value": ...}`）而不是寫好的句子：這段文字會
    直接顯示在畫面上，寫成中文句子等於不論使用者選英文或日文都看到中文 ——
    實際被回報過。翻譯交給前端的 i18n，後端只講「命中的是哪一種、命中的值是什麼」。
    """
    if field is None:
        return None
    if isinstance(field, dict):
        # pfSense 的 source/destination 物件：{"address": "..."} / {"network": "..."}
        for v in field.values():
            r = _field_matches(v, aip, alias_names)
            if r:
                return r
        return None
    text = str(field).strip()
    if not text or text.lower() in ("any", "*", "all"):
        return None
    if text in alias_names:
        return {"code": "alias_member", "value": text}
    host = text.split("/")[0]
    try:
        if "/" in text:
            if aip in ipaddress.ip_network(text, strict=False):
                return {"code": "net_covers", "value": text}
            return None
        if ipaddress.ip_address(host) == aip:
            return {"code": "exact", "value": text}
    except ValueError:
        return None
    return None


def _match_payload(why_src: dict | None, why_dst: dict | None) -> dict[str, Any]:
    """命中原因＋命中在哪一側，交給前端組句子。"""
    side = "dst" if why_dst else "src"
    why = why_dst or why_src or {}
    return {"side": side, "code": why.get("code"), "value": why.get("value")}


def _member_covers(members: list | None, aip: Any) -> bool:
    for m in members or []:
        t = str(m).strip()
        try:
            if "/" in t:
                if aip in ipaddress.ip_network(t, strict=False):
                    return True
            elif ipaddress.ip_address(t) == aip:
                return True
        except ValueError:
            continue
    return False


def _object_covers(value: Any, aip: Any) -> bool:
    """FortiGate／Palo Alto 位址物件的值涵不涵蓋這個 IP：單一位址、`位址/前綴`、`位址/遮罩`、`起-迄`。

    涵蓋全部位址的物件（FortiGate 的 `all` 是 0.0.0.0/0）不算：每個 IP 都命中，比照規則的 any 不列。
    FQDN、地理位置這類無法以位址判定的一律不命中。
    """
    text = str(value or "").strip()
    if not text:
        return False
    try:
        if "-" in text and "/" not in text:
            lo, hi = (ipaddress.ip_address(x.strip()) for x in text.split("-", 1))
            return lo.version == aip.version and lo <= aip <= hi
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return net.prefixlen > 0 and aip in net
        return ipaddress.ip_address(text) == aip
    except (ValueError, TypeError):
        return False


def _names_match(field: Any, aip: Any, names: set[str]) -> dict[str, Any] | None:
    """FortiGate／Palo Alto 的政策欄位是以逗號串起來的物件名稱（`h-a, h-b`）：逐一比對。"""
    text = str(field or "").strip()
    if not text:
        return None
    for part in [p.strip() for p in text.split(",")] if "," in text else [text]:
        r = _field_matches(part, aip, names)
        if r:
            return r
    return None


def _covering_objects(rows: list[Any], aip: Any) -> dict[Any, dict[str, str]]:
    """{防火牆 id: {涵蓋這個 IP 的物件名稱: 說明}}。群組只要有成員命中（可巢狀，最多幾層）就算。"""
    def descr(o: Any) -> str:
        return str(getattr(o, "comment", None) or getattr(o, "description", None) or "")[:120]

    hit: dict[Any, dict[str, str]] = {}
    groups: list[Any] = []
    for o in rows:
        if o.kind == "group":
            groups.append(o)
        elif _object_covers(o.value, aip):
            hit.setdefault(o.firewall_id, {})[o.name] = descr(o)
    for _ in range(5):            # 群組裡還有群組：一層一層往外擴，到沒有新的為止
        grew = False
        for g in groups:
            names = hit.setdefault(g.firewall_id, {})
            if g.name in names:
                continue
            members = {str(m).strip() for m in (g.members or [])}
            if members & names.keys() or _member_covers(list(members), aip):
                names[g.name] = descr(g)
                grew = True
        if not grew:
            break
    return {k: v for k, v in hit.items() if v}


async def rules_touching_ip(session: AsyncSession, ip: str) -> dict[str, Any]:
    """回傳 {rules, nat, aliases}，每筆附 source_type／防火牆名／命中原因。"""
    from app.models.address import IPAddress
    from app.models.firewall import OPNsenseFirewall, OPNsenseSyncedAlias
    from app.models.firewall_rule import OPNsenseRule
    from app.models.fortigate import FortiGateAddressObject, FortiGateFirewall, FortiGatePolicy
    from app.models.mikrotik import MikroTikAddressList, MikroTikRouter, MikroTikRule
    from app.models.nat import NATTranslation
    from app.models.paloalto import PaloAltoAddressObject, PaloAltoFirewall, PaloAltoPolicy
    from app.models.pfsense import PfSenseFirewall, PfSenseSyncedAlias

    aip = ipaddress.ip_address(ip)
    out: dict[str, Any] = {"rules": [], "nat": [], "aliases": []}

    # ── 別名：這個 IP 在哪些別名裡（其名字之後也拿來比對規則欄位）──
    # 每筆別名都帶防火牆名稱：規則那幾行寫著是哪一台，別名也要 —— 有兩台時才分得出來
    alias_names: set[str] = set()
    opn_names = {f.id: f.name for f in (await session.execute(
        select(OPNsenseFirewall))).scalars().all()}
    for alias in (await session.execute(select(OPNsenseSyncedAlias))).scalars().all():
        if _member_covers(alias.content, aip):
            alias_names.add(alias.name)
            out["aliases"].append({"source_type": "opnsense", "name": alias.name,
                                   "firewall": opn_names.get(alias.firewall_id, "?"),
                                   "firewall_id": str(alias.firewall_id), "ref": alias.name,
                                   "descr": (alias.description or "")[:120]})
    pf_names = {f.id: f.name for f in (await session.execute(
        select(PfSenseFirewall))).scalars().all()}
    for alias in (await session.execute(select(PfSenseSyncedAlias))).scalars().all():
        if _member_covers(alias.members, aip):
            alias_names.add(alias.name)
            out["aliases"].append({"source_type": "pfsense", "name": alias.name,
                                   "firewall": pf_names.get(alias.firewall_id, "?"),
                                   "firewall_id": str(alias.firewall_id), "ref": alias.name,
                                   "descr": (alias.descr or "")[:120]})

    # ── OPNsense 規則 ──
    for r in (await session.execute(
            select(OPNsenseRule).where(OPNsenseRule.enabled.is_(True)))).scalars().all():
        why_src = _field_matches(r.source_net, aip, alias_names)
        why_dst = _field_matches(r.destination_net, aip, alias_names)
        if why_src or why_dst:
            out["rules"].append({
                "source_type": "opnsense", "firewall": opn_names.get(r.firewall_id, "?"),
                "firewall_id": str(r.firewall_id), "ref": str(r.id),
                "action": r.action, "interface": r.interface, "protocol": r.protocol,
                "src": str(r.source_net or "any"), "dst": str(r.destination_net or "any"),
                "dst_port": str(getattr(r, "destination_port", "") or ""),
                "descr": (r.description or "")[:120],
                "match": _match_payload(why_src, why_dst),
            })

    # ── pfSense 規則（JSONB）──
    for fw in (await session.execute(
            select(PfSenseFirewall).where(PfSenseFirewall.rules.is_not(None)))).scalars().all():
        # 規則存在 JSONB、沒有自己的 id：有 tracker 用 tracker，沒有就用在完整清單中的位置
        # （規則頁列的是同一份清單、同樣的順序，所以位置對得上）
        for pos, r in enumerate(fw.rules or []):
            if not isinstance(r, dict) or r.get("disabled"):
                continue
            why_src = _field_matches(r.get("source"), aip, alias_names)
            why_dst = _field_matches(r.get("destination"), aip, alias_names)
            if why_src or why_dst:
                out["rules"].append({
                    "source_type": "pfsense", "firewall": fw.name,
                    "firewall_id": str(fw.id),
                    "ref": str(r["tracker"]) if r.get("tracker") not in (None, "") else f"#{pos}",
                    "action": r.get("type"), "interface": r.get("interface"),
                    "protocol": r.get("protocol"),
                    "src": str(r.get("source") or "any"), "dst": str(r.get("destination") or "any"),
                    "dst_port": str(r.get("destination_port") or ""),
                    "descr": (r.get("descr") or "")[:120],
                    "match": _match_payload(why_src, why_dst),
                })

    # ── FortiGate 位址物件／群組 ──
    # 政策欄位寫的是物件名稱（而且常常好幾個串在一起），不先找出涵蓋這個 IP 的物件，
    # 以物件引用的政策就永遠反查不到。名稱只在同一台防火牆內有意義，所以逐台記。
    fg_names = {f.id: f.name for f in (await session.execute(
        select(FortiGateFirewall))).scalars().all()}
    fg_objs = _covering_objects(list((await session.execute(
        select(FortiGateAddressObject))).scalars().all()), aip)
    for fid, names in fg_objs.items():
        for name in sorted(names):
            out["aliases"].append({"source_type": "fortigate", "name": name,
                                   "firewall": fg_names.get(fid, "?"),
                                   "firewall_id": str(fid), "ref": name, "descr": names[name]})

    # ── FortiGate 政策 ──
    for r in (await session.execute(
            select(FortiGatePolicy))).scalars().all():
        if (r.status or "") == "disable":
            continue
        names = alias_names | set(fg_objs.get(r.firewall_id, {}))
        why_src = _names_match(getattr(r, "srcaddr", None), aip, names)
        why_dst = _names_match(getattr(r, "dstaddr", None), aip, names)
        if why_src or why_dst:
            out["rules"].append({
                "source_type": "fortigate", "firewall": fg_names.get(r.firewall_id, "?"),
                "firewall_id": str(r.firewall_id), "ref": str(r.id),
                "action": r.action, "interface": f"{r.srcintf}->{getattr(r, 'dstintf', '')}",
                "protocol": str(getattr(r, "service", "") or ""),
                "src": str(getattr(r, "srcaddr", "") or ""), "dst": str(getattr(r, "dstaddr", "") or ""),
                "dst_port": "", "descr": (r.name or "")[:120],
                "match": _match_payload(why_src, why_dst),
            })

    # ── Palo Alto 安全政策 ──
    # 服務欄位（`service`）不是 PAN-OS 規則的重點，App-ID 才是 —— 顯示時兩個都給，
    # 不然使用者看到的規則會少掉真正在管的那一半。
    pa_names = {f.id: f.name for f in (await session.execute(
        select(PaloAltoFirewall))).scalars().all()}
    pa_objs = _covering_objects(list((await session.execute(
        select(PaloAltoAddressObject))).scalars().all()), aip)
    for fid, names in pa_objs.items():
        for name in sorted(names):
            out["aliases"].append({"source_type": "paloalto", "name": name,
                                   "firewall": pa_names.get(fid, "?"),
                                   "firewall_id": str(fid), "ref": name, "descr": names[name]})
    for r in (await session.execute(select(PaloAltoPolicy))).scalars().all():
        if r.disabled:
            continue
        names = alias_names | set(pa_objs.get(r.firewall_id, {}))
        why_src = _names_match(getattr(r, "source", None), aip, names)
        why_dst = _names_match(getattr(r, "destination", None), aip, names)
        if why_src or why_dst:
            app_id = str(getattr(r, "application", "") or "")
            svc = str(getattr(r, "service", "") or "")
            out["rules"].append({
                "source_type": "paloalto", "firewall": pa_names.get(r.firewall_id, "?"),
                "firewall_id": str(r.firewall_id), "ref": str(r.id),
                "action": r.action,
                "interface": f"{r.from_zone}->{getattr(r, 'to_zone', '')}",
                "protocol": " / ".join(x for x in (app_id, svc) if x),
                "src": str(getattr(r, "source", "") or ""),
                "dst": str(getattr(r, "destination", "") or ""),
                "dst_port": "", "descr": (r.name or "")[:120],
                "match": _match_payload(why_src, why_dst),
            })

    # ── MikroTik address-list ──
    # RouterOS 的「別名」是逐筆位址的清單（不是一個物件裝很多成員），所以這裡
    # 一列就是一個成員；同名清單只需回報一次。
    mt_names = {f.id: f.name for f in (await session.execute(
        select(MikroTikRouter))).scalars().all()}
    # 去重要看「哪台路由器的哪個清單」：只看清單名稱的話，兩台剛好同名時另一台就消失了
    mt_lists: set[tuple[Any, str]] = set()
    for entry in (await session.execute(select(MikroTikAddressList))).scalars().all():
        key = (entry.router_id, entry.list_name)
        # address 是單一字串 —— 直接傳給 _member_covers 會被逐字元比對，永遠比不到
        # （以前 MikroTik 的 address-list 在這裡從來沒出現過，list: 規則也就反查不到）
        if key in mt_lists or not _member_covers([entry.address], aip):
            continue
        mt_lists.add(key)
        alias_names.add(entry.list_name)
        out["aliases"].append({"source_type": "mikrotik", "name": entry.list_name,
                               "firewall": mt_names.get(entry.router_id, "?"),
                               "firewall_id": str(entry.router_id), "ref": entry.list_name,
                               "descr": (entry.comment or "")[:120]})

    # ── MikroTik 防火牆規則 ──
    # 規則裡寫的可能是位址、也可能是 `list:<清單名>`（同步時的標記），
    # 後者靠上面收集到的 alias_names 命中。
    for r in (await session.execute(select(MikroTikRule).where(
            MikroTikRule.table_name != "mangle"))).scalars().all():
        if r.disabled:
            continue
        why_src = _field_matches(
            (r.src_address or "").removeprefix("list:"), aip, alias_names)
        why_dst = _field_matches(
            (r.dst_address or "").removeprefix("list:"), aip, alias_names)
        if why_src or why_dst:
            out["rules"].append({
                "source_type": "mikrotik", "firewall": mt_names.get(r.router_id, "?"),
                "firewall_id": str(r.router_id), "ref": str(r.id), "table": r.table_name,
                "action": r.action,
                "interface": f"{r.in_interface or ''}->{r.out_interface or ''}",
                "protocol": r.protocol or "",
                "src": r.src_address or "", "dst": r.dst_address or "",
                "dst_port": r.dst_port or "",
                "descr": f"[{r.table_name}/{r.chain or ''}] {(r.comment or '')}"[:120],
                "match": _match_payload(why_src, why_dst),
            })

    # ── NAT：指向（或來自）這個 IP 的對應 ──
    ipa = (await session.execute(
        select(IPAddress).where(IPAddress.ip == ip).limit(1))).scalars().first()
    if ipa is not None:
        for n in (await session.execute(
                select(NATTranslation).where(
                    (NATTranslation.dst_ip_id == ipa.id) | (NATTranslation.src_ip_id == ipa.id),
                    NATTranslation.disabled.is_(False)).limit(50))).scalars().all():
            out["nat"].append({
                "name": n.name, "type": n.type, "protocol": n.protocol,
                "dst_port": n.dst_port, "src_port": n.src_port,
                "source": (n.source_origin or "manual").split(":")[0],
                "descr": (n.description or "")[:120],
            })

    return out


async def attack_surface(session: AsyncSession) -> list[dict[str, Any]]:
    """對外攻擊面清單：從外面可達的 IP:port，每項配 IPAM 身分。

    異常偵測的「對外曝險」是抓問題；這裡是**清單** —— 資安稽核第一個要的東西。
    保守原則同規則劣化：**只列明確可判定的**——
    - NAT port forward（生效中）：目標經 dst_ip_id 連結，或本來就懸空（那本身是警訊）。
    - WAN 介面上、目的為單一 IP 的放行規則（pfSense JSONB＋OPNsense 規則表）。
    - 目的是別名／any／網段的規則**不列**：展開猜測會產生假清單，假清單比沒有更危險
      （稽核拿去簽名的東西不能有猜的成分）。FortiGate 欄位語意逐一驗證後再納入。
    """
    from app.models.address import IPAddress
    from app.models.customer import Customer
    from app.models.firewall import OPNsenseFirewall
    from app.models.firewall_rule import OPNsenseRule
    from app.models.nat import NATTranslation
    from app.models.pfsense import PfSenseFirewall
    from app.models.subnet import Subnet
    from app.models.wazuh import WazuhAgent

    items: list[dict[str, Any]] = []

    async def identity(ip_str: str | None, ip_id: Any = None) -> dict[str, Any]:
        """目標的 IPAM 身分。未登錄不是省略，是警訊 —— 對外開口指向不明主機。"""
        ipa = None
        if ip_id is not None:
            ipa = await session.get(IPAddress, ip_id)
        elif ip_str:
            ipa = (await session.execute(
                select(IPAddress).where(IPAddress.ip == ip_str).limit(1))).scalars().first()
        if ipa is None:
            return {"registered": False}
        sub = await session.get(Subnet, ipa.subnet_id)
        cust = (await session.get(Customer, sub.customer_id)) if (sub and sub.customer_id) else None
        wa = (await session.execute(
            select(WazuhAgent).where(WazuhAgent.ip == str(ipa.ip)).limit(1))).scalars().first()
        return {
            "registered": True, "ip": str(ipa.ip), "ip_id": str(ipa.id),
            "hostname": ipa.hostname, "status": ipa.effective_status,
            # 「設備類型」欄（對外開的是攝影機、NAS 還是伺服器）
            "device_kind": ipa.device_kind, "device_model": ipa.device_model,
            "subnet": str(sub.cidr) if sub else None,
            "customer": cust.name if cust else None,
            "wazuh": None if wa is None else (wa.status or "present"),
        }

    # ── NAT port forwards（各廠牌共用的正規化表）──
    from app.models.fortigate import FortiGateFirewall
    from app.models.mikrotik import MikroTikRouter as _MT
    from app.models.paloalto import PaloAltoFirewall as _PA
    inst_names: dict[str, str] = {}
    for model in (OPNsenseFirewall, PfSenseFirewall, FortiGateFirewall, _PA, _MT):
        for f in (await session.execute(select(model))).scalars().all():
            inst_names[str(f.id)] = f.name
    for n in (await session.execute(
            select(NATTranslation).where(
                NATTranslation.type == "port_forward",
                NATTranslation.disabled.is_(False)).limit(300))).scalars().all():
        ident = await identity(None, n.dst_ip_id) if n.dst_ip_id else {"registered": False}
        # 目標 IP 與埠**都**不明（如 OPNsense 的 Anti-Lockout 自動規則）→ 不可判定，
        # 列出來只是一排「? 未登錄」噪音（使用者回饋）；未登錄但有埠的仍要列——懸空轉發是警訊。
        if not ident.get("ip") and not n.dst_port:
            continue
        origin = (n.source_origin or "manual").split(":")
        items.append({
            "via": "nat", "source": origin[0],
            "firewall": inst_names.get(origin[1]) if len(origin) > 1 else None,
            "name": n.name, "protocol": n.protocol,
            "port": n.dst_port, "descr": (n.description or "")[:120],
            "identity": ident,
        })

    # ── WAN 放行規則、目的為單一 IP ──
    def _single_ip(v: Any) -> str | None:
        if isinstance(v, dict):
            for x in v.values():
                r = _single_ip(x)
                if r:
                    return r
            return None
        t = str(v or "").strip()
        if not t or "/" in t or t.lower() in ("any", "*", "all"):
            return None
        try:
            ipaddress.ip_address(t)
        except ValueError:
            return None
        return t

    for fw in (await session.execute(
            select(PfSenseFirewall).where(PfSenseFirewall.rules.is_not(None)))).scalars().all():
        for r in (fw.rules or []):
            if not isinstance(r, dict) or r.get("disabled"):
                continue
            if str(r.get("type") or "").lower() not in ("pass", "match"):
                continue
            if "wan" not in str(r.get("interface") or "").lower():
                continue
            target = _single_ip(r.get("destination"))
            if not target:
                continue
            items.append({
                "via": "rule", "source": "pfsense", "firewall": fw.name,
                "name": (r.get("descr") or str(r.get("tracker") or ""))[:120],
                "protocol": r.get("protocol"), "port": str(r.get("destination_port") or ""),
                "descr": (r.get("descr") or "")[:120],
                "identity": await identity(target),
            })

    opn_names = {f.id: f.name for f in (await session.execute(
        select(OPNsenseFirewall))).scalars().all()}
    for r in (await session.execute(
            select(OPNsenseRule).where(OPNsenseRule.enabled.is_(True)))).scalars().all():
        if "wan" not in str(r.interface or "").lower():
            continue
        if str(r.action or "").lower() not in ("pass", "accept"):
            continue
        target = _single_ip(r.destination_net)
        if not target:
            continue
        items.append({
            "via": "rule", "source": "opnsense",
            "firewall": opn_names.get(r.firewall_id, "?"),
            "name": (r.description or "")[:120],
            "protocol": r.protocol, "port": str(getattr(r, "destination_port", "") or ""),
            "descr": (r.description or "")[:120],
            "identity": await identity(target),
        })

    items = items[:500]
    await _attach_fqdns(session, items)
    return items


async def _attach_fqdns(session: AsyncSession, items: list[dict[str, Any]]) -> None:
    """替每一項補上「指向這個 IP 的 FQDN」，供 FQDN 視角檢視。

    稽核與對外服務盤點時，人記得的是名字不是位址：問「meet.example.com 對外開了什麼」
    比問「198.51.100.7 開了什麼」自然得多。名稱由 IPAM 已同步的 DNS 記錄推導 ——
    A/AAAA 直接指向該 IP，CNAME 再往上一層（別名同樣到得了那台主機）。
    **不做即時 DNS 查詢**：清單要可重現，且不能因為外部解析變動而每次不同。
    """
    from app.models.dns import DNSRecord, DNSZone

    ips = {str(it["identity"].get("ip")) for it in items if it["identity"].get("ip")}
    if not ips:
        return

    def _fqdn(name: str, zone: str) -> str:
        n, z = (name or "").strip().rstrip("."), (zone or "").strip().rstrip(".")
        if not n or n == "@":
            return z
        return n if (z and n.endswith(f".{z}")) or not z else f"{n}.{z}"

    rows = (await session.execute(
        select(DNSRecord.name, DNSRecord.type, DNSRecord.value, DNSZone.name)
        .join(DNSZone, DNSZone.id == DNSRecord.zone_id)
        .where(DNSRecord.type.in_(("A", "AAAA", "CNAME")))
    )).all()

    by_ip: dict[str, set[str]] = {}
    fqdn_to_ip: dict[str, str] = {}
    cnames: list[tuple[str, str]] = []     # (別名 FQDN, 指向的目標)
    for name, rtype, value, zone in rows:
        fq = _fqdn(str(name), str(zone))
        val = str(value or "").strip().rstrip(".")
        if rtype in ("A", "AAAA"):
            if val in ips:
                by_ip.setdefault(val, set()).add(fq)
                fqdn_to_ip[fq.lower()] = val
        else:
            cnames.append((fq, val))

    # CNAME 逐層跟進（限 3 層，避免自我指向的迴圈）
    for _ in range(3):
        progressed = False
        for alias, target in cnames:
            ip = fqdn_to_ip.get(target.lower())
            if ip and alias.lower() not in fqdn_to_ip:
                by_ip.setdefault(ip, set()).add(alias)
                fqdn_to_ip[alias.lower()] = ip
                progressed = True
        if not progressed:
            break

    for it in items:
        ip = it["identity"].get("ip")
        if ip:
            it["identity"]["fqdns"] = sorted(by_ip.get(str(ip), ()))


async def is_virtual_guest(session: AsyncSession, ip: str | None, mac: str | None = None) -> bool:
    """虛擬化整合回報這個位址（或 MAC）是某台虛擬機／容器的網卡。

    判讀設備類型時用：虛擬化讓 nmap 的 TCP/IP 指紋失準（PVE 的 LXC 容器被判成 HP NAS，2026-10-02），
    定期 OS 偵測、手動探測、探測完成的通知都要用同一個答案，同一台才不會在不同畫面判成不同東西。"""
    return await virtual_guest_kind(session, ip, mac) is not None


#: Proxmox VE 指派給虛擬機／容器網卡的 OUI（Proxmox Server Solutions GmbH）：實體主機的網卡不會是這段
PROXMOX_GUEST_OUI = "bc:24:11:"


async def virtual_guest_kind(session: AsyncSession, ip: str | None, mac: str | None = None) -> str | None:
    """"ct"（LXC 容器）、"vm"（KVM 虛擬機或其他平台的虛擬機）或 None（不知道，不代表實體機）。

    容器一定是 Linux；虛擬機可能是防火牆、Windows（同一個網段裡就有好幾台），判讀時要分開。網卡是 Proxmox 指派的
    MAC（bc:24:11）時，就算盤點沒對到也是 PVE 上的虛擬機或容器（192.0.2.82 的 TrueNAS 虛擬機，對抗式驗證 2026-10-05）。"""
    m = await vm_match_for(session, ip=ip, macs=[mac] if mac else None) if (ip or mac) else None
    if m is not None:
        return "ct" if m.get("kind") == "ct" else "vm"
    if mac and str(mac).lower().startswith(PROXMOX_GUEST_OUI):
        return "vm"
    return None


async def vm_match_for(session: AsyncSession, *, ip: str | None = None,
                       macs: list[str] | None = None) -> dict[str, Any] | None:
    """這個 IP／這些 MAC 是不是虛擬化平台回報的某台 VM。

    對應鏈：VMInterface.primary_ip == ip，或 VMInterface.mac ∈ macs。
    比對得到才回 {vm, cluster, platform}；比對不到回 None ——
    **比對不到不代表是實體機**（虛擬化整合可能沒涵蓋），呼叫端不得反向斷言。
    多筆命中（同 IP 多張網卡）取第一筆即可，都是同一台 VM 的機率遠大於誤配。
    """
    from app.models.virt import VirtCluster, VirtualMachine, VMInterface

    conds = []
    want = {str(m).lower() for m in (macs or []) if m}
    if ip:
        conds.append(VMInterface.primary_ip == ip)
    if want:
        conds.append(VMInterface.mac.in_(sorted(want)))  # bounded: MACs of one IP（macaddr 本身不分大小寫）
    if not conds:
        return None
    from sqlalchemy import or_
    rows = (await session.execute(
        select(VMInterface, VirtualMachine)
        .join(VirtualMachine, VMInterface.vm_id == VirtualMachine.id)
        .where(or_(*conds)).limit(8))).all()
    # 只有 IP 對到、而兩邊的 MAC 都知道卻不同 → DHCP 位址換了主人，不是這台 VM（2026-10-05 iPhone 被標成
    # vm-lab-02 虛擬機）。MAC 對到的優先
    row = next((r for r in rows if r[0].mac and str(r[0].mac).lower() in want), None) or next(
        (r for r in rows if not (want and r[0].mac and str(r[0].mac).lower() not in want)), None)
    if row is None:
        return None
    vm = row[1]
    cluster = await session.get(VirtCluster, vm.cluster_id)
    return {"vm": vm.name,
            "cluster": cluster.name if cluster else None,
            "platform": cluster.type if cluster else "proxmox",
            # PVE 的 qemu（KVM 虛擬機）＝"vm"、lxc 容器＝"ct"；VMware 沒有這個區分（None）
            "kind": vm.kind,
            # 調查用：在哪個節點、現在的狀態、哪張網卡對到的（PVE 的 VMID）
            "node": vm.node, "status": vm.status, "vmid": vm.legacy_vmid,
            "interface": row[0].name,
            "matched_by": "mac" if row[0].mac and str(row[0].mac).lower() in want else "ip"}
