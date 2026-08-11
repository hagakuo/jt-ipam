"""VMware ESXi / vCenter 同步（vSphere SOAP，VIM API）。

**自己送 SOAP，不用 pyvmomi**：SDK 會繞過 `safe_request`（SSRF 檢查、每次重導向重新
驗 URL、統一的 verify_tls），而本專案每個對外整合都走那一層，OWASP 又是硬性需求。
只讀不寫的話需要的呼叫其實很少：

    RetrieveServiceContent → Login → CreateContainerView → RetrievePropertiesEx(+Continue) → Logout

同一套實作**同時涵蓋單機 ESXi 與 vCenter**：兩者都是 `/sdk` 上的 VIM API，
差別只在物件層次的深度，而 ContainerView 已經把那件事吸收掉了。

解析一律容錯：不同版本／授權之間欄位有無差異很大（關機的 VM 沒有 `guest.*`、
沒裝 VMware Tools 的沒有 IP、範本沒有 `runtime.host`）。少一個欄位就整批失敗的話，
一台有問題的 VM 會讓整個同步一無所獲。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

import httpx
from defusedxml.ElementTree import fromstring as _safe_xml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import UnsafeOutboundURL, safe_request
from app.core.security import decrypt_secret, encrypt_secret
from app.models.esxi import ESXiInstance

VIM = "urn:vim25"
SOAP_HEADERS = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '"urn:vim25/8.0.2.0"'}
TIMEOUT = 30.0
# 一次取幾台。太大在大型 vCenter 上會拖很久且吃記憶體，太小則來回次數多。
PAGE_SIZE = 200

# 要取的屬性。只取畫面與比對真正會用到的，不整包搬回來。
VM_PROPS = (
    "name",
    "runtime.powerState",
    "runtime.host",
    "config.hardware.numCPU",
    "config.hardware.memoryMB",
    "config.template",
    "config.annotation",
    "guest.hostName",
    "guest.ipAddress",
    "guest.net",
)


class ESXiError(Exception):
    """對外可讀的錯誤（連線、認證、SOAP Fault）。"""


# ────────────────────────── 憑證 ──────────────────────────

def _aad(instance_id: Any) -> bytes:
    return f"esxi_instance:{instance_id}:password".encode()


def encrypt_password(instance_id: Any, raw: str) -> tuple[bytes, bytes]:
    return encrypt_secret(raw, aad=_aad(instance_id))


def _decrypt_password(inst: ESXiInstance) -> str:
    return decrypt_secret(
        inst.password_enc, inst.password_nonce, aad=_aad(inst.id)
    ).decode("utf-8")


# ────────────────────────── SOAP 封包 ──────────────────────────

def _envelope(body: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
        ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"
    )


def _esc(v: Any) -> str:
    """一律跳脫：密碼與名稱可能含 & < >，直接拼接會產生無效 XML 或被誤讀。"""
    return _xml_escape(str(v))


def build_service_content() -> str:
    return _envelope(
        f'<RetrieveServiceContent xmlns="{VIM}">'
        '<_this type="ServiceInstance">ServiceInstance</_this>'
        "</RetrieveServiceContent>"
    )


def build_login(session_manager: str, user: str, password: str) -> str:
    return _envelope(
        f'<Login xmlns="{VIM}">'
        f'<_this type="SessionManager">{_esc(session_manager)}</_this>'
        f"<userName>{_esc(user)}</userName>"
        f"<password>{_esc(password)}</password>"
        "</Login>"
    )


def build_logout(session_manager: str) -> str:
    return _envelope(
        f'<Logout xmlns="{VIM}">'
        f'<_this type="SessionManager">{_esc(session_manager)}</_this>'
        "</Logout>"
    )


def build_container_view(view_manager: str, root: str) -> str:
    return _envelope(
        f'<CreateContainerView xmlns="{VIM}">'
        f'<_this type="ViewManager">{_esc(view_manager)}</_this>'
        f'<container type="Folder">{_esc(root)}</container>'
        "<type>VirtualMachine</type><recursive>true</recursive>"
        "</CreateContainerView>"
    )


def build_retrieve(collector: str, view: str) -> str:
    """對 ContainerView 裡的每一台 VM 取屬性。

    ObjectSpec 指向 view 本身（skip=true，因為 view 自己不是 VM），
    再用 TraversalSpec 沿著 `view` 這個屬性走到實際的 VirtualMachine。
    """
    props = "".join(f"<pathSet>{p}</pathSet>" for p in VM_PROPS)
    return _envelope(
        f'<RetrievePropertiesEx xmlns="{VIM}">'
        f'<_this type="PropertyCollector">{_esc(collector)}</_this>'
        "<specSet>"
        f"<propSet><type>VirtualMachine</type><all>false</all>{props}</propSet>"
        "<objectSet>"
        f'<obj type="ContainerView">{_esc(view)}</obj><skip>true</skip>'
        '<selectSet xsi:type="TraversalSpec">'
        "<name>view</name><type>ContainerView</type><path>view</path><skip>false</skip>"
        "</selectSet>"
        "</objectSet>"
        "</specSet>"
        f"<options><maxObjects>{PAGE_SIZE}</maxObjects></options>"
        "</RetrievePropertiesEx>"
    )


def build_continue(collector: str, token: str) -> str:
    return _envelope(
        f'<ContinueRetrievePropertiesEx xmlns="{VIM}">'
        f'<_this type="PropertyCollector">{_esc(collector)}</_this>'
        f"<token>{_esc(token)}</token>"
        "</ContinueRetrievePropertiesEx>"
    )


def build_destroy_view(view: str) -> str:
    return _envelope(
        f'<DestroyView xmlns="{VIM}">'
        f'<_this type="ContainerView">{_esc(view)}</_this>'
        "</DestroyView>"
    )


# ────────────────────────── 解析 ──────────────────────────

def _tag(el: Any) -> str:
    """去掉命名空間前綴 —— 實機上同一份回應裡兩種寫法都出現過。"""
    t = el.tag
    return t.split("}", 1)[1] if "}" in t else t


def _find(el: Any, name: str) -> Any:
    for c in el.iter():
        if _tag(c) == name:
            return c
    return None


def _text(el: Any, name: str) -> str | None:
    c = _find(el, name)
    if c is None:
        return None
    v = (c.text or "").strip()
    return v or None


def raise_for_fault(xml: str) -> None:
    """SOAP Fault → 可讀的錯誤。

    VMware 把認證失敗也包成 Fault 回 HTTP 500，直接看狀態碼會變成「伺服器錯誤」，
    使用者無從得知其實是帳密打錯。
    """
    root = _safe_xml(xml)
    for el in root.iter():
        if _tag(el) == "Fault":
            msg = _text(el, "faultstring") or _text(el, "localizedMessage") or "SOAP fault"
            raise ESXiError(msg)


def parse_service_content(xml: str) -> dict[str, Any]:
    raise_for_fault(xml)
    root = _safe_xml(xml)
    rv = _find(root, "returnval")
    if rv is None:
        raise ESXiError("RetrieveServiceContent 沒有回傳內容")
    out: dict[str, Any] = {"about": {}}
    for child in rv:
        name = _tag(child)
        if name == "about":
            out["about"] = {_tag(c): (c.text or "").strip() for c in child}
        else:
            out[name] = (child.text or "").strip()
    return out


def _as_int(v: str | None) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_vms(xml: str) -> tuple[list[dict[str, Any]], str | None]:
    """回 (VM 清單, 續抓 token)。

    **token 不能漏**：vCenter 的清單會分頁，只處理第一批不會有任何錯誤訊息，
    只會安靜地少掉一半的機器。
    """
    raise_for_fault(xml)
    root = _safe_xml(xml)
    rv = _find(root, "returnval")
    if rv is None:
        return [], None

    token = None
    out: list[dict[str, Any]] = []
    for child in rv:
        name = _tag(child)
        if name == "token":
            token = (child.text or "").strip() or None
            continue
        if name != "objects":
            continue

        vm: dict[str, Any] = {
            "moid": None, "name": None, "power_state": None, "host": None,
            "vcpus": None, "memory_mb": None, "is_template": False,
            "hostname": None, "ip": None, "notes": None, "nics": [],
        }
        for sub in child:
            st = _tag(sub)
            if st == "obj":
                vm["moid"] = (sub.text or "").strip() or None
                continue
            if st != "propSet":
                continue
            pname = _text(sub, "name")
            val = None
            for c in sub:
                if _tag(c) == "val":
                    val = c
                    break
            if pname is None or val is None:
                continue
            raw = (val.text or "").strip()
            if pname == "name":
                vm["name"] = raw or None
            elif pname == "runtime.powerState":
                vm["power_state"] = raw or None
            elif pname == "runtime.host":
                vm["host"] = raw or None
            elif pname == "config.hardware.numCPU":
                vm["vcpus"] = _as_int(raw)
            elif pname == "config.hardware.memoryMB":
                vm["memory_mb"] = _as_int(raw)
            elif pname == "config.template":
                vm["is_template"] = raw.lower() == "true"
            elif pname == "config.annotation":
                vm["notes"] = raw or None
            elif pname == "guest.hostName":
                vm["hostname"] = raw or None
            elif pname == "guest.ipAddress":
                vm["ip"] = raw or None
            elif pname == "guest.net":
                for nic in val:
                    if _tag(nic) != "GuestNicInfo":
                        continue
                    mac = _text(nic, "macAddress")
                    ips = [
                        (c.text or "").strip()
                        for c in nic if _tag(c) == "ipAddress" and (c.text or "").strip()
                    ]
                    # port group（`network`）＝這張網卡接在哪個網路上。VMware 沒有
                    # 「橋接」的概念，port group 就是對應的東西 —— 之前沒讀，所以那一欄
                    # 一直是空的，而畫面上分不出「沒有這個資料」與「抓失敗」。
                    net = _text(nic, "network")
                    if mac or ips or net:
                        vm["nics"].append({"mac": (mac or "").lower() or None, "ips": ips,
                                           "network": net or None})
        if vm["moid"] or vm["name"]:
            out.append(vm)
    return out, token


# ────────────────────────── 連線 ──────────────────────────

def candidate_urls(inst: ESXiInstance) -> list[str]:
    """主位址 + 備援位址（換行／逗號分隔），去重後依序回傳。

    vCenter 可能有多個位址，或 vCenter 停機時想改打某台 ESXi —— 與 Proxmox 同一套作法。
    """
    urls = [inst.api_url.rstrip("/")]
    for line in (inst.extra_api_urls or "").replace(",", "\n").splitlines():
        u = line.strip().rstrip("/")
        if u and u not in urls:
            urls.append(u)
    return urls


def _sdk_url(base: str) -> str:
    return f"{base.rstrip('/')}/sdk"


async def _call(
    inst: ESXiInstance, body: str, cookie: str | None, *, base: str | None = None,
) -> httpx.Response:
    """對單一位址送一次 SOAP。`base` 未指定時用主位址（登入後就固定在通的那一個）。"""
    headers = dict(SOAP_HEADERS)
    if cookie:
        headers["Cookie"] = cookie
    try:
        return await safe_request(
            "POST", _sdk_url(base or inst.api_url), headers=headers,
            content=body.encode("utf-8"), timeout=TIMEOUT, verify=inst.verify_tls,
        )
    except (UnsafeOutboundURL, httpx.HTTPError) as exc:
        raise ESXiError(f"連線失敗：{exc}") from exc


async def resolve_base(inst: ESXiInstance) -> tuple[str, dict[str, Any]]:
    """依序試候選位址，回傳第一個答得出 ServiceContent 的 (位址, 內容)。

    只有**連線層級**的失敗才換下一個。帳密錯、權限不足這類問題換位址也沒用，
    而且換過去只會得到同一個錯誤、還讓使用者以為是網路問題。
    """
    urls = candidate_urls(inst)
    last: Exception | None = None
    for base in urls:
        try:
            resp = await _call(inst, build_service_content(), None, base=base)
            return base, parse_service_content(resp.text)
        except ESXiError as exc:
            last = exc
            continue
    raise ESXiError(
        f"所有位址都連不上（試了 {len(urls)} 個）：{last}" if len(urls) > 1 else str(last)
    )


class Session:
    """一次登入的生命週期。用 async with 確保**一定會 logout** —— 中途出錯就留著
    session 的話，ESXi 上會累積到達上限而拒絕新連線。"""

    def __init__(self, inst: ESXiInstance) -> None:
        self.inst = inst
        self.cookie: str | None = None
        self.content: dict[str, Any] = {}
        self.base: str | None = None      # 實際連上的位址（備援時可能不是主位址）

    async def __aenter__(self) -> Session:
        self.base, self.content = await resolve_base(self.inst)
        pw = _decrypt_password(self.inst)
        login = await _call(
            self.inst,
            build_login(self.content["sessionManager"], self.inst.username, pw),
            None, base=self.base,
        )
        raise_for_fault(login.text)
        raw_cookie = login.headers.get("set-cookie") or ""
        self.cookie = raw_cookie.split(";", 1)[0] or None
        if not self.cookie:
            raise ESXiError("登入沒有取得 session cookie")
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        try:
            if self.cookie and self.content.get("sessionManager"):
                await _call(self.inst, build_logout(self.content["sessionManager"]),
                            self.cookie, base=self.base)
        except ESXiError:
            pass          # 登出失敗不該蓋掉原本的錯誤

    async def call(self, body: str) -> str:
        # 登入後固定用同一個位址：session cookie 只在那台有效
        resp = await _call(self.inst, body, self.cookie, base=self.base)
        raise_for_fault(resp.text)
        return resp.text

    async def list_vms(self) -> list[dict[str, Any]]:
        view = _text(
            _safe_xml(await self.call(
                build_container_view(self.content["viewManager"], self.content["rootFolder"])
            )),
            "returnval",
        )
        if not view:
            raise ESXiError("建立 ContainerView 失敗")
        collector = self.content["propertyCollector"]
        try:
            vms, token = parse_vms(await self.call(build_retrieve(collector, view)))
            while token:
                more, token = parse_vms(await self.call(build_continue(collector, token)))
                vms.extend(more)
        finally:
            try:
                await self.call(build_destroy_view(view))
            except ESXiError:
                pass      # view 沒清掉不影響結果，ESXi 會隨 session 一起回收
        return vms


async def healthcheck(inst: ESXiInstance) -> dict[str, Any]:
    """測試連線：回產品名稱與版本，順便確認帳密可用。"""
    async with Session(inst) as s:
        about = s.content.get("about") or {}
        return {
            "ok": True,
            "product": about.get("name"),
            "version": about.get("version"),
            "full_name": about.get("fullName"),
        }


async def diagnose(inst: ESXiInstance) -> list[dict[str, Any]]:
    """逐步診斷。沒有實機時這是唯一能看出「卡在哪一步」的方式，
    也是接上真機後對照欄位的起點。"""
    steps: list[dict[str, Any]] = []

    async def step(name: str, fn: Any) -> Any:
        try:
            v = await fn()
            steps.append({"step": name, "ok": True, "detail": v})
            return v
        except Exception as exc:   # 診斷本來就是要把錯誤顯示出來
            steps.append({"step": name, "ok": False, "detail": str(exc)[:300]})
            return None

    content: dict[str, Any] = {}

    base_used: str | None = None

    async def _content() -> str:
        nonlocal content, base_used
        base_used, content = await resolve_base(inst)
        ab = content.get("about") or {}
        extra = f"　位址：{base_used}" if len(candidate_urls(inst)) > 1 else ""
        return f"{ab.get('fullName') or ab.get('name')} (API {ab.get('apiVersion')}){extra}"

    if await step("RetrieveServiceContent", _content) is None:
        return steps

    sess = Session(inst)
    sess.content = content
    sess.base = base_used

    async def _login() -> str:
        pw = _decrypt_password(inst)
        r = await _call(inst, build_login(content["sessionManager"], inst.username, pw),
                        None, base=base_used)
        raise_for_fault(r.text)
        sess.cookie = (r.headers.get("set-cookie") or "").split(";", 1)[0] or None
        if not sess.cookie:
            raise ESXiError("沒有取得 session cookie")
        return "ok"

    if await step("Login", _login) is None:
        return steps
    try:
        await step("RetrievePropertiesEx", lambda: _count_vms(sess))
    finally:
        await sess.__aexit__(None, None, None)
    return steps


async def _count_vms(sess: Session) -> str:
    vms = await sess.list_vms()
    powered = sum(1 for v in vms if v.get("power_state") == "poweredOn")
    tmpl = sum(1 for v in vms if v.get("is_template"))
    return f"{len(vms)} 台（開機 {powered}、範本 {tmpl}）"


# ────────────────────────── 同步 ──────────────────────────

def _scope_ids(inst: ESXiInstance) -> set[Any]:
    out: set[Any] = set()
    for s in (inst.scope_subnet_ids or []):
        try:
            out.add(uuid.UUID(str(s)))
        except (TypeError, ValueError):
            continue
    return out


def pick_vm_ip(candidates: list[str | None]) -> str | None:
    """從 VMware Tools 回報的位址裡挑一個「有用」的。

    實機回報：VM 的 IP 欄出現 `fe80::a64b:c1bf:a707:5638`。鏈路本地位址
    （IPv6 `fe80::/10`、IPv4 `169.254/16`）在同一段之外沒有意義 —— 當不了管理位址，
    也對不到 IPAM 裡的任何子網路。客體還沒拿到位址、或只有 IPv6 自動組態時，
    Tools 就會回報這種位址。

    **寧可留白，也不要填一個沒有用的位址**：留白看得出「還沒拿到」，
    填了 fe80 只會讓人以為那就是它的位址。IPv4 優先 —— IPAM 的子網路、NAT、
    防火牆規則絕大多數以 IPv4 表達。
    """
    import ipaddress as _ip

    v4: list[str] = []
    v6: list[str] = []
    for raw in candidates:
        t = (raw or "").strip()
        if not t:
            continue
        try:
            addr = _ip.ip_address(t)
        except ValueError:
            continue
        if addr.is_link_local or addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            continue
        (v4 if addr.version == 4 else v6).append(str(addr))
    return (v4 or v6 or [None])[0]


async def sync_instance(session: AsyncSession, inst: ESXiInstance) -> dict[str, int]:
    """把 VM 清單鏡像進共用的虛擬化資料表。

    寫進 `virt_clusters` / `virtual_machines` / `vm_interfaces` —— 與 Proxmox 同一組表，
    所以拓樸、AI 對話、MCP 的 `list_vms` 不必為了新平台改一行。

    IP 只比對、不新建（與其他整合一致）：VMware Tools 回報的位址不一定在 IPAM 管的範圍內。
    """
    from app.models.address import IPAddress
    from app.models.virt import VirtCluster, VirtualMachine, VMInterface

    async with Session(inst) as s:
        vms = await s.list_vms()

    now = datetime.now(UTC)
    cluster = None
    if inst.cluster_id:
        cluster = await session.get(VirtCluster, inst.cluster_id)
    if cluster is None:
        cluster = (await session.execute(
            select(VirtCluster).where(VirtCluster.name == inst.name).limit(1)
        )).scalars().first()
    if cluster is None:
        # 用資料表 CHECK 約束早就預留的 "vmware"：ESXi 與 vCenter 都屬同一個平台家族，
        # 而且不必為了新平台改約束。
        cluster = VirtCluster(name=inst.name, type="vmware", is_standalone=True,
                              description=inst.description)
        session.add(cluster)
        await session.flush()
    inst.cluster_id = cluster.id

    scope = _scope_ids(inst)
    seen: set[Any] = set()
    matched_ip = 0

    for v in vms:
        moid = v.get("moid") or v.get("name")
        if not moid:
            continue
        row = (await session.execute(
            select(VirtualMachine).where(
                VirtualMachine.cluster_id == cluster.id,
                VirtualMachine.external_id == str(moid),
            ).limit(1)
        )).scalars().first()
        if row is None:
            row = VirtualMachine(cluster_id=cluster.id, external_id=str(moid),
                                 name=v.get("name") or str(moid))
            session.add(row)
            await session.flush()
        row.name = v.get("name") or row.name
        row.node = v.get("host")
        row.kind = "vm"                      # ESXi 沒有容器的概念
        row.status = "running" if v.get("power_state") == "poweredOn" else "stopped"
        row.vcpus = v.get("vcpus")
        row.memory_mb = v.get("memory_mb")
        row.is_template = bool(v.get("is_template"))
        if v.get("notes"):
            row.description = v["notes"]
        seen.add(row.id)

        # 網卡：鏡像取代（VM 換過網卡設定時舊的要消失）
        await session.execute(
            VMInterface.__table__.delete().where(VMInterface.vm_id == row.id)
        )
        for i, nic in enumerate(v.get("nics") or []):
            session.add(VMInterface(
                vm_id=row.id, name=f"nic{i}", mac=nic.get("mac"),
                bridge=nic.get("network"),
                primary_ip=pick_vm_ip(list(nic.get("ips") or []))))

        # 主要 IP：只比對既有的 IPAddress，不新建。位址挑選見 pick_vm_ip ——
        # 鏈路本地（fe80::/169.254）一律不採用，IPv4 優先。
        cand = pick_vm_ip([v.get("ip"),
                           *(ip for n in (v.get("nics") or []) for ip in (n.get("ips") or []))])
        if cand:
            stmt = select(IPAddress.id).where(func.host(IPAddress.ip) == cand)
            if scope:
                stmt = stmt.where(IPAddress.subnet_id.in_(scope))
            # 重疊網段：取兩筆判斷，剛好一筆才採用 —— 分不出來時不猜
            ids = (await session.execute(stmt.limit(2))).scalars().all()
            if len(ids) == 1:
                row.primary_ip_id = ids[0]
                matched_ip += 1

    # 這次沒看到的 VM → 從清單移除（VM 被刪掉了）
    stale = (await session.execute(
        select(VirtualMachine).where(VirtualMachine.cluster_id == cluster.id)
    )).scalars().all()
    removed = 0
    for row in stale:
        if row.id not in seen:
            await session.delete(row)
            removed += 1

    inst.last_sync_at = now
    inst.last_error = None
    return {"vms": len(vms), "matched_ip": matched_ip, "removed": removed}
