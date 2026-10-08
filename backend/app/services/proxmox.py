"""Proxmox VE 同步服務。

API：https://pve.proxmox.com/wiki/Proxmox_VE_API

認證走 API Token（推薦）：
  Authorization: PVEAPIToken=<USER@REALM>!<TOKEN_ID>=<TOKEN_SECRET>

OWASP A04：token secret 走 EncryptedSecret 表（aad 綁 instance id）；不在
ProxmoxInstance 上常駐
A05：所有對外請求一律走 safe_request；TLS verify 預設 True
A09：每次 sync 寫 audit summary
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.safe_http import UnsafeOutboundURL, safe_request, transport_detail
from app.core.security import decrypt_secret, encrypt_secret
from app.core.sqlin import in_values, not_in_values
from app.models.encrypted_secret import EncryptedSecret
from app.models.virt import (
    ProxmoxInstance,
    VirtCluster,
    VirtualMachine,
    VMInterface,
)
from app.services.ip_autocreate import (
    SubnetCandidates,
    addable_subnets,
    match_existing,
    subnet_for_ip_str,
)


class ProxmoxError(Exception):
    pass


def _scope_subnet_uuids(instance: ProxmoxInstance) -> set[Any]:
    """instance.scope_subnet_ids（JSONB 字串陣列）→ UUID set；空回空 set（不限範圍）。"""
    out: set[Any] = set()
    for s in (instance.scope_subnet_ids or []):
        try:
            out.add(uuid.UUID(str(s)))
        except (ValueError, TypeError):
            pass
    return out


def _aad(instance_id) -> bytes:  # type: ignore[no-untyped-def]
    return f"proxmox_instance:{instance_id}:token_secret".encode()


def encrypt_instance_secret(instance_id, raw: str) -> tuple[bytes, bytes]:  # type: ignore[no-untyped-def]
    return encrypt_secret(raw, aad=_aad(instance_id))


async def _get_secret(session: AsyncSession, instance: ProxmoxInstance) -> str:
    row = (
        await session.execute(
            select(EncryptedSecret).where(
                EncryptedSecret.object_type == "proxmox_instance",
                EncryptedSecret.object_id == instance.id,
                EncryptedSecret.field == "token_secret",
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise ProxmoxError(
            f"Proxmox instance {instance.id} has no token secret stored"
        )
    return decrypt_secret(row.ciphertext, row.nonce, aad=_aad(instance.id)).decode("utf-8")


def _auth_header(instance: ProxmoxInstance, secret: str) -> dict[str, str]:
    return {
        "Authorization": (
            f"PVEAPIToken={instance.auth_username}!"
            f"{instance.auth_token_id}={secret}"
        )
    }


def _candidate_urls(instance: ProxmoxInstance) -> list[str]:
    """主 api_url + extra_api_urls（換行 / 逗號分隔），去重後依序回傳。"""
    urls = [instance.api_url.rstrip("/")]
    if instance.extra_api_urls:
        for line in instance.extra_api_urls.replace(",", "\n").splitlines():
            u = line.strip().rstrip("/")
            if u and u not in urls:
                urls.append(u)
    return urls


async def _api_get(
    session: AsyncSession, instance: ProxmoxInstance, path: str,
    *, base_url: str | None = None, timeout: float = 20.0,
) -> dict[str, Any]:
    secret = await _get_secret(session, instance)
    base = (base_url or instance.api_url).rstrip("/")
    url = f"{base}{path}"
    try:
        resp = await safe_request(
            "GET", url, headers=_auth_header(instance, secret),
            timeout=timeout, verify=instance.verify_tls,
        )
    except UnsafeOutboundURL as exc:
        raise ProxmoxError(f"SSRF guard rejected URL: {exc}") from exc
    except httpx.HTTPError as exc:
        raise ProxmoxError(f"transport: {transport_detail(exc)}") from exc
    if resp.status_code != 200:
        raise ProxmoxError(f"Proxmox {path}: {resp.status_code} {resp.text[:200]}")
    return resp.json()  # type: ignore[no-any-return]


async def _resolve_base(session: AsyncSession, instance: ProxmoxInstance) -> str:
    """依序試 candidate URL，回傳第一個能成功打 /version 的 base（多節點容錯）。"""
    last: Exception | None = None
    for base in _candidate_urls(instance):
        try:
            await _api_get(session, instance, "/api2/json/version", base_url=base)
            return base
        except ProxmoxError as exc:
            last = exc
    raise ProxmoxError(f"no reachable endpoint ({len(_candidate_urls(instance))} tried): {last}")


@dataclass
class SyncSummary:
    cluster: str = ""
    nodes_seen: int = 0
    vms_seen: int = 0
    vms_inserted: int = 0
    vms_updated: int = 0
    interfaces_seen: int = 0
    ipam_linked: int = 0
    vms_removed: int = 0
    errors: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)   # 各子同步的細項（如防火牆）

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "nodes_seen": self.nodes_seen,
            "vms_seen": self.vms_seen,
            "vms_removed": self.vms_removed,
            "vms_inserted": self.vms_inserted,
            "vms_updated": self.vms_updated,
            "interfaces_seen": self.interfaces_seen,
            "ipam_linked": self.ipam_linked,
            "errors": self.errors[:20],
            **self.extra,
        }


async def healthcheck(session: AsyncSession, instance: ProxmoxInstance) -> dict[str, Any]:
    base = await _resolve_base(session, instance)
    return await _api_get(session, instance, "/api2/json/version", base_url=base)


def _clean_ip(s: str | None) -> str | None:
    """把 "10.0.0.5/24" / "dhcp" / "manual" 正規化成乾淨 host IP；非 IP 回 None。"""
    if not s:
        return None
    v = s.split("/", 1)[0].strip()
    if v.lower() in ("dhcp", "manual", "auto", ""):
        return None
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return None
    return v


def _parse_netcfg(raw: str, *, lxc: bool) -> tuple[str | None, str | None, str | None]:
    """解析 Proxmox netN 設定字串，回傳 (mac, bridge, ip)。

    qemu： "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10"
    lxc ： "name=eth0,bridge=vmbr0,hwaddr=AA:BB:..,ip=10.0.0.5/24,gw=..."
    """
    parts = dict(p.split("=", 1) for p in raw.split(",") if "=" in p)
    bridge = parts.get("bridge")
    if lxc:
        mac = (parts.get("hwaddr") or "").lower() or None
        ip = _clean_ip(parts.get("ip"))
        return mac, bridge, ip
    # qemu：model=MAC 是第一段值含五個冒號的
    mac = None
    for p in raw.split(","):
        if "=" in p:
            v = p.split("=", 1)[1]
            if v.count(":") == 5:
                mac = v.lower()
                break
    return mac, bridge, None


def _agent_ipv4_by_mac(agent_data: dict[str, Any]) -> dict[str, str]:
    """qemu guest agent network-get-interfaces → {mac: 第一個非 loopback IPv4}。"""
    out: dict[str, str] = {}
    for nic in (agent_data.get("result") or []):
        mac = (nic.get("hardware-address") or "").lower()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        for a in (nic.get("ip-addresses") or []):
            if a.get("ip-address-type") != "ipv4":
                continue
            cand = _clean_ip(a.get("ip-address"))
            if cand and not cand.startswith("127.") and not cand.startswith("169.254."):
                out[mac] = cand
                break
    return out


async def _link_ip_to_ipam(
    session: AsyncSession, ip_text: str | None, mac: str | None, hostname: str | None,
    *, scope_ids: set[Any] | None = None, create_in: SubnetCandidates | None = None, hn_run: Any = None,
    mac_run: Any = None,
) -> Any:
    """把 Proxmox 撈到的 VM/CT IP+MAC+主機名稱對應進 IPAM 的 ip_addresses。

    - 既有 IP：補 MAC（原本空才補，避免蓋掉 scanner/ARP）；記 proxmox 主機名稱觀測
    - 沒有的 IP：**只有 create_in 有值時**（實例開了 auto_create_ips）才在唯一命中的
      子網路新建一筆（discovery_source=proxmox）。落點判斷走 services/ip_autocreate：
      重疊網段造成歧義時不建 —— 這裡原本是 `ORDER BY masklen DESC LIMIT 1`，會在
      兩個單位共用同一個 CIDR 時靜靜挑一個，把 VM 掛到別人的網段底下。
    - **PVE 不知道 IP 時**（qemu 沒裝 guest agent、非 LXC、也沒有 cloud-init ipconfig）
      改用 VM 網卡 MAC 比對「IPAM 已知的 IP」（scanner/ARP 早就學到），只比對既有、絕不新建
    回傳對應到的 IPAddress（給呼叫端回填 VM.primary_ip_id），無對應子網路則 None。
    """

    from app.models.address import IPAddress
    from app.services.hostname import apply_observation

    if not ip_text:
        # MAC 後援：沒有 IP 就無從建立，只能比對既有。比到多筆（重疊網段同 MAC）視為不明確 → 不猜。
        if not mac:
            return None
        m_stmt = select(IPAddress).where(IPAddress.mac == mac)
        if scope_ids:
            m_stmt = m_stmt.where(in_values(IPAddress.subnet_id, scope_ids))
        rows = list((await session.execute(m_stmt.limit(2))).scalars().all())
        if len(rows) != 1:
            return None
        ipa = rows[0]
        if hn_run is not None:
            hn_run.report(ipa, hostname)
        elif hostname:
            await apply_observation(session, ip=ipa, source="proxmox", hostname=hostname)
        return ipa

    # 先找既有紀錄（重疊網段下同 IP 可能有多筆 → 限定在 scope 內，並取第一筆而非
    # scalar_one_or_none，後者會在多筆時炸掉整批同步）
    ipa, ambiguous = await match_existing(session, ip_text, scope_ids)
    if ambiguous:
        return None          # 重疊網段又沒設範圍：不猜是哪個單位的，也不可以新建
    if ipa is None:
        if create_in is None:
            return None                       # 沒開「信任虛擬化取得的 IP」→ 不建
        subnet_id = subnet_for_ip_str(create_in, ip_text)
        if subnet_id is None:
            return None                       # 沒有唯一落點（無包含網段或重疊歧義）→ 不建
        ipa = IPAddress(subnet_id=subnet_id, ip=ip_text, state="active",
                        discovery_source="proxmox")
        if mac:
            ipa.mac = mac
            ipa.mac_source = "proxmox"
        session.add(ipa)
        await session.flush()
        if mac_run is not None and mac:
            mac_run.report(ipa, mac)     # 同一輪另一台 guest 也報這個 IP 時，建立時的 MAC 也算一票
    elif mac:
        # 兩台 guest 設了同一個 IP：MacRun 在同一輪收齊之後只決定一次，不會每輪來回換（2026-10-05）
        if mac_run is not None:
            mac_run.report(ipa, mac)
        else:
            from app.services.arp_precedence import consider_mac
            await consider_mac(session, ip=ipa, mac=mac, source="proxmox")
    # 多台 PVE guest 可能回報同一 IP（共用/浮動 IP）→ HostnameRun 在同一輪內取固定的一個。
    # 以前用 tiebreak_min 跨輪比較：改名成字典序較大的名字就永遠不會生效（2026-09-26 稽核）
    if hn_run is not None:
        hn_run.report(ipa, hostname)
    elif hostname:
        await apply_observation(session, ip=ipa, source="proxmox", hostname=hostname)
    return ipa


_NODE_IFACE_TYPES = ("eth", "bridge", "bond", "vlan", "ovs")   # 實體NIC / bridge / bond / vlan / OVS*


async def _sync_node_ports(
    session: AsyncSession, node_name: str, node_ip: str | None, host_ifaces: list[dict[str, Any]],
    scope_ids: set[Any] | None = None,
) -> int:
    """把 PVE node 的網路介面（bridge / 實體NIC / bond / vlan）建成該節點裝置的連接埠。

    先用節點管理 IP 找到對應 jt-ipam Device（IPAddress.device_id → primary_ip → 名稱），
    再為每個介面建 device_ports（已存在的同名埠跳過）。
    """
    from sqlalchemy import func

    from app.models.address import IPAddress
    from app.models.device import Device
    from app.models.physical import DevicePort

    dev_id = None
    if node_ip:
        # 重疊網段：若 instance 設了 scope_subnet_ids，IP→IPAddress 比對限定在這些子網路內
        ip_stmt = select(IPAddress).where(func.host(IPAddress.ip) == node_ip)
        if scope_ids:
            ip_stmt = ip_stmt.where(in_values(IPAddress.subnet_id, scope_ids))
        ipa = (await session.execute(ip_stmt)).scalars().first()
        if ipa is not None:
            dev_id = ipa.device_id
            if dev_id is None:
                d = (await session.execute(
                    select(Device).where(Device.primary_ip_id == ipa.id)
                )).scalar_one_or_none()
                dev_id = d.id if d else None
    if dev_id is None:
        d = (await session.execute(
            select(Device).where(func.lower(Device.name) == node_name.lower())
        )).scalar_one_or_none()
        dev_id = d.id if d else None
    if dev_id is None:
        return 0

    existing = {p.name: p for p in (await session.execute(
        select(DevicePort).where(DevicePort.device_id == dev_id)
    )).scalars().all()}
    created = 0
    # name → 此 bridge/bond 的成員介面名（供建立 peer 穿透對應）
    link_members: dict[str, list[str]] = {}
    for itf in host_ifaces:
        name = (itf.get("iface") or "").strip()[:255]   # device_ports.name 上限 255
        itype = (itf.get("type") or "").lower()
        if not name:
            continue
        if not any(k in itype for k in _NODE_IFACE_TYPES):
            continue   # loopback / alias / unknown 不建
        ptype = _pve_port_type(itype)
        members = _pve_members(itf)
        desc = _pve_port_desc(ptype, members)
        if members:
            link_members[name] = members
        cur = existing.get(name)
        if cur is not None:
            # 回填 / 更新 bridge·bond 的類型與對應關係（這些是基礎設施，非手動建立）
            if cur.type != ptype:
                cur.type = ptype
            if desc and cur.description != desc:
                cur.description = desc
            continue
        port = DevicePort(
            device_id=dev_id, name=name, type=ptype,
            description=desc or f"proxmox {itf.get('type') or ''}".strip(),
        )
        session.add(port)
        existing[name] = port   # 同次若再遇同名（理論上不會）走更新分支
        created += 1

    # 單一上行的 bridge/bond → 設 peer_port_id 穿透對應，讓纜線追蹤可沿內部續走
    await session.flush()   # 確保新建埠取得 id 供 FK 參照
    for pname, members in link_members.items():
        if len(members) != 1:
            continue   # 多成員（bond 多 slave）無法以單一 peer 表達，留說明文字
        src = existing.get(pname)
        tgt = existing.get(members[0])
        if src is None or tgt is None or src.id == tgt.id:
            continue
        if src.peer_port_id is None:
            src.peer_port_id = tgt.id
        if tgt.peer_port_id is None:
            tgt.peer_port_id = src.id
    return created


def _pve_port_type(itype: str) -> str:
    """PVE 介面 type → device_ports.type。"""
    t = itype.lower()
    if "bridge" in t:
        return "bridge"
    if "bond" in t:
        return "bond"
    if "vlan" in t:
        return "vlan"
    return "network"


def _pve_members(itf: dict[str, Any]) -> list[str]:
    """bridge → bridge_ports（bond/NIC）；bond → slaves（成員 NIC）。"""
    t = (itf.get("type") or "").lower()
    if "bridge" in t:
        raw = (itf.get("bridge_ports") or "").strip()
        return [m for m in raw.split() if m and m.lower() != "none"]
    if "bond" in t:
        raw = (itf.get("slaves") or itf.get("bond_slaves") or "").strip()
        return [m for m in raw.split() if m]
    return []


def _pve_port_desc(ptype: str, members: list[str]) -> str | None:
    if not members:
        return None
    if ptype == "bridge":
        return "橋接 → " + ", ".join(members)
    if ptype == "bond":
        return "聚合 → " + ", ".join(members)
    return None


async def _upsert_iface(
    session: AsyncSession, vm_id: uuid.UUID, name: str,
    mac: str | None, bridge: str | None, ip: str | None,
    known: dict[tuple[Any, str], VMInterface] | None = None,
) -> None:
    """`known`：整個叢集的網卡先載好（{(vm_id, 名稱): 列}），就不必每張網卡查一次。"""
    if known is not None:
        obj = known.get((vm_id, name))
    else:
        obj = (await session.execute(
            select(VMInterface).where(VMInterface.vm_id == vm_id, VMInterface.name == name)
        )).scalar_one_or_none()
    if obj is None:
        obj = VMInterface(vm_id=vm_id, name=name, mac=mac, bridge=bridge, primary_ip=ip)
        session.add(obj)
        if known is not None:
            known[(vm_id, name)] = obj
    else:
        obj.mac = mac
        obj.bridge = bridge
        if ip:  # 沒抓到新 IP 時保留舊值
            obj.primary_ip = ip


async def _derive_cluster(
    session: AsyncSession, instance: ProxmoxInstance, base: str,
) -> tuple[str, bool]:
    """問 PVE /cluster/status → (叢集名稱, 是否獨立節點)。

    有 type=cluster 的項 → clustered，用其 name；否則用 type=node 的節點名並標獨立。
    """
    try:
        data = (await _api_get(
            session, instance, "/api2/json/cluster/status", base_url=base,
        )).get("data") or []
    except ProxmoxError:
        data = []
    cl = next((e for e in data if e.get("type") == "cluster" and e.get("name")), None)
    if cl:
        return str(cl["name"]), False
    node = next((e for e in data if e.get("type") == "node" and e.get("name")), None)
    if node:
        return str(node["name"]), True
    from urllib.parse import urlsplit
    return (urlsplit(instance.api_url).hostname or "proxmox"), True


async def _cluster_taken(
    session: AsyncSession, instance: ProxmoxInstance, obj: VirtCluster, standalone: bool,
) -> bool:
    """這個同名叢集是不是別人的（不能共用）。

    叢集以名稱為身分，但名稱不一定唯一：兩台獨立節點都叫 pve 很常見（安裝時的預設習慣），
    ESXi 的叢集也放在同一張表。共用會讓 VMID 相同的 VM 合成一筆，而且各自的清除會互刪對方的 VM。
    - 別的平台（ESXi…）的同名叢集 → 不共用。
    - 獨立節點：已經有**較早建立**的另一個實例在用 → 那是另一台同名主機，不共用。
    - 真的叢集（pvecm）：兩個實例指向同一個叢集是正常的備援設定 → 共用。
    """
    if obj.type != "proxmox":
        return True
    if not standalone:
        return False
    others = (await session.execute(select(ProxmoxInstance).where(
        ProxmoxInstance.cluster_id == obj.id, ProxmoxInstance.id != instance.id,
    ))).scalars().all()
    mine = (instance.created_at, str(instance.id))
    return any((o.created_at, str(o.id)) < mine for o in others if o.created_at and instance.created_at)


async def _upsert_cluster(
    session: AsyncSession, instance: ProxmoxInstance, name: str, standalone: bool,
) -> VirtCluster:
    from urllib.parse import urlsplit

    candidates = [name, f"{name} ({urlsplit(instance.api_url).hostname or instance.id})",
                  f"{name} ({instance.id})"]
    for cand in candidates:
        cand = cand[:128]
        obj = (await session.execute(
            select(VirtCluster).where(VirtCluster.name == cand)
        )).scalar_one_or_none()
        if obj is None:
            obj = VirtCluster(name=cand, type="proxmox", is_standalone=standalone)
            session.add(obj)
            await session.flush()
            return obj
        if not await _cluster_taken(session, instance, obj, standalone):
            obj.is_standalone = standalone
            return obj
    raise ProxmoxError(f"cannot find a free cluster name for {name!r}")


async def sync_instance(
    session: AsyncSession, instance: ProxmoxInstance,
) -> SyncSummary:
    """從 Proxmox cluster 拉所有 VM/CT 並 upsert 到 jt-ipam 對映表。

    叢集名稱以 PVE 為準：clustered → 用 PVE 叢集名；獨立節點 → 用節點名並標 is_standalone。
    instance.cluster_id 於每次同步自動指派/校正。
    """
    summary = SyncSummary()
    # 重疊網段：若 instance 設了 scope_subnet_ids，IP→IPAddress 比對限定在這些子網路內
    scope_ids = _scope_subnet_uuids(instance)
    # 開了「信任虛擬化取得的 IP」才準備候選子網路（沒開就完全不建）
    create_in = await addable_subnets(session, scope_ids) if instance.auto_create_ips else None
    try:
        base = await _resolve_base(session, instance)
        cl_name, standalone = await _derive_cluster(session, instance, base)
        cluster = await _upsert_cluster(session, instance, cl_name, standalone)
        old_cluster_id = instance.cluster_id
        if old_cluster_id != cluster.id:
            instance.cluster_id = cluster.id
            # 叢集改名/改綁 → 既有 VM/CT 一併搬到新叢集，避免重複插入。
            # 舊叢集還有別的實例在用（同名主機拆開的情況）→ 那些 VM 可能是對方的，不搬；
            # 自己的會在這一輪重新建立，舊叢集裡對方沒看到的由對方的清除處理。
            others = (await session.execute(select(ProxmoxInstance.id).where(
                ProxmoxInstance.cluster_id == old_cluster_id,
                ProxmoxInstance.id != instance.id))).first() if old_cluster_id else None
            if old_cluster_id is not None and others is None:
                from sqlalchemy import text as _text
                await session.execute(
                    _text("UPDATE virtual_machines SET cluster_id = :new "
                          "WHERE cluster_id = :old"),
                    {"new": str(cluster.id), "old": str(old_cluster_id)},
                )
        summary.cluster = cluster.name
        nodes_data = await _api_get(session, instance, "/api2/json/nodes", base_url=base)
    except ProxmoxError as exc:
        # issue #44：連不上／認證失敗（所有候選節點都不通、拿不到叢集或節點清單）是硬失敗。
        # 以前記下錯誤後照樣回傳 → 作業顯示「成功、0 筆」，使用者以為環境裡真的沒有 VM。
        # 寫 last_error 後往上拋（跟 DNS 同步一樣），作業才會是「失敗」並帶最後一個錯誤。
        instance.last_error = str(exc)
        await session.commit()
        raise

    nodes = nodes_data.get("data") or []
    summary.nodes_seen = len(nodes)
    fw_guests: list[dict[str, Any]] = []      # 給防火牆同步用（node/kind/vmid/config）

    # 各節點 host 的管理 IP（cluster/status 的 node 項帶 ip）
    node_ip_map: dict[str, str] = {}
    try:
        cs = (await _api_get(
            session, instance, "/api2/json/cluster/status", base_url=base
        )).get("data") or []
        for e in cs:
            if e.get("type") == "node" and e.get("name") and e.get("ip"):
                node_ip_map[str(e["name"])] = str(e["ip"]).split("/")[0]
    except ProxmoxError:
        pass

    _Inst = ProxmoxInstance
    from app.services.hostname_reports import HostnameRun, enabled_peers
    # origin 以叢集為單位：同一個叢集的多個節點實例（故障換手）回報的是同一份資料
    hn_run = HostnameRun(session, source="proxmox",
                         origin=f"proxmox:{instance.cluster_id or instance.id}",
                         peers=await enabled_peers(session, _Inst))
    from app.services.arp_precedence import MacRun
    mac_run = MacRun(session, source="proxmox")

    seen_vmids: set[int] = set()
    # 這個叢集的 guest 與網卡先整批載入（2026-09-30 大量資料測試：以前每台 guest、每張網卡各查一次）
    vms_by_vmid = {v.legacy_vmid: v for v in (await session.execute(
        select(VirtualMachine).where(VirtualMachine.cluster_id == cluster.id))).scalars()}
    known_ifaces = {(i.vm_id, i.name): i for i in (await session.execute(
        select(VMInterface).join(VirtualMachine, VirtualMachine.id == VMInterface.vm_id)
        .where(VirtualMachine.cluster_id == cluster.id))).scalars()}
    for node in nodes:
        node_name = node.get("node")
        if not node_name:
            continue
        # 節點 host 本身的網路（管理 IP + 各介面 IP/MAC）→ IPAM
        nip = node_ip_map.get(node_name)
        if nip and await _link_ip_to_ipam(session, nip, None, node_name,
                                          scope_ids=scope_ids, create_in=create_in,
                                          hn_run=hn_run, mac_run=mac_run):
            summary.ipam_linked += 1
        try:
            host_ifaces = (await _api_get(
                session, instance, f"/api2/json/nodes/{node_name}/network", base_url=base
            )).get("data") or []
            for itf in host_ifaces:
                addr = _clean_ip(itf.get("address"))
                hw = (itf.get("hwaddr") or "").strip().lower() or None
                if addr and await _link_ip_to_ipam(session, addr, hw, node_name,
                                                   scope_ids=scope_ids, create_in=create_in,
                                                   hn_run=hn_run, mac_run=mac_run):
                    summary.ipam_linked += 1
            # 把節點網路介面（bridge / 實體NIC / bond / vlan）建成該節點裝置的連接埠
            await _sync_node_ports(session, node_name, nip, host_ifaces, scope_ids)
        except ProxmoxError:
            hn_run.hold(node_name)     # 讀不到節點網路：它先前回報的名稱先保留
        # VMs (qemu)
        try:
            vms = (await _api_get(
                session, instance, f"/api2/json/nodes/{node_name}/qemu", base_url=base
            )).get("data") or []
        except ProxmoxError as exc:
            summary.errors.append(f"{node_name}/qemu: {exc}")
            vms = []
        # Containers (lxc)
        try:
            cts = (await _api_get(
                session, instance, f"/api2/json/nodes/{node_name}/lxc", base_url=base
            )).get("data") or []
        except ProxmoxError as exc:
            summary.errors.append(f"{node_name}/lxc: {exc}")
            cts = []

        entries = [("vm", e) for e in vms] + [("ct", e) for e in cts]
        for kind, entry in entries:
            vmid = int(entry.get("vmid") or 0)
            if vmid == 0:
                continue
            summary.vms_seen += 1
            seen_vmids.add(vmid)
            existing = vms_by_vmid.get(vmid)

            status = str(entry.get("status") or "unknown")
            if status not in (
                "running", "stopped", "paused", "migrating", "unknown"
            ):
                status = "unknown"

            if existing is None:
                vm = VirtualMachine(
                    cluster_id=cluster.id,
                    legacy_vmid=vmid,
                    name=entry.get("name") or f"{kind}-{vmid}",
                    node=node_name,
                    kind=kind,
                    status=status,
                    vcpus=int(entry.get("cpus") or 0) or None,
                    memory_mb=int(entry.get("maxmem") or 0) // (1024 * 1024) or None,
                    disk_gb=int(entry.get("maxdisk") or 0) // (1024**3) or None,
                    is_template=bool(entry.get("template", False)),
                )
                session.add(vm)
                await session.flush()      # 網卡的外鍵要指向它（兩者沒有 ORM 關聯，順序要自己保證）
                vms_by_vmid[vmid] = vm
                summary.vms_inserted += 1
            else:
                existing.name = entry.get("name") or existing.name
                existing.node = node_name
                existing.kind = kind
                existing.status = status
                existing.vcpus = int(entry.get("cpus") or 0) or None
                existing.memory_mb = int(entry.get("maxmem") or 0) // (1024 * 1024) or None
                existing.disk_gb = int(entry.get("maxdisk") or 0) // (1024**3) or None
                existing.is_template = bool(entry.get("template", False))
                summary.vms_updated += 1
                vm = existing

            # 網卡：qemu / lxc 都有 /config（格式不同），由 _parse_netcfg 處理
            kind_path = "qemu" if kind == "vm" else "lxc"
            cfg_failed = False
            first_linked = None
            try:
                cfg = (await _api_get(
                    session, instance,
                    f"/api2/json/nodes/{node_name}/{kind_path}/{vmid}/config",
                    base_url=base,
                )).get("data") or {}
            except ProxmoxError:
                cfg = {}
                cfg_failed = True
                hn_run.hold(vm.name)   # 設定讀不到＝不知道它的網卡與 IP：先前回報的名稱保留
            # 防火牆同步要用同一份 config（網卡的 firewall=1 旗標只在這裡看得到），
            # 不另外再打一次 API
            fw_guests.append({"node": node_name, "kind": kind_path,
                              "vmid": int(vmid), "config": cfg})

            # qemu running → 用 guest agent 撈活的 IP（以 MAC 對映），等同 ARP
            agent_ips: dict[str, str] = {}
            agent_failed = False
            if kind == "vm" and status == "running":
                try:
                    agent = (await _api_get(
                        session, instance,
                        f"/api2/json/nodes/{node_name}/qemu/{vmid}"
                        "/agent/network-get-interfaces",
                        base_url=base, timeout=6.0,
                    )).get("data") or {}
                    agent_ips = _agent_ipv4_by_mac(agent)
                except ProxmoxError:
                    # agent 沒裝 / VM 沒開 / 無回應逾時 → 略過（best-effort，不拖垮整批同步）。
                    # 這一輪可能不知道它的 IP：先前回報的名稱保留，不要清了下一輪又加回來
                    agent_failed = True
                    hn_run.hold(vm.name)

            # cloud-init ipconfigN → 對應 netN 的靜態 IP（qemu 無 agent 時的後援）
            ipcfg: dict[str, str] = {}
            for k, raw in cfg.items():
                if k.startswith("ipconfig") and isinstance(raw, str):
                    idx = k[len("ipconfig"):]
                    p = dict(x.split("=", 1) for x in raw.split(",") if "=" in x)
                    ip = _clean_ip(p.get("ip"))
                    if ip:
                        ipcfg[f"net{idx}"] = ip

            for key, raw in cfg.items():
                if not key.startswith("net") or not isinstance(raw, str):
                    continue
                summary.interfaces_seen += 1
                mac, bridge, ip = _parse_netcfg(raw, lxc=(kind == "ct"))
                if mac and mac in agent_ips:
                    ip = agent_ips[mac]          # 優先用 agent 的活 IP
                ip = ip or ipcfg.get(key)
                await _upsert_iface(session, vm.id, key, mac, bridge, ip, known=known_ifaces)
                # IP↔MAC↔主機名稱 對應進 IPAM
                # 沒有 IP 也要試（PVE 不知道 IP 時走 MAC 後援比對既有 IP），否則沒裝
                # guest agent 的 VM 永遠對不到、主機名稱與 primary_ip 都補不上。
                if ip or mac:
                    linked = await _link_ip_to_ipam(session, ip, mac, vm.name,
                                                    scope_ids=scope_ids, create_in=create_in,
                                                    hn_run=hn_run, mac_run=mac_run)
                    if linked is not None:
                        summary.ipam_linked += 1
                        # 此次同步第一個對應到的 IP（下面決定要不要當主 IP）
                        if first_linked is None:
                            first_linked = linked.id
            # VM 主 IP（PVE 主控台 noVNC/xterm 用：IP→VM 解析）**每輪重算**。以前只在空的時候設、
            # 之後永不重算：VM 改 IP 或 VMID 被重複使用時，從舊 IP 開主控台會開到錯的、甚至已刪除的
            # guest（2026-09-26 稽核）。設定與 agent 都讀到時照本輪結果（沒對到就清空）；
            # 資料不確定時保留原值，但有找到新的就用新的。
            if first_linked is not None:
                vm.primary_ip_id = first_linked
            elif not cfg_failed and not agent_failed:
                vm.primary_ip_id = None

    # 已從 PVE 刪除的 guest：鏡像也刪（以前永不刪，status 停在最後的值，例如 running）。
    # 只在節點與每個節點的 qemu／lxc 清單都讀到時；限定這個叢集（ESXi 也用同一張表）；
    # 讀到 0 台、之前卻有 → 多半是權限或 API 問題，不刪。網卡列會跟著 CASCADE。
    if not summary.errors and seen_vmids:
        gone = (await session.execute(select(VirtualMachine).where(
            VirtualMachine.cluster_id == cluster.id,
            not_in_values(VirtualMachine.legacy_vmid, seen_vmids)))).scalars().all()
        for g in gone:
            await session.delete(g)
        summary.vms_removed = len(gone)

    # 節點清單與每個節點的 qemu／lxc 清單都讀到了，才清掉這個叢集不再回報的名稱
    # （資料不確定的個別 guest 已在上面 hold）
    await mac_run.finish()
    hn = await hn_run.finish(complete=not summary.errors)
    if hn["breaker"]:
        summary.errors.append(f"hostname cleanup skipped: {hn['breaker']}")

    # ── 防火牆（東西向分段；可獨立關閉）──
    # **區段隔離**：讀不到防火牆不得影響上面已完成的 VM／網路／IPAM 同步。
    # 實機常態是部分端點可讀，整段中止會讓使用者以為整台壞掉（FortiGate 那次的教訓）。
    if getattr(instance, "sync_firewall", False):
        try:
            from app.services.pve_firewall import sync_firewall as _sync_fw

            async def _fw_get(path: str) -> Any:
                return (await _api_get(session, instance, path, base_url=base)).get("data")

            fw_counts = await _sync_fw(session, instance, base, _fw_get, fw_guests)
            summary.extra["firewall"] = fw_counts
        except Exception as exc:
            summary.errors.append(f"firewall: {exc}")

    instance.last_sync_at = datetime.now(UTC)
    instance.last_error = "；".join(summary.errors) if summary.errors else None
    await session.commit()
    return summary


async def sync_cluster(
    session: AsyncSession, instances: list[ProxmoxInstance],
) -> SyncSummary:
    """同一 cluster 多個節點連線 → 自動挑健康的那台同步（故障換手）。

    Proxmox API 是 cluster-aware：對任一存活節點查 /nodes 就能拿到整個 cluster 的
    VM/CT，所以只要有一台節點活著就能同步整個叢集。依序 healthcheck，第一台通過的
    就用它同步；全部不通才算失敗（並把各台的錯誤寫回 last_error）。
    """
    last_exc: Exception | None = None
    for inst in instances:
        try:
            await healthcheck(session, inst)
        except ProxmoxError as exc:
            inst.last_error = f"healthcheck failed: {exc}"
            last_exc = exc
            continue
        # 這台活著 → 用它同步整個 cluster
        return await sync_instance(session, inst)
    raise ProxmoxError(
        f"cluster has no reachable node ({len(instances)} tried): {last_exc}"
    )
