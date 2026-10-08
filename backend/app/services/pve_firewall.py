"""Proxmox VE 防火牆同步（全程唯讀，只打 GET）。

設計要點見 docs/SPEC_PVE_FIREWALL_zh-TW.md。三個實機驗證過的關鍵：

1. **API 不回傳未設定的欄位** —— `options` 只回有設過的鍵（實機叢集層只回
   `enable`/`policy_in`，guest 層甚至只回 `digest`）。缺席代表「沿用 PVE 內建預設」，
   絕不可解讀成「未啟用／無政策」，否則 posture 全盤算錯。
2. **規則存在不等於生效** —— 要三個開關都開：叢集 enable、guest enable、
   以及**每張網卡的 `firewall=1`**（藏在 VM config，不在防火牆 API）。
3. **預設政策比規則更決定結果** —— `policy_in=ACCEPT` 加零條規則等於完全不設防，
   但規則清單看起來乾乾淨淨。因此判定一律用 `posture`，不要各自看規則。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pve_firewall import (
    POSTURE_BLOCKED,
    POSTURE_FILTERED,
    POSTURE_OPEN,
    POSTURE_UNPROTECTED,
    PVEFirewallGroup,
    PVEFirewallIPSet,
    PVEFirewallRule,
    PVEFirewallState,
)
from app.models.virt import ProxmoxInstance

# PVE 內建預設值（API 沒回傳該欄位時套用）。
# 來源：PVE 防火牆文件的預設行為；有疑義時寧可標成「未明設」讓 UI 說清楚。
DEFAULT_CLUSTER_POLICY_IN = "DROP"
DEFAULT_CLUSTER_POLICY_OUT = "ACCEPT"
DEFAULT_GUEST_POLICY_IN = "DROP"
DEFAULT_GUEST_POLICY_OUT = "ACCEPT"
DEFAULT_GUEST_ENABLE = False

_ACCEPTISH = {"ACCEPT"}


def _as_bool(v: Any) -> bool:
    """PVE 布林可能是 1/0、"1"/"0"、True/False。"""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    if isinstance(v, str):
        return v.strip() in {"1", "true", "yes", "on"}
    return False


def nic_firewall_flags(config: dict[str, Any]) -> dict[str, bool]:
    """從 VM config 取每張網卡的 firewall 旗標。

    形如 `net0: virtio=AA:BB:...,bridge=vmbr0,firewall=1`。**這個旗標不在防火牆 API**，
    只看防火牆 API 會把「規則寫好但網卡沒開」誤判成有保護。
    """
    out: dict[str, bool] = {}
    for key, val in (config or {}).items():
        if not key.startswith("net") or not key[3:].isdigit():
            continue
        parts = [p.strip() for p in str(val).split(",")]
        flag = False
        for p in parts:
            if p.startswith("firewall="):
                flag = _as_bool(p.split("=", 1)[1])
        out[key] = flag
    return out


def compute_posture(
    *,
    cluster_enabled: bool,
    guest_enabled: bool,
    nic_flags: dict[str, bool],
    guest_policy_in: str | None,
    has_accept_rule: bool,
) -> tuple[bool, str]:
    """(是否生效, posture)。**UI 與異常偵測只讀這個結果，不要自行拼裝條件。**

    生效條件是三個開關同時成立（網卡至少一張開）。生效之後才看預設政策：
    ACCEPT ＝ 未命中一律放行（最隱形的「其實沒防護」）；DROP 則看有沒有放行規則。
    """
    any_nic = any(nic_flags.values()) if nic_flags else False
    effective = bool(cluster_enabled and guest_enabled and any_nic)
    if not effective:
        return False, POSTURE_UNPROTECTED
    policy = (guest_policy_in or DEFAULT_GUEST_POLICY_IN).upper()
    if policy in _ACCEPTISH:
        return True, POSTURE_OPEN
    return True, (POSTURE_FILTERED if has_accept_rule else POSTURE_BLOCKED)


def parse_rule(raw: dict[str, Any], *, scope: str, node: str | None = None,
               vmid: int | None = None, guest_kind: str | None = None) -> dict[str, Any]:
    """把 PVE 規則正規化。欄位取不到就留 None —— 實機證實未設定的欄位根本不會出現。"""
    action = str(raw.get("action") or "") or None
    rtype = str(raw.get("type") or "") or None       # PVE 用 type 表示方向（in/out）
    return {
        "scope": scope,
        "node_name": node,
        "vmid": vmid,
        "guest_kind": guest_kind,
        "pos": int(raw.get("pos") or 0),
        "direction": rtype,
        "action": action,
        # PVE 的 enable 缺席時代表啟用
        "enabled": _as_bool(raw.get("enable")) if "enable" in raw else True,
        "proto": str(raw.get("proto") or "") or None,
        "dport": str(raw.get("dport") or "") or None,
        "sport": str(raw.get("sport") or "") or None,
        "source": str(raw.get("source") or "") or None,
        "dest": str(raw.get("dest") or "") or None,
        "iface": str(raw.get("iface") or "") or None,
        "macro": str(raw.get("macro") or "") or None,
        "macro_expanded": None,     # 巨集展開表另外維護；未知一律留 None，不猜
        # action 若不是 ACCEPT/DROP/REJECT，PVE 的語意就是「引用安全群組」
        "group_ref": action if action and action.upper() not in
                     {"ACCEPT", "DROP", "REJECT"} else None,
        "comment": str(raw.get("comment") or "") or None,
        "raw": raw,
    }


def has_accept(rules: list[dict[str, Any]]) -> bool:
    """這批規則裡有沒有生效中的 IN 方向放行規則（決定 DROP 政策下是 filtered 還是 blocked）。"""
    for r in rules:
        if not r.get("enabled", True):
            continue
        if (r.get("direction") or "in").lower() != "in":
            continue
        if (r.get("action") or "").upper() == "ACCEPT":
            return True
        if r.get("group_ref"):
            return True      # 引用群組：群組內容可能放行 → 保守視為有放行
    return False


def resolve_members(
    members: list[Any], *, aliases: dict[tuple[str, int | None, str], list[str]],
    scope: str, vmid: int | None, depth: int = 0,
) -> list[str]:
    """展開 IPSet／alias 成員。

    成員可以是位址、網段，**也可以是另一個 alias**（需遞迴）。同名時 **guest 層遮蔽叢集層**，
    所以查找順序是先 (guest, vmid) 再 (datacenter, None)。
    解析不到的成員標成 `unresolved:<原值>` 而不是丟掉 —— 靜默丟掉會讓規則看起來比實際寬鬆。
    """
    out: list[str] = []
    if depth > 3:
        return [f"unresolved:{m}" for m in members]
    for m in members:
        raw = m.get("cidr") if isinstance(m, dict) else m
        val = str(raw or "").strip()
        if not val:
            continue
        if any(c in val for c in "./:") and not val.startswith("dc/"):
            out.append(val)         # 位址或網段
            continue
        key_guest = ("guest", vmid, val)
        key_dc = ("datacenter", None, val)
        nested = aliases.get(key_guest) if scope == "guest" else None
        if nested is None:
            nested = aliases.get(key_dc)
        if nested is None:
            out.append(f"unresolved:{val}")
        else:
            out.extend(resolve_members(
                [{"cidr": x} for x in nested], aliases=aliases,
                scope=scope, vmid=vmid, depth=depth + 1))
    return out


async def replace_rules(
    session: AsyncSession, instance_id: uuid.UUID, rules: list[dict[str, Any]],
) -> int:
    """鏡像取代該實例的規則（PVE 規則沒有穩定識別，逐筆 upsert 不可靠）。"""
    await session.execute(
        delete(PVEFirewallRule).where(PVEFirewallRule.instance_id == instance_id))
    now = datetime.now(UTC)
    for r in rules:
        session.add(PVEFirewallRule(instance_id=instance_id, synced_at=now, **r))
    return len(rules)


async def upsert_state(session: AsyncSession, instance_id: uuid.UUID, row: dict[str, Any]) -> None:
    existing = (await session.execute(
        select(PVEFirewallState).where(
            PVEFirewallState.instance_id == instance_id,
            PVEFirewallState.vmid == row["vmid"],
        ))).scalars().first()
    if existing is None:
        session.add(PVEFirewallState(instance_id=instance_id, **row))
        return
    for k, v in row.items():
        setattr(existing, k, v)
    existing.synced_at = datetime.now(UTC)


async def replace_groups(
    session: AsyncSession, instance_id: uuid.UUID, groups: list[dict[str, Any]],
) -> int:
    await session.execute(
        delete(PVEFirewallGroup).where(PVEFirewallGroup.instance_id == instance_id))
    for g in groups:
        session.add(PVEFirewallGroup(instance_id=instance_id, **g))
    return len(groups)


async def replace_ipsets(
    session: AsyncSession, instance_id: uuid.UUID, ipsets: list[dict[str, Any]],
) -> int:
    await session.execute(
        delete(PVEFirewallIPSet).where(PVEFirewallIPSet.instance_id == instance_id))
    for i in ipsets:
        session.add(PVEFirewallIPSet(instance_id=instance_id, **i))
    return len(ipsets)


# ─────────────────── 同步主流程 ───────────────────
async def sync_firewall(
    session: AsyncSession, instance: ProxmoxInstance, base: str, api_get: Any,
    guests: list[dict[str, Any]],
) -> dict[str, Any]:
    """同步一個 PVE 實例的防火牆。

    `api_get(path) -> data` 由呼叫端注入（沿用 proxmox.py 既有的連線與憑證）。
    `guests`：[{"node": ..., "kind": "qemu"|"lxc", "vmid": int, "config": {...}}]

    任何一段讀取失敗只影響該段，不中止整個防火牆同步（實機常態是部分端點可讀）。
    """
    counts: dict[str, Any] = {"rules": 0, "groups": 0, "ipsets": 0, "guests": 0}
    errors: list[str] = []

    async def _get(path: str) -> Any:
        return await api_get(path)

    # ── 叢集層 ──
    cluster_opts: dict[str, Any] = {}
    try:
        cluster_opts = (await _get("/api2/json/cluster/firewall/options")) or {}
    except Exception as exc:
        errors.append(f"cluster options: {exc}")

    cluster_enabled = _as_bool(cluster_opts.get("enable"))
    c_pol_in = str(cluster_opts.get("policy_in") or "").upper() or None
    c_pol_out = str(cluster_opts.get("policy_out") or "").upper() or None

    all_rules: list[dict[str, Any]] = []
    try:
        for raw in (await _get("/api2/json/cluster/firewall/rules")) or []:
            all_rules.append(parse_rule(raw, scope="datacenter"))
    except Exception as exc:
        errors.append(f"cluster rules: {exc}")

    # ── 安全群組（展開內容）──
    groups: list[dict[str, Any]] = []
    try:
        for g in (await _get("/api2/json/cluster/firewall/groups")) or []:
            name = str(g.get("group") or "")
            if not name:
                continue
            try:
                grules = (await _get(f"/api2/json/cluster/firewall/groups/{name}")) or []
            except Exception:
                grules = []
            groups.append({"name": name, "comment": g.get("comment"),
                           "rules": [parse_rule(r, scope="group") for r in grules]})
    except Exception as exc:
        errors.append(f"groups: {exc}")

    # ── IPSet 與 alias（先收集，再統一展開，因為成員可能互相引用）──
    raw_sets: list[dict[str, Any]] = []
    alias_map: dict[tuple[str, int | None, str], list[str]] = {}
    try:
        for st in (await _get("/api2/json/cluster/firewall/ipset")) or []:
            name = str(st.get("name") or "")
            if not name:
                continue
            try:
                members = (await _get(f"/api2/json/cluster/firewall/ipset/{name}")) or []
            except Exception:
                members = []
            raw_sets.append({"scope": "datacenter", "vmid": None, "kind": "ipset",
                             "name": name, "comment": st.get("comment"), "members": members})
            alias_map[("datacenter", None, name)] = [
                str(m.get("cidr")) for m in members if isinstance(m, dict) and m.get("cidr")]
    except Exception as exc:
        errors.append(f"ipset: {exc}")
    try:
        for al in (await _get("/api2/json/cluster/firewall/aliases")) or []:
            name = str(al.get("name") or "")
            if not name:
                continue
            raw_sets.append({"scope": "datacenter", "vmid": None, "kind": "alias",
                             "name": name, "comment": al.get("comment"),
                             "members": [{"cidr": al.get("cidr")}]})
            alias_map[("datacenter", None, name)] = [str(al.get("cidr") or "")]
    except Exception as exc:
        errors.append(f"aliases: {exc}")

    # ── 節點層 ──
    for node in sorted({g["node"] for g in guests if g.get("node")}):
        try:
            for raw in (await _get(f"/api2/json/nodes/{node}/firewall/rules")) or []:
                all_rules.append(parse_rule(raw, scope="node", node=node))
        except Exception as exc:
            errors.append(f"node {node} rules: {exc}")

    # ── guest 層 ──
    for g in guests:
        node, kind, vmid = g.get("node"), g.get("kind"), g.get("vmid")
        if vmid is None:
            continue
        gopts: dict[str, Any] = {}
        try:
            gopts = (await _get(
                f"/api2/json/nodes/{node}/{kind}/{vmid}/firewall/options")) or {}
        except Exception as exc:
            errors.append(f"{kind}/{vmid} options: {exc}")
        grules: list[dict[str, Any]] = []
        try:
            for raw in (await _get(
                    f"/api2/json/nodes/{node}/{kind}/{vmid}/firewall/rules")) or []:
                grules.append(parse_rule(raw, scope="guest", node=node,
                                         vmid=vmid, guest_kind=kind))
        except Exception as exc:
            errors.append(f"{kind}/{vmid} rules: {exc}")
        all_rules.extend(grules)

        nic_flags = nic_firewall_flags(g.get("config") or {})
        guest_enabled = (_as_bool(gopts.get("enable")) if "enable" in gopts
                         else DEFAULT_GUEST_ENABLE)
        g_pol_in = str(gopts.get("policy_in") or "").upper() or None
        effective, posture = compute_posture(
            cluster_enabled=cluster_enabled,
            guest_enabled=guest_enabled,
            nic_flags=nic_flags,
            guest_policy_in=g_pol_in,
            has_accept_rule=has_accept(grules),
        )
        await upsert_state(session, instance.id, {
            "vmid": vmid, "guest_kind": kind, "node_name": node,
            "cluster_enabled": cluster_enabled, "guest_enabled": guest_enabled,
            "nic_firewall": nic_flags,
            "cluster_policy_in": c_pol_in or DEFAULT_CLUSTER_POLICY_IN,
            "cluster_policy_out": c_pol_out or DEFAULT_CLUSTER_POLICY_OUT,
            "guest_policy_in": g_pol_in or DEFAULT_GUEST_POLICY_IN,
            "guest_policy_out": str(gopts.get("policy_out") or "").upper()
                                or DEFAULT_GUEST_POLICY_OUT,
            "cluster_policy_in_explicit": c_pol_in is not None,
            "guest_policy_in_explicit": g_pol_in is not None,
            "guest_enabled_explicit": "enable" in gopts,
            "effective": effective, "posture": posture,
        })
        counts["guests"] += 1

        # guest 層的 ipset（同名會遮蔽叢集層）
        try:
            for st in (await _get(
                    f"/api2/json/nodes/{node}/{kind}/{vmid}/firewall/ipset")) or []:
                name = str(st.get("name") or "")
                if not name:
                    continue
                try:
                    members = (await _get(
                        f"/api2/json/nodes/{node}/{kind}/{vmid}"
                        f"/firewall/ipset/{name}")) or []
                except Exception:
                    members = []
                raw_sets.append({"scope": "guest", "vmid": vmid, "kind": "ipset",
                                 "name": name, "comment": st.get("comment"),
                                 "members": members})
                alias_map[("guest", vmid, name)] = [
                    str(m.get("cidr")) for m in members
                    if isinstance(m, dict) and m.get("cidr")]
        except Exception:
            pass        # guest 層沒有 ipset 是常態，不算錯誤

    for rs in raw_sets:
        rs["members_resolved"] = resolve_members(
            rs.get("members") or [], aliases=alias_map,
            scope=rs["scope"], vmid=rs.get("vmid"))

    counts["rules"] = await replace_rules(session, instance.id, all_rules)
    counts["groups"] = await replace_groups(session, instance.id, groups)
    counts["ipsets"] = await replace_ipsets(session, instance.id, raw_sets)
    if errors:
        counts["errors"] = errors[:10]
    return counts
