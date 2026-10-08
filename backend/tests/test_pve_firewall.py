"""PVE 防火牆：判定邏輯的對抗式驗證。

這個功能最危險的失敗不是「讀不到資料」，而是**畫面顯示「保護中」但實際沒有保護**。
三個實機驗證過的陷阱各自有測試守著：

1. API **不回傳未設定的欄位** → 缺席必須解讀成「沿用內建預設」而非「未啟用／無政策」
2. 規則存在不等於生效 → 三個開關（叢集／guest／**網卡**）任一沒開就是 unprotected
3. **預設政策比規則更決定結果** → ACCEPT + 零規則 = 完全不設防，但規則清單看起來乾淨
"""
from __future__ import annotations

import pytest

from app.models.pve_firewall import (
    POSTURE_BLOCKED,
    POSTURE_FILTERED,
    POSTURE_OPEN,
    POSTURE_UNPROTECTED,
)
from app.services.pve_firewall import (
    compute_posture,
    has_accept,
    nic_firewall_flags,
    parse_rule,
    resolve_members,
)


# ─────────── 生效旗標 ───────────
def test_nic_flag_is_read_from_vm_config() -> None:
    """網卡的 firewall=1 藏在 VM config，不在防火牆 API —— 漏讀會誤判成有保護。"""
    cfg = {
        "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1",
        "net1": "virtio=AA:BB:CC:DD:EE:00,bridge=vmbr1",          # 沒有 firewall= → False
        "name": "not-a-nic", "scsi0": "local:vm-100-disk-0",
    }
    assert nic_firewall_flags(cfg) == {"net0": True, "net1": False}


@pytest.mark.parametrize("cluster,guest,nics,expected", [
    (False, True, {"net0": True}, POSTURE_UNPROTECTED),     # 叢集沒開
    (True, False, {"net0": True}, POSTURE_UNPROTECTED),     # guest 沒開
    (True, True, {"net0": False}, POSTURE_UNPROTECTED),     # 網卡沒開（最容易漏的一個）
    (True, True, {}, POSTURE_UNPROTECTED),                  # 沒有網卡資料
])
def test_any_switch_off_means_unprotected(cluster, guest, nics, expected) -> None:
    eff, posture = compute_posture(
        cluster_enabled=cluster, guest_enabled=guest, nic_flags=nics,
        guest_policy_in="DROP", has_accept_rule=True)
    assert (eff, posture) == (False, expected), "規則不生效卻沒標成 unprotected → 假的保護感"


def test_accept_policy_without_rules_is_open_not_filtered() -> None:
    """**最隱形的一類**：規則清單乾乾淨淨，但未命中的流量一律放行。"""
    eff, posture = compute_posture(
        cluster_enabled=True, guest_enabled=True, nic_flags={"net0": True},
        guest_policy_in="ACCEPT", has_accept_rule=False)
    assert eff is True
    assert posture == POSTURE_OPEN, "policy_in=ACCEPT 被當成有防護 —— 只看規則就會犯這個錯"


def test_drop_policy_with_and_without_accept_rules() -> None:
    """DROP + 有放行 = 正常允許清單；DROP + 沒有放行 = 全擋（多半是誤設，要提醒）。"""
    _, filtered = compute_posture(
        cluster_enabled=True, guest_enabled=True, nic_flags={"net0": True},
        guest_policy_in="DROP", has_accept_rule=True)
    _, blocked = compute_posture(
        cluster_enabled=True, guest_enabled=True, nic_flags={"net0": True},
        guest_policy_in="DROP", has_accept_rule=False)
    assert filtered == POSTURE_FILTERED
    assert blocked == POSTURE_BLOCKED


def test_missing_policy_falls_back_to_pve_default_not_open() -> None:
    """政策欄位缺席＝沿用 PVE 內建預設（DROP），**不可**當成沒有政策而放行。"""
    _, posture = compute_posture(
        cluster_enabled=True, guest_enabled=True, nic_flags={"net0": True},
        guest_policy_in=None, has_accept_rule=True)
    assert posture == POSTURE_FILTERED, "缺席被誤讀成 ACCEPT/無政策 → 會謊報成不設防"


# ─────────── 規則解析 ───────────
def test_rule_without_enable_field_is_enabled() -> None:
    """實機規則常常沒有 enable 欄位；缺席代表啟用，不是停用。"""
    r = parse_rule({"pos": 0, "type": "in", "action": "ACCEPT"}, scope="datacenter")
    assert r["enabled"] is True
    assert r["direction"] == "in"
    assert r["group_ref"] is None


def test_group_reference_is_detected() -> None:
    """action 不是 ACCEPT/DROP/REJECT 時，PVE 的語意是「引用安全群組」。"""
    r = parse_rule({"pos": 1, "type": "in", "action": "mgmt_group"}, scope="guest", vmid=112)
    assert r["group_ref"] == "mgmt_group"
    assert r["vmid"] == 112


def test_unknown_macro_is_not_guessed() -> None:
    """巨集展開表未涵蓋的值一律留空 —— 猜出來的埠會變成錯誤的稽核依據。"""
    r = parse_rule({"pos": 0, "type": "in", "action": "ACCEPT", "macro": "SomeVendorThing"},
                   scope="datacenter")
    assert r["macro"] == "SomeVendorThing"
    assert r["macro_expanded"] is None


def test_has_accept_ignores_disabled_and_out_direction() -> None:
    rules = [
        {"enabled": False, "direction": "in", "action": "ACCEPT"},   # 停用
        {"enabled": True, "direction": "out", "action": "ACCEPT"},   # 出向不影響入向姿態
    ]
    assert has_accept(rules) is False
    assert has_accept(rules + [{"enabled": True, "direction": "in", "action": "ACCEPT"}]) is True


def test_group_reference_counts_as_possible_accept() -> None:
    """引用群組時內容可能放行 → 保守視為有放行，不可武斷判成全擋。"""
    assert has_accept([{"enabled": True, "direction": "in", "action": "mgmt_group",
                        "group_ref": "mgmt_group"}]) is True


# ─────────── IPSet／alias 展開 ───────────
def test_guest_alias_shadows_datacenter_same_name() -> None:
    """同名時 guest 層遮蔽叢集層 —— 弄反就會把別人的成員掛到這台 guest 上。"""
    aliases = {
        ("datacenter", None, "admins"): ["203.0.113.0/24"],
        ("guest", 112, "admins"): ["198.51.100.5"],
    }
    got = resolve_members([{"cidr": "admins"}], aliases=aliases, scope="guest", vmid=112)
    assert got == ["198.51.100.5"]


def test_unresolvable_member_is_marked_not_dropped() -> None:
    """解析不到就標出來；靜默丟掉會讓規則看起來比實際更寬鬆。"""
    got = resolve_members([{"cidr": "ghost_set"}], aliases={}, scope="datacenter", vmid=None)
    assert got == ["unresolved:ghost_set"]


def test_addresses_pass_through_and_nesting_terminates() -> None:
    aliases = {("datacenter", None, "loop"): ["loop"]}      # 自我指向
    assert resolve_members([{"cidr": "198.51.100.7"}], aliases={},
                           scope="datacenter", vmid=None) == ["198.51.100.7"]
    # 不可無限遞迴
    out = resolve_members([{"cidr": "loop"}], aliases=aliases, scope="datacenter", vmid=None)
    assert out and all("loop" in x for x in out)


# ─────────── 同步流程（以實機回應形狀為準）───────────
@pytest.mark.anyio
async def test_sync_uses_real_device_response_shapes(db_session) -> None:
    """實機形狀：options 只回有設過的鍵；未設定的 guest options 只有 digest。

    這一支同時驗「部分端點讀不到不中止整段同步」——實機常態是 10 支有 9 支可讀。
    """
    from sqlalchemy import select as _sel

    from app.models.pve_firewall import PVEFirewallIPSet, PVEFirewallRule, PVEFirewallState
    from app.models.virt import ProxmoxInstance
    from app.services.pve_firewall import sync_firewall

    inst = ProxmoxInstance(api_url="https://192.0.2.30:8006", auth_username="ro@pve",
                           auth_token_id="jt-ipam")
    db_session.add(inst)
    await db_session.flush()

    responses = {
        # 實機：只回 digest / enable / policy_in，policy_out 根本不在鍵裡
        "/api2/json/cluster/firewall/options": {"digest": "d1", "enable": 1,
                                                "policy_in": "ACCEPT"},
        "/api2/json/cluster/firewall/rules": [
            {"pos": 0, "type": "in", "action": "ACCEPT", "source": "mgmt_hosts", "digest": "d"},
        ],
        "/api2/json/cluster/firewall/groups": [{"group": "mgmt_group", "digest": "d"}],
        "/api2/json/cluster/firewall/groups/mgmt_group": [
            {"pos": 0, "type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "22"},
        ],
        "/api2/json/cluster/firewall/ipset": [{"name": "mgmt_hosts", "digest": "d"}],
        "/api2/json/cluster/firewall/ipset/mgmt_hosts": [{"cidr": "198.51.100.5"},
                                                      {"cidr": "203.0.113.0/24"}],
        "/api2/json/cluster/firewall/aliases": [],
        "/api2/json/nodes/host-1/firewall/rules": [
            {"pos": 0, "type": "in", "action": "DROP", "proto": "tcp", "dport": "23"},
        ],
        # guest 的 options 未設定 → 只有 digest（enable/policy 都缺席）
        "/api2/json/nodes/host-1/qemu/112/firewall/options": {"digest": "d2"},
        "/api2/json/nodes/host-1/qemu/112/firewall/rules": [
            {"pos": 0, "type": "in", "action": "mgmt_group"},
        ],
    }

    calls: list[str] = []

    async def fake_get(path: str):
        calls.append(path)
        if path.endswith("/firewall/ipset") and "/qemu/" in path:
            raise RuntimeError("403 forbidden")     # guest ipset 讀不到 → 不得中止整段
        if path not in responses:
            raise RuntimeError(f"no such endpoint: {path}")
        return responses[path]

    guests = [{"node": "host-1", "kind": "qemu", "vmid": 112,
               "config": {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1"}}]

    counts = await sync_firewall(db_session, inst, "https://192.0.2.30:8006", fake_get, guests)
    await db_session.flush()

    assert counts["rules"] == 3, "叢集 + 節點 + guest 三層的規則都要收進來"
    scopes = {r.scope for r in (await db_session.execute(_sel(PVEFirewallRule).where(
        PVEFirewallRule.instance_id == inst.id))).scalars().all()}
    assert scopes == {"datacenter", "node", "guest"}, f"少了某一層：{scopes}"
    assert counts["groups"] == 1
    assert counts["guests"] == 1

    st = (await db_session.execute(_sel(PVEFirewallState).where(
        PVEFirewallState.instance_id == inst.id))).scalars().one()
    # guest 的 enable 缺席 → 沿用 PVE 預設（未啟用）→ 規則不生效
    assert st.guest_enabled is False
    assert st.guest_enabled_explicit is False, "缺席被當成明設 → UI 會分不出繼承與明設"
    assert st.effective is False
    assert st.posture == POSTURE_UNPROTECTED
    # 叢集 policy_in 是明設的 ACCEPT；policy_out 缺席 → 套用內建預設
    assert (st.cluster_policy_in, st.cluster_policy_in_explicit) == ("ACCEPT", True)
    assert st.cluster_policy_out == "ACCEPT"
    assert st.nic_firewall == {"net0": True}

    # IPSet 成員展開（叢集層）
    sets = (await db_session.execute(_sel(PVEFirewallIPSet).where(
        PVEFirewallIPSet.instance_id == inst.id))).scalars().all()
    adm = next(s for s in sets if s.name == "mgmt_hosts")
    assert adm.members_resolved == ["198.51.100.5", "203.0.113.0/24"]

    # 引用群組的規則要標出 group_ref
    rules = (await db_session.execute(_sel(PVEFirewallRule).where(
        PVEFirewallRule.instance_id == inst.id))).scalars().all()
    assert any(r.group_ref == "mgmt_group" for r in rules)
    # 讀不到的 guest ipset 沒有讓整段停掉
    assert any("/qemu/112/firewall/ipset" in c for c in calls)
