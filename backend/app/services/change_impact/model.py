"""變更影響預演的核心型別與版本化規則表。

規則表是唯一的判定來源：每條規則固定 impact／severity／disposition／預設證據強度與原因碼。
AI 不能改這些欄位（規格 §5.6、§10.3）；改規則語意就升 `RULES_VERSION`，舊結果仍以當時的版本呈現。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

ENGINE_VERSION = "1"
RULES_VERSION = "1"


@dataclass(frozen=True)
class Rule:
    category: str          # ipam / dns / dhcp / firewall / nat / monitoring / virt / cert / config / activity / text / physical
    impact: str
    severity: str
    disposition: str
    strength: str          # 預設證據強度；個別發現可以降（例如整合沒設範圍又有重疊網段）
    reason: str
    version: str = "1"


def _r(cat: str, impact: str, sev: str, disp: str, strength: str, reason: str) -> Rule:
    return Rule(cat, impact, sev, disp, strength, reason)


# 規則 id → 規則。命名：<分類>.<情況>
RULES: dict[str, Rule] = {
    # ── 新 IP（改址目標）──
    "ipam.new_ip_assigned": _r("ipam", "potential_disruption", "critical", "blocker", "explicit", "NEW_IP_ASSIGNED"),
    "ipam.new_ip_reserved": _r("ipam", "potential_disruption", "high", "blocker", "explicit", "NEW_IP_RESERVED"),
    "ipam.new_ip_overlap_record": _r("ipam", "unknown", "medium", "review", "explicit", "NEW_IP_OVERLAP_RECORD"),
    "ipam.new_ip_cooldown": _r("ipam", "unknown", "medium", "review", "explicit", "NEW_IP_COOLDOWN"),
    "dhcp.new_ip_reserved": _r("dhcp", "potential_disruption", "high", "blocker", "explicit", "NEW_IP_DHCP_RESERVED"),
    "dhcp.new_ip_leased": _r("dhcp", "potential_disruption", "high", "blocker", "explicit", "NEW_IP_DHCP_LEASED"),
    "dhcp.new_ip_in_pool": _r("dhcp", "unknown", "medium", "review", "explicit", "NEW_IP_IN_DHCP_POOL"),
    # 新位址已經保留給同一張網卡（事先準備好的）：不是衝突，但要記得之後收回舊的保留
    "dhcp.new_ip_reserved_same_mac": _r("dhcp", "reference_only", "info", "informational", "explicit",
                                        "NEW_IP_RESERVED_FOR_SAME_MAC"),
    "activity.new_ip_seen": _r("activity", "potential_disruption", "high", "blocker", "corroborated", "NEW_IP_RECENTLY_SEEN"),
    "network.cross_subnet": _r("ipam", "unknown", "medium", "review", "explicit", "CROSS_SUBNET_CHECK"),
    # ── 舊 IP／裝置 IP 的引用 ──
    "dns.address_record": _r("dns", "change_required", "medium", "review", "explicit", "OLD_IP_IN_ADDRESS_RECORD"),
    "dns.ptr_record": _r("dns", "change_required", "low", "review", "explicit", "OLD_IP_PTR_RECORD"),
    "dhcp.reservation": _r("dhcp", "change_required", "medium", "review", "explicit", "OLD_IP_DHCP_RESERVATION"),
    "dhcp.active_lease": _r("dhcp", "potential_disruption", "high", "review", "explicit", "IP_ACTIVE_LEASE"),
    "dhcp.pool_member": _r("dhcp", "reference_only", "info", "informational", "explicit", "IP_IN_DHCP_POOL"),
    "fw.rule_exact": _r("firewall", "change_required", "high", "review", "explicit", "FW_RULE_EXACT"),
    "fw.rule_group": _r("firewall", "change_required", "high", "review", "explicit", "FW_RULE_VIA_OBJECT"),
    "fw.rule_range": _r("firewall", "reference_only", "low", "review", "explicit", "FW_RULE_RANGE"),
    "fw.rule_range_both": _r("firewall", "reference_only", "info", "informational", "explicit", "FW_RULE_RANGE_COVERS_BOTH"),
    "fw.rule_disabled": _r("firewall", "reference_only", "info", "informational", "explicit", "FW_RULE_DISABLED"),
    # 反向比對（「不是這些位址」）：不估算通行結果，列為未知（規格 §5.3）
    "fw.rule_negated": _r("firewall", "unknown", "medium", "review", "explicit", "FW_RULE_NEGATED"),
    "fw.object_member": _r("firewall", "change_required", "high", "review", "explicit", "FW_OBJECT_MEMBER"),
    "fw.object_shared": _r("firewall", "change_required", "high", "review", "explicit", "FW_OBJECT_SHARED"),
    "nat.translation": _r("nat", "change_required", "high", "review", "explicit", "NAT_TRANSLATION"),
    "nat.translation_disabled": _r("nat", "reference_only", "info", "informational", "explicit", "NAT_TRANSLATION_DISABLED"),
    "monitoring.zabbix_host": _r("monitoring", "change_required", "medium", "review", "explicit", "ZABBIX_HOST"),
    "monitoring.wazuh_agent": _r("monitoring", "reference_only", "low", "review", "explicit", "WAZUH_AGENT"),
    "monitoring.librenms_device": _r("monitoring", "change_required", "medium", "review", "explicit", "LIBRENMS_DEVICE"),
    "monitoring.ocs_inventory": _r("monitoring", "reference_only", "info", "informational", "explicit", "OCS_INVENTORY"),
    "monitoring.rustdesk_peer": _r("monitoring", "reference_only", "info", "informational", "explicit", "RUSTDESK_PEER"),
    "virt.vm_interface": _r("virt", "reference_only", "info", "informational", "inferred", "VM_INTERFACE"),
    "cert.ip_san": _r("cert", "change_required", "high", "review", "explicit", "CERT_IP_SAN"),
    "cert.dns_san_only": _r("cert", "reference_only", "info", "informational", "explicit", "CERT_DNS_SAN_ONLY"),
    "config.subnet_gateway": _r("config", "potential_disruption", "critical", "review", "explicit", "SUBNET_GATEWAY"),
    "config.subnet_dns_server": _r("config", "change_required", "high", "review", "explicit", "SUBNET_DNS_SERVER"),
    "config.jump_host": _r("config", "change_required", "high", "review", "explicit", "JUMP_HOST"),
    "config.vpn_endpoint": _r("config", "change_required", "high", "review", "explicit", "VPN_ENDPOINT"),
    "config.integration_endpoint": _r("config", "change_required", "high", "review", "explicit", "INTEGRATION_ENDPOINT"),
    "config.dhcp_server_ip": _r("config", "potential_disruption", "high", "review", "explicit", "DHCP_SERVER_ADDRESS"),
    "text.hint": _r("text", "unknown", "low", "review", "inferred", "TEXT_MENTIONS_ADDRESS"),
    "activity.old_ip_active": _r("activity", "reference_only", "info", "informational", "corroborated", "IP_RECENTLY_ACTIVE"),
    # ── 裝置除役 ──
    "device.recent_activity": _r("activity", "potential_disruption", "high", "review", "corroborated", "DEVICE_STILL_ACTIVE"),
    "device.hosts_running_workloads": _r("virt", "potential_disruption", "critical", "blocker", "inferred",
                                         "DEVICE_HOSTS_RUNNING_WORKLOADS"),
    "device.hosts_stopped_workloads": _r("virt", "reference_only", "medium", "review", "inferred",
                                         "DEVICE_HOSTS_STOPPED_WORKLOADS"),
    "device.is_vm": _r("virt", "reference_only", "info", "informational", "explicit", "DEVICE_IS_VM"),
    "device.cables": _r("physical", "change_required", "low", "review", "explicit", "DEVICE_CABLES"),
    "device.power": _r("physical", "reference_only", "info", "informational", "explicit", "DEVICE_POWER"),
    "device.rack": _r("physical", "reference_only", "info", "informational", "explicit", "DEVICE_RACK"),
    "device.cert_agent": _r("cert", "change_required", "medium", "review", "explicit", "DEVICE_CERT_AGENT"),
    "device.vpn_tunnel": _r("config", "change_required", "high", "review", "explicit", "DEVICE_VPN_TUNNEL"),
    "device.circuit": _r("physical", "change_required", "medium", "review", "explicit", "DEVICE_CIRCUIT"),
    "device.nat_device": _r("nat", "change_required", "high", "review", "explicit", "DEVICE_NAT"),
    "device.no_ips": _r("ipam", "reference_only", "info", "informational", "explicit", "DEVICE_HAS_NO_IPS"),
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_DISP_RANK = {"blocker": 0, "review": 1, "informational": 2}


@dataclass
class Evidence:
    key: str
    source_type: str
    object_type: str
    label: str
    payload: dict[str, Any]
    integration_ref: str | None = None
    object_id: uuid.UUID | None = None
    object_key: str | None = None
    observed_at: datetime | None = None
    collected_at: datetime | None = None
    freshness: str = "unknown"
    # 讀取時重新檢查的可見性：("ip"|"subnet"|"device", id)、("global", None)、("admin", None)
    visibility: tuple[str, uuid.UUID | None] = ("global", None)

    def payload_hash(self) -> str:
        # 不含觀察時間：主機每次被掃到時間就變，但證據的內容沒變（快照雜湊靠它判斷核准是否過期）
        return _hash({"k": self.key, "t": self.object_type, "p": self.payload})


@dataclass
class Finding:
    rule_id: str
    subject_type: str
    subject_label: str
    evidence_keys: list[str]
    subject_id: uuid.UUID | None = None
    subject_key: str | None = None
    match_kind: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    path: list[dict[str, Any]] = field(default_factory=list)
    strength: str | None = None          # None ＝規則預設
    suggested_action: dict[str, Any] | None = None
    visibility: tuple[str, uuid.UUID | None] = ("global", None)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    def fingerprint(self) -> str:
        """rule＋穩定的主體＋比對語意＋關係路徑；不含 run／時間（規格 §13.3：前後比較靠它）。"""
        return _hash({"r": self.rule_id, "st": self.subject_type,
                      "s": str(self.subject_id) if self.subject_id else None, "sk": self.subject_key,
                      "m": self.match_kind, "p": [p.get("ref") for p in self.path],
                      "a": self.params.get("address")})

    def sort_key(self) -> str:
        r = self.rule
        return (f"{_DISP_RANK[r.disposition]}{_SEV_RANK[r.severity]}|{r.category:<10}|{self.rule_id:<32}|"
                f"{self.subject_label[:40]}|{self.fingerprint()[:12]}")


@dataclass
class Gap:
    category: str
    reason_code: str
    params: dict[str, Any] = field(default_factory=dict)
    source_scope: str | None = None
    affected_analysis: str | None = None
    remediation_hint: str | None = None

    def key(self) -> str:
        return f"{self.category}|{self.reason_code}|{self.source_scope or ''}|{_hash(self.params)[:10]}"


@dataclass
class TargetAddr:
    """分析的根位址：一筆可見的 IP 物件（以 id 為準，不以位址字串挑第一筆）。"""
    ip_id: uuid.UUID
    ip_text: str
    aip: ipaddress.IPv4Address | ipaddress.IPv6Address
    subnet_id: uuid.UUID
    subnet_cidr: str
    vrf_id: uuid.UUID | None
    customer_id: uuid.UUID | None
    hostname: str | None
    mac: str | None
    state: str

    @property
    def namespace(self) -> str:
        return f"vrf:{self.vrf_id or 'global'}"


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False).encode()).hexdigest()


def stable_hash(obj: Any) -> str:
    return _hash(obj)
