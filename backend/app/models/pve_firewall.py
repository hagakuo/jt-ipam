"""Proxmox VE 防火牆 model（東西向／主機層分段管制）。

與外層防火牆（OPNsense／pfSense／FortiGate）分開：PVE 規則管的是「同一個虛擬化環境裡
這台 VM 能不能被那台碰到」，不是「網際網路能不能進來」，因此**不併入對外開放服務清單**。

`PVEFirewallState` 是本模組的核心：規則本身無法說明結果，要合併三個開關與各層預設政策
才知道實際姿態，所以把判定收斂進 `posture`，其他地方一律只讀它。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy import DateTime as SADateTime
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDPrimaryKeyMixin

# posture 取值：見 docs/SPEC_PVE_FIREWALL_zh-TW.md §3
POSTURE_UNPROTECTED = "unprotected"   # 三個開關任一沒開 → 規則不生效
POSTURE_OPEN = "open"                 # 生效但 policy_in=ACCEPT → 未命中一律放行
POSTURE_FILTERED = "filtered"         # policy_in=DROP 且有 ACCEPT 規則 → 正常允許清單
POSTURE_BLOCKED = "blocked"           # policy_in=DROP 但無 ACCEPT 規則 → 全擋（常是誤設）


class PVEFirewallRule(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "pve_firewall_rules"

    instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("proxmox_instances.id", ondelete="CASCADE"),
        nullable=False, index=True)
    # 規則掛在哪一層決定它的意義，因此是一等欄位而不是塞進 raw
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    node_name: Mapped[str | None] = mapped_column(String(128))
    vmid: Mapped[int | None] = mapped_column(Integer)
    guest_kind: Mapped[str | None] = mapped_column(String(8))
    pos: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    direction: Mapped[str | None] = mapped_column(String(8))
    action: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    proto: Mapped[str | None] = mapped_column(String(16))
    dport: Mapped[str | None] = mapped_column(String(64))
    sport: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str | None] = mapped_column(Text)
    dest: Mapped[str | None] = mapped_column(Text)
    iface: Mapped[str | None] = mapped_column(String(64))
    macro: Mapped[str | None] = mapped_column(String(64))
    macro_expanded: Mapped[str | None] = mapped_column(Text)
    group_ref: Mapped[str | None] = mapped_column(String(64))
    comment: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    synced_at: Mapped[datetime] = mapped_column(
        SADateTime(timezone=True), server_default=func.now(), nullable=False)


class PVEFirewallState(Base, UUIDPrimaryKeyMixin):
    """每台 guest 的「實際姿態」。

    ⚠️ PVE API **不回傳未設定的欄位**，缺席代表沿用內建預設值而非「沒有設定」，
    因此政策欄位另存 `*_explicit`，UI 才能區分「設成 ACCEPT」與「沒設（繼承）」。
    """

    __tablename__ = "pve_firewall_state"
    __table_args__ = (
        UniqueConstraint("instance_id", "vmid", name="uq_pve_fw_state_instance_vmid"),
    )

    instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("proxmox_instances.id", ondelete="CASCADE"),
        nullable=False, index=True)
    vmid: Mapped[int] = mapped_column(Integer, nullable=False)
    guest_kind: Mapped[str | None] = mapped_column(String(8))
    node_name: Mapped[str | None] = mapped_column(String(128))

    cluster_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    guest_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    nic_firewall: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    cluster_policy_in: Mapped[str | None] = mapped_column(String(8))
    cluster_policy_out: Mapped[str | None] = mapped_column(String(8))
    guest_policy_in: Mapped[str | None] = mapped_column(String(8))
    guest_policy_out: Mapped[str | None] = mapped_column(String(8))

    cluster_policy_in_explicit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False)
    guest_policy_in_explicit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    guest_enabled_explicit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    effective: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    posture: Mapped[str] = mapped_column(String(16), nullable=False, default=POSTURE_UNPROTECTED)
    synced_at: Mapped[datetime] = mapped_column(
        SADateTime(timezone=True), server_default=func.now(), nullable=False)


class PVEFirewallGroup(Base, UUIDPrimaryKeyMixin):
    """安全群組（展開後存規則內容，UI 不必二次查詢）。"""

    __tablename__ = "pve_firewall_groups"
    __table_args__ = (
        UniqueConstraint("instance_id", "name", name="uq_pve_fw_group_instance_name"),
    )

    instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("proxmox_instances.id", ondelete="CASCADE"),
        nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    rules: Mapped[list[Any] | None] = mapped_column(JSONB)
    synced_at: Mapped[datetime] = mapped_column(
        SADateTime(timezone=True), server_default=func.now(), nullable=False)


class PVEFirewallIPSet(Base, UUIDPrimaryKeyMixin):
    """IPSet 與 alias 共用一張表（使用上是同一類東西）。

    ⚠️ 同名可在叢集層與 guest 層並存，**guest 層遮蔽叢集層** → 解析必須帶 scope。
    """

    __tablename__ = "pve_firewall_ipsets"

    instance_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("proxmox_instances.id", ondelete="CASCADE"),
        nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    vmid: Mapped[int | None] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    members: Mapped[list[Any] | None] = mapped_column(JSONB)
    members_resolved: Mapped[list[Any] | None] = mapped_column(JSONB)
    synced_at: Mapped[datetime] = mapped_column(
        SADateTime(timezone=True), server_default=func.now(), nullable=False)
