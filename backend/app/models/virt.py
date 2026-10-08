"""Virtualization：Cluster / VirtualMachine / VMInterface（NetBox 風格）。

主要與 Proxmox VE 對接（Phase 3：Proxmox 為唯一 reference）。Cluster 是
Proxmox cluster；每個 VM 屬於一個 cluster + 可能對映到 jt-ipam Device。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class VirtCluster(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "virt_clusters"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(32), default="proxmox", nullable=False)
    is_standalone: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="SET NULL"),
    )
    # 所屬單位 / 客戶（決定 VM 屬於哪個單位；IP 關係鏈只連同單位的 VM）
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customers.id", ondelete="SET NULL"),
        index=True,
    )

    __table_args__ = (
        CheckConstraint(
            "type IN ('proxmox','vmware','hyper-v','kvm','xenserver','other')",
            name="ck_virt_clusters_type_valid",
        ),
    )


class VirtualMachine(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "virtual_machines"

    cluster_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("virt_clusters.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    legacy_vmid: Mapped[int | None] = mapped_column(BigInteger, index=True)  # Proxmox VMID
    # 非 Proxmox 平台的外部識別碼（ESXi/vCenter 的 MoRef，例如 "vm-101"）。
    # Proxmox 用整數 VMID、VMware 用字串 MoRef，兩者不共用同一欄。
    external_id: Mapped[str | None] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # 所在節點（PVE 是節點名、ESXi 是主機 FQDN）。不設長度上限：長度是對方平台決定的，
    # 猜一個上限的代價是整批同步中斷（issue #25）。
    node: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str | None] = mapped_column(String(8))      # "vm"（qemu）/ "ct"（lxc）
    status: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    vcpus: Mapped[int | None] = mapped_column(Integer)
    memory_mb: Mapped[int | None] = mapped_column(Integer)
    disk_gb: Mapped[int | None] = mapped_column(Integer)

    primary_ip_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_addresses.id", ondelete="SET NULL"),
    )
    # 對映到 jt-ipam Device（如已連結）
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="SET NULL"),
    )

    description: Mapped[str | None] = mapped_column(Text)
    is_template: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        # Proxmox 同一叢集內 VM 名稱可重複（不同 VMID）→ 唯一鍵用 (cluster, vmid) 而非 (cluster, name)。
        # issue #8：名稱相同但 VMID 不同的 VM 原本會撞 vm_cluster_name_uq 而無法匯入。
        UniqueConstraint("cluster_id", "legacy_vmid", name="vm_cluster_vmid_uq"),
        CheckConstraint(
            "status IN ('running','stopped','paused','migrating','unknown')",
            name="ck_virtual_machines_status_valid",
        ),
    )


class VMInterface(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "vm_interfaces"

    vm_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("virtual_machines.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    mac: Mapped[str | None] = mapped_column(MACADDR)
    primary_ip: Mapped[str | None] = mapped_column(INET)
    # 橋接／連接的網段名稱。Proxmox 是 vmbr0 這種短名，但 NSX-T 會產生嵌著 UUID 的
    # 長名稱（實測 78 字元）——外部名稱一律不設上限（issue #25）。
    bridge: Mapped[str | None] = mapped_column(Text)
    vlan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vlans.id", ondelete="SET NULL"),
    )

    __table_args__ = (
        UniqueConstraint("vm_id", "name", name="vmif_vm_name_uq"),
    )


class ProxmoxInstance(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Proxmox VE API 連線實例。"""

    __tablename__ = "proxmox_instances"

    cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("virt_clusters.id", ondelete="CASCADE"),
        nullable=True,   # 同步時依 PVE 叢集名稱自動指派
        index=True,
    )
    api_url: Mapped[str] = mapped_column(Text, nullable=False)
    # 同一 cluster 其他節點的 API URL（換行 / 逗號分隔），主節點故障時自動換手
    extra_api_urls: Mapped[str | None] = mapped_column(Text)
    # Proxmox API token：username + token_id + token_secret
    auth_username: Mapped[str] = mapped_column(String(128), nullable=False)
    auth_token_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # token secret 走 EncryptedSecret 表，這裡只放索引欄位
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # 限定 sync 解析 IP 的子網路範圍（解決重疊網段）。空 = 全域比對。存 subnet UUID 字串陣列。
    scope_subnet_ids: Mapped[list[Any] | None] = mapped_column(JSONB)
    # 信任虛擬化回報的 IP：IPAM 沒有該筆位址時自動建立。**預設關閉** ——
    # 自動收錄會讓那些位址不再出現在「未授權 IP」異常偵測裡（該偵測的判定是
    # 「ARP 看得到、IPAM 沒有」），要不要放棄那道訊號應該由使用者明示。
    auto_create_ips: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default=text("false")
    )
    # 防火牆同步可獨立關閉（讀取失敗時比照 FortiGate 做區段隔離，不影響 VM／網路同步）
    sync_firewall: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False, server_default=text("true")
    )
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=600, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
