"""Palo Alto（PAN-OS）防火牆整合的資料模型。

**與 FortiGate 最大的不同：PAN-OS 有兩套 API，而且回應格式不一樣。**

- 設定類（安全政策、NAT 政策、位址物件）走 **REST**，回 JSON：
  `GET /restapi/<版本>/Policies/SecurityRules?location=vsys&vsys=vsys1`
- 執行時期狀態（ARP 表、DHCP 租約）**只有 XML API**：
  `GET /api/?type=op&cmd=<show><arp><entry name='all'/></arp></show>`，**回應只有 XML**

URI 裡那個版本號綁的是 **PAN-OS 版本**（v10.1 / v10.2 / v11.0 / v11.1…），寫死會在別的
版本整批失敗 —— 所以存成欄位（`api_version`），留空時由 `show system info` 的 `sw-version`
推導。這是這個整合最容易在別人的機器上壞掉的地方。

認證用 `X-PAN-KEY` 標頭；金鑰由管理員在 PAN-OS 上以
`POST /api/?type=keygen`（帶 user/password）產生，我們只保管金鑰、**不保管帳密**。

多 vsys 的概念對應 FortiGate 的 VDOM；另有 `location=shared` 的共用物件。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PaloAltoFirewall(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """一台 PAN-OS 防火牆（或 Panorama 管理的單台）。"""

    __tablename__ = "paloalto_firewalls"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    api_url: Mapped[str] = mapped_column(Text, nullable=False)   # 例：https://192.0.2.1
    # API 金鑰（AES-GCM；AAD 綁這一列的 id，見 services/paloalto.py）
    api_key_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    api_key_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    #: REST URI 裡的版本段（如 `v11.1`）。留空＝每次同步前由 `show system info` 推導。
    api_version: Mapped[str | None] = mapped_column(String(16))
    #: 要同步的 vsys；留空＝自動探索（探索失敗退回 `vsys1`）
    vsys_list: Mapped[list[str] | None] = mapped_column(ARRAY(String(64)), nullable=True)

    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    # 逐項同步開關（預設保守：只開 ARP，其餘由管理員自己打開）
    sync_dhcp: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_arp: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sync_policies: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_nat: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_addresses: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: 站對站 VPN（IPsec，`show vpn flow`）：一條通道一列、很輕，預設開（0171）
    sync_vpn: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False,
                                           server_default=text("true"))

    #: 限定比對的子網路；留空＝全域（重疊網段下建議設定）
    scope_subnet_ids: Mapped[list[uuid.UUID] | None] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=True,
    )
    description: Mapped[str | None] = mapped_column(Text)


class PaloAltoPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """安全政策的唯讀鏡像（比照 `fortigate_policies`）。

    PAN-OS 的規則沒有數字 id，**名稱就是識別**（同一個 vsys 內唯一）。
    """

    __tablename__ = "paloalto_policies"

    firewall_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("paloalto_firewalls.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    vsys: Mapped[str] = mapped_column(String(64), nullable=False, default="vsys1")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: 規則在該 vsys 內的順序（PAN-OS 是由上而下比對，順序本身就是語意）
    position: Mapped[int | None] = mapped_column(Integer)
    action: Mapped[str | None] = mapped_column(String(16))     # allow / deny / drop / reset-*
    disabled: Mapped[bool | None] = mapped_column(Boolean)
    from_zone: Mapped[str | None] = mapped_column(Text)
    to_zone: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(Text)
    destination: Mapped[str | None] = mapped_column(Text)
    application: Mapped[str | None] = mapped_column(Text)
    service: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)   # type: ignore[type-arg]
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("firewall_id", "vsys", "name", name="paloalto_policy_unique"),
    )


class PaloAltoAddressObject(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """位址物件／位址群組的唯讀鏡像。"""

    __tablename__ = "paloalto_address_objects"

    firewall_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("paloalto_firewalls.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    #: 物件的所在位置：某個 vsys 或 `shared`（共用物件兩邊都看得到，要分得出來）
    vsys: Mapped[str] = mapped_column(String(64), nullable=False, default="vsys1")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: ip-netmask / ip-range / ip-wildcard / fqdn（PAN-OS 的欄位名就是型別）
    obj_type: Mapped[str | None] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="address")
    value: Mapped[str | None] = mapped_column(Text)
    members: Mapped[list | None] = mapped_column(JSONB, nullable=True)   # type: ignore[type-arg]
    description: Mapped[str | None] = mapped_column(Text)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("firewall_id", "vsys", "name", "kind", name="paloalto_addr_unique"),
    )


__all__: list[Any] = ["PaloAltoAddressObject", "PaloAltoFirewall", "PaloAltoPolicy"]
