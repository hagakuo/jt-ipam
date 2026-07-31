"""FortiGate 整合 model（Beta）—— 與 OPNsense / pfSense 分開，獨立資料表與設定。

走 FortiOS 官方 REST API（`/api/v2/monitor` 即時狀態、`/api/v2/cmdb` 設定物件），
以 API token 認證（**`Authorization: Bearer` 標頭**；不用 `?access_token=` 網址參數 ——
該形式有 PSIRT 案 FG-IR-24-268，且 FortiOS 7.4.5 / 7.6.1 起預設停用）。
token 以 AES-GCM 加密（aad 綁實例 id）。**全程唯讀，只打 GET。**

支援多 VDOM：`vdoms` 留空＝自動探索（`/api/v2/cmdb/system/vdom`），非 VDOM 模式退回 root。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class FortiGateFirewall(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """FortiGate 防火牆實例（FortiOS REST API / API token）。"""

    __tablename__ = "fortigate_firewalls"

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    api_url: Mapped[str] = mapped_column(Text, nullable=False)   # 例：https://192.0.2.1（可帶自訂埠）
    # API token（AES-GCM 加密；aad 綁實例 id）
    api_token_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    api_token_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # 要同步的 VDOM；留空＝自動探索全部（非 VDOM 模式的機器會退回單一 root）
    vdoms: Mapped[list[str] | None] = mapped_column(ARRAY(String(64)), nullable=True)

    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    # 逐項同步開關（DHCP 預設關，比照 pfSense：避免與區網其他 DHCP 來源互相標記）
    sync_dhcp: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_dhcp_ranges: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_arp: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sync_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_policies: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_nat: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sync_addresses: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # 關聯子網路範圍（留空＝全域 IP 字串比對）；重疊網段時限定比對範圍
    scope_subnet_ids: Mapped[list[uuid.UUID] | None] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=True,
    )
    description: Mapped[str | None] = mapped_column(Text)


class FortiGatePolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """FortiGate 防火牆政策唯讀鏡像（比照 opnsense_rules，可依 VDOM 篩選）。"""

    __tablename__ = "fortigate_policies"

    firewall_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fortigate_firewalls.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    vdom: Mapped[str] = mapped_column(String(64), nullable=False, default="root")
    policyid: Mapped[str] = mapped_column(String(64), nullable=False)   # FortiOS policyid（數字，存字串保險）
    name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str | None] = mapped_column(String(16))             # enable / disable
    action: Mapped[str | None] = mapped_column(String(16))             # accept / deny
    srcintf: Mapped[str | None] = mapped_column(Text)
    dstintf: Mapped[str | None] = mapped_column(Text)
    srcaddr: Mapped[str | None] = mapped_column(Text)
    dstaddr: Mapped[str | None] = mapped_column(Text)
    service: Mapped[str | None] = mapped_column(Text)
    nat: Mapped[bool | None] = mapped_column(Boolean)
    comments: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)     # type: ignore[type-arg]
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("firewall_id", "vdom", "policyid", name="fortigate_policy_unique"),
    )


class FortiGateAddressObject(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """FortiGate 位址物件／位址群組唯讀鏡像（比照 *_synced_aliases）。"""

    __tablename__ = "fortigate_address_objects"

    firewall_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fortigate_firewalls.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    vdom: Mapped[str] = mapped_column(String(64), nullable=False, default="root")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # ipmask / iprange / fqdn / geography / addrgrp …（addrgrp 以 kind='group' 標示）
    obj_type: Mapped[str | None] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="address")  # address / group
    value: Mapped[str | None] = mapped_column(Text)        # 子網路 / 範圍 / FQDN 的可讀值
    members: Mapped[list | None] = mapped_column(JSONB, nullable=True)   # type: ignore[type-arg]
    comment: Mapped[str | None] = mapped_column(Text)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("firewall_id", "vdom", "name", "kind", name="fortigate_addr_unique"),
    )
