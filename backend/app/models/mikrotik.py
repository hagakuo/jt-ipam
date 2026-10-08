"""MikroTik RouterOS 整合的 ORM（migration 0135）。

與其他防火牆整合最大的不同：**安全參數是欄位，不是常數**。客戶端是主力路由器
（CCR2004／CCR1072），「不要把路由器拖慢」因此是設定層級的需求 —— 逐區段開關、
CPU 門檻、區段間隔、回應大小上限都掛在實例上，而且**重的區段預設關**，
等管理員看過連線診斷回報的列數與耗時再自己開。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import BYTEA, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class MikroTikRouter(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """一台 RouterOS 裝置（v7 REST）。"""

    __tablename__ = "mikrotik_routers"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    api_url: Mapped[str] = mapped_column(Text, nullable=False)
    api_username: Mapped[str] = mapped_column(String(128), nullable=False)
    #: 密碼走 AES-GCM，AAD 綁這一列的 id（比照其他整合）
    api_password_enc: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    api_password_nonce: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: 主力路由器 → 預設 900 秒（其他整合是 300）
    sync_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("900"))

    #: 這台路由器＝哪一台 jt-ipam 裝置（migration 0170）。介面、FDB、鄰居都落在這台裝置上；
    #: 沒指定時同步用 API 位址對到的 IP 所屬裝置自動帶入（services/mikrotik._router_device）
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), index=True)

    #: 介面 → 對應裝置的 `device_ports`（第二階段，0170）
    sync_interfaces: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    sync_dhcp: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    sync_dhcp_ranges: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    sync_firewall: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    sync_nat: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    sync_address_lists: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: `/ip/neighbor`（MNDP／CDP／LLDP）→ mikrotik_neighbors，拓樸畫出「哪個埠接著哪台裝置」
    sync_neighbors: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: ⚠️ 預設關：全表 ARP 在大型路由器上可能是上萬列，先看診斷數字再決定
    sync_arp: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    #: `/interface/bridge/host` → fdb_entries（source=mikrotik，記 jt-ipam 裝置；0170）。
    #: ⚠️ 預設關：大型 bridge 可能上萬列，先看連線診斷的列數再開
    sync_fdb: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    sync_vpn: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    #: CPU 超過這個百分比就停掉本輪剩下的區段（待實機校準）
    cpu_load_limit: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("70"))
    #: 區段之間的喘息時間
    section_delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("300"))
    #: 單一回應的大小上限（RouterOS 的 REST 沒有分頁，這是唯一的護欄）
    max_response_mb: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("8"))

    scope_subnet_ids: Mapped[list[Any] | None] = mapped_column(JSONB)
    description: Mapped[str | None] = mapped_column(Text)

    routeros_version: Mapped[str | None] = mapped_column(String(32))
    board_name: Mapped[str | None] = mapped_column(String(64))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    #: 逐區段成本：`{"arp": {"rows": 12000, "seconds": 3.2, "bytes": 900000}, "cpu": {...}}`
    last_cost: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class MikroTikRule(Base, UUIDPrimaryKeyMixin):
    """防火牆規則鏡像（filter / nat / mangle 共用一張表，以 `table_name` 分）。"""

    __tablename__ = "mikrotik_rules"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"),
        nullable=False, index=True)
    table_name: Mapped[str] = mapped_column(String(16), nullable=False)
    chain: Mapped[str | None] = mapped_column(String(64))
    #: RouterOS 的規則由上而下比對 → 順序本身就是語意
    position: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    action: Mapped[str | None] = mapped_column(String(32))
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    src_address: Mapped[str | None] = mapped_column(Text)
    dst_address: Mapped[str | None] = mapped_column(Text)
    protocol: Mapped[str | None] = mapped_column(String(32))
    src_port: Mapped[str | None] = mapped_column(String(64))
    dst_port: Mapped[str | None] = mapped_column(String(64))
    in_interface: Mapped[str | None] = mapped_column(String(64))
    out_interface: Mapped[str | None] = mapped_column(String(64))
    to_addresses: Mapped[str | None] = mapped_column(Text)
    to_ports: Mapped[str | None] = mapped_column(String(64))
    comment: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()"))


class MikroTikAddressList(Base, UUIDPrimaryKeyMixin):
    """`/ip/firewall/address-list` —— 等同其他家的 alias。"""

    # 鏡像取代（整批刪再寫），因此不設唯一鍵 —— 裝置上本來就可能有重複條目，
    # 我們的職責是照實反映，不是替它去重。
    __tablename__ = "mikrotik_address_lists"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"),
        nullable=False, index=True)
    list_name: Mapped[str] = mapped_column(String(128), nullable=False)
    address: Mapped[str] = mapped_column(Text, nullable=False)
    dynamic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    timeout: Mapped[str | None] = mapped_column(String(32))
    comment: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()"))


class MikroTikNeighbor(Base, UUIDPrimaryKeyMixin):
    """`/ip/neighbor`：對方自己宣告的「我是誰、接在你哪個埠」（MNDP／CDP／LLDP，0170）。

    與 FDB 推導不同，這是鄰居親口說的，交換器之間的連線也畫得出來。每輪完整讀到才整批換掉。
    """

    __tablename__ = "mikrotik_neighbors"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"), nullable=False, index=True)
    interface: Mapped[str] = mapped_column(String(128), nullable=False)      # 路由器這端的埠
    address: Mapped[str | None] = mapped_column(String(64))
    mac: Mapped[str | None] = mapped_column(String(32))
    identity: Mapped[str | None] = mapped_column(String(255))
    platform: Mapped[str | None] = mapped_column(String(128))
    board: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(128))
    remote_interface: Mapped[str | None] = mapped_column(String(128))       # 對方那端的埠（有宣告才有）
    discovered_by: Mapped[str | None] = mapped_column(String(32))           # cdp,lldp,mndp
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False)
