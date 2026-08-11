"""DHCP 發放範圍（pool range）— 由各 DHCP 來源各自同步回來的衍生資料。

一個子網路可能設定多段 pool，故以 (來源, 起, 迄) 多列儲存。
IP 落在任一範圍內 → 在 IP 清單／詳細資料標示為「在 DHCP 範圍內」。

**這張表只是共用的衍生資料存放處，不是統一的「DHCP 伺服器」抽象**：
OPNsense / pfSense / Windows DHCP 各自有自己的設定與同步流程，各自寫入、各自只清除自己的列
（`source_type` + `source_id`），彼此不干涉。
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# 允許的來源整合（source_type）。新增 DHCP 來源整合時要一起加進來，
# 否則這份清單會跟實際寫進 source_type 的值脫節（目前沒有 CHECK 約束在讀它，
# 但它是這張表「有哪些來源」的唯一書面依據）。
DHCP_SOURCE_TYPES = ("opnsense", "pfsense", "windows_dhcp", "fortigate")


class DHCPPoolRange(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "dhcp_pool_ranges"

    # 哪個整合寫的（不設 FK：跨多張來源表；各整合刪除時自行清除自己的列）
    source_type: Mapped[str] = mapped_column(String(24), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_name: Mapped[str | None] = mapped_column(String(128))   # 顯示用快照（免跨表 join）

    # 來源子網路；pfSense 的 DHCP 設定以介面為單位、不一定給得出 CIDR → 可為空
    subnet_cidr: Mapped[str | None] = mapped_column(String(64))
    start_ip: Mapped[str] = mapped_column(String(64), nullable=False)      # 範圍起（含）
    end_ip: Mapped[str] = mapped_column(String(64), nullable=False)        # 範圍迄（含）
    family: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    # DHCP 引擎（kea / isc / windows）—— 與 source_type（哪個整合）分工
    source: Mapped[str] = mapped_column(String(16), default="kea", nullable=False)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_dhcp_pool_ranges_source", "source_type", "source_id"),
    )


class DHCPReservation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """DHCP 固定分配（reservation / static mapping）—— 這個 MAC 固定拿這個 IP。

    與 `DHCPPoolRange` 分開的理由：範圍講的是「這段位址由 DHCP 動態發放」，固定分配講的
    是「這個位址被綁給某張網卡」。兩者的意義相反 —— 落在範圍內的位址會被回收再給別人，
    有固定分配的則不會。這個差別在追查「某台機器的資料為什麼跑到別台身上」時是關鍵。

    同樣不是統一抽象：各 DHCP 來源各自寫入、各自只清除自己的列（`source_type` + `source_id`）。
    """

    __tablename__ = "dhcp_reservations"

    source_type: Mapped[str] = mapped_column(String(24), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_name: Mapped[str | None] = mapped_column(String(128))

    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mac: Mapped[str | None] = mapped_column(String(32), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(255))
    # DHCP 引擎（kea / isc / windows / pfsense / fortigate）—— 與 source_type（哪個整合）分工
    source: Mapped[str] = mapped_column(String(16), default="kea", nullable=False)
    # 對映到 jt-ipam 的 IP 物件（比對得上才有值；只比對不新建）
    ip_address_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_dhcp_reservations_source", "source_type", "source_id"),
    )
