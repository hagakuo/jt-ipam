"""OCS Inventory NG 整合的 ORM（migration 0140）。

定位：**端點與伺服器的資產盤點來源** —— 這是本專案目前完全沒有自動來源的一塊
（`devices.serial` / `model` / `vendor` 至今只能手填；LibreNMS 給網路設備、Proxmox 給 VM，
沒有人給 PC 與實體伺服器）。OCS **不是權威**，只是眾多觀測之一。

2026-09-18 用官方 docker 映像檔 2.10 與 2.11 實機探測，設計因此有幾件事跟直覺不同，
動這個檔案或 `services/ocs.py` 前請先讀 `docs/SPEC_OCS_zh-TW.md` 與那次探測的結論：

- **REST API 兩版都內建，但預設完全沒有驗證** → 帳密欄位是**選用**（nullable）；
  連線診斷會主動測「沒帶憑證連不連得上」，連得上就要警告站台。
- **增量查詢是版本能力**：2.11 有 `/computers/lastupdate/:epoch`（嚴格大於，參數是 epoch），
  2.10 沒有、只能全量分頁。所以有 `last_incremental_epoch` 這個游標，但只有 2.11 用得到。
- **軟體清單讓每台從 ~2 KB 膨脹到 ~80 KB**（實測 300 套軟體）→ `sync_software` **預設關**，
  比照 MikroTik「重的區段預設關」。
- **來源類型 REST／DB 一開始就是欄位** —— 若客戶不開 REST 或不給細緻唯讀權限，退路是唯讀
  連 OCS 的 MySQL；晚加這個欄位會變成大改，所以現在就留著（DB 那條第二階段才實作）。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import BYTEA, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

#: 來源類型。rest = OCS REST API（首選）；db = 直接唯讀連 OCS 的 MySQL（退路，第二階段）。
OCS_SOURCE_TYPES = ("rest", "db")


class OcsServer(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """一套 OCS Inventory NG。一台 jt-ipam 可連多套（不同客戶、不同站點）。"""

    __tablename__ = "ocs_servers"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(
        String(8), nullable=False, server_default=text("'rest'"))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    # ── REST 來源 ──
    #: 站台根網址（如 https://ocs.example.com）。REST 掛在 /ocsapi。
    base_url: Mapped[str | None] = mapped_column(Text)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: 帳密**選用** —— OCS 的 REST 預設無驗證。有設才會帶 Basic Auth。
    #: 密碼走 AES-GCM，AAD 綁這一列的 id（比照其他整合）。
    api_username: Mapped[str | None] = mapped_column(String(128))
    api_password_enc: Mapped[bytes | None] = mapped_column(BYTEA)
    api_password_nonce: Mapped[bytes | None] = mapped_column(BYTEA)

    # ── DB 來源（第二階段才實作，欄位先留）──
    db_host: Mapped[str | None] = mapped_column(String(255))
    db_port: Mapped[int | None] = mapped_column(Integer)
    db_name: Mapped[str | None] = mapped_column(String(128))
    db_username: Mapped[str | None] = mapped_column(String(128))
    db_password_enc: Mapped[bytes | None] = mapped_column(BYTEA)
    db_password_nonce: Mapped[bytes | None] = mapped_column(BYTEA)

    # ── 同步範圍（逐區段開關）──
    #: 硬體與 OS 是基礎，一律同步（沒有開關）。以下是可關的：
    sync_networks: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: 序號／型號／廠牌落到對到的 Device
    sync_bios: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: ⚠️ 預設關：軟體清單讓每台從 ~2 KB 膨脹到 ~80 KB（5000 台 ≈ 400 MB/輪）
    sync_software: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    #: 限定子網路範圍（UUID 字串陣列）。重疊網段時只跟這些子網路裡的 IP 比對 MAC，
    #: 「未裝 Agent 的 IP」也只列這些子網路。空＝全域（比照 Wazuh 等整合）。
    scope_subnet_ids: Mapped[list[Any] | None] = mapped_column(JSONB)

    #: 同步頻率。2.11（有增量）跑得動每小時；2.10 只能全量，管理員應自己調長。
    sync_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("3600"))

    #: OCS 盤點資料多久算過期（天）。超過只是顯示成「久未盤點」，**不影響上線判定** ——
    #: 盤點時間不是活性訊號。也用來擋「過期的 OCS 主機名稱壓過新鮮的掃描結果」。
    stale_after_days: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("30"))

    # ── 診斷與同步狀態（連線診斷與 sync 回寫）──
    #: 偵測到的版本字串（如 "2.11.0"）。決定能不能走增量。診斷時填。
    detected_version: Mapped[str | None] = mapped_column(String(32))
    #: 2.11 增量游標：上次成功同步涵蓋到的 epoch。因為 lastupdate 是「嚴格大於」，
    #: 下次帶進去時要往前退一個重疊窗，避免邊界那一秒的異動被漏掉。
    last_incremental_epoch: Mapped[int | None] = mapped_column(BigInteger)

    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    #: 上一輪的量測：筆數、耗時、走的是全量還是增量、有沒有因故中止。
    last_cost: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    __table_args__ = (
        CheckConstraint("source_type in ('rest','db')", name="ck_ocs_source_type"),
    )
