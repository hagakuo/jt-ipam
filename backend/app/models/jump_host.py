"""跳板主機（issue #24 階段一）：主控台經由一台 SSH 跳板連到目標。

為什麼掛在子網路上就夠：主控台**不是**用 IP 字串啟動的，而是從**一筆 IP 記錄**啟動
（`/addresses/{id}/{ssh,sftp,rdp,vnc,novnc,bmc}/ws`），而每筆 IP 必然屬於唯一一個子網路。
所以「兩個客戶用同一段私網位址」這種重疊在結構上早就分開了，不需要另做消歧機制。
（幾乎每個站台的預設私網網段都一樣，這正是 issue #24 回報的情境。）

解析順序：**IP 覆寫 > 子網路 > 直連**（見 `services/console_route.resolve_route`）。
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import BYTEA
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

#: 認證方式。金鑰是預設也是建議做法；密碼是為了「客戶只給得出密碼」的現實。
AUTH_KINDS = ("key", "password")


class JumpHost(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "jump_hosts"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("22"))
    username: Mapped[str] = mapped_column(String(128), nullable=False)

    auth_kind: Mapped[str] = mapped_column(String(16), nullable=False, server_default="key")
    #: AES-GCM；AAD 綁這一列的 id（比照其他機密欄位）。只會用到其中一組。
    private_key_enc: Mapped[bytes | None] = mapped_column(BYTEA)
    private_key_nonce: Mapped[bytes | None] = mapped_column(BYTEA)
    password_enc: Mapped[bytes | None] = mapped_column(BYTEA)
    password_nonce: Mapped[bytes | None] = mapped_column(BYTEA)

    #: SHA-256 指紋釘選（`SHA256:...`）。**空值＝尚未信任**：連線時會先取回指紋要求人工確認，
    #: 不會靜靜地接受任何 host key —— 跳板是整條路徑的中間人，這一步不能省。
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    #: 每台跳板同時允許的主控台連線數。多個 session 共用同一條 SSH 連線，
    #: 但轉發本身仍佔跳板的資源 —— 客戶的跳板往往是台小機器。
    max_sessions: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("10"))

    description: Mapped[str | None] = mapped_column(Text)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
