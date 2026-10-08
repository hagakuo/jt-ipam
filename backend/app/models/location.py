"""Location 與 Rack。"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Location(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "locations"

    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    address: Mapped[str | None] = mapped_column(Text)
    latitude: Mapped[float | None] = mapped_column(Numeric(10, 7))
    longitude: Mapped[float | None] = mapped_column(Numeric(10, 7))
    description: Mapped[str | None] = mapped_column(Text)
    # 所屬單位 / 客戶（管理單位）
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customers.id", ondelete="SET NULL"),
        index=True,
    )
    # 機房平面圖底圖（上傳檔相對 upload_dir 的路徑）。Location 同時當「機房」用。
    floor_plan_path: Mapped[str | None] = mapped_column(Text)


class Rack(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "racks"

    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        index=True,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    u_height: Mapped[int] = mapped_column(Integer, default=42, nullable=False)
    # 型態（issue #30）：rack＝標準伺服器機櫃、industrial＝工業機櫃（兩者以 U 計）、
    # shelf＝一般層架、wire_shelf＝鍍鉻層架（後兩者以「層」計，沒有 U 的概念，
    # 寬度與層高也不是標準值）。見 services/rack.py 的 RACK_KINDS。
    kind: Mapped[str] = mapped_column(
        # 16 而不是剛好夠：`wire_shelf` 是 10 字，當初開 8 讓正式機一存就被
        # PostgreSQL 截斷擋下（見 tests/test_rack_slots.py 的資料庫往返測試）。
        String(16), default="rack", server_default="rack", nullable=False,
    )
    # 表面顏色（角鋼的黑／白／鍍鋅、KALLAX 的白／黑棕／橡木紋…）。null＝該型態的預設色。
    finish: Mapped[str | None] = mapped_column(String(16))
    # 實體尺寸（mm）：機房平面圖用來把機櫃方框依真實腳印按比例呈現；立面圖也用它決定
    # 要畫多寬（非標準寬度的層架才畫得對）。null = 依 kind 取預設。
    width_mm: Mapped[int | None] = mapped_column(Integer)
    # 每一列的高度（mm）：標準機櫃 1U = 44.45mm；層架一層可能 300~400mm。
    # 立面圖用它決定列高，否則三層架會被畫成三條細線。null = 依 kind 取預設。
    row_height_mm: Mapped[int | None] = mapped_column(Integer)
    # 逐層高度（mm），由第 1 層起算。層架的層板一層一層各自可調（IVAR、鍍鉻層架都是），
    # 所以存成陣列；null 或長度對不上就用 row_height_mm 補滿 —— 既有資料畫出來不變。
    level_heights: Mapped[list[int] | None] = mapped_column(JSONB)
    # 層板本身的厚度（mm）。層高填的是淨空高（不含板），總高要另外加板厚。
    # null = 依 kind 取預設（木質層架 18mm＝IKEA IVAR 官方規格）。
    board_mm: Mapped[int | None] = mapped_column(Integer)
    # 最下面那片層板離地多高（mm）。null = 0。
    floor_mm: Mapped[int | None] = mapped_column(Integer)
    depth_mm: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    # 對外公開這個機櫃的示意圖（給別的系統用 <img> 嵌入）。逐櫃開關、預設關：
    # 機櫃圖會揭露裝置名稱與位置，不能因為其中一櫃想分享就整批開放。
    expose_svg: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default="false",
    )
    # 排序編號：多機櫃並排顯示時，編號小的排左邊（同編號再依名稱）。null 視為很大、排最後。
    seq: Mapped[int | None] = mapped_column(Integer, index=True)
    # U 編號方向：top-down＝最上面是最大 U（標準機櫃）；bottom-up＝最上面是 U1。
    numbering: Mapped[str] = mapped_column(
        String(16), default="top-down", server_default="top-down", nullable=False,
    )
    # 此機櫃示意圖呈現的面：front＝正面、rear＝背面。
    face: Mapped[str] = mapped_column(
        String(8), default="front", server_default="front", nullable=False,
    )
    # 在機房平面圖上的位置（0..1 的比例座標，與底圖解析度無關）。null = 尚未擺放。
    pos_x: Mapped[float | None] = mapped_column(Numeric(6, 5))
    pos_y: Mapped[float | None] = mapped_column(Numeric(6, 5))
    # 在平面圖上的旋轉角度（任意度數），讓機櫃方框對齊現場朝向。
    pos_rot: Mapped[int] = mapped_column(Integer, default=0, nullable=False, server_default="0")
    # 在平面圖上的方框大小（0..1 比例，相對底圖寬/高）；null = 用預設大小。
    pos_w: Mapped[float | None] = mapped_column(Numeric(6, 5))
    pos_h: Mapped[float | None] = mapped_column(Numeric(6, 5))
