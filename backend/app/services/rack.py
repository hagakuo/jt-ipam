"""機櫃 U 位放置的防呆驗證（共用給 device 建立/更新、rack 改 U 高）。

規則：
- 裝置 U 位不可越界（1 ≤ u_position，且 u_position + u_size - 1 ≤ rack.u_height）
- 同一機櫃、同一安裝方向（front/rear）內，U 區間不可與其他裝置重疊
- 縮小機櫃 U 高時，不可低於既有裝置的最高 U（否則那台會越界）

失敗時 raise RackPlacementError（人讀訊息），endpoint 翻成 HTTP 400/409。
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ui_error import UiError
from app.models.device import Device
from app.models.location import Rack


class RackPlacementError(UiError, ValueError):
    """U 位放置不合法（越界 / 重疊 / 縮櫃衝突）。"""


# 一個 U（層架則是一層）的橫向分格數。**60 = 1~6 的最小公倍數**，所以 1/2、1/3、1/4、
# **1/5**、1/6 都表達得出來。
#
# 一開始取 12（只看 issue #31 要的 6 等分），但 issue #30 的層架明講「一層可以並排 3~5 台」
# —— 12 除不盡 5。格數只是個常數、不影響成本，所以取能同時滿足兩個 issue 的 60。
RACK_SLOTS = 60

# 使用者在介面上選的「寬度」→ 跨幾格。分母必須整除 RACK_SLOTS。
RACK_WIDTH_PARTS: tuple[int, ...] = (1, 2, 3, 4, 5, 6)


def slots_for(parts: int) -> int:
    """寬度 1/parts 佔幾格（parts=1 即整個 U）。"""
    if parts not in RACK_WIDTH_PARTS:
        raise ValueError(f"unsupported width 1/{parts}")
    return RACK_SLOTS // parts


# ── 立面圖的尺寸（issue #30：非標準寬度/層高的層架要畫得對） ─────────────────
# 基準＝標準 19" 機櫃：寬 482.6mm 畫成 250px、1U 44.45mm 畫成 28px。非標準的依比例縮放，
# 但夾在合理範圍內 —— 完全照實體比例，一個 350mm 高的層架單層就會有 220px，整張圖看不完。
RACK_REF_WIDTH_MM = 482.6      # 19"（面板含耳朵）
# EIA-310 的左右孔距（孔中心到孔中心）。立柱就在這條線上，它外面才是走線空間。
RACK_HOLE_SPACING_MM = 465.1
RACK_REF_ROW_MM = 44.45        # 1U
RACK_REF_WIDTH_PX = 250.0
RACK_REF_ROW_PX = 28.0
# 機架型態（issue #30）。以 U 計的是機櫃類，其餘以「層」計：
#   rack        標準伺服器機櫃（19"）
#   industrial  工業機櫃（箱體較寬，仍是 U 制）
#   lackrack    LackRack：IKEA LACK 邊桌當機櫃（兩腳淨距 450mm＝19 吋導軌開口，以 U 計）
#   shelf       一般層架（鋼板／木板層板）
#   wire_shelf  鍍鉻層架（圓管立柱 + 網狀層板，中小企業很常見）
#   wood_shelf  木質層架（松木側架 + 層板，如 IKEA IVAR）
#   angle_shelf 角鋼層架（台灣最常見的免螺絲角鋼：L 型立柱＋鋼橫桿＋夾板）
#   kallax      IKEA KALLAX 格子櫃（一格一格，外框比內隔板厚）
RACK_KINDS: tuple[str, ...] = ("rack", "industrial", "shelf", "wire_shelf", "wood_shelf",
                               "angle_shelf", "kallax", "lackrack")
_U_KINDS = frozenset({"rack", "industrial", "lackrack"})

# ── 新型態的實物規格（2026-09-24 查證） ─────────────────────────────────────
# 角鋼層架：台灣市售大宗是免螺絲角鋼 —— 40×40mm L 型立柱、葫蘆孔孔距 30mm（台尺制）。
# 正面看到的每一層是一條 50mm 高的鋼橫桿，上面跨放一片 9mm 夾板（業界叫「3 分板」）。
ANGLE_POST_MM = 40.0
ANGLE_HOLE_PITCH_MM = 30.0
ANGLE_BEAM_MM = 50.0
ANGLE_PLY_MM = 9.0
# KALLAX：格子 335mm、外框 40mm、內隔板 15mm → 外寬＝65＋350×格數；IKEA 官方的
# 41.5／76.5／111.5／146.5 公分全部吻合。沒有腳，底板直接落地。
KALLAX_CELL_MM = 335.0
KALLAX_FRAME_MM = 40.0
KALLAX_DIVIDER_MM = 15.0
# LackRack：LACK 邊桌 55×55×45 公分，桌面與桌腳都是 50mm。桌面下 400mm ≈ 9U，
# 實務上裝 8U、底下留約 44mm。疊一張多 8U（上面那張的腳站在下面那張的桌面上）。
LACK_TOP_MM = 50.0
LACK_LEG_MM = 50.0
LACK_HEIGHT_MM = 450.0
LACK_U_PER_TABLE = 8

# 機櫃（rack／industrial）的頂板與底座：有厚度，不是一條線。APC NetShelter SX 42U 外高
# 1991mm、42U＝1866.9mm → 頂板＋底座約 124mm，取頂板 50mm、底座（含底框）75mm。
CABINET_ROOF_MM = 50.0
CABINET_BASE_MM = 75.0

# 預設尺寸。木質層架取 IKEA IVAR 最小的那組：層板 42×30 公分、側架高 179 公分，
# 官方要求 179 的側架至少配 4 層，實務上多半放 6 層 → 每層約 300mm。
# 機櫃的寬度是**外尺寸**（含側板，廠商規格表上的那個「寬」）：標準機櫃最常見 600mm。
# 角鋼層架最常見 90×45×180 公分 4 層（淨空約 52 公分）；KALLAX 最常見 2×4 格（76.5 公分寬）。
_DEFAULT_WIDTH_MM = {"rack": 600, "industrial": 600, "shelf": 900,
                     "wire_shelf": 1200, "wood_shelf": 420,
                     "angle_shelf": 900, "kallax": 765, "lackrack": 550}
_DEFAULT_ROW_MM = {"rack": 44.45, "industrial": 44.45, "shelf": 350,
                   "wire_shelf": 400, "wood_shelf": 300,
                   "angle_shelf": 520, "kallax": KALLAX_CELL_MM, "lackrack": 44.45}
# 層板本身的厚度（mm）。層高填的是**淨空高**（不含板），所以總高要另外把板算進去。
# 木質層架 18mm 是 IKEA IVAR 層板的官方規格（1.8 cm）。角鋼層架是鋼橫桿＋夾板。
_DEFAULT_BOARD_MM = {"rack": 0.0, "industrial": 0.0, "shelf": 20.0,
                     "wire_shelf": 35.0, "wood_shelf": 18.0,
                     "angle_shelf": ANGLE_BEAM_MM + ANGLE_PLY_MM,
                     "kallax": KALLAX_DIVIDER_MM, "lackrack": 0.0}
# 離地高度的預設（mm）。沒列的型態維持原本的行為（沒填＝0，畫面上補一截短腳）。
_DEFAULT_FLOOR_MM = {"angle_shelf": 10.0, "kallax": 0.0,
                     "lackrack": LACK_HEIGHT_MM - LACK_TOP_MM - LACK_U_PER_TABLE * 44.45}

# 表面顏色，第一個是預設。只有外觀真的會因顏色而不同的型態才有。
FINISHES: dict[str, tuple[str, ...]] = {
    "angle_shelf": ("black", "white", "galvanized"),   # 台灣以黑、白為主，其次鍍鋅
    "kallax": ("white", "black_brown", "oak"),         # 白、黑棕、白色染橡木紋
    "lackrack": ("white", "black", "brown"),
}


def uses_rack_units(kind: str | None) -> bool:
    """這個型態的列是「U」還是「層」—— 畫面標籤與說明文字都看它。"""
    # 未知型態一律當標準機櫃 —— 跟 rack_defaults 與前端的 usesLevels 同一個規則；
    # 以前這裡把未知型態當層架，而 rack_defaults 當機櫃，兩邊各說各話
    return (kind if kind in _DEFAULT_WIDTH_MM else "rack") in _U_KINDS


def v_px_per_mm(kind: str | None) -> float:
    """垂直方向 1mm 畫成幾 px。

    以 U 計的（機櫃、工業機櫃、LackRack）沿用 1U 44.45mm＝28px —— 比水平（19 吋 482.6mm＝250px）
    多約 1.22 倍，但所有既有的機櫃圖都是這樣畫的，一張都不能變。
    層架寬高用同一個比例，畫出來才是實物的形狀：套機櫃的垂直比例的話，KALLAX 的正方形格子
    會變成直立的長方形（2026-09-25 拿掉每層 160px 上限時發現）。
    """
    if uses_rack_units(kind):
        return RACK_REF_ROW_PX / RACK_REF_ROW_MM
    return RACK_REF_WIDTH_PX / RACK_REF_WIDTH_MM


def rack_defaults(kind: str | None) -> tuple[float, float]:
    """(預設寬 mm, 預設列高 mm)。層架沒有標準值，給一組常見尺寸。"""
    k = kind if kind in _DEFAULT_WIDTH_MM else "rack"
    return float(_DEFAULT_WIDTH_MM[k]), float(_DEFAULT_ROW_MM[k])


def board_default_mm(kind: str | None) -> float:
    """層板厚度的預設值（mm）。機櫃類沒有層板，回 0。"""
    return float(_DEFAULT_BOARD_MM.get(kind or "rack", 0.0))


def floor_default_mm(kind: str | None) -> float | None:
    """離地高度的預設（mm）；None＝這個型態沒有特定值（沿用原本的行為）。"""
    v = _DEFAULT_FLOOR_MM.get(kind or "")
    return None if v is None else float(v)


def normalize_finish(kind: str | None, finish: str | None) -> str | None:
    """這個型態實際用的顏色：沒填或不適用這個型態就用預設；沒有顏色選項的型態回 None。"""
    opts = FINISHES.get(kind or "")
    if not opts:
        return None
    return finish if finish in opts else opts[0]


def kallax_columns(width_mm: int | float | None) -> int:
    """KALLAX 有幾欄：外寬＝65＋350×欄數。147／182 公分是官方四捨五入的標稱，一樣對得上。"""
    w = float(width_mm or _DEFAULT_WIDTH_MM["kallax"])
    pitch = KALLAX_CELL_MM + KALLAX_DIVIDER_MM
    return max(1, round((w - (2 * KALLAX_FRAME_MM - KALLAX_DIVIDER_MM)) / pitch))


def level_boards_px(kind: str | None, u_height: int | None,
                    board_px: float) -> tuple[float, list[float]]:
    """(最上面那一列**之上**的厚度 px, 每一列**底下**那片板的厚度 px)，由上往下。

    以前每一片板都一樣厚，只有一個 `board_px`。兩種新型態不是這樣：
    - KALLAX 的外框（40mm）比內隔板（15mm）厚：頂板與底板要畫得比中間的厚。
    - LackRack 最上面是桌面；疊了好幾張時，每張桌子之間是「桌面＋底下那段空隙」。
    - 機櫃有頂板與底座（以前只畫成一條線）。
    層架回的是一模一樣的均一值 —— 畫出來跟改版前相同。
    """
    n = max(int(u_height or 0), 0)
    rows = n + 1 if (has_open_top(kind) and n) else n
    per_mm = v_px_per_mm(kind)
    if (kind or "rack") in ("rack", "industrial") and rows >= 1:
        # 頂板在最上面那一 U 之上、底座在最下面那一 U 之下；U 與 U 之間沒有板
        return CABINET_ROOF_MM * per_mm, [*([0.0] * (rows - 1)), CABINET_BASE_MM * per_mm]
    if kind == "kallax" and rows >= 2:
        edge = KALLAX_FRAME_MM * per_mm
        return 0.0, [edge, *([board_px] * (rows - 2)), edge]
    if kind == "lackrack":
        gap = float(_DEFAULT_FLOOR_MM["lackrack"])
        seg = (gap + LACK_TOP_MM) * per_mm
        # 最上面一列是「桌面上方」（可以放東西），它底下那片板就是最上面那張桌子的桌面。
        # 接著由上往下是 U(n)…U1：U 號減 1 是 8 的倍數（而且不是 U1）的那一格是某張桌子的
        # 最底下一格 —— 它底下是「上面那張的腳下空隙＋下面那張的桌面」
        boards = [LACK_TOP_MM * per_mm] + [
            seg if (n - i) > 1 and (n - i - 1) % LACK_U_PER_TABLE == 0 else 0.0
            for i in range(n)]
        return 0.0, boards
    return 0.0, [board_px] * rows


def has_open_top(kind: str | None) -> bool:
    """這種型態的**頂板上面**放不放得了東西。

    層架沒有天花板，最上面那片板的上面本來就是可以放設備的位置（IVAR、鍍鉻層架都是）；
    機櫃有頂蓋，放不了。多出來的那個位置在資料上是「第 u_height + 1 層」。
    LackRack 雖然以 U 計，但它是一張桌子：桌面上也放東西（官方承重 10kg）。
    """
    return not uses_rack_units(kind) or kind == "lackrack"


def placeable_levels(kind: str | None, u_height: int | None) -> int:
    """可以放裝置的位置有幾個。層架多一個：最上面那片板的上面。"""
    n = max(int(u_height or 0), 0)
    return n + 1 if (has_open_top(kind) and n) else n


# 整張圖的高度預算（px）。層架的一層跟機櫃的一 U 用同一個比例（1U 44.45mm＝28px），
# 只有離譜的資料（總高超過約 3 公尺）才等比例壓回這個預算 —— 版面不能被撐爆。
#
# 以前每層最高 160px（另有 76px 的保守值），寬度卻不跟著縮：角鋼層架 518mm 的一層只畫
# 一半高，放在上面的設備看起來比實物扁（2026-09-24 使用者同意拿掉）。42U 機櫃是 1176px、
# 2.4 公尺的層架約 1512px，都在預算內，所以實際尺寸的東西全部是真實比例。
_TOTAL_MAX_PX = 1900.0


def level_heights_mm(kind: str | None, row_height_mm: int | None,
                     level_heights: list[int] | None, rows: int) -> list[float]:
    """每一層的實際高度（mm），由**第 1 層起算**（第 1 層＝編號最小的那層）。

    層架的層高本來就一層一層可以調（IVAR、鍍鉻層架都是），所以資料上存一個陣列。
    沒給、或長度對不上就用 `row_height_mm` 補滿 —— 既有資料一律走這條，畫出來不變。
    """
    n = max(int(rows or 0), 0)
    if n == 0:
        return []
    _, dr = rack_defaults(kind)
    uniform = float(row_height_mm or dr)
    out = [uniform] * n
    for i, h in enumerate(level_heights or []):
        if i >= n:
            break
        try:
            v = float(h)
        except (TypeError, ValueError):
            continue
        if v > 0:
            out[i] = v
    return out


def rack_render_size(
    kind: str | None, width_mm: int | None, row_height_mm: int | None,
    rows: int | None = None,
) -> tuple[float, float]:
    """回 (畫出來的寬 px, 每列高 px)。標準機櫃會得到與改版前完全相同的 250/28。

    `rows` 給了就用整張圖的高度預算決定列高上限，層架才畫得出真實比例。
    """
    dw, dr = rack_defaults(kind)
    w = float(width_mm or dw)
    r = float(row_height_mm or dr)
    # 機櫃再寬，裝進去的設備都是 19 吋：設備區固定畫成 19 吋寬，多出來的寬度是兩側的
    # 走線空間（另由 rack_side_px 算）。以前拿外寬直接放大設備區，600mm 的櫃子設備畫成
    # 1.24 倍寬、800mm 畫成 1.66 倍。層架的寬度就是層板本身，照舊依比例。
    if kind == "kallax":
        # 設備放在格子裡：畫的是外框以內（外框另外畫在兩側，見 rack_side_px）
        w = max(w - 2 * KALLAX_FRAME_MM, 1.0)
    px_w = RACK_REF_WIDTH_PX if uses_rack_units(kind) else RACK_REF_WIDTH_PX * (w / RACK_REF_WIDTH_MM)
    px_r = r * v_px_per_mm(kind)
    # 跟機櫃同一個比例；只有層架的整張圖超過預算才壓（不知道列數時當作一列）。
    # 以 U 計的（機櫃、LackRack）永遠不壓：一 U 就是 28px，既有的圖一張都不能變。
    if uses_rack_units(kind):
        return (min(max(px_w, 180.0), 620.0), max(px_r, 18.0))
    cap = _TOTAL_MAX_PX / max(int(rows or 1), 1)
    return (min(max(px_w, 180.0), 620.0), max(min(px_r, cap), 18.0))


_SIDE_MAX_PX = 200.0


def rack_side_px(kind: str | None, width_mm: int | None) -> float:
    """機櫃兩側「走線空間」各畫多寬（px）。KALLAX／LackRack／角鋼層架借這個值畫兩側的
    外框／桌腳／立柱 —— 畫面、匯出、嵌入三份畫法都從這裡拿，不各自寫死。

    從立柱的孔位中心線量到外緣：(外寬 − 465.1) ÷ 2 —— 600mm 各約 67mm、800mm 各約 167mm
    （800 的櫃子就是為了裝垂直理線槽）。用 482.6（面板寬）去算會兩邊各少 8.75mm，
    600mm 的櫃子看起來只剩一條細縫，跟實物不符。用跟設備區同一個比例換成 px。
    沒填寬度當作預設的 600mm；比孔距還窄的回 0（裝不下 19 吋設備，多半是填錯或 10 吋櫃）；
    層架回 0。
    """
    if kind == "kallax":
        return KALLAX_FRAME_MM * RACK_REF_WIDTH_PX / RACK_REF_WIDTH_MM     # 兩側是外框
    if kind == "angle_shelf":
        return ANGLE_POST_MM * RACK_REF_WIDTH_PX / RACK_REF_WIDTH_MM       # 兩側是 L 型立柱
    if not uses_rack_units(kind):
        return 0.0
    if kind == "lackrack":
        # 兩側是桌腳，畫整支 50mm（跟桌面一樣厚）。以前只畫耳朵外面露出來的那一截
        # (550 − 482.6) ÷ 2 ≈ 34mm，桌腳看起來比桌面細一大截，跟實物不像（使用者回報）。
        return LACK_LEG_MM * RACK_REF_WIDTH_PX / RACK_REF_WIDTH_MM
    outer = float(width_mm or rack_defaults(kind)[0])
    side_mm = max(0.0, (outer - RACK_HOLE_SPACING_MM) / 2)
    return min(side_mm * RACK_REF_WIDTH_PX / RACK_REF_WIDTH_MM, _SIDE_MAX_PX)


# IKEA OBSERVATÖR 交叉支撐桿：固定 100 公分的鍍鋅鋼條，一包一支（是一根斜桿，不是 X）。
# 因為長度固定，它能跨幾層完全由層架寬度決定 —— 斜邊固定，底邊越寬、垂直跨距就越短。
# 官方數據可以對得起來：83 公分寬的配置垂直跨距約 21 吋（53 公分）、
# 42 公分寬的約 35.5 吋（90 公分），跟 √(100² − 寬²) 幾乎一樣。
OBSERVATOR_LEN_MM = 1000.0


def brace_span_mm(width_mm: float) -> float:
    """支撐桿的垂直跨距（mm）。寬到 100 公分以上就跨不了，回 0。"""
    w = float(width_mm or 0)
    if w <= 0 or w >= OBSERVATOR_LEN_MM:
        return 0.0
    return (OBSERVATOR_LEN_MM ** 2 - w ** 2) ** 0.5


def brace_levels(kind: str | None, width_mm: int | None,
                 row_height_mm: int | None, rows: int | None,
                 level_heights: list[int] | None = None) -> int:
    """支撐桿從最底下那層往上**實際跨得到**幾層。非木質層架、或跨不了，回 0（＝不畫）。

    逐層累加而不是除法：層高可以一層一層不同，除法只在均一時才成立。
    累加到超過鋼條長度就停 —— 跨過頭的話實物根本裝不上去。
    """
    if (kind or "") != "wood_shelf":
        return 0
    dw, _ = rack_defaults(kind)
    span = brace_span_mm(float(width_mm or dw))
    if span <= 0:
        return 0
    acc = 0.0
    n = 0
    for h in level_heights_mm(kind, row_height_mm, level_heights, int(rows or 0)):
        if acc + h > span:
            break
        acc += h
        n += 1
    return n


def legacy_side_to_slots(side: str | None) -> tuple[int, int]:
    """舊的 full/left/right（含舊版系統匯出檔）→ (起始格, 跨幾格)。認不得一律視為整 U。"""
    if side == "left":
        return (0, RACK_SLOTS // 2)
    if side == "right":
        return (RACK_SLOTS // 2, RACK_SLOTS // 2)
    return (0, RACK_SLOTS)


def _face(v: str | None) -> str:
    return v or "front"


def _slot_range(slot: int | None, span: int | None) -> range:
    """把 (起始格, 跨幾格) 正規化成半開區間；None 視為佔滿整個 U。"""
    s = 0 if slot is None else int(slot)
    n = RACK_SLOTS if span is None else int(span)
    return range(s, s + n)


async def assert_placement_ok(
    session: AsyncSession,
    *,
    rack_id: uuid.UUID,
    u_position: int,
    u_size: int,
    rack_face: str | None,
    rack_slot: int | None = None,
    rack_slot_span: int | None = None,
    rack_vslot: int | None = None,
    rack_vslot_span: int | None = None,
    exclude_device_id: uuid.UUID | None = None,
) -> None:
    """驗證某裝置放在 rack_id 的 [u_position, u_position+u_size-1] 與格位是否合法。

    重疊 = **U 區間相交 且 橫向格位相交 且 層內垂直格位相交**（前後面不同不算重疊）。
    層內垂直格位是層架才有的彈性：一層放得下疊起來的兩三台，而且不必放滿。
    """
    if u_size < 1:
        raise RackPlacementError("u_size 必須 ≥ 1", code="rack_u_size_min")
    want_slots = _slot_range(rack_slot, rack_slot_span)
    if len(want_slots) < 1:
        raise RackPlacementError("橫向跨度必須 ≥ 1 格", code="rack_slot_span_min")
    if want_slots.start < 0 or want_slots.stop > RACK_SLOTS:
        raise RackPlacementError(
            f"橫向格位超出範圍：一個 U 只有 {RACK_SLOTS} 格",
            code="rack_slot_out_of_range", slots=RACK_SLOTS,
        )
    want_v = _slot_range(rack_vslot, rack_vslot_span)
    if len(want_v) < 1:
        raise RackPlacementError("層內垂直跨度必須 ≥ 1 格", code="rack_vslot_span_min")
    if want_v.start < 0 or want_v.stop > RACK_SLOTS:
        raise RackPlacementError(
            f"層內垂直格位超出範圍：一層只有 {RACK_SLOTS} 格",
            code="rack_vslot_out_of_range", slots=RACK_SLOTS,
        )
    rack = await session.get(Rack, rack_id)
    if rack is None:
        raise RackPlacementError("機櫃不存在", code="rack_not_found")

    top = u_position + u_size - 1
    # 層架多一個可放的位置：最上面那片板的**上面**（＝第 u_height + 1 層）。
    limit = placeable_levels(getattr(rack, "kind", None), rack.u_height)
    if u_position < 1 or top > limit:
        raise RackPlacementError(
            f"U 位超出機櫃範圍：裝置占 U{u_position}–U{top}，"
            f"但「{rack.name}」只有 {rack.u_height}U",
            code="rack_out_of_range", bottom=u_position, top=top,
            name=rack.name, height=rack.u_height,
        )

    face = _face(rack_face)
    others = (await session.execute(
        select(Device).where(
            Device.rack_id == rack_id,
            Device.u_position.is_not(None),
            Device.u_size.is_not(None),
        )
    )).scalars().all()
    want = set(range(u_position, top + 1))
    for d in others:
        if exclude_device_id is not None and d.id == exclude_device_id:
            continue
        if _face(d.rack_face) != face:
            continue  # 不同安裝方向（前/後）不算重疊
        if d.u_position is None or d.u_size is None:
            continue
        d_slots = _slot_range(d.rack_slot, d.rack_slot_span)
        if not (want_slots.start < d_slots.stop and d_slots.start < want_slots.stop):
            continue  # 橫向格位沒交集（並排），同 U 不算重疊
        d_v = _slot_range(getattr(d, "rack_vslot", 0), getattr(d, "rack_vslot_span", RACK_SLOTS))
        if not (want_v.start < d_v.stop and d_v.start < want_v.stop):
            continue  # 層內垂直格位沒交集（上下疊放），同一層不算重疊
        d_range = set(range(d.u_position, d.u_position + d.u_size))
        clash = sorted(want & d_range)
        if clash:
            us = ", ".join(f"U{u}" for u in clash)
            raise RackPlacementError(
                f"與「{d.name}」的 U 位重疊（{us}）；請改放空的 U 位或調整 U 數",
                code="rack_overlap", name=d.name, positions=us,
            )


async def assert_rack_height_ok(
    session: AsyncSession, *, rack_id: uuid.UUID, new_height: int,
) -> None:
    """縮小機櫃 U 高前，確認不會把既有裝置擠到範圍外。"""
    rows = (await session.execute(
        select(Device.name, Device.u_position, Device.u_size).where(
            Device.rack_id == rack_id,
            Device.u_position.is_not(None),
            Device.u_size.is_not(None),
        )
    )).all()
    offenders = [
        (name, pos, size) for (name, pos, size) in rows
        if pos is not None and size is not None and (pos + size - 1) > new_height
    ]
    if offenders:
        names = "、".join(
            f"{n}(U{p}–U{p + s - 1})" for (n, p, s) in offenders[:5]
        )
        raise RackPlacementError(
            f"無法縮小到 {new_height}U：以下裝置會超出範圍 → {names}。"
            "請先移走或下移這些裝置。",
            code="rack_shrink_blocked", height=new_height, devices=names,
        )


def level_render_px(
    kind: str | None, width_mm: int | None, row_height_mm: int | None,
    level_heights: list[int] | None, rows: int | None,
) -> tuple[float, list[float]]:
    """回 (寬 px, 每一層的高 px)。每層各自換算，所以高的層畫得高、矮的層畫得矮。

    夾住的方式與 `rack_render_size` 一致（同一個高度預算），差別只在逐層算。
    回傳的順序與 `level_heights_mm` 相同：由第 1 層起算。
    """
    n = max(int(rows or 0), 0)
    px_w, _ = rack_render_size(kind, width_mm, row_height_mm, n)
    if n == 0:
        return px_w, []
    mm = level_heights_mm(kind, row_height_mm, level_heights, n)
    px = [m * v_px_per_mm(kind) for m in mm]
    total = sum(px)
    if total > _TOTAL_MAX_PX and not uses_rack_units(kind):
        # 離譜的資料才會到這裡：整座等比例縮，高矮層的比例不變
        px = [p * _TOTAL_MAX_PX / total for p in px]
    return px_w, [max(p, 18.0) for p in px]


def scaled_board_px(kind: str | None, board_mm: int | None, width_mm: int | None,
                    row_height_mm: int | None, level_heights: list[int] | None,
                    u_height: int | None) -> float:
    """層板畫出來多厚 px（畫面、對外嵌入都叫這支，兩邊不會各算各的）。

    層高照實際比例畫；只有離譜的資料會被整張圖的預算壓扁（見 _TOTAL_MAX_PX）。板厚一直是
    照原比例換算的：多數型態的板很薄，被壓也看不出來；角鋼層架的「板」是 50mm 的鋼橫桿＋
    夾板，不跟著縮就會佔一層的比例比實物大，整座看起來全是粗鐵條 —— 所以角鋼層架的板厚
    跟層高用同一個縮放比例。其他型態維持原本的算法。
    """
    mm = board_default_mm(kind) if board_mm is None else float(board_mm)
    if mm <= 0:
        return 0.0
    px = mm * v_px_per_mm(kind)
    if kind == "angle_shelf":
        _, rows_px = level_render_px(kind, width_mm, row_height_mm, level_heights, u_height)
        real = level_heights_mm(kind, row_height_mm, level_heights, int(u_height or 0))
        if rows_px and real and real[0] > 0:
            px *= min(1.0, rows_px[0] / (real[0] * v_px_per_mm(kind)))
    return max(px, 2.0)
