"""三種新的機架型態：角鋼層架、IKEA KALLAX、LackRack。

尺寸都是查過實物規格的（2026-09-24）：
- 角鋼層架：台灣市售大宗是免螺絲角鋼 —— 40×40mm L 型立柱、葫蘆孔孔距 30mm；
  正面看到的每一層是一條 50mm 高的鋼橫桿，上面跨放一片 9mm 夾板（3 分板）。
  最常見 90×45×180 公分、4 層（淨空約 52 公分）。
- KALLAX：格子 335mm、外框 40mm、內隔板 15mm → 外寬＝65＋350×格數
  （IKEA 官方的 41.5／76.5／111.5／146.5 公分全部吻合），深 39 公分、直接落地。
- LackRack：LACK 邊桌 55×55×45 公分，桌面與桌腳都是 50mm，兩腳淨距 450mm
  ＝19 吋導軌的開口，耳朵直接鎖在桌腳上。桌面下裝 8U，底下留約 44mm；疊一張多 8U。
"""
from __future__ import annotations

import pytest

PX_PER_MM_V = 28.0 / 44.45      # 垂直：1U 44.45mm＝28px
PX_PER_MM_H = 250.0 / 482.6     # 水平：19 吋面板 482.6mm＝250px

#: 既有層架的嵌入 SVG 雜湊。改畫法時這組值不該動；真的要改既有型態的外觀，才更新這裡
#: （並說明為什麼）。歷次更新：
#: - 機櫃（rack／industrial）拿掉：2026-09-24 加上有厚度的頂板與底座，外觀本來就該變。
#: - 2026-09-24 層號改成置中在那一層自己的空間（扣掉底下那片板）：機櫃最下面那一 U 的編號
#:   原本掉進底座裡（使用者回報），同一條規則套到層架，層號往上移半片板厚（逐行比對過，
#:   只有層號的 y 變了）。
#: - 2026-09-25 層架改成寬高同一個比例（拿掉每層 160px 的上限，使用者同意；見 rack.v_px_per_mm）：
#:   層高、板厚、離地、IVAR 調整孔都改用 250px／482.6mm。對正式機舊版逐張比對過：數字遮掉後
#:   結構完全相同、文字標籤相同，只有尺寸與座標變了。
SVG_BASELINE = {"shelf": "f44f952018f8", "wire_shelf": "0676aa93769b",
                "wood_shelf": "0f01c0475163"}


def test_new_kinds_are_registered_with_the_right_unit() -> None:
    from app.services.rack import RACK_KINDS, has_open_top, uses_rack_units
    assert {"angle_shelf", "kallax", "lackrack"} <= set(RACK_KINDS)
    assert uses_rack_units("lackrack"), "LackRack 裝的是 19 吋設備，以 U 計"
    assert not uses_rack_units("angle_shelf") and not uses_rack_units("kallax")
    assert has_open_top("angle_shelf"), "最上面那片板上面也放東西"
    assert has_open_top("kallax"), "KALLAX 頂部可承重 25kg"
    assert has_open_top("lackrack"), "LACK 桌面上也放東西（官方承重 10kg）"


def test_defaults_follow_the_real_products() -> None:
    from app.services.rack import board_default_mm, floor_default_mm, rack_defaults
    assert rack_defaults("angle_shelf") == (900.0, 520.0)
    assert rack_defaults("kallax") == (765.0, 335.0)
    assert rack_defaults("lackrack") == (550.0, 44.45)
    assert board_default_mm("angle_shelf") == 59.0, "50mm 鋼橫桿＋9mm 夾板"
    assert board_default_mm("kallax") == 15.0, "內隔板；外框另計"
    assert board_default_mm("lackrack") == 0.0
    assert floor_default_mm("angle_shelf") == 10.0
    assert floor_default_mm("kallax") == 0.0, "KALLAX 沒有腳，直接落地"
    assert abs(floor_default_mm("lackrack") - (450 - 50 - 8 * 44.45)) < 0.01
    assert floor_default_mm("rack") is None, "既有型態維持原本的行為"


@pytest.mark.parametrize(("width", "cols"), [
    (415, 1), (765, 2), (1115, 3), (1465, 4), (1470, 4), (1815, 5), (1820, 5), (None, 2),
])
def test_kallax_columns_come_from_the_width(width, cols) -> None:
    from app.services.rack import kallax_columns
    assert kallax_columns(width) == cols


def test_kallax_draws_the_inside_width_and_a_40mm_frame() -> None:
    from app.services.rack import rack_render_size, rack_side_px
    w, _ = rack_render_size("kallax", 765, None)
    assert abs(w - (765 - 80) * PX_PER_MM_H) < 0.01, "設備放在格子裡：量的是外框以內"
    assert abs(rack_side_px("kallax", 765) - 40 * PX_PER_MM_H) < 0.01, "外框 40mm"


def test_angle_posts_are_40mm() -> None:
    from app.services.rack import rack_side_px
    assert abs(rack_side_px("angle_shelf", 900) - 40 * PX_PER_MM_H) < 0.01


def test_lackrack_legs_are_as_wide_as_the_tabletop_is_thick() -> None:
    """桌腳畫整支 50mm（跟桌面一樣厚，IKEA 官方線稿就是這樣）。

    以前只畫「耳朵外面露出來的那一截」(550 − 482.6) ÷ 2 ≈ 34mm，桌腳看起來比桌面細一大截，
    跟實物不像（使用者回報）。沒裝設備的那幾列本來就看得到整支桌腳。
    """
    from app.services.rack import LACK_LEG_MM, LACK_TOP_MM, rack_render_size, rack_side_px
    w, r = rack_render_size("lackrack", 550, None)
    assert (w, r) == (250.0, 28.0), "19 吋設備區、1U 列高，跟機櫃一樣"
    assert LACK_LEG_MM == LACK_TOP_MM == 50.0
    assert abs(rack_side_px("lackrack", 550) - 50 * PX_PER_MM_H) < 0.01
    assert abs(rack_side_px("lackrack", None) - 50 * PX_PER_MM_H) < 0.01, "寬度沒填也一樣"


def _luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in (r, g, b)]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_lackrack_outlines_are_visible_on_every_finish() -> None:
    """白色桌子放在白色卡片上、黑色桌腳貼著黑色桌面：輪廓線太淡就等於沒有框線（使用者回報）。"""
    from app.services.rack_svg import FINISH_COLORS
    for fin, c in FINISH_COLORS["lackrack"].items():
        assert _contrast(c["line"], c["wood"]) >= 1.8, f"{fin}：桌腳與桌面之間分不出來"
    assert _contrast(FINISH_COLORS["lackrack"]["white"]["line"], "#ffffff") >= 3.0, \
        "白色桌子在白色卡片上要看得到邊"


def test_board_list_is_uniform_for_the_existing_shelves() -> None:
    """既有層架的每一片板一樣厚、上面沒有東西 —— 換成逐片清單之後畫出來必須不變。"""
    from app.services.rack import level_boards_px
    assert level_boards_px("wood_shelf", 6, 11.3) == (0.0, [11.3] * 7)    # 開放頂端多一列


def test_cabinets_have_a_real_top_and_bottom_panel() -> None:
    """機櫃的頂板與底座有實際厚度，不是一條線（使用者回報「近乎只有一條線，不合理」）。

    APC NetShelter SX 42U 外高 1991mm、42U＝1866.9mm → 頂板＋底座約 124mm：頂板 50、底座 75。
    """
    from app.services.rack import CABINET_BASE_MM, CABINET_ROOF_MM, level_boards_px
    assert (CABINET_ROOF_MM, CABINET_BASE_MM) == (50.0, 75.0)
    for kind in ("rack", "industrial"):
        top, boards = level_boards_px(kind, 42, 0.0)
        assert abs(top - 50 * PX_PER_MM_V) < 0.01, kind
        assert abs(boards[-1] - 75 * PX_PER_MM_V) < 0.01, kind
        assert boards[:-1] == [0.0] * 41, "U 與 U 之間沒有板"


def test_kallax_outer_boards_are_thicker_than_the_dividers() -> None:
    from app.services.rack import level_boards_px
    inner = 15 * PX_PER_MM_H          # 層架寬高同一個比例
    edge = 40 * PX_PER_MM_H
    top, boards = level_boards_px("kallax", 4, inner)
    assert top == 0.0
    assert len(boards) == 5, "4 列格子＋頂部那一列"
    assert abs(boards[0] - edge) < 0.01, "頂部那一列的下面是外框頂板"
    assert abs(boards[-1] - edge) < 0.01, "最下面是外框底板"
    assert all(abs(b - inner) < 0.01 for b in boards[1:-1])


def test_lackrack_has_a_tabletop_and_one_more_per_stacked_table() -> None:
    """桌面是「頂」那一列（桌面上方，可以放東西）底下的那片板；疊幾張就再多幾片。"""
    from app.services.rack import level_boards_px
    slab = 50 * PX_PER_MM_V
    top, boards = level_boards_px("lackrack", 8, 0.0)
    assert top == 0.0
    assert len(boards) == 9, "8U＋桌面上方那一列"
    assert abs(boards[0] - slab) < 0.01, "桌面 50mm"
    assert boards[1:] == [0.0] * 8
    top, boards = level_boards_px("lackrack", 16, 0.0)
    seg = (450 - 50 - 8 * 44.45 + 50) * PX_PER_MM_V   # 上面那張的桌面下空隙＋下面那張的桌面
    # 由上往下：頂、U16…U9、U8…U1。U9 是上面那張桌子的最底下一格（index 8），它下面是下面那張的桌面
    assert abs(boards[8] - seg) < 0.01
    assert all(b == 0.0 for i, b in enumerate(boards) if i not in (0, 8))


def test_lackrack_top_is_a_placeable_position() -> None:
    from app.services.rack import placeable_levels
    assert placeable_levels("lackrack", 8) == 9, "桌面上方是第 9 個位置"
    assert placeable_levels("rack", 42) == 42, "一般機櫃有頂蓋，不變"


def test_finishes_are_per_kind_with_a_default() -> None:
    from app.services.rack import FINISHES, normalize_finish
    assert FINISHES["angle_shelf"][0] == "black", "台灣最常見黑色"
    assert set(FINISHES["angle_shelf"]) == {"black", "white", "galvanized"}
    assert set(FINISHES["kallax"]) == {"white", "black_brown", "oak"}
    assert set(FINISHES["lackrack"]) == {"white", "black", "brown"}
    assert normalize_finish("kallax", None) == "white"
    assert normalize_finish("kallax", "galvanized") == "white", "別的型態的顏色不適用就用預設"
    assert normalize_finish("angle_shelf", "white") == "white"
    assert normalize_finish("rack", "white") is None, "沒有顏色選項的型態一律 None"


@pytest.mark.anyio
async def test_diagram_carries_what_the_three_drawings_need(client, auth_headers) -> None:
    """畫面、前端匯出、對外嵌入三份畫法都吃這支端點的值 —— 顏色、欄數、逐片板厚都要給。"""
    made = {}
    for body in (
        {"name": "K-24", "kind": "kallax", "u_height": 4, "width_mm": 765, "finish": "oak"},
        {"name": "LACK-2", "kind": "lackrack", "u_height": 16, "width_mm": 550},
        {"name": "ANG-1", "kind": "angle_shelf", "u_height": 3, "finish": "white"},
        {"name": "R-STD", "kind": "rack", "u_height": 42},
    ):
        r = await client.post("/api/v1/racks", json=body, headers=auth_headers)
        assert r.status_code in (200, 201), r.text
        made[body["name"]] = r.json()
    assert made["K-24"]["finish"] == "oak", "顏色要存得進去、讀得回來"

    async def diag(name):
        r = await client.get(f"/api/v1/racks/{made[name]['id']}/diagram", headers=auth_headers)
        assert r.status_code == 200, r.text
        return r.json()

    k = await diag("K-24")
    assert (k["finish"], k["render_cols"], k["render_floor_px"]) == ("oak", 2, 0.0), \
        "KALLAX 直接落地，不畫腳"
    assert len(k["render_board_px_list"]) == 5
    assert k["render_board_px_list"][0] > k["render_board_px_list"][1], "外框比內隔板厚"
    assert k["render_divider_px"] > 0

    lack = await diag("LACK-2")
    assert lack["finish"] == "white", "沒填顏色就是預設色"
    assert lack["open_top"] is True, "桌面上方可以放東西"
    assert lack["render_board_px_list"][0] > 0, "桌面"
    assert sum(1 for b in lack["render_board_px_list"] if b > 0) == 2, "兩張疊起來：兩片桌面"
    assert lack["render_floor_px"] > 20, "桌面下 8U 之後還有約 44mm"

    ang = await diag("ANG-1")
    assert ang["finish"] == "white"
    assert ang["render_board_px_list"] == [ang["render_board_px"]] * 4

    std = await diag("R-STD")
    assert std["finish"] is None and std["render_cols"] == 1
    assert std["render_top_px"] > 30, "頂板 50mm"
    assert std["render_board_px_list"][-1] > 45, "底座 75mm"


# ─────────────────── 對外嵌入的 SVG（三份畫法之一） ───────────────────

def _svg(kind: str, rows: int, width: int | None = None, finish: str | None = None, devs=None):
    from app.services.rack_svg import build_rack_svg
    return build_rack_svg("X", rows, devs or [], kind=kind, width_mm=width, finish=finish)


def _height(svg: str) -> float:
    import re
    return float(re.search(r'<svg [^>]*height="([\d.]+)"', svg).group(1))


def test_embed_svg_draws_an_angle_shelf() -> None:
    svg = _svg("angle_shelf", 3)
    assert svg.count('class="angle-post"') == 2, "左右兩支 L 型立柱"
    assert 'id="keyholes-black"' in svg, "立柱上整排葫蘆孔；預設黑色"
    assert svg.count('class="angle-ply"') == 4, "3 層＋頂板，每層都有一片夾板"
    assert 'id="keyholes-white"' in _svg("angle_shelf", 3, finish="white")


def test_embed_svg_draws_kallax_cubes() -> None:
    svg = _svg("kallax", 4, 1465)
    assert svg.count('class="kallax-divider"') == 3, "4 欄有 3 片直的內隔板"
    assert svg.count('class="kallax-cell"') == 16, "4×4 格"
    assert "#e2d3b8" in _svg("kallax", 2, 765, finish="oak"), "橡木紋"


def test_embed_svg_draws_a_lackrack_with_one_top_per_table() -> None:
    one, two = _svg("lackrack", 8, 550), _svg("lackrack", 16, 550)
    assert one.count('class="lack-top"') == 1
    assert two.count('class="lack-top"') == 2, "疊兩張就有兩片桌面"
    assert one.count('class="lack-leg"') == 2
    # 一張桌子 450mm 高，換成 px 後兩張的圖要高出一張桌子的份量
    per_table = 450 * 28.0 / 44.45
    assert abs((_height(two) - _height(one)) - per_table) < 1.0


def test_embed_svg_is_unchanged_for_the_existing_kinds() -> None:
    """逐片板厚改成清單之後，既有型態的圖一個位元組都不能變（嵌在別人頁面上的圖）。"""
    import hashlib
    devs = [{"name": "srv", "type": "server", "u_position": 2, "u_size": 1,
             "rack_slot": 0, "rack_slot_span": 60}]
    got = {k: hashlib.sha256(_svg(k, 6, None, None, devs).encode()).hexdigest()[:12]
           for k in ("shelf", "wire_shelf", "wood_shelf")}
    assert got == SVG_BASELINE, got


def test_embed_svg_draws_the_cabinet_roof_and_base() -> None:
    for kind in ("rack", "industrial"):
        svg = _svg(kind, 6, 600)
        assert svg.count('class="rack-roof"') == 1 and svg.count('class="rack-base"') == 1, kind
    assert 'class="rack-roof"' not in _svg("wood_shelf", 6), "層架沒有頂板／底座"


def test_angle_beams_shrink_with_the_levels() -> None:
    """橫桿（50mm 鋼條＋9mm 夾板）跟層高用同一個比例。層高沒被壓時就是實際厚度；
    離譜的資料被整張圖的預算壓扁時，橫桿也要等比例縮 —— 否則橫桿佔一層的比例會比實物大，
    整座層架看起來全是粗鐵條。其他型態不受影響。"""
    from app.services.rack import level_render_px, scaled_board_px
    per_mm = 250.0 / 482.6            # 層架寬高同一個比例
    got = scaled_board_px("angle_shelf", None, None, None, None, 3)
    assert abs(got - 59 * per_mm) < 0.01, got
    # 20 層 × 520mm（10 公尺）會被預算壓：橫桿佔一層的比例要維持 59:520
    squeezed = scaled_board_px("angle_shelf", None, None, None, None, 20)
    _, rows = level_render_px("angle_shelf", None, None, None, 20)
    assert abs(squeezed / rows[0] - 59 / 520) < 0.005, (squeezed, rows[0])
    assert abs(scaled_board_px("wood_shelf", None, None, None, None, 6) - 18 * per_mm) < 1e-9
    assert scaled_board_px("rack", None, None, None, None, 42) == 0.0


def test_frontend_palette_and_floor_defaults_match_the_backend() -> None:
    """畫面、前端匯出用 rackFinish.ts 的配色，對外嵌入用 rack_svg.py 的 —— 兩份必須一樣。"""
    import re
    from pathlib import Path

    from app.services.rack import _DEFAULT_FLOOR_MM, FINISHES
    from app.services.rack_svg import FINISH_COLORS, PLY_COLOR

    root = Path(__file__).resolve().parents[2] / "frontend" / "src" / "utils"
    ts = (root / "rackFinish.ts").read_text(encoding="utf-8")
    body = ts[ts.index("export const FINISH_COLORS"):ts.index("export const PLY_COLOR")]
    found: dict[str, dict[str, dict[str, str]]] = {}
    kind = None
    for line in body.splitlines():
        m = re.match(r"^  (\w+): \{$", line)
        if m:
            kind = m.group(1)
            found[kind] = {}
            continue
        m = re.match(r"^    (\w+): \{(.*)\},$", line)
        if m and kind:
            found[kind][m.group(1)] = dict(re.findall(r'(\w+): "([^"]+)"', m.group(2)))
    assert found == FINISH_COLORS
    assert f'PLY_COLOR = "{PLY_COLOR}"' in ts
    for k, opts in FINISHES.items():
        assert re.search(rf'{k}: \[{", ".join(f"{chr(34)}{o}{chr(34)}" for o in opts)}\]', ts), k

    slots = (root / "rackSlots.ts").read_text(encoding="utf-8")
    line = next(ln for ln in slots.splitlines() if "RACK_FLOOR_MM" in ln and "=" in ln)
    front = {k: float(v) for k, v in re.findall(r"(\w+): ([\d.]+)", line.split("=", 1)[1])}
    assert front.keys() == _DEFAULT_FLOOR_MM.keys()
    for k, v in _DEFAULT_FLOOR_MM.items():
        assert round(v) == front[k], f"{k}: 前端 {front[k]} vs 後端 {v}"


def test_kallax_frame_is_as_thick_on_top_as_on_the_sides() -> None:
    """KALLAX 的外框四邊都是 40mm：上下的板要跟兩側一樣厚（寬高同一個比例才做得到）。"""
    from app.services.rack import level_boards_px, rack_side_px
    _, boards = level_boards_px("kallax", 4, 0.0)
    assert abs(boards[0] - rack_side_px("kallax", 765)) < 0.01
    assert abs(boards[-1] - rack_side_px("kallax", 765)) < 0.01
