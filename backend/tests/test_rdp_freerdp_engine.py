"""FreeRDP 引擎的接線。

這裡守的是「換了引擎之後畫面是不是還送得出去」與「缺套件時講不講得清楚」——
兩者壞掉都不會報錯，只會讓使用者看到一片空白或一句沒有內容的「連線失敗」。
"""

from __future__ import annotations

import asyncio
import pathlib
from types import SimpleNamespace

import pytest
from app.services.rdp_freerdp import (
    required_binaries,
    REQUIRED_MODULES,
    FreeRdpConnection,
    VideoTile,
    availability,
)


def test_video_tile_has_the_fields_the_bridge_sends():
    """`_bridge` 直接讀 `.x/.y/.width/.height/.data` —— 欄位名改了畫面就不會出現。"""
    t = VideoTile(x=1, y=2, width=3, height=4, data=b"png")
    assert (t.x, t.y, t.width, t.height, t.data) == (1, 2, 3, 4, b"png")


def test_bridge_accepts_a_tile_without_a_type_field():
    """FreeRDP 的 tile 沒有 aardwolf 的 `type` 欄位。

    原本的判斷是 `data.type == RDPDATATYPE.VIDEO`，FreeRDP 的畫面會全部被丟掉，
    而且一聲不響 —— 使用者只會看到永遠空白的畫面。
    """
    from app.api.v1.endpoints.rdp_console import _is_video

    assert _is_video(VideoTile(x=0, y=0, width=8, height=8, data=b"x")) is True


def test_bridge_still_rejects_non_video():
    from app.api.v1.endpoints.rdp_console import _is_video

    class _Empty:
        data = b""

    assert _is_video(_Empty()) is False
    assert _is_video(None) is False


def test_availability_names_what_is_missing():
    """缺東西時要講得出缺哪一個套件，設定頁才說得出「怎麼裝」。"""
    av = availability()
    assert set(av) == {"ok", "missing_packages", "missing_modules"}
    if not av["ok"]:
        assert av["missing_packages"] or av["missing_modules"]
    # 套件名是要印給人照著 apt install 的，不能是空字串
    assert all(required_binaries().values())
    assert all(REQUIRED_MODULES.values())


def test_engine_available_reports_per_engine(monkeypatch):
    """『RDP 能不能用』是逐引擎的問題。

    以前只看 aardwolf 這個全域旗標；只裝了 FreeRDP 的機器會被整個關掉功能。
    """
    from app.api.v1.endpoints import rdp_console

    monkeypatch.setattr(rdp_console, "RDP_AVAILABLE", False)
    ok, missing = rdp_console.engine_available("aardwolf")
    assert ok is False and "aardwolf" in missing

    monkeypatch.setattr("app.services.rdp_freerdp.availability",
                        lambda: {"ok": True, "missing_packages": [], "missing_modules": []})
    assert rdp_console.engine_available("freerdp") == (True, "")


def test_freerdp_password_never_reaches_argv():
    """密碼只能走 stdin。

    `/p:<password>` 會讓本機**任何**使用者從 `ps` 讀到目標主機的密碼。
    這是靜態檢查：原始碼裡不該出現把密碼接進參數列的寫法。
    """
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "rdp_freerdp.py"
    text = src.read_text()
    assert "/from-stdin:force" in text, "沒有走 stdin 的密碼輸入"
    assert 'f"/p:' not in text and '"/p:"' not in text, "密碼被放進 argv 了"


def test_terminate_is_safe_before_connect():
    """連線還沒建立就被收掉（使用者馬上關掉分頁）不可以炸。"""
    import asyncio

    from app.services.rdp_freerdp import FreeRdpConnection

    conn = FreeRdpConnection(host="192.0.2.1", port=3389, username="u",
                             password="p", domain=None, width=800, height=600)
    asyncio.run(conn.terminate())
    asyncio.run(conn.terminate())      # 第二次也要安靜地過


def test_clipboard_is_off_unless_the_admin_enabled_it():
    """FreeRDP 的剪貼簿重導**預設是開的** —— 這個引擎必須顯式關掉它。

    管理者把「控制端貼上」關掉，是明確關閉了一條資料通道。換引擎時把它默默打開，
    等於用一個「效能／相容性」的選擇改變了資安姿態，而且畫面上看不出來。
    """
    from app.services.rdp_freerdp import FreeRdpConnection

    off = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                            domain=None, width=800, height=600, clip_enabled=False)
    on = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                           domain=None, width=800, height=600, clip_enabled=True)
    assert off._clip_enabled is False
    assert on._clip_enabled is True
    # 預設值就是關的：呼叫端忘了傳也不會意外打開
    dflt = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)
    assert dflt._clip_enabled is False


async def test_pasting_is_refused_when_disabled():
    """沒開就不該默默吞掉 —— 要講出原因，否則使用者會以為貼上成功了。"""
    import pytest
    from app.services.rdp_freerdp import FreeRdpConnection, FreeRdpError

    conn = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=800, height=600, clip_enabled=False)
    conn._display = ":99"
    with pytest.raises(FreeRdpError):
        await conn.set_current_clipboard_text("hello")


def test_the_engine_does_not_need_aardwolf_for_mouse_buttons():
    """滑鼠按鍵不可以綁在 aardwolf 的列舉上。

    否則「用 FreeRDP 引擎」仍然得先裝 aardwolf，兩個引擎等於沒有真的分開 ——
    而 FreeRDP 存在的理由，正是給 aardwolf 連不上的環境用。
    """
    from app.api.v1.endpoints.rdp_console import _mouse_button

    for b, name in ((0, "MOUSEBUTTON_LEFT"), (1, "MOUSEBUTTON_RIGHT"), (2, "MOUSEBUTTON_MIDDLE")):
        btn = _mouse_button(b)
        assert btn.name == name
        assert type(btn).__module__.startswith("app."), "按鍵型別來自 aardwolf"


def test_display_number_is_not_read_from_a_pipe():
    """不可以用 `-displayfd` 從管線讀顯示編號。

    uvicorn 預設跑在 uvloop 上，而 `connect_read_pipe` 在那裡讀到的是立即 EOF ——
    我們拿到空字串、Xvfb 卻還活著，錯誤只剩「啟動失敗（結束碼 None）」。
    用標準 asyncio 跑獨立腳本完全測不出來（2026-09-17 正式環境）。

    改走 X 自己的仲裁：鎖檔 + 等 socket 出現，純檔案檢查，與事件迴圈無關。
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    # 只看實際呼叫：註解裡解釋「為什麼不用」是應該留著的
    code = "\n".join(ln for ln in src.splitlines()
                      if not ln.lstrip().startswith("#"))
    assert '"-displayfd"' not in code, "又用回管線讀編號了 —— 那在 uvloop 下會壞"
    assert "connect_read_pipe(" not in code
    assert "os.pipe()" not in code
    assert "_X11_LOCK_PREFIX" in src, "沒有用鎖檔挑顯示編號"


def test_a_taken_display_number_moves_on_to_the_next():
    """編號被佔走時要換下一個，不可以直接失敗。

    同一台機器上可能同時有好幾條 RDP 連線（也可能有別的 X 伺服器）。
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    assert "for step in range(span)" in src and "_DISPLAY_MIN + (start + step) % span" in src
    assert "await self._kill_xvfb()" in src, "試失敗的那個 Xvfb 沒有收掉 → 會留下孤兒"


def test_children_are_cleaned_up_without_forking_in_a_thread():
    """子行程不可以用 `preexec_fn` 收尾，孤兒交給 systemd 的 cgroup。

    正常收線走 `terminate()`；後端被 SIGKILL 帶走時（OOM、`systemctl kill`、部署腳本
    出手）那段不會執行，Xvfb／xfreerdp／ffmpeg 會變成孤兒繼續佔記憶體 —— 它們不吵不鬧，
    直到機器被一堆看不出來歷的 Xvfb 吃光。

    這件事**曾經**用 `preexec_fn` 設 `PR_SET_PDEATHSIG`，但在多執行緒行程裡 fork 慢得
    離譜：同一台機器單執行緒建立連線 2.85 秒，有 8 個工作執行緒時 14.76 秒 —— uvicorn
    的 worker 本來就有執行緒，直接衝破連線逾時（2026-09-17 正式環境「連線逾時」）。
    改由 systemd 的 `KillMode=mixed` 對 cgroup 內剩餘行程送 SIGKILL，同一件事零成本。

    所以這裡守兩件事：原始碼不可以又把 `preexec_fn` 加回來，單元檔要有 `KillMode=mixed`。
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    src = (root / "backend" / "app" / "services" / "rdp_freerdp.py").read_text()
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert "preexec_fn" not in code, "又用回 preexec_fn 了 —— 那會讓連線在有負載時逾時"

    unit = (root / "deploy" / "systemd" / "jt-ipam-backend.service").read_text()
    assert "KillMode=mixed" in unit, "沒有 KillMode=mixed，後端被 SIGKILL 後會留下孤兒 Xvfb"


def test_terminate_kills_in_the_right_order():
    """先收畫面擷取與 RDP，最後才收 Xvfb。

    反過來的話，xfreerdp 與 ffmpeg 會對著一個不存在的顯示噴一堆錯誤才死。
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    assert "for proc in (self._grab, self._rdp, self._xvfb):" in src


def test_the_x11_socket_directory_is_created():
    """`/tmp/.X11-unix` 不存在時要自己建。

    X 的 unix socket 路徑是協定寫死的，而 **Xvfb 以非 root 身分不會自己建那個目錄**
    （`_XSERVTransmkdir: ERROR: euid != 0`），然後安靜地失敗、連顯示編號都不回報。

    開發機上看不到這個問題，因為那個目錄早就在了。正式環境的 systemd 單元帶
    `PrivateTmp=yes` —— 服務拿到的是全新的空 /tmp，於是第一次連線就失敗
    （2026-09-17 實際發生）。
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    assert "_ensure_x11_socket_dir()" in src, "沒有在啟動 Xvfb 前確保 socket 目錄存在"
    assert "makedirs(_X11_SOCKET_DIR" in src
    # 既有目錄的權限不該被我們動：沒有 PrivateTmp 的機器上那是共用的
    assert "os.chmod(_X11_SOCKET_DIR" not in src, "不要改既有 X11 socket 目錄的權限"


def test_xvfb_failures_carry_its_own_words():
    """Xvfb 起不來時要把它自己說的話帶出來。

    只說「顯示編號看不懂」會讓人去查我們的解析，真正的原因在 Xvfb 的 stderr 裡。

    ⚠️ stderr 要寫**檔案**不是管線：失敗時管線可能已經關掉或還沒有東西可讀，
    於是原因就消失了（2026-09-17 正式環境上只剩一句「啟動失敗」，查不下去）。
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    assert "找不到可用的虛擬顯示" in src
    assert "stderr=self._xvfb_err" in src, "Xvfb 的 stderr 沒有導進檔案"
    assert "_xvfb_stderr_tail" in src, "失敗時沒有把 Xvfb 說的話讀回來"


def test_xvfb_stderr_tail_filters_the_keysym_noise():
    """xkbcomp 的一長串 keysym 警告會把真正的那一行淹掉。"""
    from app.services.rdp_freerdp import FreeRdpConnection

    conn = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)

    class _Fake:
        name = ""
        def flush(self): pass

    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False,
                                     encoding="utf-8") as fh:
        fh.write("The XKEYBOARD keymap compiler (xkbcomp) reports:\n")
        for i in range(40):
            fh.write(f"> Warning: Could not resolve keysym XF86Thing{i}\n")
        fh.write("_XSERVTransmkdir: ERROR: euid != 0, directory /tmp/.X11-unix will not be created.\n")
        path = fh.name
    _Fake.name = path
    conn._xvfb_err = _Fake()
    tail = conn._xvfb_stderr_tail()
    import os
    os.unlink(path)
    assert "_XSERVTransmkdir" in tail, "真正的錯誤被噪音擠掉了"
    assert "Could not resolve keysym" not in tail


def test_freerdp_errors_are_not_run_through_the_aardwolf_classifier():
    """FreeRDP 的錯誤不可以套 aardwolf 的失敗分類。

    那個分類器是照 aardwolf 的樣態寫的。把「虛擬顯示起不來」丟進去，會得到
    「連線/認證失敗（帳號、密碼、網域或 NLA 設定）」—— 指著完全無關的方向，
    而使用者會照著去查密碼（2026-09-17 正式環境實際發生）。
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "api" / "v1" / "endpoints" / "rdp_console.py").read_text()
    i = src.index("if err is not None:")
    block = src[i:i + 1600]
    assert "isinstance(err, FreeRdpError)" in block, "沒有先辨認 FreeRDP 的錯誤"
    assert block.index("isinstance(err, FreeRdpError)") < block.index("_classify_connect_error"), \
        "FreeRDP 的錯誤仍會落進 aardwolf 的分類器"


def test_freerdp_gets_its_own_home():
    """xfreerdp 要用這條連線專用的家目錄。

    FreeRDP 會往 `$HOME/.config/freerdp` 寫東西。家目錄不可寫時它不直說，而是在
    後面回 `ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED`（「安全層協商失敗」）——
    指向完全無關的方向。給它自己的臨時目錄，就不必管服務的 HOME 是什麼。
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    assert 'HOME=self._home' in src, "沒有給 xfreerdp 自己的家目錄"
    assert "mkdtemp" in src and "rmtree" in src, "臨時家目錄沒有建立或沒有清掉"


async def test_the_temp_home_is_removed_on_terminate():
    """臨時家目錄要跟著 session 消失，不可以累積。"""
    import os

    from app.services.rdp_freerdp import FreeRdpConnection

    conn = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)
    import tempfile
    conn._home = tempfile.mkdtemp(prefix="jtipam-rdp-test-")
    path = conn._home
    assert os.path.isdir(path)
    await conn.terminate()
    assert not os.path.isdir(path), "臨時家目錄沒有被清掉"


def test_odd_widths_are_rounded_down():
    """RDP 的桌面寬度必須是偶數。

    奇數寬度會讓連線在 post_connect 階段失敗，而 FreeRDP 回的是
    `ERRCONNECT_CONNECT_TRANSPORT_FAILED` —— 讀起來像「連不到目標」，
    但其實 TCP 早就通了。瀏覽器視窗寬度剛好是奇數的人會**每次都連不上**，
    而錯誤訊息指向網路（2026-09-17 正式環境：1525 寬）。

    實測：1525x979 與 1525x978 都失敗，1524x979 與 1524x978 都成功 ——
    所以是寬度，不是高度。
    """
    from app.services.rdp_freerdp import FreeRdpConnection

    conn = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=1525, height=979)
    assert conn._width == 1524, "奇數寬度沒有被對齊"
    assert conn._width % 2 == 0
    # 已經是偶數的不要動
    same = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=1280, height=800)
    assert (same._width, same._height) == (1280, 800)


def test_post_connect_is_not_treated_as_the_graphics_stage():
    """`freerdp_post_connect failed` **不是**畫面參數階段的訊號。

    這個測試原本斷言相反的事。當時只看過一種失敗（桌面寬度是奇數），就把
    `post_connect` 當成「TCP 與認證都過了、卡在畫面參數協商」的判準。
    2026-09-18 把四種失敗的原始輸出抓下來才發現：**連接埠沒人聽、那個埠不是 RDP、
    位址不存在，全都會印這一行**，於是三種網路失敗都被講成
    「被控端拒絕了這組畫面參數（解析度或色彩深度）」，使用者照著去查解析度永遠查不到。

    教訓：判準要選**只有那一種失敗才會出現**的字串，不能選「那種失敗也會出現」的。
    真正屬於畫面參數階段的訊號是 `DEACTIVATE_ALL` / `demand_active`（實測成因是
    指定了 `/bpp`），那個仍然要講成畫面參數。
    """
    from app.services.rdp_freerdp import _explain

    generic = _explain("ERRCONNECT_CONNECT_TRANSPORT_FAILED [0x0002000D] freerdp_post_connect failed")
    assert "畫面參數" not in generic
    assert "傳輸" in generic

    graphics = _explain("expected PDU_TYPE_DEMAND_ACTIVE 0001, got 0006 (DEACTIVATE_ALL)")
    assert "畫面參數" in graphics


def test_the_captured_frame_carries_no_cursor():
    """畫面裡不可以烘進游標 —— 瀏覽器自己會畫一個，兩個疊在一起就是「游標偏移」。

    ffmpeg 畫的是 **X 的**游標（被控端的游標形狀是另一回事），位置雖然正確，但使用者
    看到的是自己的箭頭加上畫面裡的那一個。aardwolf 引擎沒有這個現象，換引擎後才冒出來。
    順帶：滑鼠在空白處移動時不再產生任何更新，閒置流量歸零。
    """
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text("utf-8")
    assert '"-draw_mouse", "0"' in src
    assert '"-draw_mouse", "1"' not in src


def _record_xtest(monkeypatch):
    """攔下 xtest.fake_input，記下每一次注入。"""
    from Xlib.ext import xtest
    calls: list[tuple] = []
    monkeypatch.setattr(xtest, "fake_input",
                        lambda disp, kind, detail=0, **kw: calls.append((kind, detail, kw)))
    return calls


@pytest.mark.parametrize(("name", "pressed", "wheel", "expect"), [
    ("MOUSEBUTTON_LEFT", True, 0, [("press", 1)]),
    ("MOUSEBUTTON_LEFT", False, 0, [("release", 1)]),
    ("MOUSEBUTTON_RIGHT", True, 0, [("press", 3)]),
    ("MOUSEBUTTON_RIGHT", False, 0, [("release", 3)]),
    ("MOUSEBUTTON_MIDDLE", True, 0, [("press", 2)]),
    ("MOUSEBUTTON_HOVER", False, 0, []),
    ("MOUSEBUTTON_WHEEL_UP", False, 120, [("press", 4), ("release", 4)]),
    ("MOUSEBUTTON_WHEEL_UP", False, 0x100 | 120, [("press", 5), ("release", 5)]),
    ("MOUSEBUTTON_WHEEL_UP", False, 240, [("press", 4), ("release", 4)] * 2),
])
async def test_every_button_and_the_wheel_reach_x(monkeypatch, name, pressed, wheel, expect):
    from Xlib import X
    calls = _record_xtest(monkeypatch)
    conn = FreeRdpConnection(host="h", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)
    conn._disp = SimpleNamespace(sync=lambda: None)

    class _B:
        def __init__(self, n: str) -> None: self.name = n

    await conn.send_mouse(_B(name), 123, 45, pressed, wheel)
    kind = {X.ButtonPress: "press", X.ButtonRelease: "release"}
    assert calls[0][0] == X.MotionNotify, "每次都要先把指標移到座標上"
    assert calls[0][2] == {"x": 123, "y": 45}
    assert [(kind[k], d) for k, d, _ in calls[1:]] == expect


async def test_mouse_coordinates_are_clamped_to_the_framebuffer():
    """寬度被捨成偶數後，前端仍可能送來最後那一欄 —— 不可以送出畫面外的座標。"""
    conn = FreeRdpConnection(host="h", port=3389, username="u", password="p",
                             domain=None, width=1525, height=801)
    seen: list[tuple[int, int]] = []
    conn._disp = SimpleNamespace(sync=lambda: None)
    from Xlib.ext import xtest
    orig = xtest.fake_input
    try:
        xtest.fake_input = lambda d, k, detail=0, **kw: seen.append((kw.get("x"), kw.get("y")))

        class _B:
            name = "MOUSEBUTTON_HOVER"

        await conn.send_mouse(_B(), 1524, 800, False)
        await conn.send_mouse(_B(), -5, -5, False)
    finally:
        xtest.fake_input = orig
    assert seen == [(1523, 799), (0, 0)]


def test_the_engine_reports_the_size_it_actually_got():
    """捨成偶數之後的尺寸要講出來，前端才畫得對。

    前端把 canvas 開成它「要求」的寬度，但 framebuffer 是捨過的。差 1 px 會讓最右邊
    那一欄永遠是黑的，而且 `mapXY` 用錯的比例換算 —— 邊緣愈靠右愈偏。
    """
    conn = FreeRdpConnection(host="h", port=3389, username="u", password="p",
                             domain=None, width=1525, height=801)
    assert conn.framebuffer_size == (1524, 800)
    even = FreeRdpConnection(host="h", port=3389, username="u", password="p",
                             domain=None, width=1366, height=830)
    assert even.framebuffer_size == (1366, 830)


def test_a_character_the_layout_cannot_produce_is_reported_not_swallowed():
    """打不出來的字元要出聲。

    FreeRDP 引擎把 X 的按鍵交給 xfreerdp，而 xfreerdp 是用**固定的 keycode→掃描碼
    對照表**翻譯的 —— 借一顆沒人用的 keycode 綁上中文 keysym，送出去的是一顆沒有掃描碼
    的鍵，被控端什麼也不會發生。2026-09-18 在真機上把 5 顆分佈不同的空 keycode 都試過
    （8／178／248／250／254），一顆都沒有反應；FreeRDP 2.11 也沒有任何 Unicode 輸入選項。

    所以這條路是**走不通**的，不是沒調好。真正不能接受的是原本的行為：安靜地丟掉，
    使用者只會覺得鍵盤壞了。現在改成回報 `console_char_not_typable`，畫面會說
    「請改用貼上」—— 剪貼簿那條路實測連中文都貼得進去。
    """
    from app.services.rdp_freerdp import UnsupportedCharacter

    conn = FreeRdpConnection(host="h", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)

    class _Disp:
        def keysym_to_keycodes(self, _sym):
            return []

        def sync(self):
            pass

    conn._disp = _Disp()
    with pytest.raises(UnsupportedCharacter) as got:
        asyncio.run(conn.send_key_char("測", True))
    assert got.value.char == "測"


def test_the_engine_no_longer_remaps_keycodes():
    """不可以再把 keycode 借來重綁。

    那是為了打非 ASCII 字元加的，實測完全無效（見上一個測試），而且它會**改動那個 X
    顯示的鍵盤配置**——有副作用、沒有效果。
    """
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert "change_keyboard_mapping" not in code
    assert "_spare_keycode" not in code


def test_ascii_still_takes_the_normal_path():
    """ASCII 不受影響：查得到就照原本的 keycode 打，需要時補 Shift。"""
    conn = FreeRdpConnection(host="h", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)

    class _Disp:
        def keysym_to_keycodes(self, _sym):
            return [(38, 1)]        # 第 1 階 → 要按 Shift

        def sync(self):
            pass

    conn._disp = _Disp()
    assert conn._plan_char(ord("A")) == (38, True)


def test_altgr_levels_are_not_typed_as_shift():
    """第 2／3 階（AltGr）不可以當成 Shift 送出去。

    `bool(index)` 對 index=2 也是 True，會按著 Shift 敲出一個**別的字元** ——
    比打不出來更糟：畫面上會出現使用者沒有輸入的東西。
    """
    conn = FreeRdpConnection(host="h", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)

    class _Disp:
        def keysym_to_keycodes(self, _sym):
            return [(26, 2)]        # 只在 AltGr 階上

        def sync(self):
            pass

    conn._disp = _Disp()
    assert conn._plan_char(0x20AC) is None


#: 2026-09-18 從真機抓下來的四種失敗，逐字保留（只截掉時間戳與 pid）。
#: 分類要照這些證據寫，不要照猜的。
_REAL_STDERR = {
    "refused": """[ERROR][com.freerdp.core.transport] - BIO_should_retry returned a system error 32: Broken pipe
[ERROR][com.freerdp.core] - transport_write:freerdp_set_last_error_ex ERRCONNECT_CONNECT_TRANSPORT_FAILED [0x0002000D]
[ERROR][com.freerdp.client.x11] - freerdp_post_connect failed""",
    "not_rdp": """[ERROR][com.freerdp.core.transport] - BIO_read returned a system error 104: Connection reset by peer
[ERROR][com.freerdp.core] - transport_read_layer:freerdp_set_last_error_ex ERRCONNECT_CONNECT_TRANSPORT_FAILED [0x0002000D]
[ERROR][com.freerdp.client.x11] - freerdp_post_connect failed""",
    "unreachable": """[ERROR][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex ERRCONNECT_CONNECT_FAILED [0x00020006]
[ERROR][com.freerdp.client.common] - failed to connect to 192.0.2.77""",
    "bad_password": """[ERROR][com.freerdp.core.nla] - SPNEGO received NTSTATUS: STATUS_LOGON_FAILURE [0xC000006D] from server
[ERROR][com.freerdp.core] - nla_recv_pdu:freerdp_set_last_error_ex ERRCONNECT_LOGON_FAILURE [0x00020014]
[ERROR][com.freerdp.core.rdp] - rdp_recv_callback: CONNECTION_STATE_NLA - nla_recv_pdu() fail""",
}


def test_four_different_failures_do_not_get_the_same_sentence():
    """四種失敗要講四種話。

    2026-09-18 實測抓到：連接埠沒人聽、那個埠不是 RDP、位址不存在 —— 三種都被講成
    「被控端拒絕了這組畫面參數（解析度或色彩深度）」。原因是分類器拿 `post_connect`
    當判準，而 **`freerdp_post_connect failed` 是任何失敗都會印的一行**，不是圖形階段
    的訊號。使用者照著那句話去查解析度，永遠查不到。
    """
    from app.services.rdp_freerdp import _explain

    said = {k: _explain(v) for k, v in _REAL_STDERR.items()}
    heads = {k: v.split("：")[0] for k, v in said.items()}
    assert len(set(heads.values())) == 4, f"有失敗共用同一句話：{heads}"
    assert "畫面參數" not in " ".join(heads.values()), "網路層的失敗不可以講成畫面參數"
    assert "密碼" in heads["bad_password"]
    for key in ("refused", "not_rdp", "unreachable"):
        assert "連" in heads[key], f"{key} 應該講成連線問題：{heads[key]!r}"


def test_the_underlying_words_are_kept():
    """分類之後底層原文還要在 —— 分錯的時候，原文是唯一能救回來的東西。

    但**不可以從半個字中間切開**：原本是把整段壓成一行再取最後 240 字元，
    結果開頭會是 `5:598]` 這種切一半的時間戳。
    """
    from app.services.rdp_freerdp import _explain

    out = _explain(_REAL_STDERR["unreachable"])
    assert "ERRCONNECT_CONNECT_FAILED" in out or "failed to connect" in out
    detail = out.split("：", 1)[1]
    assert not detail.startswith(("]", ":")), f"原文從半個字切開了：{detail[:20]!r}"
    # 時間戳與 pid 是雜訊，留著只會把真正的訊息擠掉
    assert "[ERROR]" not in detail and "com.freerdp" not in detail


def test_an_empty_stderr_still_says_something():
    from app.services.rdp_freerdp import _explain

    assert _explain("").strip()


def test_a_display_is_only_ours_if_the_lock_file_says_so(tmp_path):
    """socket 存在**不代表**那個顯示是我們的。

    2026-09-18 實測：三條連線同時開，全部拿到 `:100` —— 它們共用同一個虛擬螢幕，
    等於**同時連線的使用者會看到彼此的畫面**，鍵盤滑鼠也會互相干擾。

    競態是這樣來的：三個都先檢查 `/tmp/.X100-lock` 不存在 → 三個都去起 Xvfb →
    只有一個搶得到鎖，另外兩個立刻結束；但我們的判斷只是「socket 檔案出現了嗎」，
    而那個 socket 是贏家建的。輸家於是拿著別人的顯示繼續跑。

    X 的鎖檔裡寫的就是持有者的 PID —— 拿它跟我們自己起的那個 Xvfb 比對，
    才是真的證明。
    """
    from app.services.rdp_freerdp import _display_owner

    lock = tmp_path / ".X100-lock"
    lock.write_text("%10d\n" % 4242)
    assert _display_owner(str(lock)) == 4242

    lock.write_text("not a pid\n")
    assert _display_owner(str(lock)) is None
    assert _display_owner(str(tmp_path / "does-not-exist")) is None


def test_the_socket_check_is_paired_with_an_ownership_check():
    """靜態守門：不可以再只憑 socket 存在就宣告成功。"""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    body = src[src.index("async def _try_display"):src.index("async def _kill_xvfb")]
    assert "_display_owner" in body, "拿到顯示之後沒有驗證擁有者"
    assert "self._xvfb.pid" in body, "沒有跟自己起的 Xvfb 比對 PID"


def test_display_scan_does_not_always_start_at_the_same_number():
    """每條連線從不同的號碼開始掃，減少互搶。

    擁有者檢查已經保證正確性；起點打散只是不要讓每一條都先去撞 100。
    """
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    body = src[src.index("async def _start_xvfb"):src.index("async def _try_display")]
    assert "randbelow" in body or "randrange" in body


def test_the_handshake_is_serialised_across_workers():
    """交握要排隊，而且是**跨行程**排隊。

    2026-09-18 實測（gnome-remote-desktop）：三條**依序**開、都保持連著，全部成功；
    兩條**同一瞬間**開始交握就固定壞一條。壞的那一條回的還不一定一樣 ——
    有時是安全層協商失敗，有時直接是 `STATUS_LOGON_FAILURE`，
    也就是**密碼明明是對的，使用者卻被告知帳號或密碼不正確**。

    為什麼不是「失敗就重試一次」：重試等於把憑證再送一次。實測那一次重試拿到的正是
    `LOGON_FAILURE` —— 在有鎖定政策的目標上，那是拿使用者的帳號去換一次失敗登入。
    排隊不碰憑證，成本只是多等一輪交握（實測約 2.5 秒）。

    uvicorn 預設跑多個 worker，所以 `asyncio.Lock` 不夠 —— 那只擋得住同一個行程裡的。
    用檔案鎖（`flock`）才是整台機器一份。
    """
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert "flock" in code, "沒有跨行程的鎖 —— 多個 uvicorn worker 還是會撞在一起"
    assert "_HANDSHAKE_LOCK_PATH" in code


def test_the_handshake_lock_cannot_wedge_everyone():
    """拿不到鎖也要繼續試，不可以因為別人卡住就整個連不上。

    排隊是為了避開一個**偶發**的碰撞，不是為了把它變成單一失效點。
    """
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    assert "_HANDSHAKE_LOCK_WAIT" in src


def test_credentials_are_never_sent_twice_for_one_attempt():
    """一次連線只送一次憑證 —— 不可以再把「失敗就重試」加回來。"""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "services" / "rdp_freerdp.py").read_text()
    body = src[src.index("async def connect("):src.index("async def _start_xvfb")]
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    assert "_CONNECT_RETRIES" not in code and "_worth_retrying" not in code
    assert code.count("await self._start_xfreerdp()") == 1


# ── FreeRDP 3（GitHub issue #39）─────────────────────────────────────────
# Ubuntu 25.10／26.04 已經沒有 freerdp2-x11，只剩 freerdp3-x11（執行檔叫 xfreerdp3）。
# 以前只認 xfreerdp，在那些版本上 FreeRDP 引擎根本裝不起來 —— 而那正是 aardwolf 也裝不起來
# （Python 3.14 沒有 wheel）的那批主機，兩個引擎都用不了。

def test_the_engine_falls_back_to_freerdp3(monkeypatch):
    import app.services.rdp_freerdp as m
    have = {"xfreerdp3": "/usr/bin/xfreerdp3"}
    monkeypatch.setattr(m.shutil, "which", lambda b: have.get(b))
    monkeypatch.delenv("JT_IPAM_FREERDP_BIN", raising=False)
    assert m.freerdp_binary() == "/usr/bin/xfreerdp3"
    have["xfreerdp"] = "/usr/bin/xfreerdp"
    assert m.freerdp_binary() == "/usr/bin/xfreerdp", "兩個都有時用驗證較久的 FreeRDP 2"
    monkeypatch.setenv("JT_IPAM_FREERDP_BIN", "xfreerdp3")
    assert m.freerdp_binary() == "/usr/bin/xfreerdp3", "可以用環境變數指定"


def test_availability_is_satisfied_by_freerdp3_alone(monkeypatch):
    import app.services.rdp_freerdp as m
    have = {"xfreerdp3", "Xvfb", "ffmpeg"}
    monkeypatch.setattr(m.shutil, "which", lambda b: f"/usr/bin/{b}" if b in have else None)
    monkeypatch.delenv("JT_IPAM_FREERDP_BIN", raising=False)
    m.freerdp_package.cache_clear()       # 套件判斷有快取，別讓假的 which 留下錯的結果
    try:
        assert "freerdp" not in " ".join(m.availability()["missing_packages"])
    finally:
        m.freerdp_package.cache_clear()


def test_the_package_to_install_follows_what_the_os_offers(monkeypatch):
    import app.services.rdp_freerdp as m
    m.freerdp_package.cache_clear()
    monkeypatch.setattr(m, "_apt_has_candidate", lambda pkg: pkg == "freerdp3-x11")
    assert m.freerdp_package() == "freerdp3-x11"
    assert "freerdp3-x11" in m.freerdp_apt_hint()
    m.freerdp_package.cache_clear()
    monkeypatch.setattr(m, "_apt_has_candidate", lambda pkg: True)
    assert m.freerdp_package() == "freerdp2-x11", "兩個都有時裝驗證較久的 FreeRDP 2"
    m.freerdp_package.cache_clear()


def test_the_installer_picks_freerdp3_where_freerdp2_is_gone():
    from pathlib import Path
    sh = (Path(__file__).resolve().parents[2] / "scripts" / "jt-ipam.sh").read_text(encoding="utf-8")
    assert "freerdp3-x11" in sh, "Ubuntu 25.10 起只有 freerdp3-x11"
    present = sh[sh.index("freerdp_apt_present() {"):]
    present = present[:present.index("}")]
    assert "xfreerdp3" in present, "裝好 FreeRDP 3 要算有裝"


@pytest.mark.anyio
async def test_terminate_does_not_hang_when_nobody_reads_the_queue():
    """控制端斷線時沒有人在讀畫面佇列；佇列滿了（最多 8 張）的話，`await put(None)` 會永遠
    卡住，後面收掉 xfreerdp 與 Xvfb 的步驟就不會執行 —— 每斷一次線就留下一組行程。
    （對 FreeRDP 3 做整合測試時抓到的，FreeRDP 2 一樣會中。）
    """
    import asyncio

    conn = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)
    for i in range(conn.ext_out_queue.maxsize):
        conn.ext_out_queue.put_nowait(VideoTile(x=0, y=0, width=1, height=1, data=b"%d" % i))
    async with asyncio.timeout(3):
        await conn.terminate()
    # 結束訊號還是要送到（控制端若還在讀，要知道畫面到此為止）
    items = []
    while not conn.ext_out_queue.empty():
        items.append(conn.ext_out_queue.get_nowait())
    assert items[-1] is None


@pytest.mark.anyio
async def test_terminate_does_not_hang_on_a_capture_process_nobody_reads():
    """抓畫面的 ffmpeg 一直往管線寫；串流收掉之後沒人讀，管線滿了它就卡在 write 上。

    收的時候：SIGTERM 對卡在 write 的它沒效果；SIGKILL 殺得掉，但 asyncio（Python 3.12）的
    `proc.wait()` 要等**所有管線都斷開**才會回來 —— 讀取端因為緩衝滿了而暫停著，永遠等不到 EOF，
    於是永遠卡住，後面收 xfreerdp 與 Xvfb 的步驟都不會執行（每斷一次線留下一組行程）。
    用一個真的、不停寫 stdout 的行程重現。
    """
    import asyncio

    conn = FreeRdpConnection(host="192.0.2.1", port=3389, username="u", password="p",
                             domain=None, width=800, height=600)
    # ffmpeg 有自己的 SIGTERM 處理，卡在 write 上時不會結束，只能靠 SIGKILL —— 而 SIGKILL 之後
    # 的那次 wait 才是會永遠卡住的地方。`trap "" TERM` 再 exec 讓 yes 也忽略 SIGTERM，情況相同。
    conn._grab = await asyncio.create_subprocess_exec(
        "sh", "-c", 'trap "" TERM; exec yes 0123456789abcdef0123456789abcdef',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    await asyncio.sleep(0.5)          # 讓管線寫滿、讀取端暫停
    async with asyncio.timeout(15):
        await conn.terminate()
    assert conn._grab is None
