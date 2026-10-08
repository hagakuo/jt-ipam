"""FreeRDP 連線引擎：以 FreeRDP 取代 aardwolf 連到 RDP 目標。

為什麼需要它
------------
aardwolf 走的 `asyauth` 0.0.23 在 NTLM 認證時不送 MIC（原始碼裡是一行 TODO）。
MS-NLMP 3.1.5.1.2 說：伺服器的 CHALLENGE 帶了 `MsvAvTimestamp` 時，用戶端就該回 MIC；
FreeRDP 的伺服器端會**強制**檢查這一點，而 gnome-remote-desktop 用的正是它。
實測（2026-09-17，Ubuntu 24 + GNOME 遠端登入）：同一台主機、同一組帳密，
FreeRDP 認證成功，aardwolf 回 `STATUS_LOGON_FAILURE (0xc000006d)`。

怎麼做
------
FreeRDP 沒有可用的 Python 繫結，所以用它的 X11 用戶端：開一個只有這個 session 看得到的
虛擬顯示（Xvfb），讓 `xfreerdp` 畫在上面，我們再從那個顯示把畫面抓下來、把輸入打進去。

對外介面刻意與 aardwolf 的連線物件**一模一樣**（`ext_out_queue` / `send_mouse` /
`send_key_scancode` / `send_key_char` / `terminate`），所以 `rdp_console._bridge()`
與整個前端都不用改 —— 換引擎對上層是透明的。

資安
----
- 密碼走 `/from-stdin:force`，**不進 argv** —— `/p:` 會讓本機任何使用者從 `ps` 讀到。
- Xvfb 用 `-nolisten tcp`，顯示只存在於本機 unix socket。
- 行程與 WS session 同生共死；`terminate()` 一定要把兩個子行程收掉，否則會留下孤兒
  Xvfb 一直佔著記憶體。
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import functools
import logging
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("jt-ipam.rdp.freerdp")

# RDP 用戶端：FreeRDP 2 叫 xfreerdp、FreeRDP 3 叫 xfreerdp3。Ubuntu 25.10／26.04 起只剩
# freerdp3-x11（GitHub issue #39）—— 以前只認 xfreerdp，那些版本上這個引擎根本裝不起來，
# 而那正是 aardwolf 也裝不起來（Python 3.14 沒有 wheel）的主機。兩個都有時用驗證較久的 2；
# `JT_IPAM_FREERDP_BIN` 可以指定（測試 FreeRDP 3 也靠它）。命令列選項兩版相同（已實測）。
FREERDP_BINARIES = ("xfreerdp", "xfreerdp3")


def freerdp_binary() -> str | None:
    """實際要執行的 RDP 用戶端路徑；都沒有就 None。"""
    forced = os.environ.get("JT_IPAM_FREERDP_BIN", "").strip()
    if forced:
        return shutil.which(forced)
    for name in FREERDP_BINARIES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _apt_has_candidate(pkg: str) -> bool:
    """這台的 apt 有沒有這個套件可以裝（`apt-cache policy` 的 Candidate 不是 (none)）。"""
    apt_cache = shutil.which("apt-cache")
    if apt_cache is None:                 # 不是 Debian／Ubuntu：沒有 apt 可問
        return False
    try:
        # pkg 只會是這個模組裡寫死的套件名（freerdp2-x11），不是外部輸入
        out = subprocess.run([apt_cache, "policy", pkg], capture_output=True,  # noqa: S603
                             text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    for line in out.splitlines():
        if line.strip().startswith("Candidate:"):
            return "(none)" not in line
    return False


@functools.lru_cache(maxsize=1)
def freerdp_package() -> str:
    """要裝哪個 FreeRDP 套件：這台還有 freerdp2-x11 就用它，沒有（Ubuntu 25.10 起）就 freerdp3-x11。"""
    return "freerdp2-x11" if _apt_has_candidate("freerdp2-x11") else "freerdp3-x11"


def required_binaries() -> dict[str, str]:
    """需要的外部程式 → 要裝的套件。少任何一個就不能用這個引擎 —— 由 `availability()` 回報，
    讓設定頁講得出「缺什麼、怎麼裝」，而不是讓使用者連到一半才看到錯誤。
    `xfreerdp` 代表「RDP 用戶端」，FreeRDP 2 或 3 任一個都算（見 `freerdp_binary`）。"""
    return {"xfreerdp": freerdp_package(), **REQUIRED_BINARIES}


def binary_present(exe: str) -> bool:
    return freerdp_binary() is not None if exe == "xfreerdp" else shutil.which(exe) is not None


# 除了 RDP 用戶端之外需要的外部程式
REQUIRED_BINARIES: dict[str, str] = {
    "Xvfb": "xvfb",
    # 抓畫面。不是「順便用用看」——`XGetImage` 經 python-xlib 要 334 ms/張（1280x800，
    # 純 Python 解析 4 MB 像素），上限 2.8 fps，互動主控台不能用。ffmpeg 的 x11grab
    # 內部走 MIT-SHM，同一台機器量到 47 fps。（游標不畫進來 —— 見 `_start_capture`。）
    "ffmpeg": "ffmpeg",
}
# 純 Python 相依（抓畫面與打鍵盤滑鼠）
REQUIRED_MODULES: dict[str, str] = {
    "Xlib": "python-xlib",
    "PIL": "pillow",
}

#: 被 systemd 的系統呼叫過濾器擋下來時要說的話。Xvfb 需要幾個後端本身用不到的呼叫，
#: 而 `SystemCallFilter` 的預設動作是**殺掉**行程（不是回錯誤），所以它會瞬間消失、
#: 一個字都不留 —— 沒有這段說明的話，畫面上只會是一句查不下去的「起不來」。
_SECCOMP_HINT = (
    "虛擬顯示被系統呼叫過濾器擋下（SIGSYS）。FreeRDP 引擎需要放寬四個呼叫，"
    "請安裝對應的 systemd 設定：\n"
    "  sudo install -d /etc/systemd/system/jt-ipam-backend.service.d\n"
    "  printf '[Service]\\nSystemCallFilter=mincore setresuid setuid fchown\\n' | "
    "sudo tee /etc/systemd/system/jt-ipam-backend.service.d/freerdp.conf\n"
    "  sudo systemctl daemon-reload && sudo systemctl restart jt-ipam-backend"
)

def freerdp_apt_hint() -> str:
    """缺套件時印給人照著貼的指令。這串由後端算，前端不要自己維護一份 —— 兩份會不一致。"""
    return f"sudo apt-get install -y {freerdp_package()} xvfb xclip ffmpeg"

_CONNECT_TIMEOUT = 25.0        # 秒；與 aardwolf 那條路一致
_CAPTURE_FPS = 15              # 交給 ffmpeg 的取樣率；畫面沒變時我們仍然不送
_XVFB_READY_TIMEOUT = 10.0
#: 顯示編號的搜尋範圍。避開低位號碼（那些可能是真的桌面工作階段）。
_DISPLAY_MIN, _DISPLAY_MAX = 100, 400
#: X 的顯示鎖檔前綴。路徑由 X 協定決定，不是我們挑的暫存位置。
_X11_LOCK_PREFIX = "/tmp/.X"  # noqa: S108
#: X 伺服器 unix socket 的目錄。這個路徑是 X 協定寫死的，不是我們選的暫存檔位置，
#: 也不接受覆寫 —— 所以 S108（暫存目錄用法可疑）在這裡不適用。
_X11_SOCKET_DIR = "/tmp/.X11-unix"  # noqa: S108


def _ensure_x11_socket_dir() -> None:
    """確保 `/tmp/.X11-unix` 存在。

    X 伺服器的 unix socket 路徑是寫死的 `/tmp/.X11-unix`，而 **Xvfb 以非 root 身分
    不會自己建這個目錄**（它會說 `_XSERVTransmkdir: ERROR: euid != 0`），接著就
    安靜地失敗、連顯示編號都不回報。

    平常的機器上這個目錄早就在了，所以開發時看不到這個問題。但正式環境的 systemd
    單元有 `PrivateTmp=yes` —— 服務拿到的是一個全新的、空的 `/tmp`。
    每次連線都檢查一次（成本是一個 syscall），因為那個私有 /tmp 會隨服務重啟而重建。
    """
    # 只在「不存在」時建立，**不去改既有目錄的權限**：在沒有 PrivateTmp 的機器上
    # 那是一個共用目錄，可能是別人（或系統）建的，放寬它的權限不是我們的事。
    with contextlib.suppress(Exception):
        os.makedirs(_X11_SOCKET_DIR, mode=0o1777, exist_ok=True)


# 子行程的清理靠兩層，**刻意不用 `preexec_fn`**：
#
#   1. 正常收線 → `terminate()` 逐一收掉。
#   2. 後端被強制帶走（OOM、`systemctl kill`、部署腳本）→ systemd 的
#      `KillMode=mixed` 會對 cgroup 內所有剩餘行程送 SIGKILL，它們跟著一起走。
#
# 原本這裡用 `preexec_fn` 設 `PR_SET_PDEATHSIG`。那在單執行緒的腳本上沒問題，但
# **在多執行緒行程裡 fork 會慢得離譜**：實測同一台機器上，單執行緒建立連線 2.85 秒，
# 有 8 個工作執行緒時變成 14.76 秒 —— 而 uvicorn 的 worker 本來就有執行緒，再加上
# 四個 worker 的真實負載就衝破連線逾時，畫面上只看到「連線逾時」
# （2026-09-17 正式環境）。systemd 已經處理了同一件事，不需要為它付這個代價。


#: 交握要排隊的路徑。**跨行程**：uvicorn 預設跑多個 worker，`asyncio.Lock` 只擋得住
#: 同一個行程裡的。檔案鎖是整台機器一份。
_HANDSHAKE_LOCK_PATH = "/tmp/jt-ipam-rdp-handshake.lock"  # noqa: S108
#: 最多等多久。等不到就照樣去試 —— 排隊是為了避開一個偶發的碰撞，
#: 不是為了把它變成單一失效點。
_HANDSHAKE_LOCK_WAIT = 30.0


@contextlib.asynccontextmanager
async def _handshake_slot() -> Any:
    """一次只讓一條連線在交握。

    2026-09-18 實測（gnome-remote-desktop）：三條**依序**開、都保持連著，全部成功；
    兩條**同一瞬間**開始交握就固定壞一條，而且回的話不一定一樣 —— 有時是安全層協商
    失敗，有時直接是 `STATUS_LOGON_FAILURE`，也就是**密碼是對的，使用者卻被告知
    帳號或密碼不正確**。

    為什麼不是「失敗就重試」：重試等於把憑證再送一次，實測那一次重試拿到的正是
    `LOGON_FAILURE` —— 在有鎖定政策的目標上，那是拿使用者的帳號去換一次失敗登入。
    排隊完全不碰憑證，成本只是多等一輪交握（實測約 2.5 秒）。
    """
    fd = None
    try:
        fd = await asyncio.to_thread(os.open, _HANDSHAKE_LOCK_PATH,
                                     os.O_CREAT | os.O_RDWR, 0o600)

        def _acquire() -> bool:
            deadline = time.monotonic() + _HANDSHAKE_LOCK_WAIT
            while time.monotonic() < deadline:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    time.sleep(0.15)
                else:
                    return True
            return False

        if not await asyncio.to_thread(_acquire):
            logger.warning("freerdp: 等不到交握排隊（%.0fs），照樣試", _HANDSHAKE_LOCK_WAIT)
            yield
            return
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError as exc:      # 鎖檔開不起來不該讓主控台整個不能用
        logger.warning("freerdp: 交握排隊不可用（%s），照樣試", exc)
        yield
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def _display_owner(lock_path: str) -> int | None:
    """讀 X 的鎖檔，回傳持有那個顯示編號的行程 PID；讀不到或格式不對回 None。

    X 伺服器啟動時會把自己的 PID 以 `%10d\n` 寫進 `/tmp/.X<N>-lock`。這是**唯一**
    能證明「這個顯示是誰的」的東西 —— socket 檔案存在只代表有人建了它，不代表是我們。
    """
    try:
        with open(lock_path, encoding="ascii") as fh:
            return int(fh.read(32).strip())
    except (OSError, ValueError):
        return None


class UnsupportedCharacter(Exception):
    """這個字元沒辦法用 FreeRDP 引擎打出來。

    xfreerdp 用**固定的 keycode→掃描碼對照表**把 X 的按鍵翻成 RDP 事件，而不是看 keysym。
    所以「把字元暫時綁到一顆沒人用的 keycode 再敲」送出去的是一顆沒有掃描碼的鍵 ——
    被控端什麼也不會發生（2026-09-18 在真機上試過 5 顆分佈不同的空 keycode，全部沒反應；
    FreeRDP 2.11 也沒有任何 Unicode 輸入選項）。

    這條路走不通，但**不可以安靜地丟掉** —— 使用者只會以為鍵盤壞了。呼叫端要把它
    轉成畫面上看得到的提示，並指向剪貼簿：貼上那條路連中文都進得去。
    """

    def __init__(self, char: str) -> None:
        super().__init__(char)
        self.char = char


@dataclass(slots=True)
class VideoTile:
    """一塊畫面更新。欄位名與 aardwolf 的 video data 相同，`_bridge` 才不用分辨來源。"""

    x: int
    y: int
    width: int
    height: int
    data: bytes          # PNG


def availability() -> dict[str, Any]:
    """這台機器能不能用 FreeRDP 引擎，缺什麼。

    回傳 `{ok, missing_packages, missing_modules, install_hint}`。設定頁直接顯示這個 ——
    「選項在那裡但按了才發現不能用」比沒有這個選項更糟。
    """
    missing_pkgs = sorted({pkg for exe, pkg in required_binaries().items()
                           if not binary_present(exe)})
    missing_mods: list[str] = []
    for mod, pkg in REQUIRED_MODULES.items():
        try:
            __import__(mod)
        except Exception:
            missing_mods.append(pkg)
    return {
        "ok": not missing_pkgs and not missing_mods,
        "missing_packages": missing_pkgs,
        "missing_modules": sorted(missing_mods),
    }


def _close_pipes(proc: Any) -> None:
    """關掉我們這一端的 stdin／stdout／stderr 管線。"""
    transport = getattr(proc, "_transport", None)
    if transport is None:
        return
    for fd in (0, 1, 2):
        with contextlib.suppress(Exception):
            pipe = transport.get_pipe_transport(fd)
            if pipe is not None:
                pipe.close()


async def _stop_process(proc: Any, grace: float = 5.0) -> None:
    """收掉一個子行程，**一定會回來**。

    兩個會讓它永遠卡住的地方（對 FreeRDP 3 做整合測試時抓到，FreeRDP 2 一樣會中）：
    - 抓畫面的 ffmpeg 一直往管線寫；串流收掉之後沒人讀，管線滿了它就卡在 write 上，
      而它自己處理 SIGTERM —— 卡在 write 上時不會結束。
    - asyncio（Python 3.12）的 `proc.wait()` 要等**所有管線都斷開**才回來；讀取端因為緩衝滿了
      而暫停著，永遠等不到 EOF —— 就算 SIGKILL 已經把它殺了也一樣。
    所以先關掉我們這一端的管線（ffmpeg 會拿到 EPIPE 立刻結束，asyncio 也不用再等管線），
    而且每一次等待都有時限。卡住的後果是後面的 xfreerdp 與 Xvfb 都收不掉，每斷一次線留下一組。
    """
    if proc is None:
        return
    _close_pipes(proc)
    if proc.returncode is not None:
        return
    for send in (proc.terminate, proc.kill):
        with contextlib.suppress(ProcessLookupError):
            send()
        try:
            async with asyncio.timeout(grace):
                await proc.wait()
            return
        except TimeoutError:
            continue
    logger.warning("freerdp: 子行程 pid=%s 收不掉（SIGKILL 之後仍未結束）", proc.pid)


class FreeRdpError(Exception):
    """連線失敗；訊息帶得住底層原文，不要只說「連線失敗」。"""


# ── 輸入 ────────────────────────────────────────────────────────────────────
#
# 上層送進來的是 RDP 的掃描碼（PC Set-1）與 unicode 字元，但我們能操作的是 X。
# 中間這張表把掃描碼翻成 X 的 keysym 名稱，再由 X 自己查出對應的 keycode ——
# 直接假設「X keycode = 掃描碼 + 8」在擴充鍵（方向鍵、Delete…）上會錯，
# 而那些正是主控台最常按的鍵。
_SCANCODE_KEYSYM: dict[int, str] = {
    0x1C: "Return", 0x0E: "BackSpace", 0x0F: "Tab", 0x01: "Escape", 0x39: "space",
    0x53: "Delete", 0x47: "Home", 0x4F: "End", 0x49: "Prior", 0x51: "Next",
    0x52: "Insert", 0x48: "Up", 0x50: "Down", 0x4B: "Left", 0x4D: "Right",
    0x1D: "Control_L", 0x2A: "Shift_L", 0x38: "Alt_L", 0x5B: "Super_L",
    0x3B: "F1", 0x3C: "F2", 0x3D: "F3", 0x3E: "F4", 0x3F: "F5", 0x40: "F6",
    0x41: "F7", 0x42: "F8", 0x43: "F9", 0x44: "F10", 0x57: "F11", 0x58: "F12",
    # 字母與數字列（與 rdp_console._CODE_SCANCODES 同一組掃描碼）
    0x1E: "a", 0x30: "b", 0x2E: "c", 0x20: "d", 0x12: "e", 0x21: "f", 0x22: "g",
    0x23: "h", 0x17: "i", 0x24: "j", 0x25: "k", 0x26: "l", 0x32: "m", 0x31: "n",
    0x18: "o", 0x19: "p", 0x10: "q", 0x13: "r", 0x1F: "s", 0x14: "t", 0x16: "u",
    0x2F: "v", 0x11: "w", 0x2D: "x", 0x15: "y", 0x2C: "z",
    0x02: "1", 0x03: "2", 0x04: "3", 0x05: "4", 0x06: "5",
    0x07: "6", 0x08: "7", 0x09: "8", 0x0A: "9", 0x0B: "0",
    0x0C: "minus", 0x0D: "equal", 0x1A: "bracketleft", 0x1B: "bracketright",
    0x2B: "backslash", 0x27: "semicolon", 0x28: "apostrophe", 0x29: "grave",
    0x33: "comma", 0x34: "period", 0x35: "slash",
}

# 上層的滑鼠按鍵值（aardwolf 的 MOUSEBUTTON）→ X 的按鈕編號。
# 這裡刻意比對名稱而不是 enum 本身：FreeRDP 這條路不該為了一個常數而 import aardwolf。
_XBUTTON_BY_NAME: dict[str, int] = {
    "MOUSEBUTTON_LEFT": 1, "MOUSEBUTTON_MIDDLE": 2, "MOUSEBUTTON_RIGHT": 3,
}


class _InputMixin:
    """滑鼠與鍵盤注入。拆成 mixin 只是為了讓上面的連線邏輯讀起來不被沖散。"""

    _disp: Any
    _root: Any
    _display: str | None
    _char_down: dict[str, tuple[int, bool]]
    _width: int
    _height: int

    async def _x(self, fn: Any, *a: Any) -> None:
        """Xlib 是同步的，一律丟到執行緒，別卡住 event loop。"""
        if self._disp is None:
            return
        await asyncio.to_thread(fn, *a)

    async def send_mouse(self, button: Any, x: int, y: int, pressed: bool,
                         wheel_data: int = 0) -> None:
        name = getattr(button, "name", str(button))
        x = max(0, min(int(x), self._width - 1))
        y = max(0, min(int(y), self._height - 1))

        def _do() -> None:
            from Xlib import X
            from Xlib.ext import xtest
            xtest.fake_input(self._disp, X.MotionNotify, x=x, y=y)
            if name == "MOUSEBUTTON_HOVER":
                pass
            elif name == "MOUSEBUTTON_WHEEL_UP":
                # 上層把方向塞進 steps 的 0x100 位（WHEEL_NEGATIVE），量值是 120 的倍數
                down = bool(int(wheel_data) & 0x100)
                btn = 5 if down else 4
                clicks = max(1, (int(wheel_data) & 0xFF) // 120) or 1
                for _ in range(clicks):
                    xtest.fake_input(self._disp, X.ButtonPress, btn)
                    xtest.fake_input(self._disp, X.ButtonRelease, btn)
            else:
                btn = _XBUTTON_BY_NAME.get(name, 1)
                xtest.fake_input(
                    self._disp, X.ButtonPress if pressed else X.ButtonRelease, btn)
            self._disp.sync()

        await self._x(_do)

    async def send_key_scancode(self, scancode: int, pressed: bool,
                                _extended: bool = False) -> None:
        keysym_name = _SCANCODE_KEYSYM.get(int(scancode))
        if keysym_name is None:
            logger.debug("freerdp: 不認得的掃描碼 0x%02x，略過", scancode)
            return

        def _do() -> None:
            from Xlib import XK, X
            from Xlib.ext import xtest
            keysym = XK.string_to_keysym(keysym_name)
            keycode = self._disp.keysym_to_keycode(keysym)
            if not keycode:
                return
            xtest.fake_input(self._disp, X.KeyPress if pressed else X.KeyRelease, keycode)
            self._disp.sync()

        await self._x(_do)

    async def send_key_char(self, ch: str, pressed: bool) -> None:
        """打出一個字元，用目前鍵盤配置上的那顆鍵（必要時補 Shift）。

        配置上沒有的字元（中文、日文、emoji…）丟 `UnsupportedCharacter` ——
        **不可以安靜地丟掉**。詳見那個例外的說明與替代做法（貼上）。
        """
        if len(ch) != 1:
            return
        cp = ord(ch)
        keysym = cp if cp < 0x100 else 0x01000000 + cp

        if pressed:
            plan = await asyncio.to_thread(self._plan_char, keysym)
            if plan is None:
                raise UnsupportedCharacter(ch)
            self._char_down[ch] = plan
        else:
            plan = self._char_down.pop(ch, None)
            if plan is None:
                # 按下時就已經回報過了，放開不必再講一次
                return
        keycode, needs_shift = plan

        def _do() -> None:
            from Xlib import XK, X
            from Xlib.ext import xtest
            shift_kc = self._disp.keysym_to_keycode(XK.string_to_keysym("Shift_L"))
            if pressed:
                if needs_shift and shift_kc:
                    xtest.fake_input(self._disp, X.KeyPress, shift_kc)
                xtest.fake_input(self._disp, X.KeyPress, keycode)
            else:
                xtest.fake_input(self._disp, X.KeyRelease, keycode)
                if needs_shift and shift_kc:
                    xtest.fake_input(self._disp, X.KeyRelease, shift_kc)
            self._disp.sync()

        await self._x(_do)

    def _plan_char(self, keysym: int) -> tuple[int, bool] | None:
        """決定這個字元要敲哪一顆鍵、要不要按 Shift。回傳 `(keycode, needs_shift)`。

        只接受配置上的第 0／1 階（原鍵與 Shift）。**第 2／3 階（AltGr）要回 None**：
        `bool(index)` 對 index=2 也是 True，會按著 Shift 敲出一個*別的*字元 ——
        那比打不出來更糟，畫面上會出現使用者沒有輸入的東西。

        配置上沒有的字元一律回 None，由呼叫端丟 `UnsupportedCharacter`。
        以前這裡會借一顆 keycode 重綁；那對 xfreerdp 無效，見那個例外的說明。
        """
        for keycode, index in self._disp.keysym_to_keycodes(keysym):
            if keycode and index in (0, 1):
                return keycode, bool(index)
        return None

    async def set_current_clipboard_text(self, text: str) -> None:
        """控制端貼上。

        FreeRDP 的剪貼簿重導走的是 X selection：把文字放進那個顯示的 CLIPBOARD，
        xfreerdp 就會把它同步到被控端。這裡用 `xclip` 之外的做法會牽進整套
        selection owner 事件迴圈，先以外部工具處理；沒裝 xclip 就當作不支援。

        單向性是**結構上**成立的，不是靠設定：我們只會往那個 X 顯示寫，從來不讀。
        被控端的剪貼簿即使被 xfreerdp 同步過來，也只停在那個虛擬顯示裡，隨 session
        一起消滅，不會回到控制端。
        """
        if not self._clip_enabled:
            raise FreeRdpError("這個站台沒有開啟「控制端貼上」")
        if not text or self._display is None:
            return
        if shutil.which("xclip") is None:
            raise FreeRdpError("這台沒有安裝 xclip，FreeRDP 引擎無法轉送剪貼簿")
        proc = await asyncio.create_subprocess_exec(
            "xclip", "-selection", "clipboard",
            env=dict(os.environ, DISPLAY=self._display or ""),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate(text.encode())


class FreeRdpConnection(_InputMixin):
    """一條 FreeRDP 連線（含它專屬的 Xvfb）。

    介面與 aardwolf 的連線物件相同，供 `rdp_console._bridge()` 直接使用。
    """

    def __init__(self, *, host: str, port: int, username: str, password: str,
                 domain: str | None, width: int, height: int,
                 clip_enabled: bool = False) -> None:
        self._host, self._port = host, port
        self._clip_enabled = clip_enabled
        self._username, self._password = username, password
        self._domain = domain or None
        # ⚠️ RDP 的桌面寬度必須是偶數。奇數寬度會讓連線在 post_connect 階段失敗，
        # 而 FreeRDP 回的是 `ERRCONNECT_CONNECT_TRANSPORT_FAILED` —— 看起來像「連不到」，
        # 其實已經連上了。瀏覽器視窗寬度是奇數的人會每次都中（2026-09-17：1525 寬）。
        # 高度沒有這個限制，但一起對齊比較不會讓人以為只有寬度特別。
        self._width = width - (width % 2)
        self._height = height - (height % 2)
        # 捨過的尺寸要回報給前端（見 `framebuffer_size`），否則 canvas 會比畫面大一格。

        self.ext_out_queue: asyncio.Queue[VideoTile | None] = asyncio.Queue(maxsize=8)
        self._xvfb: asyncio.subprocess.Process | None = None
        self._rdp: asyncio.subprocess.Process | None = None
        self._grab: asyncio.subprocess.Process | None = None
        self._home: str | None = None      # 給 xfreerdp 的臨時家目錄（見 _start_xfreerdp）
        self._xvfb_err: Any = None         # Xvfb 的 stderr 檔（失敗時要讀得到）
        self._display: str | None = None
        self._disp: Any = None              # Xlib display
        self._root: Any = None
        self._grab_task: asyncio.Task[None] | None = None
        self._watch_task: asyncio.Task[None] | None = None
        # xfreerdp 為什麼結束的（有值代表是它先走的，不是我們收掉它）
        self.exit_reason: str | None = None
        # 目前按住的字元 → (keycode, 要不要 Shift)。放開時要用按下時的同一顆。
        self._char_down: dict[str, tuple[int, bool]] = {}
        self._closed = False
        self._frames = 0          # 已送出的畫面張數（給效能量測與日誌用）

    # ── 生命週期 ────────────────────────────────────────────────────────────

    async def connect(self) -> tuple[Any, Exception | None]:
        """回傳 `(result, error)` —— 與 aardwolf 的 `connect()` 同形狀。"""
        try:
            await self._start_xvfb()
            # 交握排隊：見 `_handshake_slot`。只圈住真正會撞在一起的那一段，
            # 起 Xvfb 與之後的畫面擷取都不必排。
            async with _handshake_slot():
                await self._start_xfreerdp()
            await self._open_x_display()
            await self._start_capture()
            self._grab_task = asyncio.create_task(self._grab_loop())
            self._watch_task = asyncio.create_task(self._watch_child())
            return None, None
        except Exception as exc:          # 一律轉成 (None, err) 交給呼叫端處理
            await self.terminate()
            return None, exc

    async def _start_xvfb(self) -> None:
        """開一個只給這條連線用的虛擬顯示。

        **不要用 `-displayfd`。** 那需要從管線非同步讀回編號，而 uvicorn 預設跑在
        uvloop 上 —— 在那裡 `connect_read_pipe` 讀到的是立即 EOF，於是我們拿到空字串、
        Xvfb 卻還活著，錯誤訊息只剩「啟動失敗（結束碼 None）」。用標準 asyncio
        跑獨立腳本測不出來（2026-09-17 為此查了很久）。

        改用 X 自己的仲裁方式：每個顯示編號對應一個鎖檔 `/tmp/.X<N>-lock`，Xvfb 啟動時
        會去搶；搶不到就立刻結束。所以我們只要逐一試、看 socket 有沒有出現就好 ——
        純粹的檔案存在檢查，跟事件迴圈無關。
        """
        _ensure_x11_socket_dir()
        last_err = ""
        # 起點打散：不然每條連線都先去撞 _DISPLAY_MIN，同時開三條就三個一起搶同一號。
        # 正確性靠下面的擁有者檢查，這裡只是別讓大家排隊撞同一扇門。
        span = _DISPLAY_MAX - _DISPLAY_MIN
        start = secrets.randbelow(span)
        for step in range(span):
            num = _DISPLAY_MIN + (start + step) % span
            # 已經有人佔著就不必浪費一次 fork。鎖檔路徑是 X 協定寫死的。
            if await asyncio.to_thread(os.path.exists, f"{_X11_LOCK_PREFIX}{num}-lock"):
                continue
            if await self._try_display(num):
                self._display = f":{num}"
                logger.info("freerdp: Xvfb 就緒 display=%s size=%dx%d",
                            self._display, self._width, self._height)
                return
            last_err = self._xvfb_stderr_tail()
            await self._kill_xvfb()
        raise FreeRdpError(
            f"找不到可用的虛擬顯示{'：' + last_err if last_err else ''}")

    async def _try_display(self, num: int) -> bool:
        """在 `:num` 上起 Xvfb，而且要**證明那個顯示是我們的**才算成功。

        ⚠️ 只看「socket 檔案出現了嗎」是不夠的。三條連線同時進來時，三個都會看到鎖檔
        還不存在、三個都去起 Xvfb，只有一個搶得到鎖 —— 但輸家看到的是贏家建的 socket，
        於是拿著別人的顯示繼續跑：**兩個使用者共用一個虛擬螢幕，看得到彼此的畫面**
        （2026-09-18 實測，三條全部拿到 `:100`）。

        X 的鎖檔裡寫的就是持有者的 PID，拿它跟我們自己起的那個 Xvfb 比對才是證明。
        """
        self._xvfb_err = tempfile.NamedTemporaryFile(
            prefix="jtipam-xvfb-", suffix=".log", delete=False)
        self._xvfb = await asyncio.create_subprocess_exec(
            "Xvfb", f":{num}",
            "-screen", "0", f"{self._width}x{self._height}x24",
            "-nolisten", "tcp", "-noreset",
            stdout=asyncio.subprocess.DEVNULL, stderr=self._xvfb_err,
        )
        sock = os.path.join(_X11_SOCKET_DIR, f"X{num}")
        lock = f"{_X11_LOCK_PREFIX}{num}-lock"
        deadline = time.monotonic() + _XVFB_READY_TIMEOUT
        while time.monotonic() < deadline:
            if await asyncio.to_thread(os.path.exists, sock):
                owner = await asyncio.to_thread(_display_owner, lock)
                if owner == self._xvfb.pid:
                    return True
                if owner is not None:
                    # 鎖是別人的 → 我們輸了這一號，換下一個。不可以就這樣用下去。
                    logger.debug("freerdp: :%d 已被 pid=%s 佔住，換下一個", num, owner)
                    return False
            if self._xvfb.returncode is not None:
                # 被 seccomp 殺掉（SIGSYS）是很特殊的死法：瞬間結束、什麼都不寫。
                # 這時候一個一個換顯示編號試三百次是白費力氣，而且使用者會看到
                # 一句毫無線索的「找不到可用的虛擬顯示」。直接講出真正的原因。
                if self._xvfb.returncode == -signal.SIGSYS:
                    raise FreeRdpError(_SECCOMP_HINT)
                return False        # 其餘多半是鎖被別人搶走了 → 換下一個編號
            await asyncio.sleep(0.05)
        return False

    async def _kill_xvfb(self) -> None:
        """收掉這一輪失敗的 Xvfb 與它的 stderr 檔。"""
        proc, self._xvfb = self._xvfb, None
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            with contextlib.suppress(Exception), contextlib.suppress(TimeoutError):
                async with asyncio.timeout(3):
                    await proc.wait()
        if self._xvfb_err is not None:
            with contextlib.suppress(Exception):
                name = self._xvfb_err.name
                self._xvfb_err.close()
                os.unlink(name)
            self._xvfb_err = None

    def _xvfb_stderr_tail(self, limit: int = 300) -> str:
        """Xvfb 到目前為止抱怨了什麼。失敗時一定要講得出來。"""
        if self._xvfb_err is None:
            return ""
        with contextlib.suppress(Exception):
            self._xvfb_err.flush()
            with open(self._xvfb_err.name, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            # xkbcomp 的一長串 keysym 警告是噪音，濾掉才看得到真正的那一行
            lines = [ln for ln in text.splitlines()
                     if ln.strip() and "Could not resolve keysym" not in ln
                     and "XKEYBOARD keymap compiler" not in ln]
            return " ".join(" ".join(lines).split())[-limit:]
        return ""

    async def _start_xfreerdp(self) -> None:
        """起 xfreerdp。密碼走 stdin，不進 argv。"""
        args = [
            freerdp_binary() or "xfreerdp",
            f"/v:{self._host}:{self._port}",
            f"/u:{self._username}",
            f"/size:{self._width}x{self._height}",
            # ⚠️ 不要指定 /bpp：gnome-remote-desktop 收到明確的色深要求就會在能力交換階段
            # 回 DEACTIVATE_ALL（FreeRDP 報 `expected PDU_TYPE_DEMAND_ACTIVE 0001, got 0006`），
            # 連線直接斷。讓伺服器自己決定色深就沒事 —— 我們抓畫面時本來就會轉成 RGB。
            "/cert:ignore",          # 目標憑證多半是自簽；信任由網路層與跳板決定
            "/from-stdin:force",     # ⚠️ 密碼只能走這裡
            "-wallpaper", "-themes", "-menu-anims", "-decorations",
            "+auto-reconnect",
            # ⚠️ FreeRDP 的剪貼簿重導**預設是開的**。管理者關掉「控制端貼上」時，
            # 換到這個引擎不可以把它默默打開 —— 那是把一個被明確關閉的資料通道
            # 重新接上。deny by default，與 aardwolf 那條路（沒開就不掛 cliprdr）一致。
            "+clipboard" if self._clip_enabled else "-clipboard",
            "/log-level:WARN",
        ]
        if self._domain:
            args.insert(3, f"/d:{self._domain}")

        # FreeRDP 會在 `$HOME/.config/freerdp` 底下寫設定與 known_hosts。家目錄不可寫時
        # 它不會直說，而是在後面回一句 `ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED`
        # ——「安全層協商失敗」，指向完全無關的方向（2026-09-17 查了一輪才發現）。
        # 給它一個這條連線專用的臨時家目錄，就不必管服務的 HOME 是什麼、可不可寫；
        # 順便讓 known_hosts 隨 session 消滅（我們本來就用 /cert:ignore，不靠它釘憑證）。
        self._home = tempfile.mkdtemp(prefix="jtipam-rdp-")
        env = dict(os.environ, DISPLAY=self._display or "", HOME=self._home)
        self._rdp = await asyncio.create_subprocess_exec(
            *args, env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        assert self._rdp.stdin is not None
        self._rdp.stdin.write(self._password.encode() + b"\n")
        with contextlib.suppress(Exception):
            await self._rdp.stdin.drain()
        self._rdp.stdin.close()
        # 密碼只在這個物件上留到這裡為止
        self._password = ""

        await self._await_connected()

    async def _await_connected(self) -> None:
        """等 xfreerdp 真的連上。

        判準是「視窗出現在那個顯示上」而不是「行程還活著」—— 行程在認證失敗後
        還會存活一小段時間，只看行程會把失敗說成成功（升級腳本踩過同一種錯，
        見 `scripts/jt-ipam.sh` 的 wait_until_serving）。
        """
        assert self._rdp is not None
        deadline = time.monotonic() + _CONNECT_TIMEOUT
        stderr_buf = b""
        while time.monotonic() < deadline:
            if self._rdp.returncode is not None:
                if self._rdp.stderr is not None:
                    with contextlib.suppress(Exception):
                        stderr_buf = await self._rdp.stderr.read(4096)
                raise FreeRdpError(_explain(stderr_buf.decode("utf-8", "replace")))
            if await self._has_window():
                logger.info("freerdp: 已連上 %s:%s", self._host, self._port)
                return
            await asyncio.sleep(0.25)
        raise FreeRdpError("FreeRDP 在時限內沒有畫出畫面（可能卡在認證或協定協商）")

    async def _has_window(self) -> bool:
        """那個顯示上有沒有已經對映的視窗。"""
        def _check() -> bool:
            try:
                from Xlib import display as xdisplay
                d = xdisplay.Display(self._display)
                try:
                    root = d.screen().root
                    kids = root.query_tree().children
                    for w in kids:
                        attrs = w.get_attributes()
                        if attrs.map_state == 2:      # IsViewable
                            return True
                    return False
                finally:
                    d.close()
            except Exception:
                return False
        return await asyncio.to_thread(_check)

    async def _open_x_display(self) -> None:
        def _open() -> tuple[Any, Any]:
            from Xlib import display as xdisplay
            d = xdisplay.Display(self._display)
            root = d.screen().root
            return d, root
        self._disp, self._root = await asyncio.to_thread(_open)

    @property
    def framebuffer_size(self) -> tuple[int, int]:
        """實際拿到的畫面尺寸 —— 不一定等於呼叫端要求的（寬度會被捨成偶數）。

        前端要照這個開 canvas：照「要求的」開會多出永遠黑著的一欄，而且座標換算的
        比例也差了那一格，愈往右偏得愈多。
        """
        return self._width, self._height

    async def _start_capture(self) -> None:
        """把畫面交給 ffmpeg 抓，我們只負責從管線讀原始像素。

        `-draw_mouse 0`：**不要**把游標烘進畫面。瀏覽器自己會在 canvas 上畫一個游標，
        再疊一個進來就是兩個，使用者看到的就是「游標有偏移」（2026-09-17 回報）。
        而且 ffmpeg 畫的是 **X 這端**的游標 —— 被控端沒送過 pointer update 時它是
        X11 的預設叉叉，形狀根本不是遠端那一個，留著也換不到正確的形狀提示。
        aardwolf 引擎從來就只有瀏覽器那一個游標，關掉才是兩個引擎一致的行為。
        順帶：指標在空白處移動不再產生任何畫面更新，閒置流量歸零。
        """
        size = self._width * self._height * 3
        self._grab = await asyncio.create_subprocess_exec(
            "ffmpeg", "-loglevel", "error",
            "-f", "x11grab", "-draw_mouse", "0",
            "-video_size", f"{self._width}x{self._height}",
            "-framerate", str(_CAPTURE_FPS),
            "-i", self._display or "",
            "-pix_fmt", "rgb24", "-f", "rawvideo", "-",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            # 預設的資料流上限是 64 KB，一張 1280x800 是 3 MB —— 不放大會一直卡住
            limit=size + (1 << 20),
        )
        logger.info("freerdp: 畫面擷取已啟動 %dx%d @%d fps",
                    self._width, self._height, _CAPTURE_FPS)

    async def _watch_child(self) -> None:
        """xfreerdp 自己結束時要出聲。

        它死掉之後畫面就停在最後一張 —— 不會有錯誤、不會斷線，使用者只看到一個
        不再更新的桌面，還以為是網路慢。最常見的原因是被控端把工作階段換掉了
        （GNOME 從登入畫面交接到使用者工作階段就會這樣）。
        """
        if self._rdp is None:
            return
        rc = await self._rdp.wait()
        if self._closed:
            return
        detail = ""
        if self._rdp.stderr is not None:
            with contextlib.suppress(Exception):
                detail = (await self._rdp.stderr.read(2048)).decode("utf-8", "replace")
        self.exit_reason = _explain(detail) if detail.strip() else f"FreeRDP 結束（代碼 {rc}）"
        logger.info("freerdp: 子行程結束 rc=%s reason=%s", rc, self.exit_reason)
        # 讓串流那一端知道該收了；`_bridge` 會因此結束，WS 才會關掉而不是無聲凍結
        with contextlib.suppress(Exception):
            self.ext_out_queue.put_nowait(None)

    async def terminate(self) -> None:
        if self._closed:
            return
        self._closed = True
        for task in (self._watch_task,):
            if task is not None:
                task.cancel()
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await task
        self._watch_task = None
        if self._grab_task is not None:
            self._grab_task.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await self._grab_task
        # 結束訊號不能用 `await put()`：控制端斷線時沒有人在讀，佇列滿了（最多 8 張）就會永遠卡在這，
        # 後面收掉 xfreerdp 與 Xvfb 的步驟都不會執行 —— 每斷一次線留下一組行程（對 FreeRDP 3 做
        # 整合測試時抓到，FreeRDP 2 一樣會中）。滿了就先丟掉一張畫面，再不等待地放進去。
        with contextlib.suppress(asyncio.QueueEmpty):
            if self.ext_out_queue.full():
                self.ext_out_queue.get_nowait()
        with contextlib.suppress(asyncio.QueueFull):
            self.ext_out_queue.put_nowait(None)
        if self._disp is not None:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self._disp.close)
            self._disp = None
        # 先收 RDP 再收 Xvfb（反過來會讓 xfreerdp 對著不存在的顯示噴一堆錯）
        for proc in (self._grab, self._rdp, self._xvfb):
            await _stop_process(proc)
        self._grab = self._rdp = self._xvfb = None
        if self._home:
            with contextlib.suppress(Exception):
                shutil.rmtree(self._home, ignore_errors=True)
            self._home = None
        if self._xvfb_err is not None:
            with contextlib.suppress(Exception):
                name = self._xvfb_err.name
                self._xvfb_err.close()
                os.unlink(name)
            self._xvfb_err = None

    # ── 畫面 ────────────────────────────────────────────────────────────────

    async def _grab_loop(self) -> None:
        """從 ffmpeg 讀畫面 → 只把「變了的那一塊」送出去。

        比對整張交給 Pillow（C 實作）做：純 Python 逐像素在 1280x800 上一秒跑不完一張。
        沒變就不送 —— 閒置的桌面不該持續佔頻寬。
        """
        from PIL import Image, ImageChops

        if self._grab is None or self._grab.stdout is None:
            return
        size = self._width * self._height * 3
        prev: Any = None
        while not self._closed:
            try:
                raw = await self._grab.stdout.readexactly(size)
            except asyncio.IncompleteReadError:
                logger.info("freerdp: 畫面擷取結束（ffmpeg 收掉了管線）")
                break
            except Exception as exc:
                logger.info("freerdp: 讀畫面失敗，結束串流：%r", exc)
                break
            cur = Image.frombytes("RGB", (self._width, self._height), raw)
            box = (0, 0, self._width, self._height) if prev is None else \
                ImageChops.difference(prev, cur).getbbox()
            prev = cur
            if box is not None:
                await self._emit(cur.crop(box), box)
                self._frames += 1

    async def _emit(self, tile: Any, box: tuple[int, int, int, int]) -> None:
        import io

        def _encode() -> bytes:
            buf = io.BytesIO()
            tile.save(buf, format="PNG", compress_level=1)   # 速度優先，頻寬其次
            return buf.getvalue()

        png = await asyncio.to_thread(_encode)
        x0, y0, x1, y1 = box
        item = VideoTile(x=x0, y=y0, width=x1 - x0, height=y1 - y0, data=png)
        try:
            self.ext_out_queue.put_nowait(item)
        except asyncio.QueueFull:
            # 控制端跟不上就丟掉這一張：畫面是「目前狀態」不是事件流，
            # 積壓只會讓延遲越拖越長，下一張整片更新會補回來。
            with contextlib.suppress(asyncio.QueueEmpty):
                self.ext_out_queue.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                self.ext_out_queue.put_nowait(item)


#: FreeRDP 的每一行長這樣：`[時間] [pid:tid] [LEVEL][元件] - 訊息`。
#: 時間戳與元件名對使用者沒有意義，留著只會把真正的訊息擠出可見範圍。
_FREERDP_LINE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*\[(?:ERROR|WARN|FATAL)\]\[[^\]]*\]\s*-\s*(?P<msg>.*\S)\s*$")


def _freerdp_words(stderr_text: str, keep: int = 3) -> str:
    """從 FreeRDP 的輸出裡撈出真正的錯誤句子。

    不可以用「壓成一行再取最後 N 個字元」—— 那會從半個時間戳中間切開，
    使用者看到的是 `5:598]` 這種東西（2026-09-18 實測）。
    """
    msgs: list[str] = []
    for line in stderr_text.splitlines():
        m = _FREERDP_LINE.match(line)
        if not m:
            continue
        msg = m.group("msg")
        if msgs and msgs[-1] == msg:        # FreeRDP 常常同一句連印兩次
            continue
        msgs.append(msg)
    if not msgs:
        # 認不得格式時退回原文，但至少從詞的邊界切
        flat = " ".join(stderr_text.split())
        return flat[-240:].lstrip("]:， ") if flat else ""
    return "；".join(msgs[-keep:])[:400]


def _explain(stderr_text: str) -> str:
    """把 FreeRDP 的錯誤講成使用者看得懂的話，但**保留底層原文**。

    ⚠️ 判準要選**只有那一種失敗才會出現**的字串。`freerdp_post_connect failed`
    不是那種字串 —— 它任何失敗都會印，先前拿它當「圖形階段失敗」的訊號，
    害三種網路失敗全被講成「被控端拒絕了這組畫面參數」，使用者照著去查解析度
    永遠查不到（2026-09-18 實測抓到）。

    順序由窄到寬；每一條的證據都是 2026-09-18 從真機抓下來的（見測試裡的樣本）。
    """
    low = stderr_text.lower()
    if "logon_failure" in low:
        hint = "帳號或密碼不正確"
    elif "errconnect_password_expired" in low:
        hint = "密碼已過期"
    elif "account_disabled" in low:
        hint = "帳號已停用"
    elif "errconnect_account_locked_out" in low:
        hint = "帳號已被鎖定"
    elif "errconnect_connect_failed" in low or "failed to connect to" in low:
        # TCP 根本沒接起來：位址不存在、被防火牆丟掉、或路由不通
        hint = "連不到被控端（位址不通或被擋下）"
    elif "connection reset by peer" in low:
        # 接起來了但對方在交握途中重置 —— 幾乎都是「那個埠上的服務不是 RDP」
        hint = "連線在交握途中被對方重置（那個連接埠可能不是 RDP 服務）"
    elif "broken pipe" in low:
        hint = "連線在交握途中被切斷（被控端的 RDP 服務可能沒有在跑）"
    elif "errconnect_security_nego_connect_failed" in low:
        hint = "安全層協商失敗（對方要求的模式與我們送出的不一致）"
    elif "demand_active" in low:
        # 伺服器在能力交換階段就回 DEACTIVATE_ALL。實測過的成因是用戶端指定了色深
        # （/bpp），gnome-remote-desktop 不接受。
        hint = "被控端在能力交換階段中斷連線（不接受我們要求的畫面參數）"
    elif "errconnect_connect_transport_failed" in low:
        hint = "連線傳輸失敗"
    else:
        hint = "FreeRDP 連線失敗"
    tail = _freerdp_words(stderr_text)
    return f"{hint}：{tail}" if tail else hint
