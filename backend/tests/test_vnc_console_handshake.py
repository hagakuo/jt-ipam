"""VNC 主控台的交握 —— 對著一個真的 RFB 伺服器跑。

由來（2026-09-02 實機）：使用者給了一台開著 VNC 的位址要我們連連看。連不上，
而我們分不出是自己的問題還是對方的問題 —— 因為**從來沒有任何測試真的完成過一次
VNC 交握**。於是拿 `frontend/e2e/fixtures/vnc-target.py`（只用標準函式庫的最小 RFB
伺服器）當靶，把客戶端這一半釘住。

當場抓到的缺陷：**不設密碼的 VNC 連不上**。RFB 3.7 以後，伺服器送出支援的安全型別
清單之後客戶端必須回一個位元組說明選了哪個；aardwolf 只在密碼那條路徑送，型別 1
（None）的分支是空的，於是雙方互等到逾時。畫面上只看得到「連線逾時」。
修法在 `api/v1/endpoints/vnc_console.py` 的 monkeypatch 區（與既有的滑鼠修正同一處）。
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from app.api.v1.endpoints.vnc_console import VNC_AVAILABLE

FIXTURE = (Path(__file__).resolve().parent.parent.parent
           / "frontend" / "e2e" / "fixtures" / "vnc-target.py")

pytestmark = pytest.mark.skipif(
    not VNC_AVAILABLE or not FIXTURE.exists(),
    reason="需要選用相依 aardwolf 與 e2e 的 VNC 測試靶",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _start_target(port: int, *, auth: bool) -> subprocess.Popen:
    cmd = [sys.executable, str(FIXTURE), "--host", "127.0.0.1", "--port", str(port)]
    if not auth:
        cmd.append("--no-auth")
    # argv 是寫死的（本專案自己的測試靶 + 本機埠號），沒有外部輸入
    proc = subprocess.Popen(  # noqa: S603
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    # 等它印出 listening 那一行才算好。**不要用「連得上就算好」**：靶收到那個連線
    # 之後就開始跑交握，等於把測試要用的那一次連線用掉了（第一版就是這樣，
    # 真正的客戶端連過去只拿到 connection refused）。
    assert proc.stdout is not None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stdout.readline()
        if "listening" in line:
            return proc
        if proc.poll() is not None:
            break
    proc.kill()
    raise AssertionError("測試用 VNC 靶沒有起來")


async def _connect(port: int, password: str) -> tuple[object, BaseException | None, object]:
    """照 vnc_console 端點的作法建立連線（同樣的 URL 形式與 IO 設定）。"""
    from urllib.parse import quote

    from aardwolf.commons.factory import RDPConnectionFactory
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.commons.queuedata.constants import VIDEO_FORMAT

    io = RDPIOSettings()
    io.video_out_format = VIDEO_FORMAT.PNG
    io.clipboard_use_pyperclip = False
    if password:
        url = f"vnc+plain-password://{quote(password, safe='')}@127.0.0.1:{port}/?timeout=10"
    else:
        url = f"vnc://127.0.0.1:{port}/?timeout=10"
    conn = RDPConnectionFactory.from_url(url, io).create_connection_newtarget("127.0.0.1", io)
    result, err = await asyncio.wait_for(conn.connect(), 20)
    return result, err, conn


@pytest.mark.parametrize(
    ("auth", "password", "label"),
    [
        (True, "any-password", "VNC 密碼驗證（安全型別 2）"),
        # 回歸：這一組在修好之前會卡在交握、最後回「連線逾時」
        (False, "", "不設密碼（安全型別 1）"),
    ],
)
def test_handshake_completes(auth: bool, password: str, label: str) -> None:
    port = _free_port()
    proc = _start_target(port, auth=auth)
    try:
        _result, err, conn = asyncio.run(_connect(port, password))
        assert err is None, f"{label} 交握失敗：{err}"
        assert int(getattr(conn, "width", 0)) == 640, f"{label} 沒讀到 ServerInit 的畫面寬度"
        assert int(getattr(conn, "height", 0)) == 480
        asyncio.run(_terminate(conn))
    finally:
        proc.kill()
        proc.wait(timeout=10)


async def _terminate(conn: object) -> None:
    with contextlib.suppress(Exception):
        await conn.terminate()  # type: ignore[attr-defined]


def test_security_type_1_sends_the_chosen_type() -> None:
    """守門：patch 還在。拿掉之後上面那個測試會變成 20 秒逾時，很難一眼看出原因。"""
    from aardwolf.vncconnection import VNCConnection

    assert getattr(VNCConnection, "_jt_patched", False), "aardwolf 的修正沒有被套用"
    name = VNCConnection._VNCConnection__authenticate.__name__  # type: ignore[attr-defined]
    assert name == "_vnc_authenticate", f"認證流程沒有被包起來（目前是 {name}）"
