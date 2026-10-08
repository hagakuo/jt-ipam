"""守門：協定進行到一半的等待都要有時限。

主控台的 WebSocket 有兩種等待，只有一種該加時限：

* **閒置等下一個指令**（終端機沒人打字）—— 等好幾個小時是正常的，加時限就是砍掉正常連線。
* **協定進行到一半在等對方**（等連線設定、等主機金鑰確認、等上傳的資料框）——
  對方不接話就會一直卡著，而且從外面看只像「系統很慢」。

第二種少了時限的後果實際發生過（SFTP 上傳，v0.5.224 修）：伺服器停在等資料框，
遠端留下 0 位元組的檔案，使用者看到「連線已中斷」，之後所有請求逾時。

這個測試盯的是**握手**：每個主控台連上來之後讀第一個設定訊息的地方，都必須走
`core/ws_timeouts` 的 helper。新增主控台時忘了加，這裡會擋下來。
"""

from __future__ import annotations

import pathlib
import re

#: 有「先收設定訊息」握手的主控台。noVNC 不在此列 —— 它是純轉發，沒有設定交換。
CONSOLES = ["ssh_console.py", "vnc_console.py", "bmc_console.py",
            "rdp_console.py", "sftp_console.py"]


def _src(name: str) -> str:
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints"
    return (root / name).read_text(encoding="utf-8")


def test_every_console_handshake_has_a_time_limit():
    bad = []
    for name in CONSOLES:
        s = _src(name)
        # 直接讀 receive_text() 當設定用 = 沒有時限
        if re.search(r"cfg\s*=\s*json\.loads\(await websocket\.receive_text\(\)\)", s):
            bad.append(name)
        elif "receive_text_within" not in s:
            bad.append(name)
    assert not bad, (
        "這些主控台的設定握手沒有時限，連上來不說話就能佔住連線："
        + "、".join(bad)
    )


def test_upload_frames_have_a_time_limit():
    s = _src("sftp_console.py")
    put = s[s.index('elif op == "put":'):]
    put = put[:put.index('elif op == "mkdir":')]
    assert "UPLOAD_STALL_TIMEOUT" in put, "上傳的資料框等待沒有時限"


def test_idle_command_loops_are_left_alone():
    """閒置迴圈**不該**有時限 —— 這條是防止有人「順手」把時限加到不該加的地方。

    終端機開著沒人打字是常態；在那裡加時限會把正常工作的連線砍掉。
    """
    s = _src("ssh_console.py")
    idle = s[s.index("raw = await websocket.receive_text()"):]
    idle = idle[:400]
    assert "wait_for" not in idle, "閒置等指令的迴圈不可以加時限（會砍掉正常閒置的終端機）"
