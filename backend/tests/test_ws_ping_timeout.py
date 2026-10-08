"""uvicorn 的 WebSocket ping 逾時不能用預設值，否則主控台上傳會被自己切斷。

實機（2026-08-30）：拖一個 5.8 MB 的檔案進 SFTP 主控台，26 秒後連線中斷。伺服器端
的紀錄是 `ws_disconnect`（對方關閉），既沒有碰到上傳逾時、路徑上也沒有反向代理。

原因是 uvicorn 的預設值：**每 20 秒送一次 WebSocket ping，20 秒內沒收到 pong 就切斷**。
瀏覽器其實立刻就回了 pong，但那個 pong 得排在**已經塞進同一條 TCP 連線的上傳資料
後面** —— 上行慢的時候它就是趕不回來，於是伺服器在傳輸途中把連線關掉，使用者看到的
是沒有原因的「連線已中斷」。

所以 ping 的間隔可以短（要能收掉真的死掉的連線），但**等回覆的耐心必須長過最長的一次
上傳**。這個測試守的就是這件事 —— 它很容易在有人「順手把逾時調回預設」時安靜地回來。
"""

from __future__ import annotations

import re
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run-backend.sh"

#: 上傳上限 100 MB。逾時要能容得下它在慢速上行上傳完，否則就是「大檔一定失敗」。
MIN_PING_TIMEOUT = 300


def _flag(name: str) -> float | None:
    text = SCRIPT.read_text(encoding="utf-8")
    m = re.search(rf"--{name}\s+([0-9.]+)", text)
    return float(m.group(1)) if m else None


def test_launcher_sets_an_explicit_ws_ping_timeout():
    assert SCRIPT.is_file(), f"找不到啟動腳本：{SCRIPT}"
    assert _flag("ws-ping-timeout") is not None, (
        "run-backend.sh 沒有指定 --ws-ping-timeout：uvicorn 會用 20 秒的預設值，"
        "慢速上行的檔案上傳會在中途被伺服器自己切斷"
    )


def test_ping_timeout_outlasts_the_longest_upload():
    t = _flag("ws-ping-timeout")
    assert t is not None and t >= MIN_PING_TIMEOUT, (
        f"--ws-ping-timeout {t}s 太短：pong 會排在上傳資料後面，"
        f"任何比它久的上傳都會被切斷（至少要 {MIN_PING_TIMEOUT}s）"
    )


def test_ping_interval_stays_short_enough_to_reap_dead_peers():
    """放寬的是「等回覆的耐心」，不是「多久探一次」—— 兩者一起放大就等於沒有偵測。"""
    i = _flag("ws-ping-interval")
    assert i is not None and i <= 60, (
        f"--ws-ping-interval {i}s 太長：真的斷掉的連線會留著不放"
    )
