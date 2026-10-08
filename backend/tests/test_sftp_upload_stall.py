"""上傳中途沒有資料時，不可以讓整條連線卡死。

客戶回報：拖兩個檔案進去上傳 → 「連線已中斷」，遠端只出現一個 **0 位元組**的檔案，
之後要再連線時 ticket 請求逾時、整個畫面很久才有回應。

串起來就是同一件事：收檔案的迴圈是

    while written < size:
        chunk = await websocket.receive_bytes()

客戶端在 `put_ready` 之後只要沒把宣告的位元組送完（大檔被瀏覽器的送出緩衝擋下、
拖曳的檔案 handle 失效…），伺服器就**無限期**停在這裡。檔案已經被 open("wb") 建出來
所以遠端看得到 0 位元組；那條協程一直佔著 WebSocket 與 asyncssh 連線；使用者以為是
「連線壞了」，實際上是伺服器還在等一個永遠不會來的框。

修法是給每一個資料框一個逾時：逾時就回報錯誤、放掉那個檔案，**連線繼續可用**。
不是把整條連線關掉 —— 一次上傳失敗不該讓人重連。
"""

from __future__ import annotations

import inspect

from app.api.v1.endpoints import sftp_console


def test_upload_receive_has_a_stall_timeout():
    """收上傳資料的地方必須有逾時保護。

    這裡用原始碼檢查而不是端到端：要真的重現「客戶端連上來、宣告大小、然後不送」
    需要一台可連的 SSH 伺服器，而這個缺陷的本質是「那一行沒有逾時」——
    直接對著它斷言最不容易因為環境而失真。
    """
    src = inspect.getsource(sftp_console)
    put_block = src[src.index('elif op == "put":'):]
    put_block = put_block[:put_block.index('elif op == "mkdir":')]

    assert "websocket.receive()" in put_block, "測試對象改名了，請一起更新"
    assert "wait_for" in put_block or "timeout" in put_block, (
        "上傳的接收迴圈沒有逾時保護：客戶端不送資料時伺服器會無限期佔住這條連線"
    )


def test_stall_timeout_is_bounded_and_sane():
    """逾時值要看得見、而且不能長到跟沒有一樣。"""
    t = getattr(sftp_console, "UPLOAD_STALL_TIMEOUT", None)
    assert t is not None, "逾時值要是一個具名常數，別埋在程式碼裡"
    assert 5 <= t <= 120, f"逾時 {t}s 不合理：太短會誤殺慢速上傳，太長等於沒有保護"


def test_a_stalled_upload_does_not_close_the_session():
    """逾時之後要能繼續用同一條連線 —— 一次上傳失敗不該逼人重連。"""
    src = inspect.getsource(sftp_console)
    put_block = src[src.index('elif op == "put":'):]
    put_block = put_block[:put_block.index('elif op == "mkdir":')]
    # 逾時的處理要在迴圈內把錯誤送回去，而不是往外拋掉整條連線
    assert "put_stalled" in put_block or "continue" in put_block, (
        "逾時後應該回報錯誤並讓連線繼續，而不是讓例外往外炸掉整個 session"
    )


def test_upload_loop_never_calls_receive_bytes_directly():
    """上傳迴圈不可以用 `receive_bytes()`。

    實機日誌（2026-08-29）抓到的當機點就是它：

        File ".../sftp_console.py", line 332, in sftp_ws
        File ".../starlette/websockets.py", line 128, in receive_bytes
        KeyError: 'bytes'

    `receive_bytes()` 收到**文字**框時會丟 KeyError，整個 handler 當掉、連線關閉。
    而客戶端在資料還沒送完就改送下一個指令（放棄這次上傳卻沒告知）是完全可能的 ——
    使用者看到的是「連線已中斷」，真正的原因只是伺服器對一個文字框沒有防備。

    正確作法是用 `receive()` 自己判斷框的型別：是指令就結束這次上傳、把指令留著照常處理。
    """
    src = inspect.getsource(sftp_console)
    put_block = src[src.index('elif op == "put":'):]
    put_block = put_block[:put_block.index('elif op == "mkdir":')]
    # 比對呼叫本身，不是註解裡提到的名字（第一版就是這樣誤判的）
    assert "websocket.receive_bytes(" not in put_block, (
        "上傳迴圈直接呼叫了 receive_bytes()：對方改送指令時會 KeyError 並斷線"
    )
    assert "websocket.receive()" in put_block, "應該用 receive() 自己判斷框的型別"


def test_a_command_during_upload_is_not_swallowed():
    """被當成「放棄上傳」的那個指令要留下來照常執行，不能吞掉 ——
    否則使用者送出的下一個動作會無聲無息地消失。"""
    src = inspect.getsource(sftp_console)
    assert "carry_over" in src, "上傳中途收到的指令沒有被保留下來處理"


def test_server_still_tells_the_client_it_may_send():
    """開檔成功後一定要送 `put_ready`。

    0.5.225 改寫上傳區塊時，這一行**被整行弄丟**：伺服器開好檔案就直接進入接收迴圈，
    客戶端卻永遠等不到「可以送了」，於是一個位元組都沒送 → 30 秒後逾時 →
    上傳功能整個失效。而且症狀（「連線已中斷」）跟原本要修的 bug 一模一樣，
    很容易被當成「還沒修好」而不是「修壞了」。

    這種「刪掉一行就全壞、但看起來像原本的老問題」的東西，值得一個專門的測試。
    """
    src = inspect.getsource(sftp_console)
    put_block = src[src.index('elif op == "put":'):]
    put_block = put_block[:put_block.index('elif op == "mkdir":')]
    assert '"put_ready"' in put_block, (
        "開檔後沒有送 put_ready：客戶端會一直等，上傳完全不會開始"
    )
