"""WebSocket 等待的時限。

主控台的 WebSocket 有兩種等待，處理方式必須不同：

**閒置等下一個指令** —— 終端機開著沒人打字是常態，等好幾個小時完全正常。
這種地方**不可以**加逾時，加了就是把正常的連線砍掉。

**協定進行到一半在等對方** —— 伺服器已經承諾了一個多步驟交換（等連線設定、等使用者
回答是否信任主機金鑰、等上傳的資料框），對方不接話就會一直卡著。這種地方**一定要**
有時限：少了它，只要開 N 條連線然後不說話，就能佔住 N 個協程與其後的連線資源，
而且從外面看起來只是「系統很慢」。

實機上就踩過：SFTP 上傳在 `put_ready` 之後沒收到資料框，伺服器無限期等待，
使用者看到的是「連線已中斷」加上之後所有請求逾時。
"""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.ui_error import UiError

#: 連上來之後，等第一個連線設定訊息的時限（秒）。正常客戶端是立刻送出。
HANDSHAKE_TIMEOUT = 30

#: 等使用者回答「是否信任這把主機金鑰」的時限（秒）。要留給人讀完訊息再決定，
#: 但不能是無限 —— 那等於把連線資源交給對方決定何時釋放。
PROMPT_TIMEOUT = 180


class WsTimeout(UiError, TimeoutError):
    """協定中途等待逾時；帶著人看得懂的說明，好讓前端直接顯示。"""


#: 在等什麼 → (翻譯代碼, 中文退路用的詞)。`what` 本身不是可以直接顯示的字：
#: 把「連線設定」當參數傳出去，等於在英文與日文的句子裡夾一個中文詞。
_WAITING_FOR = {
    "config": ("ws_timeout_config", "連線設定"),
    "host_key": ("ws_timeout_host_key", "主機金鑰確認"),
}


async def receive_text_within(websocket: Any, timeout: float, *, what: str) -> str:
    """在時限內收一則文字訊息，逾時丟 `WsTimeout`。

    `what` 說明在等的是哪一步（`config`／`host_key`），因為使用者看到的錯誤
    如果只寫 timeout，等於沒說。
    """
    try:
        return await asyncio.wait_for(websocket.receive_text(), timeout=timeout)
    except TimeoutError as exc:
        code, zh = _WAITING_FOR.get(what, ("ws_timeout", what))
        raise WsTimeout(f"等待{zh}超過 {int(timeout)} 秒，連線已關閉",
                        code=code, seconds=int(timeout), what=zh) from exc


#: 主控台連線的保活間隔（秒）。要明顯小於常見反向代理的閒置逾時（多半 60 秒）。
KEEPALIVE_INTERVAL = 20


async def keepalive_loop(websocket: Any, *, interval: float = KEEPALIVE_INTERVAL) -> None:
    """定期送一則極小的訊息，讓連線不會被中間的代理當成閒置而切斷。

    **為什麼不靠 WebSocket 的 ping/pong**：那是控制框，會被某些反向代理吞掉或不轉發；
    而且我們無法要求每個部署現場的代理都照我們的方式設定（Mode C 明確支援使用者
    自己的反向代理）。應用層的資料框則一定會被轉發 —— 代理要轉發資料才叫代理。

    實機案例：主控台開著沒有操作時，連線固定在 **60 秒**被切斷（常見代理的預設閒置
    逾時），使用者看到的是莫名其妙的「連線已中斷」。

    客戶端必須忽略 `type == "keepalive"` 的訊息（不可以拿它去解決等待中的請求）。
    """
    try:
        while True:
            await asyncio.sleep(interval)
            await websocket.send_text('{"type":"keepalive"}')
    except asyncio.CancelledError:
        raise
    except Exception:
        return          # 連線已關閉：保活本身不該製造錯誤
