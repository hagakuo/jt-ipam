"""主控台的每個回覆都要帶回請求編號。

實機（2026-08-30）：畫面顯示某個檔案「已送出 1.5 MB / 1.5 MB」並接著上傳下一個檔案，
伺服器那一側卻是 `written=0` —— 一個位元組都沒收到。客戶端會這樣認定，是因為它的
「等待中的請求」只有**一個沒有標記的欄位**：伺服器回任何一個 `ok`，都會解掉當時正在等
的那件事。只要協定有一次錯位（回覆遲到、訊息重複、順序顛倒），成功與失敗就會對調。

編號讓這件事在結構上不可能發生：對不上的回覆會被忽略，該等的請求繼續等，
於是「沒收到」會誠實地表現成「還在等」而不是「已完成」。
"""

from __future__ import annotations

import inspect

from app.api.v1.endpoints import sftp_console


def _loop_source() -> str:
    src = inspect.getsource(sftp_console)
    start = src.index('                if op == "list":')
    # 從迴圈開頭往後找：檔案前面別的函式（例如傳輸路徑測試）也有同樣的 except
    return src[start:src.index("    except WebSocketDisconnect:", start)]


def test_every_reply_in_the_command_loop_carries_the_id():
    """指令迴圈裡不可以再直接 `send()` —— 那條路徑不會帶編號。"""
    body = _loop_source()
    assert "await send({" not in body, (
        "指令迴圈裡還有不帶編號的回覆：客戶端會把它對到別的請求上"
    )
    assert "await reply({" in body, "回覆要走會補上編號的 reply()"


def test_reply_helper_injects_the_request_id():
    src = inspect.getsource(sftp_console)
    assert 'req_id = req.get("id")' in src, "沒有從請求取出編號"
    assert '"id": _rid' in src or '{**obj, "id": _rid}' in src, (
        "reply() 沒有把編號放回回覆裡"
    )


def test_missing_id_is_tolerated():
    """舊版客戶端不會帶編號 —— 那時候不可以硬塞一個 None 進去。"""
    src = inspect.getsource(sftp_console)
    assert "if _rid is not None" in src, (
        "沒有處理「請求沒帶編號」的情況；回覆裡出現 id=null 會讓舊客戶端困惑"
    )
