"""單次使用的短期 ticket：原子地「取出並刪除」。

六個主控台（SSH／SFTP／RDP／VNC／noVNC／BMC）都用同一個模式：發一張 60 秒、單次有效的
ticket，WebSocket 拿它換連線。單次性是這道門的全部 —— 取出與刪除之間若不是原子的，
同一張票就可能被用兩次。

**為什麼不直接用 `GETDEL`**：那是 Redis **6.2** 才有的指令。舊一點的 Redis 會回
`unknown command GETDEL`，於是所有主控台在那些部署上都連不上 —— 而且錯誤訊息完全
指不到原因（實機驗證時撞到）。改用 Lua：`EVAL` 從 Redis 2.6 就有，同樣是原子的。
"""

from __future__ import annotations

from typing import Any

# GET 後 DEL，整段在 Redis 內部一次跑完 —— 與 GETDEL 語意相同，但相容舊版
_TAKE_ONCE = """
local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v
"""


async def take_once(redis: Any, key: str) -> bytes | None:
    """取出並刪除 `key`；不存在回 None。同一個 key 只有第一次呼叫拿得到值。"""
    try:
        return await redis.eval(_TAKE_ONCE, 1, key)
    except Exception:
        # 極舊或受限的 Redis 可能連 EVAL 都不給（例如某些託管服務停用腳本）。
        # 退回 GET + DEL：**有極小的競爭窗**，但比整個功能不能用好，
        # 而且 ticket 本來就只有 60 秒壽命、且綁定使用者與目標。
        val = await redis.get(key)
        if val is not None:
            await redis.delete(key)
        return val
