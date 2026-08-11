"""單次 ticket 的取出語意 —— 六個主控台共用這道門。

背景：原本直接呼叫 Redis 的 `GETDEL`，那是 6.2 才有的指令；在較舊的 Redis 上會回
`unknown command GETDEL`，讓 SSH／SFTP／RDP／VNC／noVNC／BMC 全部連不上。
這裡鎖住兩件事：**單次性**（第二次拿不到）以及 **EVAL 不可用時仍能運作**。
"""

import pytest

from app.core.tickets import take_once


class _LuaRedis:
    """會跑 Lua 的 Redis（6.2 以下也有 EVAL）。"""

    def __init__(self, data: dict[str, bytes]) -> None:
        self.data = data
        self.eval_calls = 0

    async def eval(self, _script: str, _numkeys: int, key: str) -> bytes | None:
        self.eval_calls += 1
        return self.data.pop(key, None)


class _NoLuaRedis:
    """停用腳本的 Redis：EVAL 會拋錯，必須退回 GET + DEL。"""

    def __init__(self, data: dict[str, bytes]) -> None:
        self.data = data
        self.deleted: list[str] = []

    async def eval(self, *_a: object, **_k: object) -> bytes:
        raise RuntimeError("ERR unknown command 'EVAL'")

    async def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)
        self.deleted.append(key)


@pytest.mark.asyncio
async def test_ticket_can_only_be_redeemed_once() -> None:
    r = _LuaRedis({"tk:a": b"user-1"})

    assert await take_once(r, "tk:a") == b"user-1"
    assert await take_once(r, "tk:a") is None  # 第二次必須落空


@pytest.mark.asyncio
async def test_missing_ticket_returns_none() -> None:
    assert await take_once(_LuaRedis({}), "tk:nope") is None


@pytest.mark.asyncio
async def test_falls_back_when_eval_unavailable() -> None:
    """EVAL 被停用時不能整個功能掛掉 —— 退回 GET + DEL，仍然只能用一次。"""
    r = _NoLuaRedis({"tk:b": b"user-2"})

    assert await take_once(r, "tk:b") == b"user-2"
    assert r.deleted == ["tk:b"]
    assert await take_once(r, "tk:b") is None


@pytest.mark.asyncio
async def test_fallback_does_not_delete_when_absent() -> None:
    """沒中的 key 不該發 DEL —— 免得把別人剛寫進來的同名 key 誤刪。"""
    r = _NoLuaRedis({})

    assert await take_once(r, "tk:c") is None
    assert r.deleted == []
