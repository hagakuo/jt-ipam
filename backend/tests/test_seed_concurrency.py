"""啟動時的 seed 必須「並行安全」，不只是「重跑安全」。

這兩個 seed 本來就冪等（先查再建），但 uvicorn 是**多個 worker 同時啟動**的：四個行程
在同一瞬間都查到空表、都 INSERT，輸的那幾個吃到 UniqueViolation。功能其實沒壞（贏的
那個已經建好了），可是每一次全新安裝的 journal 都會噴出一整段紅色 SQL 例外 ——
客戶第一次看 log 就先看到「duplicate key value violates unique constraint」，
會以為安裝失敗。這是在乾淨 Debian 12 容器實跑安裝時看到的。

冪等 ≠ 並行安全，是這裡唯一要記住的事；解法是 seed 函式自己拿 advisory lock 排隊。
"""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import func, select

from app.api.v1.endpoints.advanced import seed_default_circuit_types
from app.models.advanced import CircuitType
from app.models.user import Group
from app.services.permission import DEFAULT_ROLES, seed_default_roles


async def _count(session, model) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


@pytest.mark.anyio
async def test_concurrent_role_seeding_does_not_raise(db_session, session_factory) -> None:
    """模擬四個 worker 同時 seed：不能有任何一個炸掉，資料也不能重複。"""
    async def one() -> int:
        async with session_factory() as s:
            return await seed_default_roles(s)

    results = await asyncio.gather(*(one() for _ in range(4)), return_exceptions=True)
    boom = [r for r in results if isinstance(r, BaseException)]
    assert not boom, f"並行 seed 仍然拋例外（正是客戶 journal 裡那段紅字）：{boom!r}"

    # 只有一個 worker 該真的建立；其餘回 0
    assert sum(r for r in results if isinstance(r, int)) == len(DEFAULT_ROLES)
    assert await _count(db_session, Group) == len(DEFAULT_ROLES)


@pytest.mark.anyio
async def test_concurrent_circuit_type_seeding_does_not_raise(
    db_session, session_factory,
) -> None:
    """電路類型同理：表為空的判斷在並行下也會四個都成立。"""
    async def one() -> int:
        async with session_factory() as s:
            return await seed_default_circuit_types(s)

    results = await asyncio.gather(*(one() for _ in range(4)), return_exceptions=True)
    boom = [r for r in results if isinstance(r, BaseException)]
    assert not boom, f"並行 seed 仍然拋例外：{boom!r}"

    total = await _count(db_session, CircuitType)
    assert total == sum(r for r in results if isinstance(r, int)), "有 worker 重複塞了一輪"
    assert total > 0
