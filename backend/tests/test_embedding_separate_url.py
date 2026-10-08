"""嵌入模型可以放在跟對話模型不同的位址（GitHub issue #33）。

回報者兩種模型是分開部署的，位址自然不同；設定裡只有一個 URL，等於逼他們二選一。
留空＝沿用對話模型那個位址（既有安裝升上來行為不變）。
"""
from __future__ import annotations

import pytest

from app.services import ai as ai_mod
from app.services.system_config import get_llm_config, set_llm_config


class _Resp:
    status_code = 200

    def json(self):
        return {"embedding": [0.0] * 768}


@pytest.mark.anyio
async def test_embed_uses_the_separate_url_when_set(db_session, monkeypatch) -> None:
    await set_llm_config(db_session, enabled=True, url="http://chat.example:11434",
                         embedding_base_url="http://embed.example:8000")
    await db_session.flush()

    seen: list[str] = []

    async def _fake(method, url, **kw):
        seen.append(url)
        return _Resp()

    monkeypatch.setattr(ai_mod, "safe_request", _fake)
    vec = await ai_mod.embed(db_session, "測試用描述")
    assert len(vec) == 768
    assert seen == ["http://embed.example:8000/api/embeddings"], seen


@pytest.mark.anyio
async def test_embed_falls_back_to_the_chat_url(db_session, monkeypatch) -> None:
    """留空＝沿用對話模型那個位址；升級上來的安裝不可以因此改變行為。"""
    await set_llm_config(db_session, enabled=True, url="http://chat.example:11434",
                         embedding_base_url="")
    await db_session.flush()

    seen: list[str] = []

    async def _fake(method, url, **kw):
        seen.append(url)
        return _Resp()

    monkeypatch.setattr(ai_mod, "safe_request", _fake)
    await ai_mod.embed(db_session, "測試用描述")
    assert seen == ["http://chat.example:11434/api/embeddings"], seen
