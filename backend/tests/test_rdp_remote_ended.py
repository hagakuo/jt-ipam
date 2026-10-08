"""被控端自己結束工作階段時，畫面要說出來 —— GitHub issue #42。

回報者用 aardwolf 引擎連一台主機，連上後約 6 毫秒伺服器就斷線；日誌只有 aardwolf 的
`TypeError: cannot unpack non-iterable NoneType object`（它的讀取迴圈拿到 None 就拆解失敗，
真正的原因被蓋掉），畫面上則只有「已中斷」。aardwolf 不像 FreeRDP 引擎會給中斷原因
（exit_reason），所以至少要分得出三種情況：

- 還沒送出任何畫面就被伺服器結束 → 多半是伺服器端拒絕（授權、遠端登入權限、工作階段已滿），
  要講出來並建議改用 FreeRDP 引擎（它會顯示伺服器給的原因）。
- 用到一半被結束（例如在遠端登出）→ 說「被控端結束了這個工作階段」。
- 使用者自己關掉分頁 → 什麼都不用說。
"""
from __future__ import annotations

import asyncio

import pytest
from app.services.rdp_freerdp import VideoTile
from starlette.websockets import WebSocketDisconnect


class _Conn:
    def __init__(self, items, reason=None):
        self.ext_out_queue: asyncio.Queue = asyncio.Queue()
        for it in items:
            self.ext_out_queue.put_nowait(it)
        if reason is not None:
            self.exit_reason = reason


class _WS:
    """瀏覽器那一端：`disconnect_after` 秒後關分頁；None＝一直開著。"""

    def __init__(self, disconnect_after: float | None = None):
        self.disconnect_after = disconnect_after

    async def receive_text(self) -> str:
        if self.disconnect_after is None:
            await asyncio.Event().wait()
        await asyncio.sleep(self.disconnect_after)
        raise WebSocketDisconnect(code=1001)


async def _run(conn, ws) -> list[dict]:
    from app.api.v1.endpoints.rdp_console import _bridge

    sent: list[dict] = []

    async def send(msg: dict) -> None:
        sent.append(msg)

    await asyncio.wait_for(_bridge(ws, conn, send), timeout=5)
    return [m for m in sent if m.get("type") == "error"]


@pytest.mark.anyio
async def test_server_ends_before_any_frame_says_so_and_suggests_freerdp() -> None:
    errs = await _run(_Conn([None]), _WS())
    assert [e["code"] for e in errs] == ["console_remote_ended_early"]
    assert "FreeRDP" in errs[0]["message"]


@pytest.mark.anyio
async def test_server_ends_mid_session_without_a_reason() -> None:
    tile = VideoTile(x=0, y=0, width=8, height=8, data=b"png")
    errs = await _run(_Conn([tile, tile, None]), _WS())
    assert [e["code"] for e in errs] == ["console_remote_ended"]


@pytest.mark.anyio
async def test_a_reason_from_the_engine_still_wins() -> None:
    errs = await _run(_Conn([None], reason="ERRINFO_LOGOFF_BY_USER"), _WS())
    assert [e["code"] for e in errs] == ["console_remote_closed"]
    assert errs[0]["params"]["reason"] == "ERRINFO_LOGOFF_BY_USER"


@pytest.mark.anyio
async def test_user_closing_the_tab_is_not_reported_as_the_server_ending() -> None:
    tile = VideoTile(x=0, y=0, width=8, height=8, data=b"png")
    errs = await _run(_Conn([tile]), _WS(disconnect_after=0.05))
    assert errs == []


@pytest.mark.anyio
async def test_vnc_server_ending_the_session_is_reported_too() -> None:
    from app.api.v1.endpoints.vnc_console import _bridge

    sent: list[dict] = []

    async def send(msg: dict) -> None:
        sent.append(msg)

    await asyncio.wait_for(_bridge(_WS(), _Conn([None]), send), timeout=5)
    assert [m["code"] for m in sent if m.get("type") == "error"] == ["console_remote_ended"]
