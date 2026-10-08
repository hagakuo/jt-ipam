"""主控台（RDP／VNC／SSH）實際要用的連線引擎。

RDP 與 VNC 的預設引擎是 guacd（2026-09-27 起；已安裝的站台由遷移 0158 強制改過來）。
設定是 guacd、而這台的 guacd 沒在跑或沒有這個協定的外掛時 —— 例如升級時這個 OS 還沒有
guacd 預編檔 —— 退回可用的內建引擎，不讓主控台整個連不上；設定頁的 guacd 狀態與
`jt-ipam.sh doctor` 會把原因講出來。

發票證時決定一次、寫進票證，WebSocket 照票證用：兩邊各自判斷的話，guacd 剛好在中間起落，
瀏覽器講 Guacamole 協定、伺服器講 JSON（或反過來），畫面只會卡住。
"""
from __future__ import annotations

import logging
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)


async def configured(session: AsyncSession, protocol: str) -> str:
    from app.services import system_config as sc
    getter = {"rdp": sc.get_rdp_engine, "vnc": sc.get_vnc_engine, "ssh": sc.get_ssh_engine}[protocol]
    return await getter(session)


async def resolve(session: AsyncSession, protocol: str, *,
                  fallbacks: Sequence[tuple[str, bool]]) -> str:
    """設定的引擎；設定是 guacd 但這台的 guacd 處理不了這個協定 → 第一個可用的內建引擎。

    fallbacks：依序的 (引擎, 這台能不能用)。都不能用就照設定回 guacd，讓錯誤訊息講 guacd 的問題
    （怎麼裝），而不是一個不相干的內建引擎錯誤。
    """
    engine = await configured(session, protocol)
    if engine != "guacd":
        return engine
    from app.services import guacd as guac
    st = await guac.probe()
    if st["protocols"].get(protocol):
        return "guacd"
    for name, ok in fallbacks:
        if ok:
            log.warning("guacd cannot serve %s (%s); using the %s engine instead",
                        protocol, st.get("error") or "protocol plugin missing", name)
            return name
    return "guacd"
