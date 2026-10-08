"""主控台中繼：伺服器交給代理的「允許範圍」（2026-10-02 使用者要求：要不要中繼、哪些埠，都在網頁上設定）。

代理照這份範圍做：被指派的子網路、允許的埠、同時上限。系統設定與掃描代理頁兩道開關都開才給，
任何一道關掉就給空的範圍 —— 代理什麼都不中繼，不會自己假設任何預設。範圍在 poll 與每個中繼工作裡
各給一次（後者讓管理員剛打開開關就能用，不必等代理下一輪 poll）。
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

#: 預設允許的埠：SSH／SFTP、RDP、VNC 顯示 0～10
DEFAULT_PORTS = "22,3389,5900-5910"
#: 一個範圍最多幾個埠、整份最多幾個埠（代理端也有同樣的上限）
MAX_RANGE = 256
MAX_PORTS = 256

EMPTY: dict[str, Any] = {"cidrs": [], "ports": [], "max": 0}


def parse_ports(spec: str | None) -> list[int]:
    """"22,3389,5900-5910" → 排序去重的埠清單；格式不對的片段丟掉（讀取用，寫入前先過 normalize_ports）。"""
    out: set[int] = set()
    for tok in (spec or "").split(",")[:64]:
        a, _, b = tok.strip().partition("-")
        a, b = a.strip(), b.strip()
        if not a.isdigit() or (b and not b.isdigit()):
            continue
        lo, hi = int(a), int(b or a)
        if 1 <= lo <= hi <= 65535 and hi - lo < MAX_RANGE:
            out.update(range(lo, hi + 1))
    return sorted(out)[:MAX_PORTS]


def normalize_ports(spec: str) -> str:
    """寫入用：每一段都要合法，否則 ValueError（不默默丟掉使用者打的字）。回傳整理過的寫法。"""
    parts: list[str] = []
    total = 0
    for tok in spec.split(","):
        a, sep, b = tok.strip().partition("-")
        a, b = a.strip(), b.strip()
        if not a.isdigit() or (sep and not b.isdigit()):
            raise ValueError(tok.strip() or "（空白）")
        lo, hi = int(a), int(b) if sep else int(a)
        if not (1 <= lo <= hi <= 65535) or hi - lo >= MAX_RANGE:
            raise ValueError(tok.strip())
        total += hi - lo + 1
        parts.append(f"{lo}-{hi}" if hi > lo else str(lo))
    if not parts or total > MAX_PORTS:
        raise ValueError(spec.strip() or "（空白）")
    return ",".join(parts)


async def relay_scope(session: AsyncSession, agent: Any) -> dict[str, Any]:
    """這台代理現在被允許中繼的範圍；不允許就是 EMPTY。"""
    from app.models.subnet import Subnet
    from app.services.system_config import get_console_relay_enabled
    if not (agent.enabled and agent.relay_allowed and await get_console_relay_enabled(session)):
        return dict(EMPTY)
    cidrs = [str(c) for (c,) in (await session.execute(
        select(Subnet.cidr).where(Subnet.scan_agent_id == agent.id, Subnet.archived_at.is_(None))
    )).all()]
    return {"cidrs": cidrs, "ports": parse_ports(agent.relay_ports or DEFAULT_PORTS),
            "max": int(agent.relay_max_sessions or 0)}
