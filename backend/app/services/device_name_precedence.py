"""裝置名稱來源優先序。

多個來源（手動 / LibreNMS / DNS / Proxmox VM 名稱 / OPNsense / SNMP sysName）可能
都替同一台 device 提供名稱。本模組決定採用誰。

排序、停用、快取等共通機制在 `services/precedence.py`；來源本身的性質
（會不會過期、屬於哪一層）登記在 `services/evidence.py`。

`resolve_device_name(candidates)` 給 sync 流程呼叫：傳入 {source: name}，
回傳依優先序應採用的名稱。
"""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.precedence import Precedence

DEVNAME_KEY = "device_name_precedence"
DEVNAME_SOURCES = ("manual", "librenms", "dns", "proxmox", "opnsense", "snmp")
# 預設：手動最優先，其次 SNMP sysName（人類可讀），再來才是 LibreNMS hostname
# （常常就是 IP，當名稱不佳）、DNS、Proxmox VM 名稱、OPNsense。
DEFAULT_DEVNAME_ORDER: list[str] = ["manual", "snmp", "librenms", "dns", "proxmox", "opnsense"]

_P = Precedence(key=DEVNAME_KEY, sources=DEVNAME_SOURCES,
                default_order=tuple(DEFAULT_DEVNAME_ORDER))


def _bust() -> None:
    _P.bust()


async def get_devname_precedence(session: AsyncSession) -> list[str]:
    return await _P.get_order(session)


async def get_devname_disabled(session: AsyncSession) -> list[str]:
    return await _P.get_disabled(session)


async def set_devname_precedence(
    session: AsyncSession, *, order: list[str],
    disabled: list[str] | None = None, updated_by_user_id: uuid.UUID | None = None,
) -> tuple[list[str], list[str]]:
    return await _P.save(session, order=order, disabled=disabled,
                         updated_by_user_id=updated_by_user_id)


def pick_name(candidates: dict[str, str], order: list[str], disabled: list[str]) -> str | None:
    """純函式：依優先序從 candidates 挑名稱（跳過停用來源與空字串）。"""
    _src, value = _P.pick(dict(candidates), order, disabled)
    return value


async def resolve_device_name(
    session: AsyncSession, candidates: dict[str, str],
) -> str | None:
    """sync 流程用：傳入 {source: name}，回傳依目前優先序應採用的名稱。"""
    order, disabled = await _P.load(session)
    return pick_name(candidates, order, disabled)
