"""裝置型號 (model) 來源優先序。

多個來源（手動 / LibreNMS hardware / Proxmox / OPNsense）可能都替同一台 device
提供型號字串。本模組決定採用誰。

排序、停用、快取等共通機制在 `services/precedence.py`；來源本身的性質登記在
`services/evidence.py`。

`resolve_device_model(candidates)` 給 sync 流程呼叫：傳入 {source: model}，
回傳依優先序應採用的型號。
"""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.precedence import Precedence

MODEL_KEY = "device_model_precedence"
MODEL_SOURCES = ("manual", "librenms", "proxmox", "opnsense")
# 預設：手動最優先，其次 LibreNMS hardware；Proxmox / OPNsense 為未來來源預留位
DEFAULT_MODEL_ORDER: list[str] = ["manual", "librenms", "proxmox", "opnsense"]

_P = Precedence(key=MODEL_KEY, sources=MODEL_SOURCES, default_order=tuple(DEFAULT_MODEL_ORDER))


def _bust() -> None:
    _P.bust()


async def get_model_precedence(session: AsyncSession) -> list[str]:
    return await _P.get_order(session)


async def get_model_disabled(session: AsyncSession) -> list[str]:
    return await _P.get_disabled(session)


async def set_model_precedence(
    session: AsyncSession, *, order: list[str],
    disabled: list[str] | None = None, updated_by_user_id: uuid.UUID | None = None,
) -> tuple[list[str], list[str]]:
    return await _P.save(session, order=order, disabled=disabled,
                         updated_by_user_id=updated_by_user_id)


def pick_model(candidates: dict[str, str], order: list[str], disabled: list[str]) -> str | None:
    """純函式：依優先序從 candidates 挑型號（跳過停用來源與空字串）。"""
    _src, value = _P.pick(dict(candidates), order, disabled)
    return value


async def resolve_device_model(
    session: AsyncSession, candidates: dict[str, str],
) -> str | None:
    """sync 流程用：傳入 {source: model}，回傳依目前優先序應採用的型號。"""
    order, disabled = await _P.load(session)
    return pick_model(candidates, order, disabled)
