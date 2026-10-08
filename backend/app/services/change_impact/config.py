"""變更影響預演的設定（system_settings 的 change_impact 鍵）。預設關閉，在網頁開。"""

from __future__ import annotations

import copy
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

KEY = "change_impact"

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    # 生效條件：這個開關「且」LLM 設定已啟用
    "ai_enabled": True,
    # 預設不允許建立者自己覆核自己的計畫（管理員例外）
    "allow_self_review": False,
    "limits": {
        "analysis_seconds": 120,
        "max_findings": 5000,
        "max_evidence": 20000,
        "group_depth": 16,
        "per_customer_active_runs": 2,
        "per_user_ai_jobs": 1,
    },
    "run_valid_hours": 24,
    "default_stale_hours": 24,
    "retention_days": 180,
    "failed_retention_days": 30,
}

# 管理員可以調，但不可以超過硬上限（防資源耗盡，規格 §8.4）
_HARD_LIMITS = {"analysis_seconds": 600, "max_findings": 50000, "max_evidence": 200000, "group_depth": 32,
                "per_customer_active_runs": 10, "per_user_ai_jobs": 5}


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge(out[k], v)
        elif k in out:
            out[k] = v
    return out


async def get_config(session: AsyncSession) -> dict[str, Any]:
    from app.models.system_setting import SystemSetting
    row = await session.get(SystemSetting, KEY)
    return _merge(DEFAULTS, row.value if row and isinstance(row.value, dict) else {})


def _validate(cfg: dict[str, Any]) -> dict[str, Any]:
    cfg["enabled"] = bool(cfg["enabled"])
    cfg["ai_enabled"] = bool(cfg["ai_enabled"])
    cfg["allow_self_review"] = bool(cfg["allow_self_review"])
    for k, hard in _HARD_LIMITS.items():
        try:
            v = int(cfg["limits"][k])
        except (TypeError, ValueError):
            v = DEFAULTS["limits"][k]
        cfg["limits"][k] = max(1, min(v, hard))
    for k, lo, hi in (("run_valid_hours", 1, 168), ("default_stale_hours", 1, 720),
                      ("retention_days", 7, 3650), ("failed_retention_days", 1, 365)):
        try:
            cfg[k] = max(lo, min(int(cfg[k]), hi))
        except (TypeError, ValueError):
            cfg[k] = DEFAULTS[k]
    return cfg


async def set_config(session: AsyncSession, patch: dict[str, Any], *, updated_by: uuid.UUID | None) -> dict[str, Any]:
    """合併後驗證再存；呼叫端負責稽核與 commit。"""
    from sqlalchemy.orm.attributes import flag_modified

    from app.models.system_setting import SystemSetting
    cfg = _validate(_merge(await get_config(session), patch))
    row = await session.get(SystemSetting, KEY)
    if row is None:
        row = SystemSetting(key=KEY, value=cfg, updated_by=updated_by)
        session.add(row)
    else:
        row.value = cfg
        row.updated_by = updated_by
        flag_modified(row, "value")
    return cfg


async def ai_available(session: AsyncSession, cfg: dict[str, Any] | None = None) -> bool:
    from app.services.system_config import get_llm_config
    cfg = cfg or await get_config(session)
    if not cfg.get("ai_enabled"):
        return False
    llm = await get_llm_config(session)
    return bool(getattr(llm, "enabled", False))
