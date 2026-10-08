"""變更影響預演：後端送出的每個代碼，前端三個語系都要有句子（否則畫面上直接露出代碼）。

規則表的原因碼、引擎與 adapter 記的缺口代碼、模板待辦代碼，都從原始碼收集，不靠手動清單。
"""
from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "backend" / "app" / "services" / "change_impact"
LOCALES = ("zh-TW", "en-US", "ja-JP")


def _locale(name: str) -> dict:
    return json.loads((ROOT / "frontend" / "src" / "i18n" / f"{name}.json").read_text())["change_impact"]


def _gap_codes() -> set[str]:
    codes: set[str] = set()
    for f in SRC.glob("*.py"):
        text = f.read_text()
        codes |= set(re.findall(r'\.gap\(\s*[^,]+,\s*"([a-z_]+)"', text))
    # 來源狀態的缺口是 f"source_{freshness}"
    codes |= {"source_stale", "source_never_synced", "source_failed", "source_partial"}
    return codes


def _template_codes() -> set[str]:
    text = (SRC / "plans.py").read_text()
    return {c for c in re.findall(r'\("(?:precheck|change|verify|rollback)", "([a-z_]+)"', text)}


def test_every_reason_gap_and_task_code_is_translated() -> None:
    from app.services.change_impact.model import RULES
    reasons = {r.reason for r in RULES.values()}
    gaps = _gap_codes()
    tasks = _template_codes() | {"update_refs", "remove_refs"}
    assert gaps and tasks and len(reasons) > 40
    missing = []
    for loc in LOCALES:
        d = _locale(loc)
        missing += [f"{loc}: reason.{c}" for c in sorted(reasons) if c not in d.get("reason", {})]
        missing += [f"{loc}: gap.{c}" for c in sorted(gaps) if c not in d.get("gap", {})]
        missing += [f"{loc}: task.{c}" for c in sorted(tasks) if c not in d.get("task", {})]
        cats = {r.category for r in RULES.values()}
        missing += [f"{loc}: category.{c}" for c in sorted(cats) if c not in d.get("category", {})]
    assert not missing, "少了翻譯：\n" + "\n".join(missing)
