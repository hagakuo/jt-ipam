"""兩份 CHANGELOG 的最新版本要一致，而且不可落後目前的版本號（v0.6.56 發版時漏了繁中版，2026-10-01 補上）。

英文版寫了、繁中版停在上一版 —— 沒有任何檢查會發現，公開的變更記錄就少一版。
"""
from __future__ import annotations

import re
from pathlib import Path

from app.version import __version__

ROOT = Path(__file__).resolve().parents[2]
HEADER = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)


def _versions(name: str) -> list[str]:
    return HEADER.findall((ROOT / name).read_text(encoding="utf-8"))


def _key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def test_both_changelogs_have_the_same_latest_version() -> None:
    en, zh = _versions("CHANGELOG.md"), _versions("CHANGELOG_zh-TW.md")
    assert en
    assert zh
    assert en[0] == zh[0], f"CHANGELOG.md 最新是 {en[0]}、CHANGELOG_zh-TW.md 最新是 {zh[0]}"


def test_changelog_is_not_behind_the_version() -> None:
    latest = _versions("CHANGELOG.md")[0]
    assert _key(latest) >= _key(__version__), f"版本號已是 {__version__}，CHANGELOG 最新卻是 {latest}"
