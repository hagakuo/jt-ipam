"""`DHCP_SOURCE_TYPES` 必須涵蓋所有真的會被寫進 `dhcp_pool_ranges.source_type` 的值。

背景：這個常數是「這張表有哪些來源」的唯一書面依據，但沒有任何 CHECK 約束或程式
在讀它 —— 所以它曾經默默過期（FortiGate 整合已經在寫 `source_type="fortigate"`，
常數卻還只列 opnsense / pfsense / windows_dhcp）。這個測試讓它不能再漂走。
"""

from __future__ import annotations

import re
from pathlib import Path

from app.models.dhcp import DHCP_SOURCE_TYPES

SERVICES = Path(__file__).resolve().parent.parent / "app" / "services"

# 掃 `source_type="..."` / `source_type='...'`（含 DHCPPoolRange(...) 的關鍵字引數）
_PATTERN = re.compile(r"""source_type\s*=\s*["']([a-z0-9_]+)["']""")


def _written_source_types() -> set[str]:
    found: set[str] = set()
    for path in SERVICES.rglob("*.py"):
        for m in _PATTERN.finditer(path.read_text(encoding="utf-8")):
            found.add(m.group(1))
    return found


def test_every_written_source_type_is_declared() -> None:
    written = _written_source_types()
    assert written, "掃不到任何 source_type= 字面值，正規式可能失效了"
    undeclared = sorted(written - set(DHCP_SOURCE_TYPES))
    assert not undeclared, (
        f"這些 source_type 有程式在寫、但沒登錄進 DHCP_SOURCE_TYPES：{undeclared}。"
        f"請加進 app/models/dhcp.py 的 DHCP_SOURCE_TYPES。"
    )


def test_declared_source_types_are_actually_used() -> None:
    """反向檢查：登錄了卻沒人寫，通常代表整合被移除或打錯字。"""
    written = _written_source_types()
    unused = sorted(set(DHCP_SOURCE_TYPES) - written)
    assert not unused, (
        f"這些 source_type 登錄了但沒有任何 service 在寫：{unused}。"
        f"若整合已移除請一併從 DHCP_SOURCE_TYPES 拿掉。"
    )


def test_known_sources_present() -> None:
    """釘住目前四個 DHCP 來源整合，避免有人手滑刪掉。"""
    for src in ("opnsense", "pfsense", "windows_dhcp", "fortigate"):
        assert src in DHCP_SOURCE_TYPES, f"{src} 不在 DHCP_SOURCE_TYPES 裡"
