"""通知帶的連結必須指得到真的頁面，而且每個通知都要帶連結。

由來（使用者回報，2026-08-30）：「我點通知的防火牆異動那個，沒帶我去應該看的那一頁。」
查下來是那個事件根本沒帶 `link`；順手全掃一遍，又發現兩個帶著**不存在的路由**
（`/admin/audit`、`/admin/event-rules` —— 那些頁面實際上在 `/audit`、`/event-rules`）。

兩種壞法在畫面上一模一樣：點了沒反應。而通知的存在意義就是「帶我去看」，
少了這件事它只是一則會消失的字。所以這裡把前端的路由表當成事實來源，逐一核對。
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTER = ROOT / "frontend" / "src" / "router" / "index.ts"
BACKEND = ROOT / "backend" / "app"


def _routes() -> set[str]:
    text = ROUTER.read_text(encoding="utf-8")
    return {m.group(1) for m in re.finditer(r'path:\s*"([^"]*)"', text)}


def _calls() -> list[tuple[str, int, str, bool]]:
    """(檔案, 行號, 函式, 有沒有帶 link)。"""
    out = []
    for f in BACKEND.rglob("*.py"):
        s = f.read_text(encoding="utf-8")
        for m in re.finditer(r"await (notify_admins_event|push_notification)\(", s):
            i, depth, j = m.end() - 1, 0, m.end() - 1
            while j < len(s):
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            call = s[i:j + 1]
            out.append((str(f.relative_to(ROOT)), s[:m.start()].count("\n") + 1,
                        m.group(1), "link=" in call))
    return out


def test_every_notification_carries_a_link():
    missing = [f"{f}:{line} {fn}" for f, line, fn, has in _calls() if not has]
    assert not missing, (
        "這些通知沒有帶連結，點了會停在原地：\n  " + "\n  ".join(missing)
    )


def test_notification_links_point_at_real_routes():
    routes = _routes()
    bad = []
    for f in BACKEND.rglob("*.py"):
        for m in re.finditer(r'link=(?:f)?"(/[^"{]*)', f.read_text(encoding="utf-8")):
            link = m.group(1)
            first = link.strip("/").split("/")[0].split("?")[0]
            if first and first not in routes:
                bad.append(f"{f.relative_to(ROOT)}：{link}")
    assert not bad, (
        "這些連結指到不存在的路由（點了會落到 404 或首頁）：\n  " + "\n  ".join(bad)
    )
