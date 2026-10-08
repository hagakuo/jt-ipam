"""相依套件弱點的豁免清單（.github/audit-allowlist.txt）要守規矩：每筆都有到期日、理由，而且沒有過期；
frontend/package.json 用 `pnpm.auditConfig.ignoreGhsas` 忽略的每一筆，都要在清單登記（pnpm audit 沒有
指令列的忽略選項，豁免只能寫在 package.json —— 不守門的話它會變成沒有到期日、沒人記得理由的永久豁免）。

到期了這支測試就會擋下 CI：重新評估（有修補版就升級並刪掉，沒有才延期並更新理由），不是自動延長。
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = ROOT / ".github" / "audit-allowlist.txt"


def _entries() -> dict[str, tuple[dt.date, str]]:
    out: dict[str, tuple[dt.date, str]] = {}
    for line in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        assert len(parts) == 3, f"格式要是「<ID>  <到期日>  <理由>」：{line}"
        vid, exp, reason = parts
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp), f"{vid} 的到期日格式不對：{exp}"
        assert len(reason) >= 20, f"{vid} 的理由太短：要寫為什麼這個環境不受影響或為什麼暫時不能升級"
        out[vid] = (dt.date.fromisoformat(exp), reason)
    return out


def test_every_exemption_has_a_future_expiry() -> None:
    today = dt.date.today()
    expired = [f"{v}（到期 {d}）" for v, (d, _r) in _entries().items() if d < today]
    assert not expired, f"豁免已到期，請重新評估：{expired}"


def test_pnpm_ignores_are_registered() -> None:
    pkg = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    ignored = pkg.get("pnpm", {}).get("auditConfig", {}).get("ignoreGhsas", [])
    missing = [g for g in ignored if g not in _entries()]
    assert not missing, f"package.json 忽略了這些弱點，卻沒有登記在 .github/audit-allowlist.txt：{missing}"
