"""授權條款只能有一個答案。

版本資訊頁要顯示授權條款 —— 那就必須保證畫面上那一行與實際的授權檔一致。
這個專案的授權**改過一次**（2026-08-15 從 Apache-2.0 改為 AGPL-3.0-or-later），
而宣告散在四個地方：`backend/pyproject.toml`、`frontend/package.json`、
根目錄 `LICENSE` 全文，以及後端要回給畫面的字串。少改一處，畫面就會理直氣壯地
顯示錯誤的授權 —— 那比不顯示更糟。

所以這裡把四處綁在一起：任何一處改了、其他沒跟上，測試就紅。
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

EXPECTED = "AGPL-3.0-or-later"


def test_backend_constant_matches_pyproject():
    from app.version import __license__

    data = tomllib.loads((REPO / "backend" / "pyproject.toml").read_text(encoding="utf-8"))
    lic = data["project"]["license"]
    declared = lic["text"] if isinstance(lic, dict) else lic
    assert __license__ == declared == EXPECTED


def test_frontend_package_json_matches():
    import json

    pkg = json.loads((REPO / "frontend" / "package.json").read_text(encoding="utf-8"))
    assert pkg["license"] == EXPECTED


def test_license_file_is_actually_that_licence():
    """SPDX 字串對得上，不代表檔案裡放的是同一份授權 —— 一起檢查。"""
    text = (REPO / "LICENSE").read_text(encoding="utf-8", errors="replace")[:400]
    assert re.search(r"GNU AFFERO GENERAL PUBLIC LICENSE", text), text[:120]
    assert "Version 3" in text


def test_version_endpoint_reports_the_license():
    """畫面上的那一行來自這裡：漏掉欄位＝版本頁少一格，而不是顯示錯的值。"""
    from app.api.v1.endpoints.system_settings import _gather_version_info

    info = _gather_version_info()
    assert info.get("license") == EXPECTED
