"""守門：版本資訊頁的相依清單不可以漏掉實際用到的套件。

那兩份清單（後端 Python、前端 npm）都是**手寫**的。手寫清單會過期，而且過期的方式
很難察覺：管理員在版本頁上看到的是一份看起來完整的表，不會知道有東西沒被列出來。
升級或稽核時就是靠這一頁核對「我這台裝的是什麼版本」。

所以這裡拿它跟真正宣告的相依（pyproject.toml / package.json）比對：
少了就擋，多了也要是刻意的（選用相依或建置工具）。
"""

from __future__ import annotations

import json
import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _page_lists() -> tuple[list[str], list[str]]:
    """從版本資訊端點的原始碼取出那兩份清單。"""
    src = (ROOT / "backend" / "app" / "api" / "v1" / "endpoints" / "system_settings.py"
           ).read_text(encoding="utf-8")
    py_block = src[src.index("    pkgs = ["):]
    py_block = py_block[:py_block.index("]") + 1]
    backend = re.findall(r'"([^"]+)"', py_block)

    fe_block = src[src.index('for p in ["vue", "naive-ui"'):]
    fe_block = fe_block[:fe_block.index("]") + 1]
    frontend = re.findall(r'"([^"]+)"', fe_block)
    return backend, frontend


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def test_backend_page_lists_every_runtime_dependency():
    data = tomllib.loads((ROOT / "backend" / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        _norm(re.split(r"[<>=!\[; ]", d)[0])
        for d in data["project"]["dependencies"]
    }
    listed = {_norm(x) for x in _page_lists()[0]}
    missing = sorted(declared - listed)
    assert not missing, (
        "這些相依有宣告但版本頁沒列出來，管理員在頁面上看不到它們的版本：\n  "
        + "\n  ".join(missing)
    )


#: 刻意列出、但不是我們直接宣告的套件 → 理由。
#: 這種項目要是沒有理由，就跟「列錯了」分不出來。
TRANSITIVE_BY_DESIGN = {
    "pillow": "aardwolf（RDP 選用相依）的傳遞相依；列出來是為了看 RDP 那組套件是否完整",
}


def test_backend_page_has_no_ghost_packages():
    """列了卻不存在的套件也是問題：頁面上會永遠顯示「未安裝」，看起來像壞掉。"""
    data = tomllib.loads((ROOT / "backend" / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {_norm(re.split(r"[<>=!\[; ]", d)[0]) for d in data["project"]["dependencies"]}
    for group in (data["project"].get("optional-dependencies") or {}).values():
        declared |= {_norm(re.split(r"[<>=!\[; ]", d)[0]) for d in group}
    listed = {_norm(x) for x in _page_lists()[0]}
    ghosts = sorted(listed - declared - set(TRANSITIVE_BY_DESIGN))
    assert not ghosts, f"版本頁列了沒有宣告的套件（會永遠顯示未安裝）：{ghosts}"


def test_frontend_page_lists_every_runtime_dependency():
    pkg = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    declared = {_norm(x) for x in (pkg.get("dependencies") or {})}
    listed = {_norm(x) for x in _page_lists()[1]}
    missing = sorted(declared - listed)
    assert not missing, (
        "這些前端相依有宣告但版本頁沒列出來：\n  " + "\n  ".join(missing)
    )
