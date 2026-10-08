"""會改「全站設定」的 e2e spec 都要登記在 frontend/e2e/global-state-specs.txt。

發版用 e2e/run-release.sh：一般的 spec 兩個 worker 平行跑，登記在清單裡的之後單一 worker 依序跑。
漏登記的話，它會跟別的 spec 平行跑、把系統設定改掉，讓同時間的 spec 失敗 —— 失敗訊息看起來像功能壞了
（2026-10-02 發版：主控台引擎被改、admin 的語言被切成日文，各害一支 spec 假失敗）。
只改自己帳號設定的 spec 不該登記，要改用 e2e/helpers/tempAdmin.ts 的臨時帳號。
"""
from __future__ import annotations

import re
from pathlib import Path

E2E = Path(__file__).resolve().parents[2] / "frontend" / "e2e"
LIST = E2E / "global-state-specs.txt"


def _listed() -> set[str]:
    return {ln.strip() for ln in LIST.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")}


def _writes_system_settings(src: str) -> bool:
    # 權限授予（/system/permissions）給的是 spec 自己建的臨時帳號，不算全站設定
    return bool(re.search(r"/api/v1/system/(?!permissions)[a-z-]+", src)
                and re.search(r'"(PUT|PATCH)"|\.(put|patch)\(', src))


def test_specs_that_write_system_settings_are_listed() -> None:
    detected = {p.name for p in E2E.glob("*.spec.ts") if _writes_system_settings(p.read_text(encoding="utf-8"))}
    assert detected, "一支都沒偵測到：偵測規則或目錄路徑壞了"
    missing = sorted(detected - _listed())
    assert not missing, f"這些 spec 會改全站設定，要登記在 e2e/global-state-specs.txt：{missing}"


def test_listed_specs_exist() -> None:
    gone = sorted(n for n in _listed() if not (E2E / n).exists())
    assert not gone, f"清單裡的 spec 不存在（改名或刪掉了）：{gone}"


def test_locale_specs_do_not_touch_the_shared_admin() -> None:
    """切換語言的 spec 要用臨時帳號登入，不可以改共用 admin 的語言。"""
    for name in ("locale-ja.spec.ts", "anomaly-i18n.spec.ts"):
        src = (E2E / name).read_text(encoding="utf-8")
        assert "createTempAdmin" in src, f"{name} 要用 helpers/tempAdmin.ts 的臨時帳號"
