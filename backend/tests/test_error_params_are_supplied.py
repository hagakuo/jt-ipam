"""帶插值參數的錯誤翻譯，送出時一定要附上那些參數。

前端的規則是「有 `errors.<code>` 的翻譯就用翻譯，沒有才退回 message」。所以一個
帶 `{reason}` 的翻譯若沒收到 `reason`，整段診斷就被翻譯**蓋掉**，畫面上只剩一個冒號 ——
比完全不翻譯還糟，因為錯誤看起來像是空的。

2026-09-17 正式環境上真的發生：RDP 引擎連不上，畫面只顯示「RDP 引擎無法建立連線：」。
"""

from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend" / "app"
LOCALES = ROOT / "frontend" / "src" / "i18n"

#: 後端送錯誤的兩種寫法。`detail_of()` 一定會補 `reason`，所以它一律安全；
#: 直接寫 `ui_detail(...)` 或手組 `{"code": ..., "message": ...}` 才需要檢查。
_SEND_CODE = re.compile(r'"code":\s*"([a-z0-9_]+)"')


def _zh_messages() -> dict[str, str]:
    d = json.loads((LOCALES / "zh-TW.json").read_text())
    return {k: v for k, v in d.get("errors", {}).items() if isinstance(v, str)}


def test_codes_sent_with_a_literal_dict_have_no_unfilled_placeholders():
    """手組 `{"code": ..., "message": ...}` 的地方，對應翻譯不可以需要參數。

    那種寫法沒有帶 params 的欄位，所以只要翻譯裡有 `{...}`，使用者就會看到空洞。
    要帶參數請改用 `ui_detail()` 或 `detail_of()`。
    """
    msgs = _zh_messages()
    offenders: list[str] = []
    for path in BACKEND.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for code in set(_SEND_CODE.findall(text)):
            tpl = msgs.get(code)
            if tpl and re.search(r"\{[a-z_]+\}", tpl):
                offenders.append(f"{path.relative_to(ROOT)} → errors.{code} = {tpl!r}")
    assert not offenders, (
        "這些錯誤碼的翻譯需要參數，但送出的地方是手組的字典（帶不了參數），"
        "使用者會看到空洞：\n  " + "\n  ".join(sorted(offenders))
        + "\n改用 ui_detail(code, message, **params) 或 detail_of(exc, code)。"
    )


def test_detail_of_always_supplies_reason():
    """`detail_of` 是「翻譯需要 reason」時唯一保證安全的出口。"""
    from app.core.ui_error import detail_of

    d = detail_of(ValueError("底層原文"), "console_engine_failed")
    assert d["code"] == "console_engine_failed"
    assert d["params"]["reason"] == "底層原文"


def test_the_rdp_engine_error_carries_its_reason():
    """釘住實際出過事的那一個。"""
    msgs = _zh_messages()
    assert "{reason}" in msgs["console_engine_failed"]
    src = (BACKEND / "api" / "v1" / "endpoints" / "rdp_console.py").read_text()
    assert 'detail_of(err, "console_engine_failed")' in src, \
        "RDP 引擎的錯誤沒有走 detail_of，reason 會是空的"
