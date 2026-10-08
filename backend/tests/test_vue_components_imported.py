"""模板裡用到的 naive-ui 元件，都必須在同一支 .vue 裡 import。

由來：`<n-checkbox>` 沒 import 時 Vue 不會報錯，它只是把標籤當成未知元素、把插槽內容
原樣印出來 —— 畫面上看到的是一行純文字，「開關不見了」。型別檢查與單元測試都抓不到，
只有真的打開那個畫面才會發現。

這支測試用靜態掃描擋住同一類問題：專案沒有全域註冊 naive-ui，每支 .vue 都是各自 import。
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "frontend" / "src"


def _pascal(tag: str) -> str:
    return "N" + "".join(p.capitalize() for p in tag[2:].split("-"))



def _split_sfc(txt: str) -> tuple[str, str]:
    """把 .vue 切成（所有 <script> 區塊的內容, 其餘部分）。"""
    scripts: list[str] = []
    rest: list[str] = []
    i = 0
    while True:
        start = txt.find("<script", i)
        if start < 0:
            rest.append(txt[i:])
            break
        open_end = txt.find(">", start)
        close = txt.find("</script>", open_end)
        if open_end < 0 or close < 0:
            rest.append(txt[i:])
            break
        rest.append(txt[i:start])
        scripts.append(txt[open_end + 1:close])
        i = close + len("</script>")
    return "\n".join(scripts), "".join(rest)


def test_every_naive_tag_used_in_a_template_is_imported() -> None:
    missing: list[str] = []
    files = sorted(SRC.rglob("*.vue"))
    assert files, "找不到任何 .vue，掃描路徑可能錯了"
    for f in files:
        txt = f.read_text(encoding="utf-8")
        # 不要用 <template>…</template> 去框範圍：SFC 裡到處是巢狀的 <template #slot>，
        # 非貪婪比對會停在第一個 </template>，結果只掃到開頭一小段（這支測試第一版就是
        # 這樣，明明把 n-switch 換回 n-checkbox 也照樣綠燈）。改成「把 script 挖掉，
        # 其餘都算模板」。用字串搜尋切，不用正規表示式（那種寫法會被當成 HTML 過濾而被掃描工具標出）
        script, template = _split_sfc(txt)
        for tag in sorted(set(re.findall(r"<(n-[a-z0-9-]+)", template))):
            name = _pascal(tag)
            if not re.search(rf"\b{name}\b", script):
                missing.append(f"{f.relative_to(SRC)}: <{tag}> 沒有 import {name}")
    assert not missing, "模板用到但沒 import 的 naive-ui 元件：\n" + "\n".join(missing)
