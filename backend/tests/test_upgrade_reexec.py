"""`jt-ipam.sh upgrade` 在 git pull 之後必須交棒給新版腳本。

沒有交棒的話：pull 把新程式碼拉下來了，但**接下來的每一步仍由舊腳本執行** ——
備份、alembic、前端 build、systemd unit、nginx 設定全都用舊邏輯。結果就是
「我們修好的安裝／升級問題，客戶要升級兩次才會真的套用」，而第一次升級看起來
完全正常、退出碼 0，沒有任何線索。

（順帶記錄一個查證過但**不成立**的猜測：擔心 git pull 改寫執行中的腳本會讓 bash
讀到錯位內容。實測 80–100KB、pull 位在檔案 95% 位置、新檔更短的情境，bash 都已
把整份讀進緩衝，舊腳本完整跑完。會截斷的是「小檔 + 就地覆寫成更短的內容」，
不是這裡的情況。所以真正的問題只有「後續步驟跑舊邏輯」這一項。）
"""
from __future__ import annotations

import re
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "jt-ipam.sh"


def _upgrade_body() -> str:
    src = SCRIPT.read_text(encoding="utf-8")
    start = src.index("cmd_upgrade() {")
    return src[start:]


def test_it_hands_over_to_the_new_script_after_pulling() -> None:
    body = _upgrade_body()
    assert "JT_IPAM_UPGRADE_REEXEC" in body, (
        "git pull 之後沒有交棒給新版腳本 —— 這次升級會用舊邏輯跑完，"
        "我們對安裝／升級的修正要等到下一次升級才生效"
    )
    m = re.search(r'exec bash "\$ROOT/scripts/jt-ipam\.sh" upgrade --no-pull', body)
    assert m, "交棒時必須帶 --no-pull（剛剛已經 pull 過，不要再拉一次）"


def test_the_hand_over_cannot_loop() -> None:
    """交棒必須只做一次 —— 少了這道防護就是無限重啟自己。"""
    body = _upgrade_body()
    assert re.search(r'\$\{JT_IPAM_UPGRADE_REEXEC:-0\}"?\s*!=\s*"?1', body), \
        "沒有檢查旗標，會一直交棒給自己"
    assert "export JT_IPAM_UPGRADE_REEXEC=1" in body, "交棒前沒有設旗標，子行程會再交棒一次"


def test_it_only_hands_over_when_the_revision_actually_changed() -> None:
    """已經是最新版就不必重跑一輪 —— 沒必要，也會讓輸出看起來像跑了兩次。"""
    body = _upgrade_body()
    assert '"$OLD_REV" != "$NEW_REV"' in body, "沒有比對 commit，就算沒更新也會重跑"
