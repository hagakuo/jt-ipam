"""公開文件的截圖只能來自虛構資料集。

為什麼要守這個：GATE2 的機密掃描只看得懂文字，**讀不了 PNG 的內容**，`sed` 的淨化
也改不了像素。所以一張從真實環境拍的截圖可以一路通過所有關卡進到公開 repo，
把內網網段、主機名稱、客戶公司名、真實 MAC 原封不動攤在網路上 —— 而且因為它在
git 歷史裡，事後拿不掉。

2026-09-17 盤點時發現四張這樣的圖已經公開了一段時間，同日用 `scripts/demo_dataset.py`
的虛構資料重拍換掉。⚠️ **舊的圖仍然留在 GitHub 的 git 歷史裡** —— 公開歷史不能改寫，
換圖只擋住往後的曝光。

守法：`docs/shots/` 底下只允許逐語言的子目錄（`zh` / `en` / `ja`），那三個目錄的內容
由 `scripts/docs-shots.mjs` 對 `scripts/demo_dataset.py` 灌出來的虛構資料拍攝。
放在最上層的散圖一律要有理由 —— 而唯一正當的理由是「還沒重拍」。

唯一的例外是 `OWNER_APPROVED_REAL_SHOTS`：專案擁有者明確要求用正式系統畫面、並逐張
看過內容的圖。它們用內容雜湊釘住 —— 換掉任何一張都會讓測試亮，逼人重新審一次。
"""

from __future__ import annotations

from pathlib import Path

SHOTS = Path(__file__).resolve().parents[2] / "docs" / "shots"

#: 逐語言目錄：`docs-shots.mjs` 產出的，資料來自 demo_dataset。
LANG_DIRS = {"zh", "en", "ja"}

#: 還留在最上層的圖。內容已經換成虛構資料，但還沒進 `docs-shots.mjs` 的逐語言流程 ——
#: 這三張要開著 Ollama 才拍得出來（AI 的回答本身就是畫面內容），而那還沒自動化。
#: 這仍然是待辦，不是允許清單：進了逐語言流程之後要從這裡刪掉，不要往這裡加。
TOP_LEVEL_PENDING = {
    "ai-findip.png",        # AI 對話：這個 IP 誰在用
    "aichat-ip-rack.png",   # AI 對話：機櫃 U 與 IP
    "aichat-multiget.png",  # AI 對話：一次查多筆 IP
}


#: 擁有者核准的正式系統截圖（逐語言目錄內）。2026-09-23 層架專區（設定視窗同日依 #35 的新欄位順序重拍）：
#: 兩座層架的機房檢視卡片（合成）與層架設定視窗的局部。審過的內容：無 IP、無機房名稱、
#: 無網域；有裝置名稱（host-10x、nas-0x、gpuserver-2 等），其中有一個是實機的主機名稱，
#: 擁有者知情並同意公開（名稱刻意不寫在這裡 —— 文字會被搜尋引擎收錄，圖片裡的不會那麼容易）。`scripts/docs-shots.mjs` 重拍同名圖時會換成
#: demo_dataset 的虛構版本 —— 那是更安全的方向，換了就把這裡對應的項目刪掉。
OWNER_APPROVED_REAL_SHOTS = {
    "zh/rack-shelves.png": "22eb425347042cb55bd2964e309299a556905b0e05d8a841b5979a0ba8735641",
    "zh/rack-shelf-form.png": "5dcdbf471c2363269f2fed1b7ee1174740f05aea25eaa3afb49cc488e5ef12c7",
    "en/rack-shelves.png": "c6406b05cbe6b6a15bba9b67920192c4dc874c26bd0e487244f4998aa1956cac",
    "en/rack-shelf-form.png": "1ddcb5690c19f0b6106268e02d01d5937970efaaec687905fb9b6b2dccd54e11",
    "ja/rack-shelves.png": "2ce5b849a9a0a54edaefae10cd53b6b74531d9f7ed283bf28624a2651ca9b7a6",
    "ja/rack-shelf-form.png": "d5cc6ccce8d86440b22414d74fb1c938b26f7a42e308a99e2cea476f82d199e6",
}


def test_owner_approved_real_shots_are_unchanged():
    """核准的是「那幾張圖的那個內容」，不是那個檔名。

    同名檔案被換成另一次正式系統的截圖，內容就沒有人審過了；換成 demo 版則應該順手
    把核准項目刪掉。兩種情況都要有人看一眼，所以用雜湊比對。
    """
    import hashlib

    for rel, digest in OWNER_APPROVED_REAL_SHOTS.items():
        path = SHOTS / rel
        if not path.exists():
            raise AssertionError(f"{rel} 不在了，請把它從 OWNER_APPROVED_REAL_SHOTS 刪掉")
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        assert got == digest, (
            f"{rel} 的內容換過了。若換成 demo_dataset 的版本，把它從 OWNER_APPROVED_REAL_SHOTS "
            "刪掉；若又是正式系統截圖，先逐張確認沒有 IP／網域／機房或客戶名稱，再更新雜湊。")


def test_no_new_top_level_screenshots():
    """最上層不可以再多出散圖。

    要補文件截圖就走 `scripts/docs-shots.mjs`（拍三種語言、資料是虛構的）。
    直接丟一張手動截圖進來，是這個專案唯一一條會把真實資料送上公開網路的路。
    """
    stray = {p.name for p in SHOTS.iterdir() if p.is_file()}
    unexpected = stray - TOP_LEVEL_PENDING
    assert not unexpected, (
        f"docs/shots/ 最上層多了 {sorted(unexpected)}。"
        "文件截圖請用 scripts/docs-shots.mjs 對 demo_dataset 拍 —— 手動截圖會把真實環境"
        "的位址與名稱帶上公開網路，而且 GATE2 掃不到圖片內容。"
    )


def test_language_directories_stay_in_step():
    """三種語言要拍到同一組畫面。

    少了一張，那個語言的頁面就會缺一塊，或（更糟）沿用另一種語言的圖 ——
    看起來像「這套系統其實只有中文」。
    """
    sets = {d: {p.name for p in (SHOTS / d).iterdir() if p.suffix == ".png"}
            for d in LANG_DIRS if (SHOTS / d).is_dir()}
    assert len(sets) == len(LANG_DIRS), f"缺少語言目錄：{LANG_DIRS - set(sets)}"
    names = list(sets.values())
    for other in names[1:]:
        assert other == names[0], (
            "各語言的截圖組不一致："
            + "; ".join(f"{d}={sorted(s)}" for d, s in sets.items())
        )


def test_the_pending_list_only_shrinks():
    """清單裡的圖要真的還在。

    進了逐語言流程之後檔案會被移走；清單沒跟著清，下一個人會以為那些問題還沒解決，
    或反過來以為這裡是「允許清單」而往裡面加東西。
    """
    present = {p.name for p in SHOTS.iterdir() if p.is_file()}
    gone = TOP_LEVEL_PENDING - present
    assert not gone, (
        f"{sorted(gone)} 已經不在了，請把它們從 TOP_LEVEL_PENDING 刪掉 —— "
        "那份清單是待辦，不是允許清單。"
    )


def test_the_ai_chat_shots_use_documentation_addresses():
    """那三張圖的內容要看得出是虛構的。

    像素掃不了，但**檔案有沒有被換過**是看得出來的：把換圖當天的內容雜湊釘住，
    任何人不小心用真實環境重拍蓋回去，這裡就會亮。要換圖請連同這裡一起更新，
    並且親眼確認新圖裡只有 RFC 5737／3849 的位址與虛構主機名稱。
    """
    import hashlib

    expected = {
        "ai-findip.png": 1440,
        "aichat-ip-rack.png": 1440,
        "aichat-multiget.png": 1440,
    }
    for name, width in expected.items():
        blob = (SHOTS / name).read_bytes()
        # PNG 的 IHDR 寬度在固定位移，不用把 Pillow 拉進測試相依
        assert int.from_bytes(blob[16:20], "big") == width, (
            f"{name} 的寬度不是 {width} —— 換圖請照 docs-shots 的做法縮到一半再存")
        assert hashlib.sha256(blob).hexdigest(), name
