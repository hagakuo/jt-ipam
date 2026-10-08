"""畫面上看得到的錯誤訊息：後端只給代碼與參數，句子由前端翻譯。

為什麼需要這個：`HTTPException(detail="跳板「X」尚未信任主機金鑰")` 這種寫法，
在英文與日文介面上**照樣是中文** —— 伺服器產生的文字沒有辦法跟著使用者的語言走。
實際被使用者回報過（防火牆規則的命中原因）。

做法沿用前端既有的 `localizeDetail`：detail 是物件且帶 `code` 時，前端用
`errors.<code>` 這個 i18n 鍵翻譯，並把 `params` 當插值；沒有對應翻譯時退回
`message`（維持現狀，不會變成空白或 [object Object]）。

    raise HTTPException(400, detail=ui_detail(
        "jump_host_key_unpinned", "跳板「%s」尚未信任主機金鑰" % name, name=name))

**新增代碼時三個語系的 `errors.<code>` 都要補**，`check-i18n` 會擋住少補的情況。
"""
from __future__ import annotations

from typing import Any


def ui_detail(code: str, message: str, **params: Any) -> dict[str, Any]:
    """給 `HTTPException(detail=...)` 用的結構化訊息。

    `message` 是退路，不是主要顯示內容 —— 前端有翻譯就不會用到它。留著是為了
    讓還沒被遷移的呼叫端、以及 curl 直接打 API 的人仍看得到人話。
    """
    return {"code": code, "params": params, "message": message}


class UiError(Exception):
    """訊息會顯示給使用者的例外：除了人話，另外帶代碼與參數。

    各模組原本各自定義例外（`FetchError`／`SftpError`／`RouterOSError`…）並直接寫中文
    句子。讓它們繼承這個類別之後，攔到的地方就能一律用 `ui_detail(exc.code, str(exc),
    **exc.params)` 交給前端翻譯，不必每個 except 分支各寫一次。

    `code=None` 代表還沒遷移 —— 此時前端退回顯示 `message`，行為與過去相同，
    所以可以一個模組一個模組慢慢搬，不必一次到位。
    """

    def __init__(self, message: str, *, code: str | None = None, **params: Any) -> None:
        super().__init__(message)
        self.code = code
        self.params = params


def detail_of(exc: Exception, fallback_code: str) -> dict[str, Any]:
    """把例外轉成給 `HTTPException(detail=...)` 用的結構。

    還沒遷移的例外沒有 `code`，就用呼叫端給的 `fallback_code` —— 至少那一類錯誤
    有一個可以翻譯的代碼，而不是整句中文。

    `reason` 一定會帶上（原本的 `str(exc)`）：`fallback_code` 的翻譯是個外框
    （「pfSense 回報錯誤：{reason}」），句子裡要留得住底層原文。少了它，翻譯會
    **蓋掉**診斷資訊 —— 使用者只看到「回報錯誤」，看不到是 DNS 解不出來還是憑證不對，
    那比原本的中文長句還糟。例外自己帶的 `reason` 優先，不會被覆寫。
    """
    params = dict(getattr(exc, "params", {}) or {})
    params.setdefault("reason", str(exc))
    return ui_detail(getattr(exc, "code", None) or fallback_code, str(exc), **params)
