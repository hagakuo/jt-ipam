"""外部帳號（LDAP / OIDC / SAML）的管理員身分，只有在設定過群組對應時才由目錄決定。

客戶回報（2026-09-01）：「新增一個 LDAP USER，透過 local admin 把管理員權限開啟，
重新用 LDAP user 登入發現這個權限會被自動關閉。」

原因是三支登入流程都無條件執行 `user.is_admin = any(g in cfg.admin_groups for g in groups)`，
而 `admin_groups` **預設是空清單** —— 空清單的 `any(...)` 恆為 False，於是每次登入都把
管理員關掉。任何外部帳號因此永遠當不了管理員，而介面上那個開關看起來是可以按的。

那是**從「沒有設定」推出「不是管理員」**。沒有設定群組對應時，這個系統對「誰該是管理員」
一無所知，正確的作法是不要動它，把決定權留給本機管理。有設定時目錄才是唯一真相 ——
那正是設定它的用意。
"""

from __future__ import annotations

import inspect

from app.services import auth as auth_svc
from app.services import oidc, saml


def _guarded(src: str) -> bool:
    """`is_admin` 的每一處覆寫都必須被「有設定 admin_groups」的條件包住。

    只比對「條件裡出現 admin_groups」而不是特定寫法 —— 條件本身還會長大
    （例如後來加上「不可以把最後一個管理員降權」），測試不該綁死在句型上。
    """
    idx = [i for i in range(len(src)) if src.startswith("user.is_admin = ", i)]
    if not idx:
        return False
    return all("admin_groups" in src[max(0, i - 500):i] for i in idx)


def test_ldap_login_does_not_demote_when_no_mapping_is_configured():
    assert _guarded(inspect.getsource(auth_svc)), (
        "LDAP 登入無條件覆寫 is_admin —— 沒設定群組對應時會把本機開的管理員關掉"
    )


def test_oidc_login_does_not_demote_when_no_mapping_is_configured():
    assert _guarded(inspect.getsource(oidc)), "OIDC 登入無條件覆寫 is_admin"


def test_saml_login_does_not_demote_when_no_mapping_is_configured():
    assert _guarded(inspect.getsource(saml)), "SAML 登入無條件覆寫 is_admin"


def test_directory_still_wins_when_mapping_is_configured():
    """有設定群組對應時，目錄仍然是唯一真相 —— 這條不能因為上面的修正而消失。"""
    for mod in (auth_svc, oidc, saml):
        src = inspect.getsource(mod)
        assert "user.is_admin = " in src, (
            f"{mod.__name__} 完全不再依目錄設定管理員了 —— 群組對應會變成沒有作用"
        )
