"""刪掉使用者或群組時，要一併清掉他們的授權。

`permissions.principal_id` 同時可能指向使用者或群組，所以建不了外鍵 ——
也就是說**沒有人會幫我們清**。不清就會留下孤兒授權：權限頁列得出來、卻對不到任何人，
稽核時看到一列「不知道是誰有這個權限」，只能靠猜。（實機資料庫裡已經有這種列）

另外守一條：登入路徑不可以把**最後一個有效管理員**降權。PATCH 與 DELETE 早就有這道
保護，登入沒有 —— 設了群組對應之後，最後一位管理員只要掉出那個群組，下次登入就鎖死
整個系統，只能到伺服器上跑 CLI 救。
"""

from __future__ import annotations

import inspect

from app.api.v1.endpoints import users as users_ep
from app.services import auth as auth_svc
from app.services import oidc, saml


def test_deleting_a_user_removes_their_permissions():
    src = inspect.getsource(users_ep.delete_user)
    assert "delete(Permission)" in src, "刪使用者沒有清掉他的授權 → 留下孤兒"
    assert 'principal_type == "user"' in src, "刪錯了對象類型"


def test_deleting_a_group_removes_its_permissions():
    src = inspect.getsource(users_ep.delete_group)
    assert "delete(Permission)" in src, "刪群組沒有清掉群組的授權 → 留下孤兒"
    assert 'principal_type == "group"' in src, "刪錯了對象類型"


def test_permission_removal_is_audited():
    """權限被清掉是權限異動，不是刪帳號的附帶效果 —— 稽核要看得到。"""
    for fn in (users_ep.delete_user, users_ep.delete_group):
        assert "permissions_removed" in inspect.getsource(fn), (
            f"{fn.__name__} 的稽核沒有記下清掉幾筆授權"
        )


def test_login_cannot_demote_the_last_admin():
    for mod in (auth_svc, oidc, saml):
        assert "_would_orphan_admins" in inspect.getsource(mod), (
            f"{mod.__name__} 的登入路徑會把最後一個管理員降權 —— 那是不可逆的鎖死"
        )


def test_deleting_an_object_removes_permissions_pointing_at_it():
    """物件被刪掉時，指向它的授權也要清掉 —— `object_id` 同樣沒有外鍵。

    留著不會讓誰多拿到權限（物件不存在，比對永遠不會命中），但那是看不見的垃圾：
    權限頁列得出來卻點不進去，稽核時也解釋不了。
    """
    import importlib

    for mod_name, otype in (
        ("subnets", "subnet"), ("sections", "section"),
        ("customers", "customer"), ("devices", "device"),
    ):
        mod = importlib.import_module(f"app.api.v1.endpoints.{mod_name}")
        src = inspect.getsource(mod)
        assert "purge_permissions_for_object" in src, f"{mod_name} 刪除時沒有清授權"
        assert f'object_type="{otype}"' in src, f"{mod_name} 清錯了物件類型"
