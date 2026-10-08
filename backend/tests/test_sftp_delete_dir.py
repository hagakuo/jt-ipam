"""刪除資料夾：非空時要講得清楚，要刪整棵樹必須是明示的。

使用者回報「刪除資料夾失敗？」，畫面上只有一行 `失敗：Failure`。原因是
**SFTP v3 沒有「目錄非空」這個狀態碼**：伺服器對 rmdir 一個有內容的目錄只能回
通用的 SSH_FX_FAILURE，asyncssh 就原封不動地變成 `SFTPFailure("Failure")`。
我們的訊息表裡雖然有 SFTPDirNotEmpty，但那個例外在實務上幾乎不會出現。

所以這裡守兩件事：
1. rmdir 失敗時**自己去查原因**（列一下目錄），非空就明講「還有 N 個項目」，
   而不是把伺服器那句沒有意義的話原樣丟給使用者。
2. 遞迴刪除是破壞性操作，必須由呼叫端明示；而且**不可以跟著符號連結走** ——
   跟著走會刪到目錄樹以外的東西，那是資料損毀等級的錯誤。
"""
from __future__ import annotations

import pytest

from app.services.sftp import SftpError, describe_rmdir_failure, walk_for_delete


class _Entry:
    def __init__(self, name: str, *, kind: str = "file"):
        self.filename = name
        self.kind = kind


class _FakeSFTP:
    """夠用的假 SFTP：只支援這幾個測試會用到的操作。"""

    def __init__(self, tree: dict[str, list[_Entry]]):
        self.tree = tree
        self.removed: list[str] = []
        self.rmdired: list[str] = []

    async def readdir(self, path: str):
        if path not in self.tree:
            raise FileNotFoundError(path)
        return self.tree[path]

    async def isdir(self, path: str) -> bool:
        return path in self.tree

    async def islink(self, path: str) -> bool:
        return path.endswith("-link")

    async def remove(self, path: str) -> None:
        self.removed.append(path)

    async def rmdir(self, path: str) -> None:
        self.rmdired.append(path)


@pytest.mark.anyio
async def test_non_empty_directory_is_explained_with_a_count() -> None:
    """非空 → 說出「還有幾個項目」，不要把 'Failure' 原樣丟出去。"""
    sftp = _FakeSFTP({"/data": [_Entry("a.txt"), _Entry("b.txt"), _Entry("sub", kind="dir")]})
    detail, empty = await describe_rmdir_failure(sftp, "/data", Exception("Failure"))
    assert empty is False
    assert detail["params"]["n"] == 3, f"沒把項目數帶給翻譯：{detail}"
    msg = str(detail["message"])
    assert "3" in msg, f"沒說出項目數：{msg}"
    assert "Failure" not in msg, "把伺服器那句沒有意義的話原樣丟給使用者了"


@pytest.mark.anyio
async def test_an_empty_directory_keeps_the_original_reason() -> None:
    """目錄其實是空的 → 失敗另有原因（多半是權限），不能謊稱「不是空的」。"""
    sftp = _FakeSFTP({"/data": []})
    detail, empty = await describe_rmdir_failure(sftp, "/data", Exception("Permission denied"))
    assert empty is True
    msg = str(detail["message"])
    assert "Permission denied" in msg or "權限" in msg


@pytest.mark.anyio
async def test_recursive_walk_is_depth_first_and_deletes_children_before_parents() -> None:
    """先刪內容再刪自己 —— 順序反了每一層都會失敗。"""
    sftp = _FakeSFTP({
        "/d": [_Entry("f1"), _Entry("sub", kind="dir")],
        "/d/sub": [_Entry("f2")],
    })
    plan = await walk_for_delete(sftp, "/d")
    assert plan == [
        ("file", "/d/f1"),
        ("file", "/d/sub/f2"),
        ("dir", "/d/sub"),
        ("dir", "/d"),
    ], plan


@pytest.mark.anyio
async def test_symlinked_directories_are_removed_not_followed() -> None:
    """符號連結只刪連結本身。

    跟著它走會刪到目錄樹外面的東西 —— 使用者以為只是刪一個資料夾，實際上把
    連結指向的正式資料一起刪了。這是資料損毀，不是使用性問題。
    """
    sftp = _FakeSFTP({
        "/d": [_Entry("elsewhere-link", kind="dir")],
        "/d/elsewhere-link": [_Entry("important.db")],
    })
    plan = await walk_for_delete(sftp, "/d")
    assert ("file", "/d/elsewhere-link") in plan, "符號連結應該當成單一項目移除"
    assert all("important.db" not in p for _, p in plan), "跟著符號連結走進去了"


@pytest.mark.anyio
async def test_walk_refuses_beyond_a_sane_limit() -> None:
    """超過上限就停手回報，不要在一條 WebSocket 上跑一個沒有盡頭的刪除。"""
    big = {"/d": [_Entry(f"f{i}") for i in range(20_001)]}
    with pytest.raises(SftpError, match="項目太多"):
        await walk_for_delete(_FakeSFTP(big), "/d")
