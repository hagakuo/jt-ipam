"""SFTP 的路徑處理與上限。

這一層刻意與連線無關，所以不必架 SSH 伺服器就測得到 —— 而路徑與上限正是最容易出錯、
出錯後果也最重的兩件事：路徑顯示與實際操作不一致，使用者會刪錯檔案。
"""
from __future__ import annotations

import pytest
from app.services.sftp import (
    MAX_FILE_BYTES,
    Entry,
    SftpError,
    check_size,
    normalize_path,
    sort_entries,
)


def test_relative_paths_resolve_against_the_current_directory():
    assert normalize_path("etc", cwd="/opt") == "/opt/etc"
    assert normalize_path("./x", cwd="/opt") == "/opt/x"


def test_dotdot_is_collapsed_so_what_you_see_is_what_you_operate_on():
    """畫面顯示的路徑必須就是實際操作的路徑 —— 殘留的 `..` 會讓兩者不一致。"""
    assert normalize_path("../x", cwd="/opt/app") == "/opt/x"
    assert normalize_path("/a/b/../../c") == "/c"
    assert ".." not in normalize_path("/a/../../../b")


def test_escaping_above_root_lands_on_root_not_somewhere_surprising():
    assert normalize_path("/..") == "/"
    assert normalize_path("../../..", cwd="/") == "/"


def test_blank_path_means_the_current_directory():
    assert normalize_path("", cwd="/var/log") == "/var/log"
    assert normalize_path(None, cwd="/var/log") == "/var/log"


def test_an_oversize_file_is_refused_with_a_reason():
    with pytest.raises(SftpError) as e:
        check_size(MAX_FILE_BYTES + 1, what="下載")
    assert "上限" in str(e.value)


def test_an_unknown_size_is_refused_rather_than_guessed():
    """遠端沒回報大小時，不能當成 0 就開始傳 —— 那正是上限形同虛設的漏洞。"""
    with pytest.raises(SftpError):
        check_size(None, what="下載")


def test_a_file_at_exactly_the_limit_is_allowed():
    assert check_size(MAX_FILE_BYTES, what="上傳") == MAX_FILE_BYTES


def test_directories_sort_before_files_and_case_insensitively():
    def e(name: str, is_dir: bool) -> Entry:
        return Entry(name=name, path="/" + name, is_dir=is_dir, is_link=False,
                     size=None, mtime=None, mode=None)
    out = sort_entries([e("beta.txt", False), e("Alpha", True), e("alpha.txt", False),
                        e("zeta", True)])
    assert [x.name for x in out] == ["Alpha", "zeta", "alpha.txt", "beta.txt"]
