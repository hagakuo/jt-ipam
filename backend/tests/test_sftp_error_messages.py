"""遠端拒絕時，訊息要是人看得懂的句子，而且要講出是哪條路徑。

原本畫面上出現的是「SFTPNoSuchFile: No such file」—— 那是例外的類別名稱，對使用者
沒有意義，也沒有說是哪條路徑打錯了（而那正是唯一有用的資訊）。
"""
from __future__ import annotations

from app.services.sftp import friendly_error


def _text(detail: dict) -> str:
    """沒有翻譯時畫面上會出現的那一句（`friendly_error` 回的是 code/params/message）。"""
    return str(detail["message"])


class SFTPNoSuchFile(Exception):
    """名稱與 asyncssh 相同；對照是照類別名稱做的，不必真的連上遠端。"""


class SFTPPermissionDenied(Exception):
    pass


class SFTPDirNotEmpty(Exception):
    pass


class SomethingNobodyMapped(Exception):
    pass


def test_missing_path_says_which_path() -> None:
    detail = friendly_error(SFTPNoSuchFile("No such file"), path="/etc/nope")
    msg = _text(detail)
    # 路徑要同時在退路句與參數裡 —— 翻譯後的句子是用參數組的，只檢查中文那句
    # 會漏掉「英文／日文介面沒有路徑」這種情況
    assert detail["code"] == "sftp_no_such_file"
    assert detail["params"]["path"] == "/etc/nope"
    assert "/etc/nope" in msg
    assert "SFTPNoSuchFile" not in msg          # 類別名稱不該出現在畫面上
    assert "No such file" not in msg            # 原始英文也不該直接露出


def test_permission_denied_says_it_is_the_remote_host() -> None:
    detail = friendly_error(SFTPPermissionDenied(""), path="/root/.ssh")
    assert detail["params"]["path"] == "/root/.ssh"
    msg = _text(detail)
    assert "權限" in msg and "/root/.ssh" in msg


def test_non_empty_directory_says_what_to_do_next() -> None:
    msg = _text(friendly_error(SFTPDirNotEmpty(""), path="/tmp/x"))
    assert "清空" in msg


def test_unknown_errors_keep_their_detail_rather_than_inventing_one() -> None:
    """沒對照過的失敗不要編故事 —— 保留原訊息，只是把類別名稱前綴拿掉。"""
    detail = friendly_error(SomethingNobodyMapped("disk on fire"), path="/a")
    assert detail["params"]["reason"] == "disk on fire"   # 翻譯後的句子也要帶得住原訊息
    msg = _text(detail)
    assert "disk on fire" in msg
    assert "SomethingNobodyMapped" not in msg


def test_unknown_error_without_a_message_still_says_something() -> None:
    """訊息空白時只剩類別名稱可用 —— 那總比一片空白好。"""
    msg = _text(friendly_error(SomethingNobodyMapped(), path="/a"))
    assert "/a" in msg and msg.strip()


def test_no_path_does_not_print_none() -> None:
    msg = _text(friendly_error(SFTPNoSuchFile("x")))
    assert "None" not in msg




def test_connection_refused_names_the_target_and_next_step() -> None:
    from app.services.sftp import friendly_connect_error
    detail = friendly_connect_error(ConnectionRefusedError(111, "Connection refused"),
                                    host="192.0.2.10", port=2222)
    assert detail["params"]["target"] == "192.0.2.10:2222"
    msg = _text(detail)
    assert "192.0.2.10:2222" in msg
    assert "Errno" not in msg and "ConnectionRefusedError" not in msg
    assert "SSH" in msg                      # 要講出下一步查什麼


def test_unknown_connect_error_keeps_its_detail() -> None:
    from app.services.sftp import friendly_connect_error
    detail = friendly_connect_error(RuntimeError("something odd"), host="h", port=22)
    assert detail["params"]["reason"] == "something odd"
    msg = _text(detail)
    assert "something odd" in msg and "h:22" in msg
