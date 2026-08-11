"""SFTP 的純邏輯：路徑正規化、上限、目錄項目的呈現。

**與連線無關的部分都放在這裡**，這樣不必架一台 SSH 伺服器就測得到上限與路徑處理 ——
而那兩件事正是最容易出錯、也最需要被守住的。

安全性立場：路徑一律原樣交給遠端，**不在這一端做沙箱**。使用者能連 SSH 就能在 shell 裡
`cat` 任何檔案，SFTP 不會多給任何權限；真正的授權邊界在遠端主機自己。這一端要做的是
不要因為自作聰明的路徑拼接而讓人存取到「他以為不是那個」的檔案。
"""

from __future__ import annotations

import posixpath
import stat as statmod
from dataclasses import dataclass
from typing import Any

# 單一檔案的上下傳上限。IPAM 的用途是設定檔、憑證、log 片段，不是搬映像檔；
# 沒有上限的話一個 20 GB 的檔案會把瀏覽器記憶體與後端一起拖垮。
MAX_FILE_BYTES = 100 * 1024 * 1024

# 一次列出的目錄項目上限。/proc 或幾十萬個檔案的目錄不該讓畫面與連線一起卡住。
MAX_ENTRIES = 2000

# 每個 chunk 的大小；太小會讓大檔的 frame 數爆掉，太大則單一 frame 佔太多記憶體
CHUNK_BYTES = 256 * 1024


class SftpError(Exception):
    """可以直接顯示給使用者看的錯誤。"""


def normalize_path(path: str | None, *, cwd: str = "/") -> str:
    """把使用者給的路徑正規化成絕對的 POSIX 路徑。

    相對路徑以 `cwd` 為基準；`..` 交給 `normpath` 收斂。**不做沙箱**（見模組說明），
    但要確保送出去的是一條明確、沒有 `..` 殘留的路徑 —— 使用者看到的路徑就是實際
    操作的路徑，兩者不一致才是真正危險的地方。
    """
    p = (path or "").strip()
    if not p:
        p = cwd or "/"
    if not p.startswith("/"):
        p = posixpath.join(cwd or "/", p)
    out = posixpath.normpath(p)
    # normpath 會把 "/.." 收成 "/"，但保險起見再確認一次
    return out if out.startswith("/") else "/"


def check_size(size: int | None, *, what: str) -> int:
    """檔案大小檢查。`None`＝遠端沒回報大小，視為未知並拒絕（寧可不傳）。"""
    if size is None:
        raise SftpError(f"{what}：遠端沒有回報檔案大小，無法確認是否超過上限")
    if size < 0:
        raise SftpError(f"{what}：檔案大小異常")
    if size > MAX_FILE_BYTES:
        mb = MAX_FILE_BYTES // (1024 * 1024)
        raise SftpError(f"{what}：檔案超過 {mb} MB 上限（這個功能是給設定檔與紀錄用的）")
    return size


@dataclass
class Entry:
    name: str
    path: str
    is_dir: bool
    is_link: bool
    size: int | None
    mtime: int | None
    mode: str | None


def _mode_str(mode: int | None) -> str | None:
    if mode is None:
        return None
    try:
        return statmod.filemode(mode)
    except (TypeError, ValueError):
        return None


def to_entry(dirpath: str, name: str, attrs: Any) -> Entry:
    """把 asyncssh 的 SFTPAttrs 轉成前端要的形狀。

    屬性可能缺（有些伺服器的 readdir 不回 size/mtime）—— 缺就是 None，不要猜成 0：
    `0 bytes` 與「不知道多大」在畫面上是兩件事。
    """
    perms = getattr(attrs, "permissions", None)
    is_dir = bool(perms is not None and statmod.S_ISDIR(perms))
    is_link = bool(perms is not None and statmod.S_ISLNK(perms))
    return Entry(
        name=name,
        path=posixpath.join(dirpath, name),
        is_dir=is_dir,
        is_link=is_link,
        size=getattr(attrs, "size", None),
        mtime=getattr(attrs, "mtime", None),
        mode=_mode_str(perms),
    )


def sort_entries(entries: list[Entry]) -> list[Entry]:
    """目錄在前、再依名稱（不分大小寫）—— 與一般檔案管理員一致。"""
    return sorted(entries, key=lambda e: (not e.is_dir, e.name.lower()))


# 遠端拒絕時 asyncssh 丟出的例外，類別名稱對使用者毫無意義（「SFTPNoSuchFile:
# No such file」看不出是哪條路徑、也不知道下一步該做什麼）。這裡把最常見的幾種
# 換成看得懂的句子，並且**一定把路徑講出來** —— 打錯路徑時那才是唯一有用的資訊。
_FRIENDLY: dict[str, str] = {
    "SFTPNoSuchFile": "找不到「{path}」，請確認路徑是否正確。",
    "SFTPNoSuchPath": "找不到「{path}」，請確認路徑是否正確。",
    "FileNotFoundError": "找不到「{path}」，請確認路徑是否正確。",
    "SFTPPermissionDenied": "沒有權限存取「{path}」（遠端主機以這個帳號拒絕了）。",
    "PermissionError": "沒有權限存取「{path}」（遠端主機以這個帳號拒絕了）。",
    "SFTPNotADirectory": "「{path}」不是資料夾。",
    "NotADirectoryError": "「{path}」不是資料夾。",
    "SFTPIsADirectory": "「{path}」是資料夾，不能當成檔案處理。",
    "IsADirectoryError": "「{path}」是資料夾，不能當成檔案處理。",
    "SFTPFileAlreadyExists": "「{path}」已經存在。",
    "FileExistsError": "「{path}」已經存在。",
    "SFTPDirNotEmpty": "資料夾「{path}」還有東西，請先清空再刪除。",
    "SFTPNoSpaceOnFilesystem": "遠端磁碟空間不足，寫不進「{path}」。",
    "SFTPQuotaExceeded": "已超過遠端的容量配額，寫不進「{path}」。",
    "SFTPWriteProtect": "遠端檔案系統是唯讀的，寫不進「{path}」。",
}


def friendly_error(exc: BaseException, *, path: str | None = None) -> str:
    """把遠端的錯誤換成使用者看得懂的句子。

    對不認得的例外**不要編故事**：保留原訊息（去掉類別名稱那個前綴），並在知道路徑時
    附上路徑。寧可訊息平淡，也不要把一個沒見過的失敗說成別的東西。
    """
    shown = path or "(未指定路徑)"
    tmpl = _FRIENDLY.get(type(exc).__name__)
    if tmpl:
        return tmpl.format(path=shown)
    detail = str(exc).strip()
    if not detail:
        return f"操作「{shown}」失敗（{type(exc).__name__}）。"
    if path:
        return f"操作「{shown}」失敗：{detail}"
    return f"操作失敗：{detail}"


# 連線階段的失敗（還沒進到檔案操作），訊息要說得出「連不上哪裡、下一步查什麼」。
# 原本直接回 "ConnectionRefusedError: [Errno 111] Connection refused"。
_CONNECT_FRIENDLY: dict[str, str] = {
    "ConnectionRefusedError": "連不上 {target}：對方拒絕連線 —— 確認該主機的 SSH 服務有在這個連接埠監聽。",
    "TimeoutError": "連線到 {target} 逾時 —— 確認網路可達，以及防火牆是否擋住這個連接埠。",
    "ConnectionResetError": "與 {target} 的連線被重設 —— 對方可能拒絕了這個來源或這種連線方式。",
    "PermissionDenied": "{target} 拒絕了這組帳密（認證失敗）。",
    "HostKeyNotVerifiable": "{target} 的主機金鑰無法驗證。",
    "OSError": "連不上 {target}。",
}


def friendly_connect_error(exc: BaseException, *, host: str, port: int) -> str:
    """連線階段的錯誤訊息。認不出來的一樣保留原訊息，不要編。"""
    target = f"{host}:{port}"
    tmpl = _CONNECT_FRIENDLY.get(type(exc).__name__)
    if tmpl:
        return tmpl.format(target=target)
    detail = str(exc).strip()
    return f"連不上 {target}：{detail}" if detail else f"連不上 {target}（{type(exc).__name__}）。"
