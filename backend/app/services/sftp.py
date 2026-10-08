"""SFTP 的純邏輯：路徑正規化、上限、目錄項目的呈現。

**與連線無關的部分都放在這裡**，這樣不必架一台 SSH 伺服器就測得到上限與路徑處理 ——
而那兩件事正是最容易出錯、也最需要被守住的。

安全性立場：路徑一律原樣交給遠端，**不在這一端做沙箱**。使用者能連 SSH 就能在 shell 裡
`cat` 任何檔案，SFTP 不會多給任何權限；真正的授權邊界在遠端主機自己。這一端要做的是
不要因為自作聰明的路徑拼接而讓人存取到「他以為不是那個」的檔案。
"""

from __future__ import annotations

import contextlib
import posixpath
import stat as statmod
import uuid
from dataclasses import dataclass
from typing import Any

import asyncssh

from app.core.ui_error import UiError, ui_detail

# 單一檔案上下傳上限的**預設值**。實際值由系統設定決定（`get_sftp_max_file_mb`，2026-09-26 起
# 可以改）：IPAM 的本意是設定檔、憑證、log 片段，所以預設小；要搬映像檔由管理者自己放大。
MAX_FILE_BYTES = 100 * 1024 * 1024

# 一次列出的目錄項目上限。原本壓在 2000 是怕畫面一次畫太多列而卡住 —— 前端改成分頁之後
# 那個理由消失了，這裡只剩「不要讓單一訊息大到拖垮連線與記憶體」這一個目的，所以放寬到
# 兩萬。真的有幾十萬個檔案的目錄（/proc、郵件佇列…）仍會截斷，畫面上會明講。
MAX_ENTRIES = 20_000

# 每個 chunk 的大小；太小會讓大檔的 frame 數爆掉，太大則單一 frame 佔太多記憶體
CHUNK_BYTES = 256 * 1024


class SftpError(UiError):
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


#: `what` 是方向（download／upload），不是可以直接顯示的字。代碼把方向寫進去
#: （`sftp_download_size_unknown`），是因為翻譯鍵沒有辦法在句子中間再查一次翻譯 ——
#: 傳一個中文的「下載」當參數，等於英日文介面裡夾一個中文詞。
_WHAT_ZH = {"download": "下載", "upload": "上傳"}


def check_size(size: int | None, *, what: str, max_bytes: int = MAX_FILE_BYTES) -> int:
    """檔案大小檢查。`None`＝遠端沒回報大小，視為未知並拒絕（寧可不傳）。

    `max_bytes` 由呼叫端帶系統設定的值；不給就是預設的 100 MB。
    """
    zh = _WHAT_ZH.get(what, what)
    if size is None:
        raise SftpError(f"{zh}：遠端沒有回報檔案大小，無法確認是否超過上限",
                        code=f"sftp_{what}_size_unknown")
    if size < 0:
        raise SftpError(f"{zh}：檔案大小異常", code=f"sftp_{what}_size_invalid")
    if size > max_bytes:
        mb = max_bytes // (1024 * 1024)
        raise SftpError(f"{zh}：檔案超過 {mb} MB 上限（這個功能是給設定檔與紀錄用的）",
                        code=f"sftp_{what}_too_large", max=mb)
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
#: 例外類別名稱 → (翻譯代碼, 中文退路句)。代碼是給前端翻的，中文那句只在沒有
#: 對應翻譯時才會被顯示。
_FRIENDLY: dict[str, tuple[str, str]] = {
    "SFTPNoSuchFile": ("sftp_no_such_file", "找不到「{path}」，請確認路徑是否正確。"),
    "SFTPNoSuchPath": ("sftp_no_such_file", "找不到「{path}」，請確認路徑是否正確。"),
    "FileNotFoundError": ("sftp_no_such_file", "找不到「{path}」，請確認路徑是否正確。"),
    "SFTPPermissionDenied": ("sftp_permission_denied",
                             "沒有權限存取「{path}」（遠端主機以這個帳號拒絕了）。"),
    "PermissionError": ("sftp_permission_denied",
                        "沒有權限存取「{path}」（遠端主機以這個帳號拒絕了）。"),
    "SFTPNotADirectory": ("sftp_not_a_directory", "「{path}」不是資料夾。"),
    "NotADirectoryError": ("sftp_not_a_directory", "「{path}」不是資料夾。"),
    "SFTPIsADirectory": ("sftp_is_a_directory", "「{path}」是資料夾，不能當成檔案處理。"),
    "IsADirectoryError": ("sftp_is_a_directory", "「{path}」是資料夾，不能當成檔案處理。"),
    "SFTPFileAlreadyExists": ("sftp_already_exists", "「{path}」已經存在。"),
    "FileExistsError": ("sftp_already_exists", "「{path}」已經存在。"),
    "SFTPDirNotEmpty": ("sftp_dir_not_empty", "資料夾「{path}」還有東西，請先清空再刪除。"),
    "SFTPNoSpaceOnFilesystem": ("sftp_no_space", "遠端磁碟空間不足，寫不進「{path}」。"),
    "SFTPQuotaExceeded": ("sftp_quota_exceeded", "已超過遠端的容量配額，寫不進「{path}」。"),
    "SFTPWriteProtect": ("sftp_read_only_fs", "遠端檔案系統是唯讀的，寫不進「{path}」。"),
}


def friendly_error(exc: BaseException, *, path: str | None = None) -> dict[str, Any]:
    """把遠端的錯誤換成使用者看得懂的句子（`{code, params, message}`）。

    回結構而不是現成句子：這些訊息會出現在畫面上，後端組好的中文在英文與日文介面
    翻不動。`message` 是沒有對應翻譯時的退路，內容與過去完全一樣。

    對不認得的例外**不要編故事**：保留原訊息（去掉類別名稱那個前綴），並在知道路徑時
    附上路徑。寧可訊息平淡，也不要把一個沒見過的失敗說成別的東西。
    """
    shown = path or "(未指定路徑)"
    hit = _FRIENDLY.get(type(exc).__name__)
    if hit:
        code, tmpl = hit
        return ui_detail(code, tmpl.format(path=shown), path=shown)
    detail = str(exc).strip()
    if not detail:
        return ui_detail("sftp_op_failed_unknown", f"操作「{shown}」失敗（{type(exc).__name__}）。",
                         path=shown, kind=type(exc).__name__)
    if path:
        return ui_detail("sftp_op_failed_at", f"操作「{shown}」失敗：{detail}",
                         path=shown, reason=detail)
    return ui_detail("sftp_op_failed", f"操作失敗：{detail}", reason=detail)


# 連線階段的失敗（還沒進到檔案操作），訊息要說得出「連不上哪裡、下一步查什麼」。
# 原本直接回 "ConnectionRefusedError: [Errno 111] Connection refused"。
_CONNECT_FRIENDLY: dict[str, tuple[str, str]] = {
    "ConnectionRefusedError": ("sftp_conn_refused",
        "連不上 {target}：對方拒絕連線 —— 確認該主機的 SSH 服務有在這個連接埠監聽。"),
    "TimeoutError": ("sftp_conn_timeout",
        "連線到 {target} 逾時 —— 確認網路可達，以及防火牆是否擋住這個連接埠。"),
    "ConnectionResetError": ("sftp_conn_reset",
        "與 {target} 的連線被重設 —— 對方可能拒絕了這個來源或這種連線方式。"),
    "PermissionDenied": ("sftp_conn_auth_failed", "{target} 拒絕了這組帳密（認證失敗）。"),
    "HostKeyNotVerifiable": ("sftp_conn_host_key", "{target} 的主機金鑰無法驗證。"),
    "OSError": ("sftp_conn_failed", "連不上 {target}。"),
}


def friendly_connect_error(exc: BaseException, *, host: str, port: int) -> dict[str, Any]:
    """連線階段的錯誤訊息。認不出來的一樣保留原訊息，不要編。"""
    target = f"{host}:{port}"
    hit = _CONNECT_FRIENDLY.get(type(exc).__name__)
    if hit:
        code, tmpl = hit
        return ui_detail(code, tmpl.format(target=target), target=target)
    detail = str(exc).strip()
    if detail:
        return ui_detail("sftp_conn_failed_reason", f"連不上 {target}：{detail}",
                         target=target, reason=detail)
    return ui_detail("sftp_conn_failed_kind", f"連不上 {target}（{type(exc).__name__}）。",
                     target=target, kind=type(exc).__name__)


async def describe_rmdir_failure(
    sftp: Any, path: str, exc: BaseException,
) -> tuple[dict[str, Any], bool]:
    """rmdir 失敗時，自己去查原因，回 (訊息, 目錄是否為空)。

    為什麼要自己查：**SFTP v3 沒有「目錄非空」這個狀態碼**。伺服器對「刪一個有內容的
    目錄」只能回通用的 SSH_FX_FAILURE，asyncssh 原封不動變成 `SFTPFailure("Failure")`，
    使用者看到的就是「操作『/某/路徑』失敗：Failure」—— 沒說原因、也沒說下一步。
    （訊息表裡的 SFTPDirNotEmpty 只在少數 v6 伺服器上才會出現。）

    列一次目錄就知道是不是非空；是的話講出項目數，不是的話保留原本的失敗原因
    （多半是權限），不要謊稱「不是空的」。
    """
    try:
        entries = await sftp.readdir(path)
    except Exception:
        # 連列都列不了 → 沒有更多線索，保留原訊息
        return friendly_error(exc, path=path), True

    names = [_entry_name(e) for e in entries]
    names = [n for n in names if n not in (".", "..")]
    if names:
        return ui_detail("sftp_dir_not_empty_count",
                         f"資料夾「{path}」不是空的（還有 {len(names)} 個項目），"
                         f"SFTP 不會刪掉有內容的資料夾。",
                         path=path, n=len(names)), False
    return friendly_error(exc, path=path), True


def _entry_name(entry: Any) -> str:
    return str(getattr(entry, "filename", entry))


async def walk_for_delete(sftp: Any, root: str) -> list[tuple[str, str]]:
    """列出「把 root 整棵刪掉」要依序做的動作：[("file"|"dir", 路徑), ...]。

    兩個刻意的規則：
    - **深度優先、內容先於自己**：順序反了每一層 rmdir 都會失敗。
    - **符號連結只刪連結本身，不跟著走**。跟著走會刪到目錄樹以外的東西 ——
      使用者以為只是刪一個資料夾，結果把連結指向的正式資料一起刪了。
    """
    plan: list[tuple[str, str]] = []
    count = 0

    async def walk(cur: str) -> None:
        nonlocal count
        for entry in await sftp.readdir(cur):
            name = _entry_name(entry)
            if name in (".", ".."):
                continue
            child = f"{cur.rstrip('/')}/{name}"
            count += 1
            if count > MAX_ENTRIES:
                raise SftpError(
                    f"「{root}」底下的項目太多（超過 {MAX_ENTRIES} 個），"
                    "請改用遠端的 shell 刪除。",
                    code="sftp_too_many_entries", path=root, max=MAX_ENTRIES)
            if await sftp.islink(child):
                plan.append(("file", child))      # 只移除連結本身
            elif await sftp.isdir(child):
                await walk(child)
                plan.append(("dir", child))
            else:
                plan.append(("file", child))

    await walk(root)
    plan.append(("dir", root))
    return plan


# ─────────────────── 上傳：同名處理＋暫存檔（2026-10-04）───────────────────
# 以前一開檔就用 "wb" 把同名檔清成 0 位元組、事前不問；上傳中斷時又 remove(path) —— 原本的檔案等於被刪掉。
# 現在一律寫到同目錄的暫存檔，完整寫完才換成正式檔名；失敗或放棄只刪暫存檔，原檔從頭到尾不動。

UPLOAD_TMP_MARK = ".jtipam-upload-"
CONFLICT_CHOICES = ("overwrite", "rename")


@dataclass
class UploadTarget:
    final_path: str
    tmp_path: str
    replaces: bool                  # 正式檔名目前已有檔案（覆蓋）
    mode: int | None = None         # 被覆蓋的檔案原本的權限，換名前套到新檔上


def _split(path: str) -> tuple[str, str]:
    d, _, n = path.rpartition("/")
    return (d or "/"), n


async def _exists(sftp: Any, path: str) -> Any | None:
    try:
        return await sftp.stat(path)
    except asyncssh.SFTPNoSuchFile:
        return None


async def begin_upload(sftp: Any, path: str, *, on_conflict: str | None) -> UploadTarget:
    """決定寫到哪裡。同名時：沒指定＝先問（丟 `sftp_exists`，什麼都不動）、overwrite＝覆蓋、rename＝兩份都留。"""
    choice = on_conflict if on_conflict in CONFLICT_CHOICES else None
    final = path
    st = await _exists(sftp, final)
    if st is not None:
        if choice is None:
            d, n = _split(final)
            raise SftpError(
                f"遠端已有同名檔案：{n}", code="sftp_exists", name=n, path=final,
                size=int(getattr(st, "size", 0) or 0), mtime=getattr(st, "mtime", None))
        if choice == "rename":
            d, n = _split(final)
            stem, dot, ext = n.rpartition(".") if "." in n.lstrip(".") else (n, "", "")
            for i in range(1, 1000):
                cand = f"{d.rstrip('/')}/{stem} ({i}){dot}{ext}"
                if await _exists(sftp, cand) is None:
                    final, st = cand, None
                    break
            else:
                raise SftpError(f"找不到可用的檔名：{n}", code="sftp_exists", name=n, path=path, size=0, mtime=None)
    d, n = _split(final)
    tmp = f"{d.rstrip('/')}/.{n}{UPLOAD_TMP_MARK}{uuid.uuid4().hex[:8]}"
    mode = (getattr(st, "permissions", None) & 0o7777) if st is not None and getattr(st, "permissions", None) else None
    return UploadTarget(final_path=final, tmp_path=tmp, replaces=st is not None, mode=mode)


async def finish_upload(sftp: Any, t: UploadTarget) -> None:
    """暫存檔換成正式檔名。覆蓋時先套原本的權限，再用 posix-rename（一步取代，原檔不會有不見的空窗）；
    伺服器不支援時退回「刪原檔再換名」。"""
    if t.mode is not None:
        with contextlib.suppress(asyncssh.SFTPError):
            await sftp.chmod(t.tmp_path, t.mode)
    if t.replaces:
        try:
            await sftp.posix_rename(t.tmp_path, t.final_path)
            return
        except (asyncssh.SFTPOpUnsupported, asyncssh.SFTPBadMessage):
            await sftp.remove(t.final_path)
    await sftp.rename(t.tmp_path, t.final_path)


async def abort_upload(sftp: Any, t: UploadTarget) -> None:
    """失敗或放棄：只刪暫存檔。"""
    with contextlib.suppress(Exception):
        await sftp.remove(t.tmp_path)
