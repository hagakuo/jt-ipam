"""SFTP 上傳遇到同名檔案、以及中途失敗時，原本的檔案不可以受損（2026-10-04 使用者問「檔案已存在會怎麼處理」）。

以前：`sftp.open(path, "wb")` 一開檔就把同名檔清成 0 位元組再寫，事前不問；上傳中斷時伺服器還會 `remove(path)` ——
同名檔等於整個被刪掉。現在：
- 同名時預設先問（`on_conflict` 沒給＝ask → 回 `sftp_exists`，一個位元組都不動）；`overwrite` 覆蓋、`rename` 兩份都留
- 一律先寫到同目錄的暫存檔，完整寫完才換成正式檔名（覆蓋時沿用原本的權限）；失敗或放棄只刪暫存檔

對一台真的 SFTP 伺服器測（asyncssh 行程內伺服器）：換名、權限、擴充指令有沒有支援，假物件測不出來。
"""
from __future__ import annotations

import os

import pytest

from app.services import sftp as svc
from tests.test_sftp_transfer import _client, sftp_server  # noqa: F401  (fixture)

pytestmark = pytest.mark.anyio


async def _write(sftp, target, data: bytes) -> None:
    async with sftp.open(target.tmp_path, "wb") as fh:
        await fh.write(data)


async def test_an_existing_file_is_not_touched_until_asked(sftp_server) -> None:
    port, root = sftp_server
    (root / "a.iso").write_bytes(b"OLD" * 100)
    conn, sftp = await _client(port)
    try:
        with pytest.raises(svc.SftpError) as exc:
            await svc.begin_upload(sftp, "/a.iso", on_conflict=None)
        assert exc.value.code == "sftp_exists"
        assert exc.value.params["size"] == 300
        assert (root / "a.iso").read_bytes() == b"OLD" * 100
    finally:
        conn.close()


async def test_overwrite_goes_through_a_temp_file_and_keeps_the_mode(sftp_server) -> None:
    port, root = sftp_server
    (root / "a.iso").write_bytes(b"OLD")
    os.chmod(root / "a.iso", 0o640)
    conn, sftp = await _client(port)
    try:
        t = await svc.begin_upload(sftp, "/a.iso", on_conflict="overwrite")
        assert t.final_path == "/a.iso" and t.tmp_path != "/a.iso"
        await _write(sftp, t, b"NEW CONTENT")
        assert (root / "a.iso").read_bytes() == b"OLD"            # 寫完之前原檔完好
        await svc.finish_upload(sftp, t)
        assert (root / "a.iso").read_bytes() == b"NEW CONTENT"
        assert (root / "a.iso").stat().st_mode & 0o777 == 0o640   # 沿用原本的權限
        assert [p.name for p in root.iterdir() if "jtipam" in p.name] == []
    finally:
        conn.close()


async def test_an_aborted_upload_leaves_the_original_intact(sftp_server) -> None:
    port, root = sftp_server
    (root / "a.iso").write_bytes(b"OLD")
    conn, sftp = await _client(port)
    try:
        t = await svc.begin_upload(sftp, "/a.iso", on_conflict="overwrite")
        await _write(sftp, t, b"HALF")
        await svc.abort_upload(sftp, t)
        assert (root / "a.iso").read_bytes() == b"OLD"
        assert [p.name for p in root.iterdir() if "jtipam" in p.name] == []
    finally:
        conn.close()


async def test_keep_both_picks_a_free_name(sftp_server) -> None:
    port, root = sftp_server
    (root / "a.iso").write_bytes(b"1")
    (root / "a (1).iso").write_bytes(b"2")
    conn, sftp = await _client(port)
    try:
        t = await svc.begin_upload(sftp, "/a.iso", on_conflict="rename")
        assert t.final_path == "/a (2).iso"
        await _write(sftp, t, b"3")
        await svc.finish_upload(sftp, t)
        assert (root / "a.iso").read_bytes() == b"1"
        assert (root / "a (2).iso").read_bytes() == b"3"
    finally:
        conn.close()


async def test_a_new_file_also_appears_only_when_complete(sftp_server) -> None:
    port, root = sftp_server
    conn, sftp = await _client(port)
    try:
        t = await svc.begin_upload(sftp, "/new.bin", on_conflict=None)
        await _write(sftp, t, b"x" * 10)
        assert not (root / "new.bin").exists()                    # 傳到一半看不到「完整檔名」的殘檔
        await svc.finish_upload(sftp, t)
        assert (root / "new.bin").read_bytes() == b"x" * 10
    finally:
        conn.close()


async def test_replace_falls_back_when_posix_rename_is_missing(sftp_server, monkeypatch) -> None:
    """有些伺服器沒有 posix-rename 擴充：退回「刪原檔再換名」。"""
    import asyncssh
    port, root = sftp_server
    (root / "a.iso").write_bytes(b"OLD")
    conn, sftp = await _client(port)
    try:
        async def no_posix(*_a, **_k):
            raise asyncssh.SFTPOpUnsupported("posix-rename not supported")
        monkeypatch.setattr(sftp, "posix_rename", no_posix)
        t = await svc.begin_upload(sftp, "/a.iso", on_conflict="overwrite")
        await _write(sftp, t, b"NEW")
        await svc.finish_upload(sftp, t)
        assert (root / "a.iso").read_bytes() == b"NEW"
    finally:
        conn.close()
