"""SFTP 端到端：對一台**真的** SFTP 伺服器上傳、下載、列目錄、刪除。

用 asyncssh 在行程內起一台伺服器（根目錄指到 tmp），所以不必動系統、不必有 sshd，
但走的是完整的 SSH/SFTP 協定 —— 「有沒有真的傳成功」這種事，用假物件測等於沒測。
"""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import asyncssh
import pytest

HOST_KEY = asyncssh.generate_private_key("ssh-rsa")
CLIENT_KEY = asyncssh.generate_private_key("ssh-rsa")


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return False          # 測試伺服器：不要求認證


@pytest.fixture
async def sftp_server(tmp_path: Path):
    """在 127.0.0.1 上起一台 SFTP 伺服器，chroot 到 tmp_path。"""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("你好，世界\n", encoding="utf-8")

    server = await asyncssh.create_server(
        _Server, "127.0.0.1", 0,
        server_host_keys=[HOST_KEY],
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(tmp_path)),
    )
    port = server.sockets[0].getsockname()[1]
    yield port, tmp_path
    server.close()
    await server.wait_closed()


async def _client(port: int):
    conn = await asyncssh.connect(
        "127.0.0.1", port=port, username="tester", known_hosts=None,
        client_keys=[CLIENT_KEY], preferred_auth=("publickey", "none"),
    )
    return conn, await conn.start_sftp_client()


@pytest.mark.anyio
async def test_listing_a_directory_returns_the_files(sftp_server):
    from app.services.sftp import normalize_path, sort_entries, to_entry
    port, _ = sftp_server
    conn, sftp = await _client(port)
    try:
        path = normalize_path("/")
        names = await sftp.readdir(path)
        entries = [to_entry(path, str(a.filename), a.attrs)
                   for a in names if a.filename not in (".", "..")]
        out = {e.name: e for e in sort_entries(entries)}
        assert "readme.txt" in out and "etc" in out
        assert out["etc"].is_dir is True
        assert out["readme.txt"].is_dir is False
        # 大小要真的帶回來 —— 缺了它畫面只能顯示「—」
        assert out["readme.txt"].size and out["readme.txt"].size > 0
    finally:
        sftp.exit(); conn.close()


@pytest.mark.anyio
async def test_a_file_round_trips_with_its_bytes_intact(sftp_server):
    """上傳再下載，內容必須一模一樣 —— 含中文（編碼是這類功能最常壞的地方）。"""
    port, root = sftp_server
    conn, sftp = await _client(port)
    payload = ("設定檔內容\n" * 500).encode("utf-8")
    try:
        async with sftp.open("/uploaded.conf", "wb") as fh:
            await fh.write(payload)
        assert (root / "uploaded.conf").read_bytes() == payload

        async with sftp.open("/uploaded.conf", "rb") as fh:
            got = await fh.read()
        assert got == payload
    finally:
        sftp.exit(); conn.close()


@pytest.mark.anyio
async def test_chunked_transfer_reassembles_correctly(sftp_server):
    """分塊傳輸：位元組數與內容都要對得起來（少一塊不會有錯誤訊息，只會檔案壞掉）。"""
    from app.services.sftp import CHUNK_BYTES
    port, _ = sftp_server
    conn, sftp = await _client(port)
    payload = bytes(range(256)) * 4096          # 1 MiB，跨多個 chunk
    try:
        async with sftp.open("/big.bin", "wb") as fh:
            await fh.write(payload)
        st = await sftp.stat("/big.bin")
        assert st.size == len(payload)

        chunks = []
        async with sftp.open("/big.bin", "rb") as fh:
            while True:
                d = await fh.read(CHUNK_BYTES)
                if not d:
                    break
                chunks.append(d)
        assert b"".join(chunks) == payload
        assert len(chunks) > 1, "測試資料要大到真的跨多個 chunk 才有意義"
    finally:
        sftp.exit(); conn.close()


@pytest.mark.anyio
async def test_mkdir_rename_and_delete(sftp_server):
    port, root = sftp_server
    conn, sftp = await _client(port)
    try:
        await sftp.mkdir("/newdir")
        assert (root / "newdir").is_dir()
        async with sftp.open("/newdir/a.txt", "wb") as fh:
            await fh.write(b"x")
        await sftp.rename("/newdir/a.txt", "/newdir/b.txt")
        assert (root / "newdir" / "b.txt").exists()
        await sftp.remove("/newdir/b.txt")
        assert not (root / "newdir" / "b.txt").exists()
        await sftp.rmdir("/newdir")
        assert not (root / "newdir").exists()
    finally:
        sftp.exit(); conn.close()


@pytest.mark.anyio
async def test_reading_a_missing_file_raises_rather_than_returning_empty(sftp_server):
    """遠端拒絕是正常情況，要能分辨「沒有這個檔案」與「空檔案」。"""
    port, _ = sftp_server
    conn, sftp = await _client(port)
    try:
        with pytest.raises(asyncssh.SFTPError):
            await sftp.stat("/nope/missing.txt")
    finally:
        sftp.exit(); conn.close()
