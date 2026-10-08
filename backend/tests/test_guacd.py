"""guacd 轉接（app/services/guacd.py）：協定、握手、錯誤、允許清單、保活。

用一個假的 guacd（asyncio 伺服器）代替真的；真的 guacd 由 e2e 與 scripts/guacd/verify.sh 驗。
"""
from __future__ import annotations

import asyncio
import contextlib

import pytest
from app.services import guacd as guac
from app.services.guacd import Parser, encode

# ───────────── 協定編解碼 ─────────────

def test_encode_counts_characters_not_bytes() -> None:
    assert encode("key", "中文", 1) == "3.key,2.中文,1.1;"


def test_parser_handles_any_split_and_delimiters_inside_values() -> None:
    stream = (encode("img", "1", "14", "0", "image/png", "0", "0") + encode("blob", "1", "a;b,c.d")
              + encode("sync", "42"))
    for step in (1, 2, 3, 7, 50):
        p = Parser()
        got: list[list[str]] = []
        for i in range(0, len(stream), step):
            got += p.feed(stream[i:i + step])
        assert got == [["img", "1", "14", "0", "image/png", "0", "0"], ["blob", "1", "a;b,c.d"], ["sync", "42"]]


@pytest.mark.parametrize("bad", ["x.key;", "3.key!", "-1.a;"])
def test_parser_rejects_malformed(bad: str) -> None:
    with pytest.raises(ValueError):
        Parser().feed(bad)


def test_parser_refuses_absurd_lengths() -> None:
    with pytest.raises(ValueError):
        Parser().feed(f"{(1 << 20) + 1}.x")


def test_helpers() -> None:
    assert guac.known_hosts_line("127.0.0.1", 40022, "ssh-ed25519 AAAA comment") == "[127.0.0.1]:40022 ssh-ed25519 AAAA"
    assert guac.known_hosts_line("192.0.2.5", 22, "ssh-rsa BBBB") == "192.0.2.5 ssh-rsa BBBB"
    assert guac.client_timezone("Asia/Taipei") == "Asia/Taipei"
    assert guac.client_timezone("Etc/GMT+8") == "Etc/GMT+8"
    for bad in ("a;b", "../x", "x" * 80, 5, None):
        assert guac.client_timezone(bad) is None
    assert guac.client_dpi("abc") == 96 and guac.client_dpi(10) == 72 and guac.client_dpi(9999) == 384
    assert guac.initial_size(encode("size", "0", "1280", "720") + encode("sync", "1")) == (1280, 720)
    assert guac.initial_size(encode("size", "3", "10", "10")) is None


# ───────────── 假 guacd ─────────────

ARGS = ["VERSION_1_5_0", "hostname", "port", "username", "password", "ignore-cert"]


class FakeGuacd:
    """記下收到的每一條指令；connect 之後照 `script` 送出指令。"""

    def __init__(self, script: list[str], *, protocols=("rdp", "vnc", "ssh")) -> None:
        self.script = script
        self.protocols = protocols
        self.received: list[list[str]] = []
        self.server: asyncio.base_events.Server | None = None
        self.port = 0

    async def __aenter__(self) -> FakeGuacd:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self.server is not None
        self.server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.server.wait_closed(), 5)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        p = Parser()
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                for ins in p.feed(data.decode()):
                    self.received.append(ins)
                    if ins[0] == "select":
                        if ins[1] not in self.protocols:
                            writer.close()                 # 真的 guacd：沒有外掛就直接斷線
                            return
                        writer.write(encode("args", *ARGS).encode())
                    elif ins[0] == "connect":
                        writer.write(encode("ready", "$abc").encode())
                        for line in self.script:
                            writer.write(line.encode())
                    await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            return
        finally:
            # 不關掉自己這一端的話，Python 3.12 的 wait_closed() 會一直等這條連線
            writer.close()


async def _open(fake: FakeGuacd) -> guac.GuacdConnection:
    return await guac.GuacdConnection.open("127.0.0.1", fake.port)


async def test_handshake_sends_values_in_the_order_guacd_asked_for() -> None:
    async with FakeGuacd([encode("size", "0", "800", "600"), encode("sync", "7")]) as fake:
        conn = await _open(fake)
        cid = await conn.handshake("rdp", {"hostname": "127.0.0.1", "port": "40001", "username": "u",
                                           "password": "p w", "ignore-cert": "true", "unknown": "x"},
                                   width=800, height=600, dpi=96, timezone="Asia/Taipei")
        assert cid == "$abc"
        initial = await conn.wait_first_frame(5)
        await conn.aclose()
    ops = [i[0] for i in fake.received]
    assert ops[:7] == ["select", "size", "audio", "video", "image", "timezone", "connect"]
    connect = next(i for i in fake.received if i[0] == "connect")
    # 版本回我們支援的；其餘照 args 的順序；沒被問到的參數（unknown）不送
    assert connect[1:] == ["VERSION_1_5_0", "127.0.0.1", "40001", "u", "p w", "true"]
    assert initial.endswith(encode("sync", "7")) and "size" in initial


@pytest.mark.parametrize("status, code", [
    (0x0301, "guacd_unauthorized"), (0x0207, "guacd_upstream_not_found"),
    (0x0202, "guacd_upstream_timeout"), (0x0303, "guacd_forbidden"), (0x9999, "guacd_upstream_error"),
])
async def test_errors_before_the_first_frame_keep_guacds_reason(status: int, code: str) -> None:
    async with FakeGuacd([encode("error", "Authentication failure (invalid credentials?)", str(status))]) as fake:
        conn = await _open(fake)
        await conn.handshake("rdp", {}, width=800, height=600)
        with pytest.raises(guac.GuacdError) as ei:
            await conn.wait_first_frame(5)
        await conn.aclose()
    assert ei.value.code == code
    # 原文要留著：只說「認證失敗」分不出是密碼錯還是 NLA、帳號權限
    assert "invalid credentials" in ei.value.reason
    assert "invalid credentials" in ei.value.ui()["message"]
    assert ei.value.ui()["params"]["reason"] == ei.value.reason


async def test_host_key_mismatch_is_named() -> None:
    async with FakeGuacd([encode("error", "Host key did not match", "519")]) as fake:
        conn = await _open(fake)
        await conn.handshake("ssh", {}, width=800, height=600)
        with pytest.raises(guac.GuacdError) as ei:
            await conn.wait_first_frame(5)
        await conn.aclose()
    assert ei.value.code == "guacd_host_key_mismatch"


async def test_required_means_credentials_were_not_accepted() -> None:
    async with FakeGuacd([encode("required", "username", "password")]) as fake:
        conn = await _open(fake)
        await conn.handshake("rdp", {}, width=800, height=600)
        with pytest.raises(guac.GuacdError) as ei:
            await conn.wait_first_frame(5)
        await conn.aclose()
    assert ei.value.code == "guacd_auth_required"


async def test_first_frame_wait_sends_keepalives(monkeypatch) -> None:
    """登入慢的目標：等第一個畫面時也要送 nop，否則 guacd 先判定我們沒回應。"""
    monkeypatch.setattr(guac, "_KEEPALIVE_SECONDS", 0.2)
    async with FakeGuacd([]) as fake:
        conn = await _open(fake)
        await conn.handshake("rdp", {}, width=800, height=600)
        with pytest.raises(guac.GuacdError) as ei:
            await conn.wait_first_frame(1.0)
        await conn.aclose()
    assert ei.value.code == "guacd_first_frame_timeout"
    assert sum(1 for i in fake.received if i[0] == "nop") >= 2


async def test_unavailable_guacd_is_a_readable_error() -> None:
    with pytest.raises(guac.GuacdError) as ei:
        await guac.GuacdConnection.open("127.0.0.1", 1, timeout=1)
    assert ei.value.code == "guacd_unavailable" and "127.0.0.1:1" in ei.value.reason


async def test_missing_protocol_plugin(monkeypatch) -> None:
    async with FakeGuacd([], protocols=("rdp",)) as fake:
        conn = await _open(fake)
        with pytest.raises(guac.GuacdError) as ei:
            await conn.handshake("ssh", {}, width=800, height=600)
        await conn.aclose()
    assert ei.value.code == "guacd_protocol_missing"


async def test_probe_reports_each_protocol(monkeypatch) -> None:
    async with FakeGuacd([], protocols=("rdp", "vnc")) as fake:
        monkeypatch.setattr(guac, "guacd_address", lambda: ("127.0.0.1", fake.port))
        st = await guac.probe(use_cache=False)
        assert st["ok"] is True and st["protocols"] == {"rdp": True, "vnc": True, "ssh": False}
        await guac.require("rdp")
        with pytest.raises(guac.GuacdError) as ei:
            await guac.require("ssh")
        assert ei.value.code == "guacd_protocol_missing"
    monkeypatch.setattr(guac, "guacd_address", lambda: ("127.0.0.1", 1))
    st = await guac.probe(use_cache=False)
    assert st["ok"] is False and st["error"]


# ───────────── 轉送 ─────────────

class FakeWebSocket:
    def __init__(self, incoming: list[str]) -> None:
        self.incoming: asyncio.Queue[str | None] = asyncio.Queue()
        for m in incoming:
            self.incoming.put_nowait(m)
        self.sent: list[str] = []

    async def send_text(self, text: str) -> None:
        self.sent.append(text)

    async def receive_text(self) -> str:
        m = await self.incoming.get()
        if m is None:
            from fastapi import WebSocketDisconnect
            raise WebSocketDisconnect(1000)
        return m

    def close_from_browser(self) -> None:
        self.incoming.put_nowait(None)


async def test_relay_forwards_allowed_and_drops_the_rest(monkeypatch) -> None:
    monkeypatch.setattr(guac, "_KEEPALIVE_SECONDS", 0.2)
    async with FakeGuacd([encode("sync", "1")]) as fake:
        conn = await _open(fake)
        await conn.handshake("rdp", {}, width=800, height=600)
        initial = await conn.wait_first_frame(5)
        ws = FakeWebSocket([
            encode("key", "65", "1") + encode("key", "65", "0"),
            # 握手已經在伺服器端做完；瀏覽器不可以另外叫 guacd 連別的地方、開檔案傳輸
            encode("connect", "192.0.2.9") + encode("file", "1", "text/plain", "x") + encode("argv", "1", "a", "b"),
            encode("mouse", "10", "20", "1"),
        ])

        async def later() -> None:
            await asyncio.sleep(0.8)
            ws.close_from_browser()

        closer = asyncio.create_task(later())
        res = await guac.relay(ws, conn, initial=initial)
        await closer
        await conn.aclose()
    assert res.ended_by == "client" and res.dropped == 3
    assert ws.sent[0] == initial                         # 等第一個畫面時收到的要先送出去
    after = [i for i in fake.received if i[0] not in ("select", "size", "audio", "video", "image", "connect")]
    ops = [i[0] for i in after]
    assert ops.count("key") == 2 and "mouse" in ops
    assert "file" not in ops and "argv" not in ops
    assert [i for i in fake.received if i[0] == "connect"] == [next(i for i in fake.received if i[0] == "connect")]
    assert not any("192.0.2.9" in i for i in fake.received), "瀏覽器送的 connect 到了 guacd"
    assert ops.count("nop") >= 2, "伺服器端保活沒有送（背景分頁會被 guacd 斷線）"


async def test_relay_ends_when_guacd_closes() -> None:
    async with FakeGuacd([encode("sync", "1")]) as fake:
        conn = await _open(fake)
        await conn.handshake("rdp", {}, width=800, height=600)
        initial = await conn.wait_first_frame(5)
        ws = FakeWebSocket([])
        task = asyncio.create_task(guac.relay(ws, conn, initial=initial))
        await asyncio.sleep(0.2)
        conn.reader.feed_eof()                             # guacd 那端結束（目標登出、網路斷）
        res = await asyncio.wait_for(task, 5)
        await conn.aclose()
    assert res.ended_by == "remote"


def test_every_guacd_error_code_is_translated() -> None:
    """guacd 的錯誤代碼是組出來的（`GuacdError.code`），掃原始碼的守門測試看不到 —— 這裡逐一對。

    翻譯裡要有 {reason}（guacd 講的原文）：少了它，「認證失敗」分不出是密碼錯、NLA 還是帳號權限。
    """
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n"
    codes = set(guac._FALLBACK) | set(guac._STATUS_CODES.values())
    for loc in ("zh-TW", "en-US", "ja-JP"):
        errors = json.loads((root / f"{loc}.json").read_text(encoding="utf-8"))["errors"]
        missing = sorted(c for c in codes if c not in errors)
        assert not missing, f"{loc} 缺翻譯：{missing}"
        for c in codes:
            if "{reason}" in guac._FALLBACK.get(c, "{reason}"):
                assert "{reason}" in errors[c], f"{loc} 的 errors.{c} 沒有帶 {{reason}}"


async def test_self_check_treats_guacd_as_required(db_session, monkeypatch) -> None:
    """guacd 是必要元件（2026-09-27，GitHub issue #42）：連不到一律列成失敗並給修法，
    有協定選了它時要講「目前暫時改用內建引擎」；缺某個協定的外掛也是失敗。"""
    from app.services import self_check
    from app.services.system_config import set_rdp_engine, set_ssh_engine, set_vnc_engine

    state = {"ok": False, "address": "127.0.0.1:4822", "protocols": {}, "error": "connection refused"}

    async def fake_probe(*, use_cache: bool = True):
        return dict(state)
    monkeypatch.setattr(guac, "probe", fake_probe)

    c = await self_check._guacd_check(db_session)                      # 預設：RDP、VNC 用 guacd
    assert c.status == "bad" and c.params["protocols"] == "RDP、VNC"
    assert "內建引擎" in c.detail and "connection refused" in c.detail
    assert "jt-ipam.sh upgrade" in c.fix

    await set_rdp_engine(db_session, engine="aardwolf")
    await set_vnc_engine(db_session, engine="builtin")
    c = await self_check._guacd_check(db_session)                      # 沒人用也是必要元件
    assert c.status == "bad" and c.detail_key == "doctor.d_guacd_down_idle"

    await set_rdp_engine(db_session, engine="guacd")
    await set_ssh_engine(db_session, engine="guacd")
    state.update(ok=True, error="", protocols={"rdp": True, "vnc": True, "ssh": False})
    c = await self_check._guacd_check(db_session)
    assert c.status == "bad" and c.params["protocols"] == "SSH"      # 缺 SSH 外掛

    state["protocols"]["ssh"] = True
    c = await self_check._guacd_check(db_session)
    assert c.status == "ok"


async def test_generic_abort_points_to_the_log() -> None:
    """guacd 只回「Aborted. See logs.」時，原因換成去哪裡看日誌（原樣顯示等於沒說）。"""
    async with FakeGuacd([encode("error", "Aborted. See logs.", str(0x0301))]) as fake:
        conn = await _open(fake)
        await conn.handshake("ssh", {}, width=800, height=600)
        with pytest.raises(guac.GuacdError) as ei:
            await conn.wait_first_frame(5)
        await conn.aclose()
    assert ei.value.code == "guacd_unauthorized"
    assert ei.value.reason == "journalctl -u jt-ipam-guacd"


def test_host_key_algs_follow_the_pinned_type() -> None:
    from app.api.v1.endpoints.ssh_console import _host_key_algs
    assert _host_key_algs("ssh-ed25519 AAAA") == ["ssh-ed25519"]
    assert _host_key_algs("ssh-rsa AAAA") == ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
    assert _host_key_algs("ecdsa-sha2-nistp256 AAAA") == ["ecdsa-sha2-nistp256"]


async def test_pinned_key_check_asks_for_the_pinned_algorithm(monkeypatch) -> None:
    """演算法要用 get_server_host_key 自己的參數傳 —— 塞在 options 裡會被它的預設值蓋掉，
    伺服器照自己的偏好給 RSA，正確的 ed25519 被判成不符（2026-09-25 正式機實測）。"""
    import asyncssh
    from app.api.v1.endpoints import ssh_console

    ed = asyncssh.generate_private_key("ssh-ed25519")
    pinned = ed.export_public_key("openssh").decode("ascii").strip()
    calls: list[dict] = []

    async def fake_get(host, port=22, **kw):
        calls.append(kw)
        algs = kw.get("server_host_key_algs") or []
        return ed if "ssh-ed25519" in algs else asyncssh.generate_private_key("ssh-rsa")
    monkeypatch.setattr(asyncssh, "get_server_host_key", fake_get)

    assert await ssh_console._pinned_key_still_matches("192.0.2.9", 22, pinned) is True
    assert calls[-1]["server_host_key_algs"] == ["ssh-ed25519"]
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode("ascii")
    assert await ssh_console._pinned_key_still_matches("192.0.2.9", 22, other) is False


async def test_vnc_not_found_after_a_good_tcp_check_means_rejected() -> None:
    """guacd 的 VNC 密碼錯也回「連不到」；TCP 已確認連得上時要改說「被拒絕，多半是密碼錯誤」。"""
    e = guac.refine_vnc_error(guac.GuacdError("guacd_upstream_not_found", "journalctl -u jt-ipam-guacd", status=0x0207))
    assert e.code == "guacd_vnc_rejected" and "密碼" in e.ui()["message"]
    other = guac.GuacdError("guacd_upstream_timeout", "x")
    assert guac.refine_vnc_error(other) is other
    async with FakeGuacd([]) as fake:
        assert await guac.tcp_reachable("127.0.0.1", fake.port) is None
    assert await guac.tcp_reachable("127.0.0.1", 1, timeout=1)


def test_vnc_asking_for_a_username_says_to_fill_the_username_field() -> None:
    """帳號欄空著連要帳號的 VNC（VeNCrypt 帳密實測）：guacd 回 required,username,password。"""
    e = guac.refine_vnc_error(guac.GuacdError("guacd_auth_required", "username,password"))
    assert e.code == "guacd_vnc_username_required"
    only_pw = guac.GuacdError("guacd_auth_required", "password")
    assert guac.refine_vnc_error(only_pw) is only_pw


def test_vnc_tcp_check_only_runs_after_guacd_failed() -> None:
    """事前的 TCP 探測會被 TigerVNC 算成一次認證失敗（連上就斷），每次連線都扣額度、幾次就被封鎖
    （2026-09-25 實測）。只能在 guacd 回報連不到之後才試。"""
    from pathlib import Path
    src = (Path(__file__).parents[1] / "app/api/v1/endpoints/vnc_console.py").read_text(encoding="utf-8")
    assert src.count("tcp_reachable(") == 1
    assert src.index('conn.handshake("vnc"') < src.index("tcp_reachable(")
    assert src.index("except guac.GuacdError") < src.index("tcp_reachable(")


# ─────────────────── argv：只放行呼叫端明確允許的參數（SSH 字級），值要驗證 ───────────────────
# 使用者回報：SSH 主控台按 A−／A+ 沒反應。瀏覽器有送 argv，但代理的允許清單把它丟掉了。
# argv 能在連線中改 guacd 允許修改的參數（RDP 甚至包含帳號密碼），所以只能逐一開放。

def _font_ok(v: str) -> bool:
    return v.isdigit() and 6 <= int(v) <= 32


async def _relay_with(messages: list[str], allow) -> tuple[FakeGuacd, guac.RelayResult]:  # noqa: ANN001
    async with FakeGuacd([encode("sync", "1")]) as fake:
        conn = await _open(fake)
        await conn.handshake("ssh", {}, width=800, height=600)
        initial = await conn.wait_first_frame(5)
        ws = FakeWebSocket(messages)

        async def later() -> None:
            await asyncio.sleep(0.6)
            ws.close_from_browser()

        closer = asyncio.create_task(later())
        res = await guac.relay(ws, conn, initial=initial, argv_allow=allow)
        await closer
        await conn.aclose()
    return fake, res


def _argv(stream: str, name: str, value: str) -> str:
    import base64
    return (encode("argv", stream, "text/plain", name)
            + encode("blob", stream, base64.b64encode(value.encode()).decode()) + encode("end", stream))


async def test_relay_passes_an_allowed_argv_with_a_valid_value() -> None:
    fake, res = await _relay_with([_argv("3", "font-size", "14")], {"font-size": _font_ok})
    got = [i for i in fake.received if i[0] in ("argv", "blob", "end")]
    assert got == [["argv", "3", "text/plain", "font-size"], ["blob", "3", "MTQ="], ["end", "3"]]
    assert res.dropped == 0


async def test_relay_drops_argv_that_is_not_allowed_or_invalid() -> None:
    fake, res = await _relay_with(
        [_argv("3", "password", "x"), _argv("4", "font-size", "999"), _argv("5", "font-size", "12;x")],
        {"font-size": _font_ok})
    assert not [i for i in fake.received if i[0] in ("argv", "blob", "end")]
    assert res.dropped >= 3


async def test_relay_without_an_allow_list_still_drops_argv_but_keeps_clipboard() -> None:
    import base64
    clip = (encode("clipboard", "7", "text/plain") + encode("blob", "7", base64.b64encode(b"hi").decode())
            + encode("end", "7"))
    fake, _ = await _relay_with([_argv("3", "font-size", "14"), clip], None)
    ops = [i[0] for i in fake.received]
    assert "argv" not in ops
    assert ["blob", "7", "aGk="] in fake.received      # 剪貼簿的 blob／end 照常轉送
    assert ["end", "7"] in fake.received
