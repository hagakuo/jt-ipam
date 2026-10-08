"""guacd（Apache Guacamole 的伺服器端）轉接：RDP／VNC／SSH 主控台的另一個引擎。

guacd 是一個獨立的常駐程式（預編檔見 scripts/guacd/，裝在本機 127.0.0.1:4822）。
這個模組只做三件事：

1. **握手**（`GuacdConnection.handshake`）：在伺服器端替瀏覽器跟 guacd 說好要連哪裡、用什麼帳密。
   帳密只在這裡出現，**不會經過瀏覽器**；目標主機也是呼叫端從 IP 記錄算出來的（跟其他引擎一樣防 SSRF）。
2. **等第一個畫面**（`wait_first_frame`）：guacd 收到 connect 就回 ready，真正登入目標是之後的事 ——
   帳密錯、連不上都要等一下才會以 `error` 指令回來。等到第一個 `sync`（第一個畫面畫完）才算連上，
   這樣「已連線」與稽核的 session_open 才是真的，錯誤也能用跟其他引擎一樣的方式顯示。
3. **轉送**（`relay`）：之後瀏覽器（guacamole-common-js）與 guacd 直接講 Guacamole 協定。
   瀏覽器送來的指令只放行允許清單（鍵盤、滑鼠、尺寸、剪貼簿…）；伺服器另外每幾秒替瀏覽器送 `nop` ——
   guacd 15 秒沒收到東西就判定「User is not responding」斷線，而瀏覽器背景分頁的計時器會被節流到
   一分鐘一次，只靠前端保活的話，分頁切到背景五分鐘就會被斷線。

⚠️ guacd 的 4822 埠**沒有任何驗證**：誰連得到它就能叫它去連任何主機。所以一定只綁 127.0.0.1
（systemd 單元與安裝腳本都這樣設定），而且只有這個模組會連它。
"""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from app.core.config import get_settings

_log = logging.getLogger("jt-ipam.guacd")

#: 協定版本：guacd 在 args 的第一個值問「你講哪一版」，回我們支援的最新版
_PROTOCOL_VERSION = "VERSION_1_5_0"
_KEEPALIVE_SECONDS = 5.0
#: 瀏覽器可以送給 guacd 的指令。其餘（select／connect／file／put／pipe／argv…）一律丟掉：
#: 握手已經在伺服器端做完，檔案傳輸也沒有開放。
ALLOWED_CLIENT_OPCODES = frozenset({
    "key", "mouse", "size", "sync", "nop", "disconnect", "touch",
    "clipboard", "blob", "end", "ack",
})
#: 單一指令的上限（剪貼簿一段、一個 blob）。guacd 自己也有限制，這裡擋掉明顯異常的
_MAX_INSTRUCTION_CHARS = 1 << 20

#: Guacamole 協定的狀態碼（guacamole-common 的 GuacamoleStatus）→ 我們的錯誤代碼
_STATUS_CODES: dict[int, str] = {
    0x0200: "guacd_server_error",
    0x0201: "guacd_server_busy",
    0x0202: "guacd_upstream_timeout",
    0x0203: "guacd_upstream_error",
    0x0204: "guacd_resource_not_found",
    0x0207: "guacd_upstream_not_found",
    0x0208: "guacd_upstream_unavailable",
    0x0209: "guacd_session_conflict",
    0x020A: "guacd_session_timeout",
    0x020B: "guacd_session_closed",
    0x0300: "guacd_bad_request",
    0x0301: "guacd_unauthorized",
    0x0303: "guacd_forbidden",
    0x0308: "guacd_client_timeout",
    0x031D: "guacd_too_many",
}


class GuacdError(Exception):
    """guacd 這條路失敗。`code` 對應前端 `errors.<code>`，`reason` 帶 guacd 講的原文。"""

    def __init__(self, code: str, reason: str = "", *, status: int | None = None) -> None:
        super().__init__(reason or code)
        self.code = code
        self.reason = reason
        self.status = status

    def ui(self) -> dict[str, Any]:
        from app.core.ui_error import ui_detail
        return ui_detail(self.code, _FALLBACK.get(self.code, "guacd 連線失敗：{reason}").format(
            reason=self.reason), reason=self.reason)


# 後端的中文備援句（前端有 errors.<code> 翻譯時用翻譯）；{reason} 是 guacd 或底層給的原文
_FALLBACK: dict[str, str] = {
    "guacd_unavailable": "連不到 guacd（{reason}）。請確認伺服器上的 jt-ipam-guacd 服務有在執行。",
    "guacd_protocol_missing": "guacd 沒有這個協定的支援：{reason}",
    "guacd_handshake_failed": "guacd 交握失敗：{reason}",
    "guacd_first_frame_timeout": "遠端主機一直沒有送出畫面（{reason}）",
    "guacd_auth_required": "遠端主機要求帳號密碼，但沒有提供或不正確",
    "guacd_server_error": "guacd 內部錯誤：{reason}",
    "guacd_server_busy": "guacd 忙碌中：{reason}",
    "guacd_upstream_timeout": "連線到遠端主機逾時：{reason}",
    "guacd_upstream_error": "遠端主機回報錯誤：{reason}",
    "guacd_resource_not_found": "找不到要連的資源：{reason}",
    "guacd_upstream_not_found": "連不到遠端主機（主機不存在或連接埠沒開）：{reason}",
    "guacd_upstream_unavailable": "遠端主機目前無法使用：{reason}",
    "guacd_session_conflict": "遠端工作階段衝突（可能被另一個登入取代）：{reason}",
    "guacd_session_timeout": "遠端工作階段逾時：{reason}",
    "guacd_session_closed": "遠端主機結束了工作階段：{reason}",
    "guacd_bad_request": "連線參數有誤：{reason}",
    "guacd_unauthorized": "認證失敗（帳號、密碼或金鑰錯誤）：{reason}",
    "guacd_forbidden": "遠端主機拒絕登入（帳號可能沒有遠端登入權限）：{reason}",
    "guacd_client_timeout": "瀏覽器太久沒有回應，guacd 結束了連線：{reason}",
    "guacd_too_many": "同時連線太多：{reason}",
    "guacd_host_key_mismatch": "主機金鑰與先前釘選不符，可能遭中間人攻擊（連線中止）：{reason}",
    "guacd_vnc_rejected": "VNC 伺服器拒絕了這次連線，最常見的原因是帳號或密碼錯誤（也可能是伺服器要求的認證方式不支援；連續失敗太多次時，部分伺服器會暫時封鎖來源）：{reason}",
    "guacd_vnc_username_required": "這台 VNC 伺服器要求帳號與密碼，請在「帳號」欄填入帳號",
}


# ───────────────────────── 協定編解碼 ─────────────────────────

def encode(*parts: object) -> str:
    """一條指令：`<長度>.<值>,…;`。長度算的是 Unicode 字元數（不是位元組）。"""
    vals = ["" if p is None else str(p) for p in parts]
    return ",".join(f"{len(v)}.{v}" for v in vals) + ";"


class Parser:
    """增量解析：資料可能在任何地方被切開（TCP 分段、WebSocket 一幀一幀），留到下次再接。

    ⚠️ 不可以每次都從頭重新解析整個緩衝 —— 畫面資料量大，那會慢到跟不上，
    guacd 會把我們當成沒回應而斷線（2026-09-25 試作時踩過）。
    """

    def __init__(self) -> None:
        self._buf = ""
        self._pos = 0

    def feed(self, text: str) -> list[list[str]]:
        self._buf += text
        out: list[list[str]] = []
        while True:
            ins = self._one()
            if ins is None:
                break
            out.append(ins)
        if self._pos:
            self._buf = self._buf[self._pos:]
            self._pos = 0
        return out

    def _one(self) -> list[str] | None:
        i = self._pos
        parts: list[str] = []
        buf = self._buf
        while True:
            dot = buf.find(".", i)
            if dot < 0:
                if len(buf) - self._pos > _MAX_INSTRUCTION_CHARS:
                    raise ValueError("instruction too long")
                return None
            try:
                n = int(buf[i:dot])
            except ValueError as exc:
                raise ValueError("malformed instruction") from exc
            if n < 0 or n > _MAX_INSTRUCTION_CHARS:
                raise ValueError("instruction too long")
            end = dot + 1 + n
            if end >= len(buf):
                return None
            parts.append(buf[dot + 1:end])
            term = buf[end]
            if term == ";":
                self._pos = end + 1
                return parts
            if term != ",":
                raise ValueError("malformed instruction")
            i = end + 1


# ───────────────────────── 連線 ─────────────────────────

def installed_version() -> str | None:
    """安裝腳本裝的 jt-ipam-guacd 版本（SOURCE 檔的 version 行）；沒裝回 None。"""
    from pathlib import Path
    try:
        for line in Path("/opt/jt-ipam-guacd/share/doc/jt-ipam-guacd/SOURCE").read_text(
                encoding="utf-8").splitlines():
            if line.startswith("version:"):
                return line.split(":", 1)[1].strip() or None
    except OSError:
        return None
    return None


def guacd_address() -> tuple[str, int]:
    s = get_settings()
    return s.guacd_host, int(s.guacd_port)


@dataclass
class GuacdConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    protocol: str = ""
    connection_id: str = ""
    _decoder: Any = field(default_factory=lambda: codecs.getincrementaldecoder("utf-8")("replace"))
    _parser: Parser = field(default_factory=Parser)
    _pending: list[list[str]] = field(default_factory=list)

    @classmethod
    async def open(cls, host: str | None = None, port: int | None = None,
                   *, timeout: float = 5.0) -> GuacdConnection:
        h, p = guacd_address()
        host, port = host or h, port or p
        try:
            async with asyncio.timeout(timeout):
                reader, writer = await asyncio.open_connection(host, port)
        except (TimeoutError, OSError) as exc:
            from app.core.safe_http import transport_detail
            raise GuacdError("guacd_unavailable", f"{host}:{port} {transport_detail(exc, limit=120)}") from exc
        return cls(reader=reader, writer=writer)

    async def send(self, *parts: object) -> None:
        self.writer.write(encode(*parts).encode("utf-8"))
        await self.writer.drain()

    async def send_raw(self, text: str) -> None:
        self.writer.write(text.encode("utf-8"))
        await self.writer.drain()

    async def read_chunk(self) -> str:
        """原始資料（已解成字串）；guacd 關掉連線時回空字串。"""
        data = await self.reader.read(65536)
        if not data:
            return self._decoder.decode(b"", final=True)
        return self._decoder.decode(data)

    async def read_instruction(self, timeout: float) -> list[str]:
        async with asyncio.timeout(timeout):
            while not self._pending:
                chunk = await self.read_chunk()
                if chunk == "" and self.reader.at_eof():
                    raise EOFError("guacd closed the connection")
                self._pending.extend(self._parser.feed(chunk))
        return self._pending.pop(0)

    async def handshake(self, protocol: str, params: dict[str, str], *,
                        width: int, height: int, dpi: int = 96,
                        image: Iterable[str] = ("image/png", "image/jpeg", "image/webp"),
                        timezone: str | None = None, timeout: float = 10.0) -> str:
        """select → args → size／audio／video／image／timezone → connect → ready。回傳 connection id。"""
        self.protocol = protocol
        try:
            await self.send("select", protocol)
            args = await self.read_instruction(timeout)
            if args[0] == "error":
                raise GuacdError("guacd_protocol_missing", f"{protocol}: {args[1] if len(args) > 1 else ''}")
            if args[0] != "args":
                raise GuacdError("guacd_handshake_failed", f"expected args, got {args[0]}")
            names = args[1:]
            await self.send("size", width, height, dpi)
            await self.send("audio")
            await self.send("video")
            await self.send("image", *image)
            if timezone:
                await self.send("timezone", timezone)
            values = [(_PROTOCOL_VERSION if n.startswith("VERSION_") else params.get(n, "")) for n in names]
            await self.send("connect", *values)
            ready = await self.read_instruction(timeout)
        except TimeoutError as exc:
            raise GuacdError("guacd_handshake_failed", "timeout") from exc
        except EOFError as exc:
            # guacd 沒有這個協定的外掛時，select 之後就直接斷線（日誌裡才有原因）
            raise GuacdError("guacd_protocol_missing", protocol) from exc
        except ValueError as exc:
            raise GuacdError("guacd_handshake_failed", str(exc)) from exc
        if ready[0] == "error":
            raise _from_error_instruction(ready)
        if ready[0] != "ready":
            raise GuacdError("guacd_handshake_failed", f"expected ready, got {ready[0]}")
        self.connection_id = ready[1] if len(ready) > 1 else ""
        return self.connection_id

    async def wait_first_frame(self, timeout: float) -> str:
        """等到第一個 sync（第一個畫面完成）；回傳這段期間收到的指令（原樣，要先送給瀏覽器）。

        期間照樣每幾秒送 nop，否則慢的目標（RDP NLA、GNOME 遠端登入）還沒登入完，
        guacd 就先把我們當成沒回應。
        """
        buffered: list[str] = []
        deadline = time.monotonic() + timeout
        last_nop = time.monotonic()
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise GuacdError("guacd_first_frame_timeout", f"{int(timeout)}s")
            if now - last_nop >= _KEEPALIVE_SECONDS:
                await self.send("nop")
                last_nop = now
            try:
                ins = await self.read_instruction(min(_KEEPALIVE_SECONDS, deadline - now))
            except TimeoutError:
                continue
            except EOFError as exc:
                raise GuacdError("guacd_session_closed", "guacd closed the connection") from exc
            op = ins[0]
            if op == "error":
                raise _from_error_instruction(ins)
            if op == "required":
                # 目標要求帳密（例如 RDP NLA 沒給密碼）—— 我們不會在這裡跟使用者要，
                # 帳密是在表單上給的；給了還被要就是不對
                raise GuacdError("guacd_auth_required", ",".join(ins[1:]))
            if op == "disconnect":
                raise GuacdError("guacd_session_closed", "disconnect")
            buffered.append(encode(*ins))
            if op == "sync":
                return "".join(buffered)

    async def terminate(self) -> None:
        """跟其他引擎的連線物件同名，讓主控台的 finally 不必分辨用的是哪個引擎。"""
        await self.aclose()

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.write(encode("disconnect").encode("utf-8"))
            await self.writer.drain()
        with contextlib.suppress(Exception):
            self.writer.close()
            await self.writer.wait_closed()


async def tcp_reachable(host: str, port: int, timeout: float = 5.0) -> str | None:
    """連得上回 None，連不上回底層原因（給錯誤訊息用）。"""
    try:
        async with asyncio.timeout(timeout):
            _r, w = await asyncio.open_connection(host, port)
        w.close()
        with contextlib.suppress(Exception):
            await w.wait_closed()
        return None
    except (OSError, TimeoutError) as exc:
        from app.core.safe_http import transport_detail
        return transport_detail(exc, limit=160)


def refine_vnc_error(exc: GuacdError) -> GuacdError:
    """guacd 的 VNC 不論密碼錯、認證方式不支援或真的連不到，都只回「連不到 VNC 伺服器」（0x0207），
    原因只寫在它自己的日誌（「VNC connection failed: Authentication failure」）。
    呼叫端在 guacd 失敗之後確認過 TCP 連得上，這時的「連不到」其實是對方拒絕 —— 說成「主機不存在或
    連接埠沒開」會把人帶去查網路（2026-09-25 正式機上用錯的密碼實測）。
    TCP 只能在失敗之後才試：TigerVNC 等把「連上就斷」算成一次認證失敗，事前探測會讓每次連線都扣額度。
    """
    if exc.code == "guacd_upstream_not_found":
        return GuacdError("guacd_vnc_rejected", exc.reason, status=exc.status)
    if exc.code == "guacd_auth_required" and "username" in exc.reason.split(","):
        # 伺服器用的是要帳號的認證（VeNCrypt 帳密、macOS 螢幕共享、UltraVNC MS 登入），
        # 但表單的帳號欄空著 —— 直接講要填帳號，別只說「要求帳號密碼」讓人去懷疑密碼
        return GuacdError("guacd_vnc_username_required", exc.reason, status=exc.status)
    return exc


def initial_size(text: str) -> tuple[int, int] | None:
    """第一批指令裡預設圖層（0）的尺寸 —— VNC 的桌面大小由目標決定，要從這裡讀。"""
    try:
        for ins in Parser().feed(text):
            if ins[0] == "size" and len(ins) >= 4 and ins[1] == "0":
                return int(ins[2]), int(ins[3])
    except ValueError:
        return None
    return None


def known_hosts_line(host: str, port: int, known_host: str) -> str:
    """釘選的主機金鑰（`ssh-ed25519 AAAA…`）→ guacd `host-key` 參數要的 known_hosts 一行。

    guacd（libssh2）用「實際連線的主機與連接埠」查這一行，所以要寫**撥出去的那個位址** ——
    走跳板時是 127.0.0.1 加本機轉發埠，不是目標 IP。非 22 埠要寫成 `[host]:port`。
    """
    key = " ".join(known_host.split()[:2])
    who = host if int(port) == 22 else f"[{host}]:{int(port)}"
    return f"{who} {key}"


def client_dpi(value: object) -> int:
    try:
        dpi = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 96
    return max(72, min(384, dpi))


def client_timezone(value: object) -> str | None:
    """瀏覽器的時區（IANA 名稱）。只收看起來像時區的字串 —— 這個值會原樣交給 guacd。"""
    import re
    if isinstance(value, str) and len(value) <= 64 and re.fullmatch(r"[A-Za-z0-9_+\-]+(/[A-Za-z0-9_+\-]+)*", value):
        return value
    return None


#: guacd 很多錯誤只回這一句，真正的原因寫在它自己的日誌 —— 原樣顯示等於沒說，改成告訴人去哪裡看
_GENERIC_ABORT = "Aborted. See logs."
_SEE_LOG = "journalctl -u jt-ipam-guacd"


def _from_error_instruction(ins: list[str]) -> GuacdError:
    message = ins[1] if len(ins) > 1 else ""
    if message.strip() == _GENERIC_ABORT:
        message = _SEE_LOG
    try:
        status = int(ins[2]) if len(ins) > 2 else 0
    except ValueError:
        status = 0
    if "host key" in message.lower():
        return GuacdError("guacd_host_key_mismatch", message, status=status)
    return GuacdError(_STATUS_CODES.get(status, "guacd_upstream_error"), message, status=status)


# ───────────────────────── 轉送 ─────────────────────────

@dataclass
class RelayResult:
    #: 誰先結束：「client」＝瀏覽器關了／斷了；「remote」＝guacd 那一端結束（目標登出、網路斷）
    ended_by: str = ""
    dropped: int = 0       # 被允許清單擋掉的指令數（稽核用；正常使用應該是 0）


#: argv 的值最多幾個字元（字級、配色這類短字串；長的一律當異常）
_MAX_ARGV_VALUE = 64


async def relay(websocket: Any, conn: GuacdConnection, *, initial: str = "",
                argv_allow: dict[str, Callable[[str], bool]] | None = None) -> RelayResult:
    """瀏覽器 ⇄ guacd。回傳誰先結束。websocket 是 FastAPI 的 WebSocket。

    `argv_allow`：連線中允許瀏覽器修改的參數名稱 → 值的驗證函式（例如 SSH 的 font-size）。
    argv 能改 guacd 允許修改的任何參數（RDP 甚至包含帳號密碼），所以預設全擋，只放行呼叫端
    明確列出的名稱；值要整段收齊、驗證通過，才把 argv／blob／end 一起送出。
    """
    import base64
    import binascii

    from fastapi import WebSocketDisconnect

    result = RelayResult()
    if initial:
        await websocket.send_text(initial)

    async def pump_out() -> None:
        # guacd → 瀏覽器：原樣轉（不逐條解析；guamole-common-js 的 Parser 會接好被切開的指令）
        while True:
            chunk = await conn.read_chunk()
            if not chunk:
                if conn.reader.at_eof():
                    return
                continue
            await websocket.send_text(chunk)

    # argv 串流：stream → [名稱, 已收到的值]；end 時驗證，通過才整段送出
    argv_streams: dict[str, list[Any]] = {}
    rejected_streams: set[str] = set()      # 被拒的 argv：它後面的 blob／end 也要擋

    def take_argv(ins: list[str]) -> list[str] | None:
        """處理 argv 與它的 blob／end。回傳要送給 guacd 的指令（None＝不是 argv 串流、照一般規則）。"""
        op = ins[0]
        if op == "argv":
            if (argv_allow and len(ins) == 4 and ins[2] == "text/plain" and ins[3] in argv_allow
                    and ins[1] not in argv_streams):
                argv_streams[ins[1]] = [ins[3], ""]
            else:
                result.dropped += 1
                if len(ins) > 1:
                    rejected_streams.add(ins[1])
            return []
        if op in ("blob", "end") and len(ins) >= 2 and ins[1] in rejected_streams:
            if op == "end":
                rejected_streams.discard(ins[1])
            return []
        if op in ("blob", "end") and len(ins) >= 2 and ins[1] in argv_streams:
            name, value = argv_streams[ins[1]]
            if op == "blob":
                try:
                    value += base64.b64decode(ins[2] if len(ins) > 2 else "", validate=True).decode()
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    value = "\x00invalid"
                argv_streams[ins[1]][1] = value
                return []
            del argv_streams[ins[1]]
            check = (argv_allow or {}).get(name)
            if len(value) > _MAX_ARGV_VALUE or check is None or not check(value):
                result.dropped += 1
                return []
            b64 = base64.b64encode(value.encode()).decode()
            return [encode("argv", ins[1], "text/plain", name), encode("blob", ins[1], b64), encode("end", ins[1])]
        if op == "argv":
            return []
        return None

    async def pump_in() -> None:
        parser = Parser()
        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    instructions = parser.feed(raw)
                except ValueError:
                    _log.warning("guacd: 瀏覽器送來格式錯誤的指令，結束連線")
                    return
                out: list[str] = []
                for ins in instructions:
                    handled = take_argv(ins) if ins else None
                    if handled is not None:
                        out.extend(handled)
                        continue
                    if not ins or ins[0] not in ALLOWED_CLIENT_OPCODES:
                        result.dropped += 1
                        continue
                    out.append(encode(*ins))
                    if ins[0] == "disconnect":
                        await conn.send_raw("".join(out))
                        return
                if out:
                    await conn.send_raw("".join(out))
        except WebSocketDisconnect:
            return

    async def keepalive() -> None:
        # 見模組說明：瀏覽器背景分頁的計時器會被節流，guacd 的 15 秒不能只靠前端
        while True:
            await asyncio.sleep(_KEEPALIVE_SECONDS)
            await conn.send("nop")

    out_task = asyncio.create_task(pump_out())
    in_task = asyncio.create_task(pump_in())
    ka_task = asyncio.create_task(keepalive())
    done, pending = await asyncio.wait({out_task, in_task, ka_task}, return_when=asyncio.FIRST_COMPLETED)
    result.ended_by = "remote" if out_task in done else "client"
    for t in pending:
        t.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for t in done:
        exc = t.exception()
        if exc is not None and not isinstance(exc, (WebSocketDisconnect, ConnectionError)):
            _log.warning("guacd: 轉送中止：%r", exc)
    return result


# ───────────────────────── 可用性 ─────────────────────────

PROTOCOLS: tuple[str, ...] = ("rdp", "vnc", "ssh")
_probe_cache: dict[str, Any] = {"at": 0.0, "value": None}
_PROBE_TTL = 30.0


async def probe(*, use_cache: bool = True) -> dict[str, Any]:
    """guacd 有沒有在跑、每個協定的外掛載不載得到。設定頁與發票證時用。

    逐協定開一條連線問 `select`：有外掛會回 args，沒有的話 guacd 直接斷線。
    結果快取 30 秒（每次發票證都去問一輪不必要）。
    """
    now = time.monotonic()
    if use_cache and _probe_cache["value"] is not None and now - _probe_cache["at"] < _PROBE_TTL:
        return dict(_probe_cache["value"])
    host, port = guacd_address()
    out: dict[str, Any] = {"ok": False, "address": f"{host}:{port}", "protocols": {}, "error": ""}
    for proto in PROTOCOLS:
        try:
            conn = await GuacdConnection.open(timeout=2.0)
        except GuacdError as exc:
            out["error"] = exc.reason
            break
        try:
            await conn.send("select", proto)
            ins = await conn.read_instruction(3.0)
            out["protocols"][proto] = ins[0] == "args"
        except (TimeoutError, EOFError, ValueError):
            out["protocols"][proto] = False
        finally:
            with contextlib.suppress(Exception):
                conn.writer.close()
    out["ok"] = any(out["protocols"].values())
    _probe_cache.update(at=now, value=out)
    return dict(out)


async def require(protocol: str) -> None:
    """發票證前確認 guacd 能處理這個協定；不行就丟 GuacdError（呼叫端轉成 503）。"""
    st = await probe()
    if not st["protocols"]:
        raise GuacdError("guacd_unavailable", st.get("error") or st["address"])
    if not st["protocols"].get(protocol):
        raise GuacdError("guacd_protocol_missing", protocol)
