"""匯入檔的串流讀取（2026-10-01）。

以前匯入是：整份封套 `json.loads` → payload 整段 base64 解碼 → AES-GCM 一次解密 → gzip 一次解壓 →
整份 inner JSON 解析成 Python 物件 —— 每一步都是一份完整副本。27.5 MB 的匯出檔（42.7 萬列）
尖峰吃到 1.36 GB，而匯入是在後端程序裡跑的。

這裡改成兩趟、都只讀檔案：

1. `scan()`：逐段解密、解壓，**驗證 GCM 標籤**（＝密碼對、檔案沒被改），順便從結尾取出各表筆數。
   不保留內容。取代模式要先清空資料表 —— 一定要在確認檔案可信之後才做。
2. `iter_events()`：再逐段解密、解壓，逐列解析，產生「這張表的下一批列」。結尾再驗一次標籤；
   檔案若在兩趟之間被換掉，這裡會丟錯，呼叫端的交易整個還原。

明文（含解密後的機密）從頭到尾不落地。檔案格式完全不變，舊檔照樣能讀。
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.services.system_transfer import crypto

#: payload 前面的封套欄位（format、kdf、nonce…）一定在這個範圍內；超過就當成損毀
_HEAD_MAX = 1 << 20
_CHUNK = 1 << 20
_TAG = 16
#: 結尾留多少解壓後的文字來找 counts（counts 是 inner JSON 的最後一個欄位，幾 KB）
_TAIL_KEEP = 1 << 20
#: 單一個 JSON 值（一列）最多能多大；超過就是檔案壞了，不要為了等它把整份讀進記憶體
_VALUE_MAX = 64 << 20
_DEC = json.JSONDecoder()
_WS = " \t\r\n"


def _broken(msg: str = "匯出檔封套損毀或欄位缺失") -> crypto.TransferCryptoError:
    return crypto.TransferCryptoError(msg, code="xfer_envelope_broken")


@dataclass
class Head:
    """封套裡 payload 以外的欄位，以及 payload 在檔案中的位置。"""

    env: dict[str, Any]
    payload_start: int                       # payload 字串第一個字元的位元組位置
    trailing: dict[str, Any] = field(default_factory=dict)   # payload 之後還有欄位時（手動排版過的檔）


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in _WS:
        i += 1
    return i


def read_head(path: str | Path) -> Head:
    """讀封套開頭到 payload 為止。payload 前面一定要有解密需要的欄位（每一版的匯出都是這樣寫）。"""
    with open(path, "rb") as f:
        raw = f.read(_HEAD_MAX)
    text = raw.decode("utf-8", errors="replace")
    try:
        i = _skip_ws(text, 0)
        if text[i:i + 1] != "{":
            raise crypto.TransferCryptoError("不是有效的 JSON 匯出檔", code="xfer_not_json")
        i += 1
        env: dict[str, Any] = {}
        while True:
            i = _skip_ws(text, i)
            if text[i:i + 1] == "}":
                break
            key, i = _DEC.raw_decode(text, i)
            i = _skip_ws(text, i)
            if text[i:i + 1] != ":":
                raise _broken()
            i = _skip_ws(text, i + 1)
            if key == "payload":
                if text[i:i + 1] != '"':
                    raise _broken()
                start = len(text[:i + 1].encode("utf-8"))
                if env.get("format") != crypto.FORMAT:
                    raise crypto.TransferCryptoError("這不是有效的 jt-ipam 系統匯出檔",
                                                     code="xfer_not_export_file")
                return Head(env=env, payload_start=start)
            env[key], i = _DEC.raw_decode(text, i)
            i = _skip_ws(text, i)
            if text[i:i + 1] == ",":
                i += 1
    except (ValueError, IndexError) as exc:
        if isinstance(exc, crypto.TransferCryptoError):
            raise
        raise _broken() from exc
    raise _broken()


def _key_for(head: Head, passphrase: str) -> tuple[bytes, bytes]:
    env = head.env
    fv = env.get("format_version")
    if not isinstance(fv, int) or fv > crypto.FORMAT_VERSION:
        raise crypto.TransferCryptoError(f"匯出檔格式版本 {fv} 較新，此實例無法解析（請升級後再匯入）",
                                         code="xfer_format_newer", version=fv)
    kdf = env.get("kdf") or {}
    try:
        salt = base64.b64decode(str(kdf["salt"]))
        nonce = base64.b64decode(str(env["nonce"]))
        n, r, p = int(kdf.get("n", 2**15)), int(kdf.get("r", 8)), int(kdf.get("p", 1))
    except (KeyError, ValueError, TypeError) as exc:
        raise _broken() from exc
    return crypto._derive_key(passphrase, salt, n=n, r=r, p=p), nonce


def _parse_trailing(text: str) -> dict[str, Any]:
    """payload 結尾引號之後的部分：`}`，或（排版過的檔）還有幾個欄位。"""
    out: dict[str, Any] = {}
    i = _skip_ws(text, 0)
    while i < len(text) and text[i] == ",":
        i = _skip_ws(text, i + 1)
        key, i = _DEC.raw_decode(text, i)
        i = _skip_ws(text, i)
        if text[i:i + 1] != ":":
            raise _broken()
        out[key], i = _DEC.raw_decode(text, _skip_ws(text, i + 1))
        i = _skip_ws(text, i)
    if text[i:i + 1] != "}" or text[i + 1:].strip():
        raise _broken()
    return out


def iter_plain_gzip(path: str | Path, head: Head, passphrase: str, *, chunk: int = _CHUNK) -> Iterator[bytes]:
    """逐段 base64 解碼＋AES-GCM 解密，產生 gzip 後的 inner JSON。

    **最後才驗證標籤**（產生完最後一段之後）：中途產生的內容尚未驗證，呼叫端不可在
    這個產生器結束前把結果當成可信（見本檔開頭的兩趟設計）。
    """
    key, nonce = _key_for(head, passphrase)
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
    hold = b""        # 最後 16 位元組是標籤，要留到最後
    carry = b""       # base64 不滿 4 個字的尾巴
    with open(path, "rb") as f:
        f.seek(head.payload_start)
        while True:
            block = f.read(chunk)
            if not block:
                raise _broken()                       # 找不到 payload 的結尾引號
            q = block.find(b'"')
            data = block if q < 0 else block[:q]
            b64 = carry + data
            cut = len(b64) if q >= 0 else len(b64) - len(b64) % 4
            carry = b64[cut:]
            try:
                raw = base64.b64decode(b64[:cut], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise _broken() from exc
            buf = hold + raw
            if len(buf) > _TAG:
                out = dec.update(buf[:-_TAG])
                hold = buf[-_TAG:]
                if out:
                    yield out
            else:
                hold = buf
            if q >= 0:
                rest = block[q + 1:] + f.read(_HEAD_MAX + 1)
                if len(rest) > _HEAD_MAX:
                    raise _broken()
                try:
                    head.trailing = _parse_trailing(rest.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    if isinstance(exc, crypto.TransferCryptoError):
                        raise
                    raise _broken() from exc
                break
    if len(hold) != _TAG:
        raise _broken()
    try:
        tail = dec.finalize_with_tag(hold)
    except InvalidTag as exc:
        raise crypto.TransferCryptoError("密碼錯誤或檔案已損毀", code="xfer_bad_passphrase") from exc
    if tail:
        yield tail


def iter_text(path: str | Path, head: Head, passphrase: str, *, chunk: int = _CHUNK) -> Iterator[str]:
    """解壓＋UTF-8 解碼後的 inner JSON 文字，一段一段。"""
    gz = zlib.decompressobj(31)                       # 31＝gzip 格式
    utf8 = codecs.getincrementaldecoder("utf-8")()
    try:
        for part in iter_plain_gzip(path, head, passphrase, chunk=chunk):
            text = utf8.decode(gz.decompress(part))
            if text:
                yield text
        text = utf8.decode(gz.flush(), final=True)
    except zlib.error as exc:
        raise crypto.TransferCryptoError("匯出檔內容無法解壓/解析", code="xfer_unreadable") from exc
    except UnicodeDecodeError as exc:
        raise crypto.TransferCryptoError("匯出檔內容無法解壓/解析", code="xfer_unreadable") from exc
    if not gz.eof or gz.unused_data:
        raise crypto.TransferCryptoError("匯出檔內容無法解壓/解析", code="xfer_unreadable")
    if text:
        yield text


@dataclass
class ScanResult:
    metadata: dict[str, Any]          # crypto.read_metadata 的結果
    counts: dict[str, int] | None     # 各表筆數（匯出時寫在 inner JSON 結尾）；舊檔沒有就是 None


def scan(path: str | Path, passphrase: str) -> ScanResult:
    """第一趟：驗證密碼與完整性，取出 metadata 與各表筆數。不保留內容。"""
    head = read_head(path)
    # 先只解密、驗標籤（AES 很快）：密碼錯時解出來的是亂碼，直接解壓會先報「無法解壓」，
    # 使用者就看不出其實是密碼打錯了
    for _ in iter_plain_gzip(path, head, passphrase):
        pass
    tail = ""
    for text in iter_text(path, head, passphrase):
        tail = (tail + text)[-_TAIL_KEEP:]
    env = {**head.env, **head.trailing}
    return ScanResult(metadata=crypto.read_metadata(env), counts=_counts_from_tail(tail))


def _counts_from_tail(tail: str) -> dict[str, int] | None:
    i = tail.rfind('"counts"')
    if i < 0:
        return None
    try:
        j = _skip_ws(tail, i + len('"counts"'))
        if tail[j:j + 1] != ":":
            return None
        val, _end = _DEC.raw_decode(tail, _skip_ws(tail, j + 1))
    except ValueError:
        return None
    if not isinstance(val, dict) or not all(isinstance(v, int) for v in val.values()):
        return None
    return {str(k): int(v) for k, v in val.items()}


# ─────────────────── 逐列解析 inner JSON ───────────────────


class _Reader:
    """在一段一段送進來的文字上，解析已知結構的 JSON。

    標準函式庫沒有串流 JSON 解析器；這裡只需要一層：`{"tables": {名稱: [列, …]}, 其他欄位…}`。
    每一列交給 `json.JSONDecoder.raw_decode` —— 內容不完整就再讀一段重試（一段 1 MB 起跳，
    一列通常幾百位元組，重試很少）。只對物件、陣列、字串呼叫，不在最外層解析裸數字
    （數字被截在段落邊界時會「成功」解出一半）。
    """

    def __init__(self, chunks: Iterator[str]) -> None:
        self._chunks = chunks
        self.buf = ""
        self.pos = 0
        self.eof = False

    def _more(self) -> bool:
        if self.eof:
            return False
        try:
            nxt = next(self._chunks)
        except StopIteration:
            self.eof = True
            return False
        if self.pos > (1 << 20):
            self.buf, self.pos = self.buf[self.pos:], 0
        self.buf += nxt
        return True

    def peek(self) -> str:
        while True:
            while self.pos < len(self.buf) and self.buf[self.pos] in _WS:
                self.pos += 1
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self._more():
                raise crypto.TransferCryptoError("匯出檔內容無法解壓/解析", code="xfer_unreadable")

    def take(self, ch: str) -> None:
        if self.peek() != ch:
            raise crypto.TransferCryptoError("匯出檔內容格式不正確", code="xfer_bad_content")
        self.pos += 1

    def value(self) -> Any:
        if self.peek() not in '{["':
            raise crypto.TransferCryptoError("匯出檔內容格式不正確", code="xfer_bad_content")
        while True:
            try:
                val, end = _DEC.raw_decode(self.buf, self.pos)
            except ValueError:
                if len(self.buf) - self.pos > _VALUE_MAX or not self._more():
                    raise crypto.TransferCryptoError("匯出檔內容格式不正確", code="xfer_bad_content") from None
                continue
            self.pos = end
            return val

    def at_end(self) -> bool:
        while True:
            rest = self.buf[self.pos:]
            if rest.strip():
                return False
            self.pos = len(self.buf)
            if not self._more():
                return True


def parse_events(chunks: Iterator[str], *, batch: int = 1000) -> Iterator[tuple[Any, ...]]:
    """產生 ("table", 名稱)、("rows", 名稱, [列…])、("end", 名稱)、("key", 欄位, 值)。"""
    r = _Reader(chunks)
    r.take("{")
    if r.peek() == "}":
        r.pos += 1
    else:
        while True:
            key = r.value()
            if not isinstance(key, str):
                raise crypto.TransferCryptoError("匯出檔內容格式不正確", code="xfer_bad_content")
            r.take(":")
            if key == "tables":
                yield from _parse_tables(r, batch)
            else:
                yield ("key", key, r.value())
            if r.peek() == ",":
                r.pos += 1
                continue
            r.take("}")
            break
    if not r.at_end():
        raise crypto.TransferCryptoError("匯出檔內容格式不正確", code="xfer_bad_content")


def _parse_tables(r: _Reader, batch: int) -> Iterator[tuple[Any, ...]]:
    r.take("{")
    if r.peek() == "}":
        r.pos += 1
        return
    while True:
        name = r.value()
        if not isinstance(name, str):
            raise crypto.TransferCryptoError("匯出檔內容格式不正確", code="xfer_bad_content")
        r.take(":")
        r.take("[")
        yield ("table", name)
        rows: list[dict[str, Any]] = []
        if r.peek() == "]":
            r.pos += 1
        else:
            while True:
                row = r.value()
                if not isinstance(row, dict):
                    raise crypto.TransferCryptoError("匯出檔內容格式不正確", code="xfer_bad_content")
                rows.append(row)
                if len(rows) >= batch:
                    yield ("rows", name, rows)
                    rows = []
                if r.peek() == ",":
                    r.pos += 1
                    continue
                r.take("]")
                break
        if rows:
            yield ("rows", name, rows)
        yield ("end", name)
        if r.peek() == ",":
            r.pos += 1
            continue
        r.take("}")
        return


def iter_events(path: str | Path, passphrase: str, *, batch: int = 1000,
                chunk: int = _CHUNK) -> Iterator[tuple[Any, ...]]:
    """第二趟：逐列產生匯入事件。標籤在最後一段之後驗證（不對就丟 TransferCryptoError）。"""
    head = read_head(path)
    yield from parse_events(iter_text(path, head, passphrase, chunk=chunk), batch=batch)
