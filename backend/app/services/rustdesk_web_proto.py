"""相容 RustDesk 的網頁連線：後端用到的協定片段（純函式，不碰網路）。

唯一依據是 docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md（乾淨室實作，章節編號照規格）。後端只負責：
- TCP 的長度前綴（2.1）
- 會合與中繼用的 RendezvousMessage（4、5，訊息定義見 13）
- 驗 hbbs 簽章過的受控端身分（6.1）。這一步瀏覽器也會做；後端在連 hbbr 之前先驗一次，
  驗不過就不佔用中繼，而且錯誤會留在稽核裡
- 用已存的密碼算這一次連線的密碼雜湊（7.2，附錄 D.3）：只回 h2，h1 與明文都不離開這個函式

配對之後的對話（Message）一律是瀏覽器在處理，後端不解析、也解不開（密文）。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: 控制端宣稱的相容版本（4.1、7.3 的建議值）
CLAIMED_VERSION = "1.4.1"

#: 單則訊息上限（2.3：至少 16 MB）
MAX_MESSAGE = 16 * 1024 * 1024

# 4.1 的列舉值
NAT_SYMMETRIC = 2
CONN_DEFAULT = 0

# 4.2 PunchHoleResponse.Failure → 錯誤代碼（第 11 節）
FAILURE_CODES = {
    0: "rd_id_not_exist",
    2: "rd_offline",
    3: "rd_key_mismatch",
    4: "rd_key_overuse",
}

# RendezvousMessage 的 oneof 欄位編號（13）
_RENDEZVOUS_KINDS = {
    8: "punch_hole_request",
    11: "punch_hole_response",
    18: "request_relay",
    19: "relay_response",
    25: "key_exchange",
}


class ProtoError(ValueError):
    """位元組串不是合法的 protobuf。"""


class HandshakeError(Exception):
    """6.1 的身分驗證失敗。code 是第 11 節的錯誤代碼。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ── 2.1 長度前綴 ──────────────────────────────────────────────────────────────

def length_header(n: int) -> bytes:
    """標頭的值是 (n << 2) | (標頭位元組數 − 1)，little-endian，1 到 4 bytes。"""
    if n < 0:
        raise ValueError("negative length")
    if n <= 0x3F:
        size = 1
    elif n <= 0x3FFF:
        size = 2
    elif n <= 0x3FFFFF:
        size = 3
    elif n <= 0x3FFFFFFF:
        size = 4
    else:
        raise ValueError("message too long for the length prefix")
    return ((n << 2) | (size - 1)).to_bytes(4, "little")[:size]


def header_size(first: int) -> int:
    """第一個位元組的最低 2 位元 +1 就是標頭長度。"""
    return (first & 0x03) + 1


def parse_header(hdr: bytes) -> int:
    return int.from_bytes(hdr, "little") >> 2


def frame(body: bytes) -> bytes:
    return length_header(len(body)) + body


# ── 3 protobuf（只做用得到的部分）──────────────────────────────────────────────

def varint(n: int) -> bytes:
    """int32／int64 的負值要編成 10 bytes（64 位元二補數）。"""
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def zigzag(n: int) -> int:
    """sint32／sint64 用的 zigzag。"""
    return (n << 1) ^ (n >> 63)


def _key(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def f_varint(field: int, value: int) -> bytes:
    """proto3：預設值（0）不出現在線上。"""
    return _key(field, 0) + varint(value) if value else b""


def f_bool(field: int, value: bool) -> bytes:
    return _key(field, 0) + b"\x01" if value else b""


def f_bytes(field: int, value: bytes) -> bytes:
    return _key(field, 2) + varint(len(value)) + value if value else b""


def f_str(field: int, value: str) -> bytes:
    return f_bytes(field, value.encode("utf-8"))


def f_msg(field: int, body: bytes) -> bytes:
    """子訊息一律寫出（oneof 裡內容全是預設值的子訊息也要有這個欄位）。"""
    return _key(field, 2) + varint(len(body)) + body


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = 0
    result = 0
    while True:
        if i >= len(buf):
            raise ProtoError("truncated varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift >= 70:
            raise ProtoError("varint too long")


Fields = dict[int, list[Any]]


def parse(buf: bytes) -> Fields:
    """欄位編號 → 值的串列（varint 為 int，長度前綴為 bytes，固定長度為 bytes）。未知欄位照收、呼叫端不看就是忽略。"""
    out: Fields = {}
    i = 0
    n = len(buf)
    while i < n:
        key, i = _read_varint(buf, i)
        field, wire = key >> 3, key & 0x07
        if field == 0:
            raise ProtoError("field number 0")
        value: Any
        if wire == 0:
            value, i = _read_varint(buf, i)
        elif wire == 1:
            if i + 8 > n:
                raise ProtoError("truncated fixed64")
            value, i = buf[i:i + 8], i + 8
        elif wire == 2:
            ln, i = _read_varint(buf, i)
            if i + ln > n:
                raise ProtoError("truncated length-delimited field")
            value, i = buf[i:i + ln], i + ln
        elif wire == 5:
            if i + 4 > n:
                raise ProtoError("truncated fixed32")
            value, i = buf[i:i + 4], i + 4
        else:
            raise ProtoError(f"unsupported wire type {wire}")
        out.setdefault(field, []).append(value)
    return out


def get_bytes(fields: Fields, field: int) -> bytes:
    """純量欄位重複出現時以最後一個為準（proto3 規則）。"""
    vals = fields.get(field)
    if not vals:
        return b""
    v = vals[-1]
    return v if isinstance(v, bytes) else b""


def get_str(fields: Fields, field: int) -> str:
    return get_bytes(fields, field).decode("utf-8", errors="replace")


def get_int(fields: Fields, field: int) -> int:
    vals = fields.get(field)
    if not vals:
        return 0
    v = vals[-1]
    return v if isinstance(v, int) else 0


def parse_rendezvous(buf: bytes) -> tuple[str | None, Fields]:
    """RendezvousMessage → (oneof 的種類, 子訊息的欄位)。認不得的種類回 (None, {})。"""
    top = parse(buf)
    kind_field = None
    for field in top:
        if field in _RENDEZVOUS_KINDS:
            kind_field = field              # oneof 只會有一個；萬一有多個，取最後出現的（proto3）
    if kind_field is None:
        return None, {}
    raw = top[kind_field][-1]
    if not isinstance(raw, bytes):
        raise ProtoError("oneof message field is not length-delimited")
    return _RENDEZVOUS_KINDS[kind_field], parse(raw)


# ── 4、5 會合與中繼的訊息 ──────────────────────────────────────────────────────

def punch_hole_request(peer_id: str, licence_key: str) -> bytes:
    """4.1：nat_type=SYMMETRIC（打洞沒用，請建中繼）、conn_type=DEFAULT_CONN、token 空、force_relay=true。"""
    body = (f_str(1, peer_id) + f_varint(2, NAT_SYMMETRIC) + f_str(3, licence_key)
            + f_varint(4, CONN_DEFAULT) + f_str(5, "") + f_str(6, CLAIMED_VERSION) + f_bool(8, True))
    return f_msg(8, body)


def request_relay_hbbs(peer_id: str, uuid: str, relay_server: str) -> bytes:
    """4.3：收到可直連的回覆時，改向 hbbs 要中繼。secure 一定要填（要求受控端做安全握手）。"""
    body = f_str(1, peer_id) + f_str(2, uuid) + f_str(4, relay_server) + f_bool(5, True) + f_str(8, "")
    return f_msg(18, body)


def request_relay_hbbr(peer_id: str, uuid: str, licence_key: str) -> bytes:
    """5.1：連上 hbbr 的第一則。licence_key 不符時 hbbr 直接斷線、不回任何訊息。"""
    body = f_str(1, peer_id) + f_str(2, uuid) + f_str(6, licence_key) + f_varint(7, CONN_DEFAULT)
    return f_msg(18, body)


@dataclass(frozen=True)
class RelayResponse:
    uuid: str
    relay_server: str
    pk: bytes
    refuse_reason: str
    version: str

    @classmethod
    def of(cls, f: Fields) -> RelayResponse:
        return cls(uuid=get_str(f, 2), relay_server=get_str(f, 3), pk=get_bytes(f, 5),
                   refuse_reason=get_str(f, 6), version=get_str(f, 7))


@dataclass(frozen=True)
class PunchHoleResponse:
    socket_addr: bytes
    pk: bytes
    failure: int
    relay_server: str
    other_failure: str

    @classmethod
    def of(cls, f: Fields) -> PunchHoleResponse:
        return cls(socket_addr=get_bytes(f, 1), pk=get_bytes(f, 2), failure=get_int(f, 3),
                   relay_server=get_str(f, 4), other_failure=get_str(f, 7))


# ── 6.1 hbbs 簽章過的受控端身分 ────────────────────────────────────────────────

def verify_signed_id_pk(signed: bytes, server_key_b64: str, peer_id: str) -> bytes:
    """驗 ed25519「簽章附訊息」（前 64 bytes 簽章、後面是 IdPk），回傳受控端的 ed25519 公鑰（32 bytes）。

    - 沒有簽章身分、或 IdPk.pk 是空的：上游會退回不加密，我們不退（6.1.3、6.5）→ rd_insecure_refused
    - 簽章不過、IdPk.id 不是要連的 ID → rd_bad_server_signature
    """
    if not signed:
        raise HandshakeError("rd_insecure_refused", "hbbs 沒有提供簽章過的受控端身分，拒絕在沒有加密的情況下連線")
    try:
        key = base64.b64decode(server_key_b64 or "", validate=True)
        pub = Ed25519PublicKey.from_public_bytes(key)
    except (binascii.Error, ValueError) as exc:
        raise HandshakeError("rd_bad_server_signature", "jt-ipam 存的伺服器公鑰格式不對") from exc
    if len(signed) < 64:
        raise HandshakeError("rd_bad_server_signature", "簽章過的身分長度不足")
    sig, msg = signed[:64], signed[64:]
    try:
        pub.verify(sig, msg)
    except InvalidSignature as exc:
        raise HandshakeError("rd_bad_server_signature", "受控端身分的 hbbs 簽章驗證失敗") from exc
    try:
        f = parse(msg)
    except ProtoError as exc:
        raise HandshakeError("rd_bad_server_signature", "簽章過的身分無法解析") from exc
    if get_str(f, 1) != peer_id:
        raise HandshakeError("rd_bad_server_signature", "簽章過的身分不是要連的 RustDesk ID")
    pk = get_bytes(f, 2)
    if not pk:
        raise HandshakeError("rd_insecure_refused", "受控端沒有回報公鑰，拒絕在沒有加密的情況下連線")
    if len(pk) != 32:
        raise HandshakeError("rd_bad_server_signature", "受控端公鑰長度不對")
    return pk


def password_h2(password: str, salt: str, challenge: str) -> bytes:
    """7.2：h1 = SHA-256(UTF-8(密碼) ‖ UTF-8(salt))、h2 = SHA-256(h1 ‖ UTF-8(challenge))，回 h2 的 32 bytes。

    附錄 D.1：h1 對同一台受控端是固定值、等同密碼，所以只在這裡算、不回傳也不保存；
    h2 只對這一次連線的 challenge 有效。
    """
    h1 = hashlib.sha256(password.encode("utf-8") + salt.encode("utf-8")).digest()
    return hashlib.sha256(h1 + challenge.encode("utf-8")).digest()
