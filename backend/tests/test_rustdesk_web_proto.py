"""相容 RustDesk 的網頁連線：後端用到的協定片段（docs/SPEC_RUSTDESK_WEBCLIENT_zh-TW.md）。

後端只做會合（hbbs）與中繼（hbbr）：TCP 的長度前綴（2.1）、會合用的 protobuf 訊息（4、5、13）、
hbbs 簽章過的受控端身分（6.1，後端在連 hbbr 前先驗一次，瀏覽器自己也會驗）。
測試向量全部取自規格。
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.services import rustdesk_web_proto as proto

# ── 2.1 長度前綴 ──

_FRAME_VECTORS = [
    (0, "00"), (10, "28"), (63, "fc"), (64, "0101"), (100, "9101"), (16383, "fdff"),
    (16384, "020001"), (300000, "824f12"), (4194303, "feffff"), (4194304, "03000001"),
]


@pytest.mark.parametrize(("n", "hexhdr"), _FRAME_VECTORS)
def test_length_header_matches_spec_vectors(n: int, hexhdr: str) -> None:
    assert proto.length_header(n).hex() == hexhdr


@pytest.mark.parametrize(("n", "hexhdr"), _FRAME_VECTORS)
def test_length_header_round_trips(n: int, hexhdr: str) -> None:
    hdr = bytes.fromhex(hexhdr)
    assert proto.header_size(hdr[0]) == len(hdr)
    assert proto.parse_header(hdr) == n


def test_zero_length_message_is_legal() -> None:
    assert proto.frame(b"") == b"\x00"


def test_frame_prefixes_the_body() -> None:
    body = b"x" * 100
    assert proto.frame(body) == bytes.fromhex("9101") + body


def test_too_long_for_four_bytes_is_refused() -> None:
    with pytest.raises(ValueError):
        proto.length_header(0x40000000)


# ── 3 protobuf ──

def test_zigzag_vectors() -> None:
    assert proto.zigzag(-1) == 1
    assert proto.zigzag(100) == 200
    assert proto.zigzag(-1920) == 3839


def test_negative_int32_is_ten_byte_varint() -> None:
    assert len(proto.varint(-1)) == 10


def test_decoder_accepts_empty_submessage_in_oneof() -> None:
    # RendezvousMessage { relay_response (19) = {} }：0 bytes 的子訊息也算「有這個欄位」
    kind, sub = proto.parse_rendezvous(bytes([0x9A, 0x01, 0x00]))   # 鍵 (19<<3)|2=154 → varint 9a 01
    assert kind == "relay_response"
    assert sub == {}


def test_decoder_ignores_unknown_fields() -> None:
    msg = proto.f_str(2, "u" * 36) + proto.f_str(99, "future") + proto.f_varint(77, 5)
    fields = proto.parse(msg)
    assert proto.get_str(fields, 2) == "u" * 36


def test_decoder_rejects_truncated_input() -> None:
    with pytest.raises(proto.ProtoError):
        proto.parse(bytes([2 << 3 | 2, 10]) + b"abc")


# ── 4.1 PunchHoleRequest ──

def test_punch_hole_request_fields() -> None:
    raw = proto.punch_hole_request("123456789", "K" * 43 + "=")
    kind, sub = proto.parse_rendezvous(raw)
    assert kind == "punch_hole_request"
    assert proto.get_str(sub, 1) == "123456789"
    assert proto.get_int(sub, 2) == 2                 # SYMMETRIC
    assert proto.get_str(sub, 3) == "K" * 43 + "="
    assert proto.get_int(sub, 4) == 0                 # DEFAULT_CONN（預設值不出現在線上）
    assert 4 not in sub
    assert proto.get_str(sub, 6) == "1.4.1"
    assert proto.get_int(sub, 8) == 1                 # force_relay
    # 不填 udp_port、upnp_port 之類的欄位
    assert set(sub) == {1, 2, 3, 6, 8}


def test_request_relay_to_hbbs_requires_secure() -> None:
    raw = proto.request_relay_hbbs("123456789", "u" * 36, "relay.example.com:21117")
    kind, sub = proto.parse_rendezvous(raw)
    assert kind == "request_relay"
    assert proto.get_str(sub, 1) == "123456789"
    assert proto.get_str(sub, 2) == "u" * 36
    assert proto.get_str(sub, 4) == "relay.example.com:21117"
    assert proto.get_int(sub, 5) == 1                 # secure 一定要填
    assert 6 not in sub                           # 4.3 的表沒有 licence_key


def test_request_relay_to_hbbr_carries_the_key() -> None:
    raw = proto.request_relay_hbbr("123456789", "u" * 36, "K" * 43 + "=")
    kind, sub = proto.parse_rendezvous(raw)
    assert kind == "request_relay"
    assert proto.get_str(sub, 6) == "K" * 43 + "="
    assert 5 not in sub


def test_parse_relay_response() -> None:
    body = proto.f_str(2, "u" * 36) + proto.f_str(3, "rd.example.com") + proto.f_bytes(5, b"p" * 109) + proto.f_str(7, "1.4.1")
    kind, sub = proto.parse_rendezvous(proto.f_msg(19, body))
    assert kind == "relay_response"
    rr = proto.RelayResponse.of(sub)
    assert rr.uuid == "u" * 36 and rr.relay_server == "rd.example.com"
    assert rr.pk == b"p" * 109 and rr.version == "1.4.1" and rr.refuse_reason == ""


def test_parse_punch_hole_failure_defaults_to_id_not_exist() -> None:
    # proto3：failure 欄位不存在＝0＝ID_NOT_EXIST
    kind, sub = proto.parse_rendezvous(proto.f_msg(11, b""))
    ph = proto.PunchHoleResponse.of(sub)
    assert kind == "punch_hole_response"
    assert ph.socket_addr == b"" and ph.failure == 0 and ph.other_failure == ""


# ── 6.1 hbbs 簽章過的受控端身分 ──

def _keys() -> tuple[Ed25519PrivateKey, str]:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, base64.b64encode(pub).decode()


def _signed(sk: Ed25519PrivateKey, msg: bytes) -> bytes:
    return sk.sign(msg) + msg                    # 簽章附訊息：前 64 bytes 是簽章


def test_signed_peer_identity_verifies() -> None:
    sk, pub = _keys()
    idpk = proto.f_str(1, "123456789") + proto.f_bytes(2, b"\x07" * 32)
    assert proto.verify_signed_id_pk(_signed(sk, idpk), pub, "123456789") == b"\x07" * 32


def test_forged_signature_is_rejected() -> None:
    sk, pub = _keys()
    other, _ = _keys()
    idpk = proto.f_str(1, "123456789") + proto.f_bytes(2, b"\x07" * 32)
    with pytest.raises(proto.HandshakeError) as e:
        proto.verify_signed_id_pk(_signed(other, idpk), pub, "123456789")
    assert e.value.code == "rd_bad_server_signature"


def test_tampered_message_is_rejected() -> None:
    sk, pub = _keys()
    signed = bytearray(_signed(sk, proto.f_str(1, "123456789") + proto.f_bytes(2, b"\x07" * 32)))
    signed[-1] ^= 1
    with pytest.raises(proto.HandshakeError) as e:
        proto.verify_signed_id_pk(bytes(signed), pub, "123456789")
    assert e.value.code == "rd_bad_server_signature"


def test_identity_for_another_id_is_rejected() -> None:
    sk, pub = _keys()
    idpk = proto.f_str(1, "999999999") + proto.f_bytes(2, b"\x07" * 32)
    with pytest.raises(proto.HandshakeError) as e:
        proto.verify_signed_id_pk(_signed(sk, idpk), pub, "123456789")
    assert e.value.code == "rd_bad_server_signature"


def test_missing_identity_refuses_to_downgrade() -> None:
    _sk, pub = _keys()
    with pytest.raises(proto.HandshakeError) as e:
        proto.verify_signed_id_pk(b"", pub, "123456789")
    assert e.value.code == "rd_insecure_refused"


def test_identity_without_peer_key_refuses_to_downgrade() -> None:
    sk, pub = _keys()
    with pytest.raises(proto.HandshakeError) as e:
        proto.verify_signed_id_pk(_signed(sk, proto.f_str(1, "123456789")), pub, "123456789")
    assert e.value.code == "rd_insecure_refused"


def test_bad_server_key_is_reported_as_signature_failure() -> None:
    sk, _pub = _keys()
    idpk = proto.f_str(1, "123456789") + proto.f_bytes(2, b"\x07" * 32)
    with pytest.raises(proto.HandshakeError) as e:
        proto.verify_signed_id_pk(_signed(sk, idpk), "not-base64!", "123456789")
    assert e.value.code == "rd_bad_server_signature"
