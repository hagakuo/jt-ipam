"""ICMP 送封包的兩條路：非特權 datagram socket，與需要 CAP_NET_RAW 的 raw socket。

實機（LXC + 服務沙箱）踩到的組合：

1. `net.ipv4.ping_group_range` 在容器內唯讀 → 非特權 datagram socket 開不起來
2. 退回外部 `/usr/bin/ping` → **被 `SystemCallFilter=~@privileged` 的 seccomp 殺掉**，
   因為 iputils 的 ping 啟動時會呼叫 `capset()` 丟棄多餘權限。行程直接 SIGSYS，
   連錯誤訊息都沒有，畫面只能顯示「無法送出封包」。
3. 但**行程自己**開 raw socket 完全沒問題：它持有 ambient CAP_NET_RAW，
   而 socket / sendto / recvfrom 都在允許清單內。

所以正解是自己送，不要 exec —— 也不必為了 ping 放寬沙箱。
"""
from __future__ import annotations

import socket

from app.services import netdiag


def test_icmp_socket_kind_prefers_unprivileged(monkeypatch):
    """兩種都可用時要選非特權的 —— 它不需要任何 capability。"""
    monkeypatch.setattr(netdiag, "_can_open", lambda kind: True)
    assert netdiag.icmp_socket_kind() == socket.SOCK_DGRAM


def test_falls_back_to_raw_when_unprivileged_is_blocked(monkeypatch):
    """LXC 的情況：ping_group_range 改不動，但有 CAP_NET_RAW。"""
    monkeypatch.setattr(netdiag, "_can_open", lambda kind: kind == socket.SOCK_RAW)
    assert netdiag.icmp_socket_kind() == socket.SOCK_RAW


def test_none_when_neither_is_available(monkeypatch):
    monkeypatch.setattr(netdiag, "_can_open", lambda kind: False)
    assert netdiag.icmp_socket_kind() is None


def test_icmp_socket_available_still_reflects_either(monkeypatch):
    """舊的布林 API 要涵蓋兩條路，否則呼叫端會以為完全不能送。"""
    monkeypatch.setattr(netdiag, "_can_open", lambda kind: kind == socket.SOCK_RAW)
    assert netdiag.icmp_socket_available() is True


def test_raw_reply_parsing_skips_the_ip_header():
    """raw socket 收到的封包**含 IP 標頭**，datagram socket 不含。

    不跳過的話會把 IP 標頭當成 ICMP 來讀，永遠對不到 seq —— 表現就是「送得出去、
    但每一個都逾時」，比完全不能送更難查。
    """
    # 20 byte IP 標頭（IHL=5）＋ echo reply（type 0），seq=7
    ip_hdr = bytes([0x45]) + bytes(19)
    icmp = bytes([0, 0, 0, 0, 0x12, 0x34, 0, 7])
    assert netdiag._icmp_payload(ip_hdr + icmp, socket.SOCK_RAW) == icmp
    assert netdiag._icmp_payload(icmp, socket.SOCK_DGRAM) == icmp


def test_raw_reply_with_options_uses_the_ihl_field():
    """IP 標頭長度由 IHL 決定，不是固定 20 —— 寫死 20 遇到帶選項的封包就錯位。"""
    ip_hdr = bytes([0x46]) + bytes(23)      # IHL=6 → 24 bytes
    icmp = bytes([0, 0, 0, 0, 0x12, 0x34, 0, 9])
    assert netdiag._icmp_payload(ip_hdr + icmp, socket.SOCK_RAW) == icmp


def test_reply_matching_ignores_other_icmp_traffic():
    """raw socket 會收到本機所有 ICMP —— 自己的 request、別人的回應都會進來。

    只認 type 0（echo reply）且 id 與 seq 都對得上的那一個。少了這層過濾，
    實測 127.0.0.1 會變成 0/2、區網主機掉一半，看起來像網路有問題。
    """
    import struct
    ident, seq = 0x1234, 5

    def reply(i: int, sq: int, typ: int = 0) -> bytes:
        return bytes([typ, 0, 0, 0]) + struct.pack("!HH", i, sq)

    own_request = reply(ident, seq, typ=8)        # 我們自己送的那一個
    other_host = reply(0x9999, seq)               # 別的行程在 ping 別台
    wrong_seq = reply(ident, seq + 1)             # 上一輪的回應
    correct = reply(ident, seq)

    def matches(msg: bytes) -> bool:
        if len(msg) < 8 or msg[0] != 0:
            return False
        got_id, got_seq = struct.unpack("!HH", msg[4:8])
        return got_seq == seq and got_id == ident

    assert not matches(own_request)
    assert not matches(other_host)
    assert not matches(wrong_seq)
    assert matches(correct)
