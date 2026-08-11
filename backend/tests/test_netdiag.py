"""網路診斷：目標驗證與輸出解析。不打真的網路 —— 用實機取得的輸出樣本。"""

from __future__ import annotations

import pathlib

import pytest
from app.services import netdiag as nd

# 本機 iputils ping 的實際輸出
_PING_OK = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=113 time=5.49 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=113 time=5.31 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 5.310/5.400/5.490/0.090 ms
"""
_PING_DEAD = """PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.

--- 192.0.2.1 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1024ms
"""
# tracepath 的實際輸出格式（位址改為文件保留範圍 RFC 5737，格式一字未改）
_TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.0.2.1                                           0.886ms
 1:  192.0.2.1                                           0.632ms
 2:  no reply
 3:  198.51.100.14                                        5.045ms
 4:  no reply
 5:  203.0.113.70                                         6.294ms asymm  7
     Too many hops: pmtu 1500
"""


def test_parse_ping_alive():
    r = nd.parse_ping_output("8.8.8.8", _PING_OK)
    assert r.alive is True
    assert (r.sent, r.received) == (2, 2)
    assert r.loss_pct == 0.0
    assert r.rtt_avg_ms == 5.400


def test_parse_ping_unreachable():
    r = nd.parse_ping_output("192.0.2.1", _PING_DEAD)
    assert r.alive is False
    assert r.received == 0
    assert r.loss_pct == 100.0
    assert r.rtt_avg_ms is None


def test_tracepath_keeps_hops_that_did_not_answer():
    """沒回應的躍點必須列出來。

    省略掉的話路徑看起來是 1→3→5 中間沒東西，讀的人會以為那幾跳不存在，
    而不是「不回應」—— 那是誤導，也是這裡曾經的 bug。
    """
    res = nd.parse_tracepath("8.8.8.8", _TRACEPATH)
    assert res.path_mtu == 1500
    assert [h.hop for h in res.hops] == [1, 2, 3, 4, 5]     # 2 與 4 不可消失
    assert res.hops[1].host is None
    assert res.hops[1].note == "無回應"
    assert res.hops[0].host == "192.0.2.1"                # 同一跳重複探測只留一筆
    assert res.hops[4].rtt_ms == 6.294


@pytest.mark.parametrize("raw", ["8.8.8.8", "example.com", "sub.example.co.uk", "2001:db8::1"])
def test_accepts_addresses_and_hostnames(raw):
    assert nd.normalize_target(raw)


@pytest.mark.parametrize("raw", [
    "$(whoami)", "`id`", "8.8.8.8|cat /etc/passwd", "../../etc/passwd",
    "-oProxyCommand=x", "", "   ", "a" * 300,
])
def test_rejects_anything_that_is_not_a_target(raw):
    """不經 shell 所以本來就不可能注入；這是第二道防線，也擋掉會被誤當旗標的字串。"""
    with pytest.raises(nd.NetDiagError):
        nd.normalize_target(raw)


def test_cidr_expands_to_hosts():
    assert nd.expand_targets("192.0.2.0/30") == ["192.0.2.1", "192.0.2.2"]


def test_mixed_separators_and_dedup():
    assert nd.expand_targets("8.8.8.8, 8.8.8.8\n1.1.1.1  8.8.4.4") == [
        "8.8.8.8", "1.1.1.1", "8.8.4.4"]


def test_target_cap_is_enforced():
    """沒有上限的話一個 /16 就是六萬多個目標，等於把伺服器當掃描器用。"""
    with pytest.raises(nd.NetDiagError, match="上限"):
        nd.expand_targets("10.0.0.0/16")
    assert len(nd.expand_targets(f"192.0.2.0/{32 - 6}")) <= nd.MAX_TARGETS


def test_unavailable_is_a_distinct_error():
    """端點靠這個分辨 501（環境缺工具）與其他錯誤；混在一起會把兩種問題講成同一種。"""
    assert issubclass(nd.NetDiagUnavailable, nd.NetDiagError)


def test_tool_availability_shape():
    caps = nd.tool_availability()
    assert set(caps) == {"ping", "tracepath", "traceroute", "tcp"}
    assert caps["tcp"] is True      # 純 Python，不依賴外部指令


def test_udp_probe_payloads_are_real_protocol_packets():
    """空封包多數服務不會回應 —— 常見埠要送真的協定封包才拿得到「確定開啟」。"""
    dns_name, dns_pkt = nd._UDP_PROBES[53]
    assert dns_name == "dns"
    assert dns_pkt[2:4] == b"\x01\x00"          # standard query, RD
    assert dns_pkt[-4:] == b"\x00\x02\x00\x01"  # NS / IN
    ntp_name, ntp_pkt = nd._UDP_PROBES[123]
    assert ntp_name == "ntp"
    assert len(ntp_pkt) == 48
    assert ntp_pkt[0] == 0x1B          # LI=0 VN=3 Mode=3 (client)


@pytest.mark.parametrize(("probe", "data", "expected"), [
    ("dns", b"\x12\x34\x81\x80" + b"\x00" * 8, "DNS NOERROR"),
    ("dns", b"\x12\x34\x81\x83" + b"\x00" * 8, "DNS NXDOMAIN"),
    ("dns", b"\x12\x34\x81\x85" + b"\x00" * 8, "DNS REFUSED"),
    ("ntp", b"\x1c\x03" + b"\x00" * 46, "NTP stratum 3"),
    ("empty", b"whatever", None),
    ("dns", b"\x12", None),                     # 太短不能亂解讀
])
def test_reply_is_described_in_human_terms(probe, data, expected):
    assert nd._describe_reply(probe, data) == expected


def test_udp_states_are_three_not_two():
    """「沒有回應」在 UDP 無法判定，必須自成一態。

    把它顯示成「開啟」是安靜地說謊：可能開著不回應、被防火牆丟棄、或封包遺失。
    這裡守的是資料結構本身 —— 預設值就是 no_reply，而不是 open 或 closed。
    """
    r = nd.UdpResult(target="192.0.2.1", port=161)
    assert r.state == "no_reply"


def test_hostname_matching_follows_san_then_cn_with_wildcards():
    assert nd._hostname_matches("a.example.com", "CN=x", ["a.example.com"])
    assert nd._hostname_matches("a.example.com", "CN=x", ["*.example.com"])
    assert not nd._hostname_matches("a.b.example.com", "CN=x", ["*.example.com"])  # 只吃一層
    assert not nd._hostname_matches("other.com", "CN=x", ["a.example.com"])
    # 沒有 SAN 才退回 CN —— 有 SAN 就不該再看 CN
    assert nd._hostname_matches("host.example", "host.example", [])
    assert not nd._hostname_matches("host.example", "host.example", ["other.example"])


def test_ping_failure_message_does_not_claim_the_target_is_down():
    """權限不足時不能只說「沒有回應」—— 那會被讀成「目標不通」。"""
    src = (pathlib.Path(nd.__file__)).read_text()
    assert "這不代表目標不可達" in src
    assert "ping_group_range" in src


# ── uvloop 沒有 sock_sendto / sock_recv ──────────────────────────────────────
# 實測：在「非特權 ICMP socket 開得起來」的機器上，ping 端點直接 500（uvloop 對
# loop.sock_sendto 丟 NotImplementedError）。諷刺的是**開不起來**的機器反而正常，
# 因為它會退回外部 ping —— 所以這個錯只在把 ping_group_range 放寬之後才會冒出來，
# 也就是照著我們自己給的排除說明做之後。

async def test_sock_sendto_falls_back_when_loop_lacks_it():
    import socket as _socket

    from app.services.netdiag import _sock_sendto

    class _FakeLoop:
        async def sock_sendto(self, *a, **kw):
            raise NotImplementedError            # uvloop 就是這樣

        async def run_in_executor(self, _ex, fn, *args):
            return fn(*args)

    sent: list[tuple] = []

    class _FakeSock:
        def sendto(self, data, addr):
            sent.append((data, addr))
            return len(data)

    await _sock_sendto(_FakeLoop(), _FakeSock(), b"payload", ("127.0.0.1", 0))
    assert sent == [(b"payload", ("127.0.0.1", 0))]
    assert _socket  # 只是確保 import 沒被 lint 掉


async def test_sock_recv_falls_back_when_loop_lacks_it():
    from app.services.netdiag import _sock_recv

    class _FakeLoop:
        def __init__(self):
            self.readers: dict[int, object] = {}

        async def sock_recv(self, *a, **kw):
            raise NotImplementedError

        def create_future(self):
            import asyncio as _a
            return _a.get_running_loop().create_future()

        def add_reader(self, fd, cb):
            self.readers[fd] = cb
            cb()                                  # 立刻可讀

        def remove_reader(self, fd):
            self.readers.pop(fd, None)

    class _FakeSock:
        def fileno(self):
            return 999

        def recv(self, n):
            return b"reply"[:n]

    assert await _sock_recv(_FakeLoop(), _FakeSock(), 16) == b"reply"
