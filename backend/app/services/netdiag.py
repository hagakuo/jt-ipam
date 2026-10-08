"""網路診斷：ping / 路徑追蹤 / TCP 埠連通性。

與 `nettools.py`（純計算）分開：這裡會**實際送封包**，所以安全考量完全不同。

三個不可妥協的原則：

1. **絕不經過 shell。** 一律 `create_subprocess_exec` 加參數陣列 —— 目標字串永遠是
   一個獨立引數，不會被解讀成指令。目標另有嚴格驗證當第二道防線。
2. **一定有上限。** 目標數、併發數、單目標逾時、整體期限都設上限，避免一個請求
   就把伺服器或網路打爆（也避免被當成掃描跳板）。
3. **工具不存在要講清楚。** `traceroute` 在 Debian 預設不裝，這裡優先用 iputils 的
   `tracepath`（不需特權）；都沒有時回可行動的訊息，而不是一句「失敗」。

⚠️ ICMP 需要 `cap_net_raw`。Debian/Ubuntu 的 `ping` 預設帶 `cap_net_raw=ep`，所以
非 root 的服務帳號可以用；若某些環境把 capability 拔掉，ping 會失敗且訊息會指出這點。
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import re
import shutil
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.ui_error import UiError

MAX_TARGETS = 64
MAX_CONCURRENCY = 32
MAX_COUNT = 10
MAX_HOPS = 30
OVERALL_DEADLINE = 120.0        # 單一請求的總時限，避免長時間佔住連線

# 主機名稱：字母/數字/連字號/點，且不以連字號起訖。這是第二道防線 ——
# 我們不經 shell，所以注入本來就不可能；但把明顯不是主機名稱的東西擋在外面仍然值得。
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)


class NetDiagError(UiError, ValueError):
    """輸入不合法或環境缺工具。"""


class NetDiagUnavailable(NetDiagError):
    """伺服器上沒有需要的工具 —— 端點回 501（不是使用者的錯，也不是逾時）。"""


def normalize_target(raw: str) -> str:
    """接受 IP 或主機名稱，其餘拒絕。回傳去空白後的字串。"""
    t = (raw or "").strip()
    if not t:
        raise NetDiagError("目標不可為空", code="nd_target_empty")
    if len(t) > 253:
        raise NetDiagError("目標過長", code="nd_target_too_long")
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(t):
        return t
    raise NetDiagError(f"不是有效的 IP 或主機名稱：{raw}", code="nd_bad_target", value=raw)


def expand_targets(raw: str | list[str]) -> list[str]:
    """把使用者輸入（換行/逗號/空白分隔，或 CIDR）展開成目標清單。

    支援 CIDR 是因為「這個網段裡哪些有回應」是最常見的用途；但要卡上限，
    不然一個 /16 就是六萬多個目標。
    """
    if isinstance(raw, list):
        parts = raw
    else:
        parts = [p for p in re.split(r"[\s,;]+", raw or "") if p]

    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        if "/" in p:
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError as exc:
                raise NetDiagError(f"不是有效的網段：{p}", code="nd_bad_cidr", value=p) from exc
            hosts = list(net.hosts()) or [net.network_address]
            if len(out) + len(hosts) > MAX_TARGETS:
                raise NetDiagError(
                    f"{p} 展開後超過上限（最多 {MAX_TARGETS} 個目標）",
                    code="nd_cidr_too_big", value=p, max=MAX_TARGETS,
                )
            for h in hosts:
                s = str(h)
                if s not in seen:
                    seen.add(s)
                    out.append(s)
            continue
        t = normalize_target(p)
        if t not in seen:
            seen.add(t)
            out.append(t)
    if not out:
        raise NetDiagError("沒有可用的目標", code="nd_no_targets")
    if len(out) > MAX_TARGETS:
        raise NetDiagError(f"目標過多（{len(out)}），最多 {MAX_TARGETS} 個",
                           code="nd_too_many_targets", n=len(out), max=MAX_TARGETS)
    return out


ICMP_BLOCKED = (
    "ping 無法送出封包：服務沙箱使 cap_net_raw 失效，且此群組不在 "
    "net.ipv4.ping_group_range 內。這不代表目標不可達。"
)


@dataclass
class PingResult:
    target: str
    alive: bool = False
    sent: int = 0
    received: int = 0
    loss_pct: float | None = None
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    rtt_max_ms: float | None = None
    error: str | None = None
    # 機器可辨識的失敗原因（目前只有 "icmp_blocked"）。讓 UI 能在旁邊放「怎麼修」的
    # 說明 —— 只丟一句錯誤訊息，使用者知道壞了卻不知道要做什麼。
    error_code: str | None = None


# `ping -c N -W t` 的統計行，各發行版格式略有差異，只抓需要的數字
_STATS_RE = re.compile(r"(\d+) packets transmitted,\s*(\d+)\s*(?:packets )?received")
_RTT_RE = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?\s*ms")


def parse_ping_output(target: str, out: str) -> PingResult:
    """解析 ping 輸出（純函式，好測；不同發行版的措辭差異都在這裡吸收）。"""
    r = PingResult(target=target)
    m = _STATS_RE.search(out)
    if m:
        r.sent, r.received = int(m.group(1)), int(m.group(2))
        r.alive = r.received > 0
        if r.sent:
            r.loss_pct = round((r.sent - r.received) / r.sent * 100, 1)
    m2 = _RTT_RE.search(out)
    if m2:
        r.rtt_min_ms = float(m2.group(1))
        r.rtt_avg_ms = float(m2.group(2))
        r.rtt_max_ms = float(m2.group(3))
    return r


async def _run(argv: list[str], timeout: float) -> tuple[int, str]:
    """執行外部指令並取合併輸出。逾時就砍掉，不留孤兒程序。"""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        data, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, data.decode(errors="replace")


async def _run_partial(argv: list[str], timeout: float) -> tuple[str, bool]:
    """同上，但**逾時時回傳已經收到的輸出**而不是丟掉。

    路徑追蹤會逐跳印出結果，跑不完就整個放棄等於把已經查到的路徑丟掉 ——
    對診斷來說，「前 8 跳長這樣、後面沒跑完」遠比「逾時」有用。
    回 (輸出, 是否被截斷)。
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    chunks: list[bytes] = []
    truncated = False
    assert proc.stdout is not None
    try:
        async with asyncio.timeout(timeout):
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                chunks.append(line)
    except TimeoutError:
        truncated = True
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
    return b"".join(chunks).decode(errors="replace"), truncated


def _ping_binary(target: str) -> str:
    """IPv6 目標在較舊的系統要用 ping6；新版 iputils 的 ping 兩者通吃。"""
    try:
        v6 = ipaddress.ip_address(target).version == 6
    except ValueError:
        v6 = False
    if v6 and shutil.which("ping") is None and shutil.which("ping6"):
        return "ping6"
    return "ping"


def _can_open(kind: int) -> bool:
    import socket
    try:
        sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
    except OSError:
        return False
    sock.close()
    return True


def icmp_socket_kind() -> int | None:
    """這台機器能用哪一種 ICMP socket 送封包（不能就回 None）。

    優先非特權的 datagram socket：`net.ipv4.ping_group_range` 就是為此而生，
    群組落在範圍內即可送 ICMP，**不需要任何 capability**。

    退而求其次用 raw socket（需要 CAP_NET_RAW）。**LXC 容器一定走這條** ——
    那個 sysctl 屬於宿主核心，容器內改不動。

    為什麼不退回外部 `/usr/bin/ping`：服務單元的
    `SystemCallFilter=~@privileged` 會直接殺掉它 —— iputils 的 ping 啟動時呼叫
    `capset()` 丟棄多餘權限，那支被 seccomp 擋下，行程 SIGSYS 結束、連錯誤訊息都沒有。
    自己送就沒有這個問題，也不必為了 ping 放寬沙箱。
    """
    import socket
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        if _can_open(kind):
            return kind
    return None


def icmp_socket_available() -> bool:
    """能不能自己送 ICMP（兩種 socket 任一可用即可）。"""
    return icmp_socket_kind() is not None


def _icmp_payload(data: bytes, kind: int) -> bytes:
    """從收到的封包取出 ICMP 部分。

    raw socket 收到的**含 IP 標頭**，datagram socket 不含。不跳過的話會把 IP 標頭
    當成 ICMP 讀，永遠對不到 seq —— 表現是「送得出去但每一個都逾時」，比完全不能送更難查。

    標頭長度看 IHL（第一個 byte 的低 4 bits × 4），不是固定 20：帶選項的封包會更長。
    """
    import socket
    if kind != socket.SOCK_RAW or not data:
        return data
    ihl = (data[0] & 0x0F) * 4
    return data[ihl:] if 0 < ihl <= len(data) else data


def _icmp_echo(seq: int, ident: int, payload: bytes = b"jt-ipam") -> bytes:
    """組一個 ICMP echo request（type 8）。核心會在送出時填好識別碼。"""
    import struct
    head = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    chk = _checksum(head + payload)
    return struct.pack("!BBHHH", 8, 0, chk, ident, seq) + payload


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


async def _sock_sendto(loop: Any, sock: Any, data: bytes, addr: Any) -> None:
    """`loop.sock_sendto`，uvloop 上退回執行緒版本。

    uvloop 沒有實作 `sock_sendto`，直接呼叫會丟 `NotImplementedError`。socket 是
    non-blocking 的，`sendto` 不會卡住，丟到執行緒只是為了拿到一致的介面。
    """
    try:
        await loop.sock_sendto(sock, data, addr)
    except NotImplementedError:
        await loop.run_in_executor(None, sock.sendto, data, addr)


async def _sock_recv(loop: Any, sock: Any, n: int) -> bytes:
    """`loop.sock_recv`；uvloop 沒有時退回自己等可讀。"""
    try:
        return await loop.sock_recv(sock, n)
    except NotImplementedError:
        fut = loop.create_future()

        def _ready() -> None:
            loop.remove_reader(sock.fileno())
            if not fut.done():
                try:
                    fut.set_result(sock.recv(n))
                except OSError as exc:
                    fut.set_exception(exc)

        loop.add_reader(sock.fileno(), _ready)
        try:
            return await fut
        finally:
            try:
                loop.remove_reader(sock.fileno())
            except (OSError, ValueError):
                pass


# 封包之間的間隔（秒）。標準 ping 是 1 秒，網頁上等 10 秒太久；0.25 秒既能拉開時間軸
# （看得到抖動與間歇掉包），10 次也只要 2.5 秒。**不能小於 0.2** —— iputils 的 ping
# 在 -i < 0.2 時要求 root，那會讓外部那條路整個不能用。
PING_INTERVAL = 0.25


def ping_argv(target: str, *, count: int, timeout: float) -> list[str]:
    """外部 ping 的指令。明確帶 -i，不要靠它每秒一個的預設值 —— 那會讓同一組設定
    在兩條路徑上量到完全不同的東西（自己送 0.05 秒 vs 外部 9 秒）。"""
    return [_ping_binary(target), "-n", "-c", str(count),
            "-i", str(PING_INTERVAL),
            "-W", str(int(max(1, timeout))), target]


async def _ping_native(target: str, count: int, timeout: float) -> PingResult:
    """用非特權 ICMP socket 自己送 echo request。

    不呼叫外部 `ping` 的原因：服務單元設了 `NoNewPrivileges=true`，那會讓 `ping` 的
    file capability（cap_net_raw）**完全失效** —— 在 shell 裡好好的，在服務底下卻連
    127.0.0.1 都不通。自己開 datagram socket 就不需要任何 capability。
    """
    import socket
    import struct

    res = PingResult(target=target, sent=count)
    kind = icmp_socket_kind()
    if kind is None:
        res.error = ICMP_BLOCKED
        res.error_code = "icmp_blocked"
        return res
    loop = asyncio.get_running_loop()
    try:
        addr = await loop.getaddrinfo(target, None, family=socket.AF_INET,
                                      type=socket.SOCK_DGRAM)
        ip = addr[0][4][0]
    except OSError as exc:
        res.error = f"名稱解析失敗：{exc.strerror or exc}"
        return res

    rtts: list[float] = []
    ident = os.getpid() & 0xFFFF
    for seq in range(count):
        # 封包之間要拉開 —— 連發量到的是同一個 50 毫秒瞬間，看不到抖動也看不到
        # 間歇掉包，而且對 ICMP 有速率限制的裝置會回報出不存在的遺失。
        if seq:
            await asyncio.sleep(PING_INTERVAL)
        sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        try:
            t0 = time.monotonic()
            # uvloop 沒有實作 loop.sock_sendto（會丟 NotImplementedError）。
            # 不接住的話整支請求會 500 —— 而且只在「socket 開得起來」的機器上才會發生，
            # 開不起來的機器反而正常（因為走外部 ping）。
            await _sock_sendto(loop, sock, _icmp_echo(seq, ident), (ip, 0))
            # **要讀到對的那一個為止**。raw socket 會收到本機所有的 ICMP 流量 ——
            # 包括我們自己剛送出的那一個 request（loopback 上一定看得到）、
            # 以及其他行程 ping 別台的往來。只讀一次的話，讀到不相干的封包就會被
            # 當成逾時：實測 127.0.0.1 變成 0/2、區網主機掉一半，看起來像網路有問題。
            deadline = t0 + timeout
            while True:
                remain = deadline - time.monotonic()
                if remain <= 0:
                    break
                try:
                    data = await asyncio.wait_for(_sock_recv(loop, sock, 1024), timeout=remain)
                except TimeoutError:
                    break
                msg = _icmp_payload(data, kind)
                if len(msg) < 8 or msg[0] != 0:      # type 0 = echo reply
                    continue                          # 自己的 request（type 8）等等
                got_id, got_seq = struct.unpack("!HH", msg[4:8])
                # datagram socket 的 id 由核心改寫，只能比對 seq；raw 兩個都比對，
                # 才不會把別人的回應算成自己的
                if got_seq == seq and (kind != socket.SOCK_RAW or got_id == ident):
                    rtts.append((time.monotonic() - t0) * 1000)
                    break
        except OSError as exc:
            res.error = exc.strerror or str(exc)
            return res
        finally:
            sock.close()

    res.received = len(rtts)
    res.alive = res.received > 0
    res.loss_pct = round((count - res.received) / count * 100, 1)
    if rtts:
        res.rtt_min_ms = round(min(rtts), 3)
        res.rtt_avg_ms = round(sum(rtts) / len(rtts), 3)
        res.rtt_max_ms = round(max(rtts), 3)
    return res


async def ping_many(
    targets: list[str], *, count: int = 3, timeout: float = 2.0, concurrency: int = 8,
) -> list[PingResult]:
    """對多個目標並行 ping。回傳順序與輸入一致（方便逐列對照）。"""
    native = icmp_socket_available()
    if not native and shutil.which("ping") is None and shutil.which("ping6") is None:
        raise NetDiagUnavailable("伺服器上找不到 ping（請安裝 iputils-ping）", code="nd_no_ping")
    count = max(1, min(count, MAX_COUNT))
    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    timeout = max(0.5, min(timeout, 10.0))
    # 單目標最壞情況約 count × timeout，再加點餘裕；另有整體期限兜底
    per_target = count * (timeout + PING_INTERVAL) + 5.0
    sem = asyncio.Semaphore(concurrency)
    started = time.monotonic()

    async def one(t: str) -> PingResult:
        async with sem:
            if time.monotonic() - started > OVERALL_DEADLINE:
                return PingResult(target=t, error="整體時間上限已到，未執行")
            if native:
                return await _ping_native(t, count, timeout)
            argv = ping_argv(t, count=count, timeout=timeout)
            try:
                _, out = await _run(argv, per_target)
            except TimeoutError:
                return PingResult(target=t, sent=count, received=0, loss_pct=100.0,
                                  error="逾時")
            except OSError as exc:
                return PingResult(target=t, error=f"無法執行 ping：{exc}")
            res = parse_ping_output(t, out)
            if not res.sent and not res.alive:
                # 沒有統計行通常是名稱解析失敗一類；把第一行原文帶回去比「失敗」有用
                first = next((ln for ln in out.splitlines() if ln.strip()), "")
                # 外部 ping 一個字都沒吐＝它自己起不來，多半是 NoNewPrivileges 讓
                # cap_net_raw 失效。回「沒有回應」會被誤讀成「目標不通」——那是說謊。
                # 帶一個機器可辨識的代碼，前端才能在旁邊給「怎麼修」的說明。
                # 只丟一句「送不出封包」，使用者知道壞了卻不知道要做什麼。
                res.error = first[:200] or ICMP_BLOCKED
                if not first:
                    res.error_code = "icmp_blocked"
            return res

    return list(await asyncio.gather(*(one(t) for t in targets)))


@dataclass
class TraceHop:
    hop: int
    host: str | None = None
    fqdn: str | None = None      # 反查得到的名稱（查不到＝None，不顯示）
    rtt_ms: float | None = None
    note: str | None = None


@dataclass
class TraceResult:
    target: str
    tool: str
    hops: list[TraceHop] = field(default_factory=list)
    path_mtu: int | None = None
    truncated: bool = False      # 逾時被截斷：下面的躍點是已探到的部分，不是完整路徑
    reached: bool = False        # 最後一跳是不是目的地本人 —— 不是的話要明講，不能默默停在半路
    raw: str = ""


# tracepath 每一跳可能印多行（每次探測一行），沒回應的那跳印 "no reply"。
_TRACEPATH_RE = re.compile(r"^\s*(\d+):\s+(no reply|\S+)\s*(?:([\d.]+)ms)?(.*)$")
_TRACEROUTE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_PMTU_RE = re.compile(r"pmtu\s+(\d+)")


def parse_tracepath(target: str, out: str) -> TraceResult:
    """解析 tracepath 輸出（含路徑 MTU —— traceroute 沒有這個資訊）。"""
    res = TraceResult(target=target, tool="tracepath", raw=out)
    seen: set[int] = set()
    for line in out.splitlines():
        m = _PMTU_RE.search(line)
        if m and res.path_mtu is None:
            res.path_mtu = int(m.group(1))
        m2 = _TRACEPATH_RE.match(line)
        if not m2:
            continue
        hop = int(m2.group(1))
        host = m2.group(2)
        if host == "[LOCALHOST]" or hop in seen:
            continue          # 同一跳的重複探測只留第一筆
        seen.add(hop)
        no_reply = host == "no reply"
        # 沒回應的那一跳仍然要列出來。把它省略會讓路徑看起來 1→3→5 中間沒東西，
        # 讀的人會以為那幾跳不存在，而不是「不回應」——那是誤導。
        res.hops.append(TraceHop(
            hop=hop,
            host=None if no_reply else host,
            rtt_ms=float(m2.group(3)) if m2.group(3) else None,
            note="無回應" if no_reply else ((m2.group(4) or "").strip() or None),
        ))
    return res


def parse_traceroute(target: str, out: str) -> TraceResult:
    res = TraceResult(target=target, tool="traceroute", raw=out)
    for line in out.splitlines():
        m = _TRACEROUTE_RE.match(line)
        if not m or line.lstrip().startswith("traceroute"):
            continue
        rest = m.group(2).strip()
        rtt = re.search(r"([\d.]+)\s*ms", rest)
        host = None if rest.startswith("*") else rest.split()[0]
        res.hops.append(TraceHop(
            hop=int(m.group(1)), host=host,
            rtt_ms=float(rtt.group(1)) if rtt else None,
            note=None if host else "無回應",
        ))
    return res


async def traceroute(target: str, *, max_hops: int = 20, timeout: float = 0.0) -> TraceResult:
    """路徑追蹤。

    優先用 `tracepath`：Debian/Ubuntu 的 iputils 內建、**不需特權**，而且會回報
    路徑 MTU（診斷 MTU 黑洞很有用）。沒有才退回 `traceroute`。
    """
    max_hops = max(1, min(max_hops, MAX_HOPS))
    # 逾時要跟著躍點數走：對不回 port-unreachable 的目標（如 8.8.8.8），tracepath
    # 會一路探到最大躍點，每跳都要等。固定 45 秒配預設 20 跳＝開箱必定逾時。
    timeout = max(5.0, min(timeout if timeout > 0 else 6.0 + max_hops * 3.5, OVERALL_DEADLINE))
    tr = _find_tool("traceroute")
    if tr:
        argv = [tr, "-I", "-n", "-q", "1", "-m", str(max_hops), "-w", "2", target]
        parse = parse_traceroute
    elif shutil.which("tracepath"):
        argv = ["tracepath", "-n", "-m", str(max_hops), target]
        parse = parse_tracepath
    else:
        raise NetDiagUnavailable(
            "伺服器上找不到 traceroute 或 tracepath（請安裝 traceroute）",
            code="nd_no_traceroute",
        )
    try:
        out, truncated = await _run_partial(argv, timeout)
    except OSError as exc:
        raise NetDiagError(f"無法執行：{exc}", code="nd_exec_failed", reason=str(exc)[:200]) from exc
    res = parse(target, out)
    res.truncated = truncated
    return res



class TracepathIncremental:
    """逐行解析 tracepath 輸出，一次吐一跳。

    與 `parse_tracepath` 規則相同（同一跳的重複探測只留第一筆、`[LOCALHOST]` 不算一跳、
    沒回應的那跳照樣列出來），差別只在它是邊讀邊吐，好讓畫面能一列一列長出來。
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self.path_mtu: int | None = None
        self._seen: set[int] = set()

    def feed(self, line: str) -> dict[str, Any] | None:
        m = _PMTU_RE.search(line)
        if m and self.path_mtu is None:
            self.path_mtu = int(m.group(1))
        m2 = _TRACEPATH_RE.match(line)
        if not m2:
            return None
        hop = int(m2.group(1))
        host = m2.group(2)
        if host == "[LOCALHOST]" or hop in self._seen:
            return None
        self._seen.add(hop)
        no_reply = host == "no reply"
        return {
            "type": "hop", "hop": hop,
            "host": None if no_reply else host,
            "rtt_ms": float(m2.group(3)) if m2.group(3) else None,
            # note 可能是路由器回的旗標（`!H`…）原文，所以留著；「無回應」是我們自己
            # 造的句子，另外給代碼讓前端翻得動。
            "note": "無回應" if no_reply else ((m2.group(4) or "").strip() or None),
            "note_code": "nd_no_reply" if no_reply else None,
        }


class TracerouteIncremental:
    """`traceroute` 的逐行版（沒有 tracepath 時的退路）。"""

    def __init__(self, target: str) -> None:
        self.target = target
        self.path_mtu: int | None = None

    def feed(self, line: str) -> dict[str, Any] | None:
        m = _TRACEROUTE_RE.match(line)
        if not m or line.lstrip().startswith("traceroute"):
            return None
        rest = m.group(2).strip()
        rtt = re.search(r"([\d.]+)\s*ms", rest)
        host = None if rest.startswith("*") else rest.split()[0]
        return {
            "type": "hop", "hop": int(m.group(1)), "host": host,
            "rtt_ms": float(rtt.group(1)) if rtt else None,
            "note": None if host else "無回應",
            "note_code": None if host else "nd_no_reply",
        }


def _find_tool(name: str) -> str | None:
    """找執行檔：服務的 PATH 常常沒有 /usr/sbin（systemd 環境），traceroute 就住在那
    —— shutil.which 找不到不代表沒裝。明確補查常見 sbin 路徑。"""
    import os
    found = shutil.which(name)
    if found:
        return found
    for cand in (f"/usr/sbin/{name}", f"/sbin/{name}", f"/usr/local/sbin/{name}"):
        if os.access(cand, os.X_OK):
            return cand
    return None


async def rdns(ip: str, timeout: float = 0.8) -> str | None:
    """反查 FQDN：查得到就附在節點旁（跟終端機 traceroute 的體驗一致）。

    短逾時、失敗回 None —— 反查慢或沒有 PTR 不該拖慢整條追蹤，更不該報錯。
    """
    import socket
    try:
        loop = asyncio.get_running_loop()
        name, _ = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout=timeout)
        return None if name == ip else name
    except Exception:
        return None


def trace_argv(target: str, *, max_hops: int) -> list[str]:
    """組出路徑追蹤的指令。

    **前面掛 `stdbuf -oL` 是這整個功能的關鍵**：C 程式的 stdout 接到 pipe 時是整塊
    緩衝的，所有行會等到行程結束才一次湧出（實測 6.02 秒時全部到達）。加了它才會
    +0.02 / +3.02 / +6.03 逐行送達。沒有 stdbuf 的系統仍可執行，只是退回一次呈現。
    """
    # 優先 `traceroute -I`（ICMP）：tracepath 用 UDP 高埠，路徑後段與許多目的地
    # （例如 8.8.8.8 之前的骨幹）會把它濾掉 —— 實測同一條路 mac 的 traceroute
    # 9 跳到站，tracepath 第 8 跳起全靜默、永遠「未到達」。ICMP echo 幾乎都放行。
    # CAP_NET_RAW 已由 systemd AmbientCapabilities 授予且子行程繼承（LXC ping 同一套）。
    tr = _find_tool("traceroute")
    if tr:
        argv = [tr, "-I", "-n", "-q", "1", "-m", str(max_hops), "-w", "2", target]
    elif shutil.which("tracepath"):
        argv = ["tracepath", "-n", "-m", str(max_hops), target]
    else:
        raise NetDiagUnavailable(
            "伺服器上找不到 traceroute 或 tracepath（請安裝 traceroute）",
            code="nd_no_traceroute",
        )
    return (["stdbuf", "-oL", *argv] if shutil.which("stdbuf") else argv)


async def traceroute_stream(
    target: str, *, max_hops: int = 20, timeout: float = 0.0,
) -> AsyncIterator[dict[str, Any]]:
    """邊跑邊吐：每解析出一跳就 yield 一個 hop，結束時 yield 一個 done。

    沒回應的躍點要等滿逾時才能確定，15 跳可能要 30～60 秒 —— 全部壓到最後才呈現的話，
    使用者只會看到一個按下去長時間毫無反應的按鈕，分不出是在跑、卡住、還是壞了。
    """
    max_hops = max(1, min(max_hops, MAX_HOPS))
    timeout = max(5.0, min(timeout if timeout > 0 else 6.0 + max_hops * 3.5, OVERALL_DEADLINE))
    argv = trace_argv(target, max_hops=max_hops)
    # argv 可能被 stdbuf -oL 前綴，判斷工具要掃整個 argv，不能只看第一個
    tool = "traceroute" if any("traceroute" in a for a in argv[:3]) else "tracepath"
    parser: Any = (TracepathIncremental(target) if tool == "tracepath"
                   else TracerouteIncremental(target))

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        raise NetDiagError(f"無法執行：{exc}", code="nd_exec_failed", reason=str(exc)[:200]) from exc

    truncated = False
    last_host: str | None = None
    deadline = time.monotonic() + timeout
    try:
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                truncated = True
                break
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=remain)
            except TimeoutError:
                truncated = True
                break
            if not raw:
                break
            hop = parser.feed(raw.decode("utf-8", "replace").rstrip())
            if hop:
                host = hop.get("host")
                if host and hop.get("note") != "no reply":
                    last_host = str(host)
                    hop["fqdn"] = await rdns(last_host)
                yield hop
    finally:
        # 逾時或用戶端中斷時一定要收掉子行程，否則 tracepath 會繼續跑到自己結束
        if proc.returncode is None:
            proc.kill()
            with contextlib.suppress(ProcessLookupError):
                await proc.wait()

    # 有到目的地嗎？最後一個「有回應」的躍點得是目標本人 —— 沒到要明講，
    # 默默停在半路看起來像結果，其實是半份結果。
    reached = last_host == target
    yield {"type": "done", "tool": tool, "target": target,
           "path_mtu": parser.path_mtu, "truncated": truncated, "reached": reached}


@dataclass
class PortResult:
    target: str
    port: int
    open: bool = False
    latency_ms: float | None = None
    error: str | None = None


async def tcp_check(
    targets: list[str], ports: list[int], *, timeout: float = 2.0, concurrency: int = 16,
) -> list[PortResult]:
    """TCP 連線測試。

    純 asyncio，不需外部指令也不需特權 —— 而且對**擋 ICMP 的主機**比 ping 有用：
    ping 不通不代表服務不通，這裡測的是實際要用的那個埠。
    """
    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    timeout = max(0.2, min(timeout, 10.0))
    for p in ports:
        if not 1 <= p <= 65535:
            raise NetDiagError(f"埠號超出範圍：{p}", code="nd_port_range", value=str(p))
    if len(targets) * len(ports) > MAX_TARGETS * 4:
        raise NetDiagError("目標與埠的組合過多", code="nd_too_many_pairs")

    sem = asyncio.Semaphore(concurrency)
    started = time.monotonic()

    async def one(t: str, port: int) -> PortResult:
        async with sem:
            if time.monotonic() - started > OVERALL_DEADLINE:
                return PortResult(target=t, port=port, error="整體時間上限已到，未執行")
            try:
                addr = await _diag_addr(t, port)
            except NetDiagError as exc:
                return PortResult(target=t, port=port, error=str(exc))
            t0 = time.monotonic()
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(addr, port), timeout=timeout)
                return PortResult(target=t, port=port, open=True,
                                  latency_ms=round((time.monotonic() - t0) * 1000, 2))
            except TimeoutError:
                return PortResult(target=t, port=port, error="逾時")
            except OSError as exc:
                return PortResult(target=t, port=port, error=exc.strerror or str(exc))
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass

    jobs = [one(t, p) for t in targets for p in ports]
    return list(await asyncio.gather(*jobs))


def tool_availability() -> dict[str, Any]:
    """哪些診斷工具在這台機器上可用 —— 前端據此把不能用的功能標示出來。"""
    return {
        "ping": bool(shutil.which("ping") or shutil.which("ping6")),
        "tracepath": bool(shutil.which("tracepath")),
        "traceroute": bool(_find_tool("traceroute")),
        "tcp": True,   # 純 Python，永遠可用
    }


# ─────────────────── UDP 探測 ───────────────────

@dataclass
class UdpResult:
    target: str
    port: int
    state: str = "no_reply"     # open / closed / no_reply
    probe: str = "empty"        # 送出去的是哪種封包
    latency_ms: float | None = None
    reply_bytes: int | None = None
    detail: str | None = None


def _dns_query_packet() -> bytes:
    """對根區送一個 NS 查詢。任何 DNS 伺服器都會回應，所以「有回應」＝確定開著。"""
    return (b"\x12\x34"            # transaction id
            b"\x01\x00"            # standard query, recursion desired
            b"\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x00"                # root
            b"\x00\x02\x00\x01")   # NS, IN


def _ntp_packet() -> bytes:
    """LI=0 VN=3 Mode=3（client），其餘留空 —— 48 bytes。"""
    return b"\x1b" + b"\x00" * 47


# 對這些埠送真實協定封包，才拿得到「確定開啟」而不是一片沉默。
_UDP_PROBES: dict[int, tuple[str, bytes]] = {
    53: ("dns", _dns_query_packet()),
    123: ("ntp", _ntp_packet()),
}


class _UdpProto(asyncio.DatagramProtocol):
    def __init__(self, done: asyncio.Future) -> None:
        self.done = done

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self.done.done():
            self.done.set_result(("open", data))

    def error_received(self, exc: Exception) -> None:
        # ICMP port unreachable 會以 ConnectionRefusedError 回到這裡 ——
        # 這是 UDP 唯一能「確定關閉」的訊號，不需要 raw socket。
        if not self.done.done():
            self.done.set_result(("closed", b""))


async def udp_check(
    targets: list[str], ports: list[int], *, timeout: float = 2.0, concurrency: int = 16,
) -> list[UdpResult]:
    """UDP 埠探測。

    ⚠️ **UDP 沒有交握，「沒有回應」本質上無法判定** —— 可能開著但不回應、被防火牆
    丟棄、或封包遺失。所以這裡回三種狀態而不是二元的開/關：

      open     收到回應（或 ICMP 以外的資料）→ 確定開著
      closed   收到 ICMP port unreachable    → 確定關閉
      no_reply 什麼都沒收到                   → **無法判定**，交給使用者判斷

    把 no_reply 顯示成「開啟」會是安靜地說謊，所以它自成一態。
    對 53 / 123 會送真實協定封包，否則多數服務根本不會回應空封包。
    """
    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    timeout = max(0.2, min(timeout, 10.0))
    for p in ports:
        if not 1 <= p <= 65535:
            raise NetDiagError(f"埠號超出範圍：{p}", code="nd_port_range", value=str(p))
    if len(targets) * len(ports) > MAX_TARGETS * 4:
        raise NetDiagError("目標與埠的組合過多", code="nd_too_many_pairs")

    sem = asyncio.Semaphore(concurrency)
    started = time.monotonic()

    async def one(host: str, port: int) -> UdpResult:
        async with sem:
            if time.monotonic() - started > OVERALL_DEADLINE:
                return UdpResult(target=host, port=port, detail="整體時間上限已到，未執行")
            name, payload = _UDP_PROBES.get(port, ("empty", b"\x00"))
            res = UdpResult(target=host, port=port, probe=name)
            try:
                addr = await _diag_addr(host, port)
            except NetDiagError as exc:
                res.state = "no_reply"
                res.detail = str(exc)
                return res
            loop = asyncio.get_running_loop()
            done: asyncio.Future = loop.create_future()
            transport = None
            t0 = time.monotonic()
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _UdpProto(done), remote_addr=(addr, port))
                transport.sendto(payload)
                state, data = await asyncio.wait_for(done, timeout=timeout)
                res.state = state
                res.latency_ms = round((time.monotonic() - t0) * 1000, 2)
                if state == "open":
                    res.reply_bytes = len(data)
                    res.detail = _describe_reply(name, data)
            except TimeoutError:
                res.state = "no_reply"
            except OSError as exc:
                res.state = "closed" if isinstance(exc, ConnectionRefusedError) else "no_reply"
                res.detail = exc.strerror or str(exc)
            finally:
                if transport is not None:
                    transport.close()
            return res

    jobs = [one(t, p) for t in targets for p in ports]
    return list(await asyncio.gather(*jobs))


def _describe_reply(probe: str, data: bytes) -> str | None:
    """對已知協定，把回應解讀成一句人看得懂的話。"""
    if probe == "dns" and len(data) >= 4:
        rcode = data[3] & 0x0F
        names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
        return f"DNS {names.get(rcode, f'rcode={rcode}')}"
    if probe == "ntp" and len(data) >= 48:
        stratum = data[1]
        return f"NTP stratum {stratum}" if stratum else "NTP (kiss-o'-death / 未同步)"
    return None


# ─────────────────── TLS 憑證檢查 ───────────────────

@dataclass
class TlsResult:
    target: str
    port: int
    ok: bool = False
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    sans: list[str] = field(default_factory=list)
    serial: str | None = None
    sig_algorithm: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    self_signed: bool = False
    trusted: bool | None = None       # 對系統信任庫驗得過嗎
    hostname_match: bool | None = None
    error: str | None = None


def _name_str(name: Any) -> str:
    from cryptography.x509.oid import NameOID
    try:
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return str(cn[0].value)
    except Exception:
        pass
    return name.rfc4514_string()


async def tls_check(
    targets: list[str], port: int = 443, *, server_name: str | None = None,
    timeout: float = 5.0, concurrency: int = 8,
) -> list[TlsResult]:
    """看對方實際送出的是什麼憑證。

    刻意**不驗證**就先取回憑證 —— 這支工具的用途正是「這台送的到底是哪一張、什麼時候到期」，
    憑證有問題（自簽、過期、名稱不符）才更需要看得到。是否通過系統信任庫另外單獨回報，
    不會因為驗不過就什麼都不給。
    """
    import ssl

    from cryptography import x509

    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    timeout = max(1.0, min(timeout, 15.0))
    sem = asyncio.Semaphore(concurrency)

    async def one(host: str) -> TlsResult:
        async with sem:
            sni = server_name or host
            res = TlsResult(target=host, port=port)
            try:
                addr = await _diag_addr(host, port)
            except NetDiagError as exc:
                res.error = str(exc)
                return res
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            writer = None
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(addr, port, ssl=ctx, server_hostname=sni),
                    timeout=timeout)
                sslobj = writer.get_extra_info("ssl_object")
                der = sslobj.getpeercert(binary_form=True)
                res.tls_version = sslobj.version()
                c = sslobj.cipher()
                res.cipher = c[0] if c else None
                cert = x509.load_der_x509_certificate(der)
                res.ok = True
                res.subject = _name_str(cert.subject)
                res.issuer = _name_str(cert.issuer)
                res.not_before = cert.not_valid_before_utc.isoformat()
                res.not_after = cert.not_valid_after_utc.isoformat()
                res.days_remaining = (cert.not_valid_after_utc
                                      - datetime.now(UTC)).days
                res.serial = format(cert.serial_number, "x")
                res.sig_algorithm = cert.signature_algorithm_oid._name
                res.self_signed = cert.subject == cert.issuer
                try:
                    san = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName).value
                    res.sans = san.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    res.sans = []
                res.hostname_match = _hostname_matches(sni, res.subject, res.sans)
            except TimeoutError:
                res.error = "逾時"
            except ssl.SSLError as exc:
                res.error = f"TLS 交握失敗：{exc.reason or exc}"
            except OSError as exc:
                res.error = exc.strerror or str(exc)
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, ssl.SSLError):
                        pass
            if res.ok:
                res.trusted = await _verify_trusted(addr, port, sni, timeout)
            return res

    return list(await asyncio.gather(*(one(t) for t in targets)))


def _hostname_matches(name: str, subject: str | None, sans: list[str]) -> bool:
    """RFC 6125 的簡化比對：SAN 優先，沒有 SAN 才看 CN；支援單層萬用字元。"""
    candidates = sans or ([subject] if subject else [])
    n = name.lower().rstrip(".")
    for c in candidates:
        c = (c or "").lower().rstrip(".")
        if c == n:
            return True
        if c.startswith("*.") and "." in n and n.split(".", 1)[1] == c[2:]:
            return True
    return False


async def _verify_trusted(host: str, port: int, sni: str, timeout: float) -> bool:
    """再連一次，這次開啟完整驗證 —— 通過與否單獨回報，不影響上面的憑證內容。"""
    import ssl
    ctx = ssl.create_default_context()
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni), timeout=timeout)
        return True
    except (ssl.SSLError, OSError, TimeoutError):
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass


# ─────────────────── HTTP 檢查 ───────────────────

@dataclass
class HttpHop:
    url: str
    status: int
    location: str | None = None


@dataclass
class HttpResult:
    url: str
    ok: bool = False
    status: int | None = None
    final_url: str | None = None
    elapsed_ms: float | None = None
    server: str | None = None
    content_type: str | None = None
    hsts: str | None = None
    redirects: list[HttpHop] = field(default_factory=list)
    error: str | None = None


class DiagTargetBlocked(NetDiagError):
    """HTTP 檢查不可以打到 jt-ipam 主機自己或雲端中繼資料位址。"""


async def _assert_diag_http_target(url: str) -> None:
    """HTTP 檢查的目標檢查（CodeQL 標出的 SSRF，2026-09-29）。

    這是內網診斷工具，**私有網段是本來的用途，不擋**；但本機（127.0.0.0/8、::1）、link-local
    （169.254.0.0/16 ＝ 雲端中繼資料 169.254.169.254、fe80::/10）、多播與未指定位址不是診斷對象 ——
    打得到就等於任何登入的人都能讓伺服器替他去讀本機服務與雲端憑證。主機名稱要先解析，
    解析出來的每個位址都檢查（DNS 可以把好看的名字指到 127.0.0.1）。
    """
    import asyncio
    import socket
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise DiagTargetBlocked(f"not an http(s) URL: {url[:200]}")
    host = parts.hostname
    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                           type=socket.SOCK_STREAM)
        except OSError as exc:
            raise DiagTargetBlocked(f"DNS resolution failed for {host}: {exc}") from exc
        addrs = [ipaddress.ip_address(i[4][0]) for i in infos]
    _diag_check(host, addrs)


async def _diag_addr(host: str, port: int) -> str:
    """TCP／UDP／TLS 檢查要連的位址：解析、套用診斷規則，回傳**檢查過的那個 IP**。

    直接連那個 IP（不再讓 asyncio 自己解析一次），檢查與連線之間 DNS 換答案也不怕。
    名稱解析失敗丟 NetDiagError（訊息跟以前 open_connection 給的一樣是系統的原因）。
    """
    from app.core.safe_http import UnsafeOutboundURL, _aresolve
    try:
        addrs = await _aresolve(host, port)
    except UnsafeOutboundURL as exc:
        cause = exc.__cause__
        raise NetDiagError(getattr(cause, "strerror", None) or str(exc)) from exc
    if not addrs:
        raise NetDiagError(f"沒有可用的位址：{host}")
    _diag_check(host, addrs)
    return str(addrs[0])


_LOCAL_CACHE: tuple[float, frozenset[str]] = (0.0, frozenset())


def _local_addresses() -> frozenset[str]:
    """這台伺服器自己的位址（迴路以外）。Linux 讀 /proc/net/fib_trie 的 LOCAL 項與 /proc/net/if_inet6；
    讀不到就退回主機名稱解析。快取 60 秒（介面位址不常變，每次 HTTP 檢查都讀檔沒必要）。"""
    import ipaddress
    import socket
    import time
    global _LOCAL_CACHE
    now = time.monotonic()
    if now - _LOCAL_CACHE[0] < 60:
        return _LOCAL_CACHE[1]
    out: set[str] = set()
    try:
        last = None
        with open("/proc/net/fib_trie", encoding="ascii", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s.startswith("|--"):
                    last = s[3:].strip()
                elif "host LOCAL" in s and last:
                    out.add(last)
    except OSError:
        pass
    try:
        with open("/proc/net/if_inet6", encoding="ascii", errors="replace") as fh:
            for line in fh:
                h = line.split()[0] if line.split() else ""
                if len(h) == 32:
                    out.add(str(ipaddress.ip_address(int(h, 16))))
    except (OSError, ValueError):
        pass
    if not out:
        try:
            out.update(socket.gethostbyname_ex(socket.gethostname())[2])
        except OSError:
            pass
    clean = set()
    for a in out:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if not ip.is_loopback:
            clean.add(str(ip))
    _LOCAL_CACHE = (now, frozenset(clean))
    return _LOCAL_CACHE[1]


def _diag_check(host: str, addrs: list[Any]) -> None:
    """診斷工具的位址規則：私網是本來的用途（不擋），本機／link-local／多播不是。

    送出前檢查一次（錯誤訊息清楚）；連線當下再套用一次（`GuardedTransport`）—— 兩次之間
    DNS 可以換答案。`_ip_in` 會把 `::ffff:127.0.0.1` 這類 IPv4 對映位址當成它代表的 IPv4。
    """
    from app.core.safe_http import _BLOCKED_CIDRS, _ip_in

    local = _local_addresses()
    for ip in addrs:
        if _ip_in(ip, _BLOCKED_CIDRS):
            raise DiagTargetBlocked(f"{host} ({ip}) is loopback / link-local / multicast — not a diagnostic target")
        # 伺服器自己的區網位址：打得到就能讀本機上只綁區網介面的服務（2026-10-06 CodeQL 判讀）
        mapped = getattr(ip, "ipv4_mapped", None)
        if str(ip) in local or (mapped is not None and str(mapped) in local):
            raise DiagTargetBlocked(f"{host} ({ip}) is this server — not a diagnostic target")


async def http_check(url: str, *, timeout: float = 10.0, max_redirects: int = 5,
                     verify_tls: bool = False) -> HttpResult:
    """取狀態碼、轉址鏈與幾個關鍵標頭。

    預設**不驗證 TLS**：這是診斷工具，對方憑證有問題正是要看的事情之一，
    因驗證失敗而什麼都拿不到反而沒用（是否受信任請用 TLS 憑證檢查那支）。
    """
    from app.core.safe_http import guarded_client

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    timeout = max(1.0, min(timeout, 30.0))
    max_redirects = max(0, min(max_redirects, 10))
    res = HttpResult(url=url)
    current = url
    t0 = time.monotonic()
    try:
        async with guarded_client(timeout=timeout, verify=verify_tls, http2=False,
                                  check=_diag_check) as client:
            for _ in range(max_redirects + 1):
                # 每一跳都先檢查目標（轉址可以把人帶去本機或雲端中繼資料位址）
                await _assert_diag_http_target(current)
                r = await client.get(current)
                if r.is_redirect and r.headers.get("location"):
                    res.redirects.append(HttpHop(url=current, status=r.status_code,
                                                 location=r.headers["location"]))
                    current = str(r.next_request.url) if r.next_request else r.headers["location"]
                    continue
                res.ok = True
                res.status = r.status_code
                res.final_url = str(r.url)
                res.server = r.headers.get("server")
                res.content_type = r.headers.get("content-type")
                res.hsts = r.headers.get("strict-transport-security")
                break
            else:
                res.error = f"轉址超過 {max_redirects} 次"
    except Exception as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    res.elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
    return res


# ─────────────────── 批次反向 DNS ───────────────────

@dataclass
class RdnsResult:
    ip: str
    ptr: str | None = None
    error: str | None = None


async def rdns_many(targets: list[str], *, timeout: float = 3.0,
                    concurrency: int = 16) -> list[RdnsResult]:
    """整批查 PTR。用途是「這個網段哪些位址沒有反解」—— 逐台查太慢也看不出全貌。"""
    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    timeout = max(0.5, min(timeout, 10.0))
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)

    async def one(ip: str) -> RdnsResult:
        async with sem:
            try:
                info = await asyncio.wait_for(
                    loop.getnameinfo((ip, 0), 0), timeout=timeout)
            except TimeoutError:
                return RdnsResult(ip=ip, error="逾時")
            except OSError as exc:
                return RdnsResult(ip=ip, error=exc.strerror or str(exc))
            name = info[0]
            # 沒有 PTR 時 getnameinfo 會把 IP 原樣回來 —— 那不是主機名稱
            return RdnsResult(ip=ip, ptr=None if name == ip else name)

    return list(await asyncio.gather(*(one(t) for t in targets)))
