#!/usr/bin/env python3
"""jt-ipam scan agent (push model, standard library only).

Runs inside the target network segment and connects OUT to the jt-ipam server:
  1. GET  {SERVER}/api/v1/scan-agents/poll    -> subnets to scan (+ server agent sha)
  2. Run the requested probes per subnet (icmp / tcp / arp / rdns / os / ports ...)
  3. POST {SERVER}/api/v1/scan-agents/report  -> send results back

Auth: every request carries header  X-Agent-Key: <enrollment key>  (server compares sha256).

Capability self-report: each poll also carries header  X-Agent-Probes  listing the
probe keys this host can actually perform (depends on tools/permissions available).

Auto-update: each poll returns the server's agent.py sha256. If it differs from this
running copy, the agent downloads the new agent.py, overwrites itself and re-executes.

排程（重點）：輕量探測（icmp/tcp/arp/rdns）跟著 fast loop（interval_seconds）每輪跑；
重量探測（os/ports，可能上 nmap）只在距離上次執行超過 intervals[probe] 秒時才跑。
每個探測的「上次執行時間」存在記憶體裡，依此節流。

Environment variables:
  JT_IPAM_URL        e.g. https://ipam.example.com    (required)
  JT_IPAM_AGENT_KEY  enrollment key from the agent page (required)
  JT_IPAM_INTERVAL   fallback fast-loop seconds if server omits interval_seconds, default 300
  JT_IPAM_INSECURE   =1 to skip TLS verification (self-signed server)
  JT_IPAM_MAX_HOSTS  max hosts scanned per subnet per cycle, default 4096; larger subnets are
                     scanned in rotating chunks (a /16 takes 16 cycles to cover once)
  JT_IPAM_AUTO_UPDATE =0 to disable self-update (default on)
  JT_IPAM_DHCPD_CONF    dhcpd.conf path when this host runs isc-dhcp-server and an "ISC DHCP"
                        source in jt-ipam points at this agent (default: first existing of
                        /etc/dhcp/dhcpd.conf, /etc/dhcpd.conf, /usr/local/etc/dhcpd.conf)
  JT_IPAM_DHCPD_LEASES  dhcpd.leases path (default: first existing of /var/lib/dhcp/dhcpd.leases,
                        /var/lib/dhcpd/dhcpd.leases, /var/db/dhcpd.leases)
                        Only parsed ranges / fixed addresses / active leases are sent -- never the
                        file contents (dhcpd.conf often holds DDNS/OMAPI keys). The server cannot
                        change these paths.
  Console relay (SSH/SFTP/RDP/VNC from the browser into the subnets this agent scans) is switched on
  and configured in the jt-ipam web UI (system settings + the agent page); nothing to set here. The
  agent relays only what the server currently allows. Optional local limits for the host owner:
  JT_IPAM_RELAY         =0 refuses all relaying on this host, whatever the server says
  JT_IPAM_RELAY_PORTS   only relay to these ports (narrows the list set in the web UI)
  JT_IPAM_RELAY_MAX     at most this many concurrent sessions (narrows the web UI setting)
  JT_IPAM_RELAY_CIDRS   comma separated: only relay into these networks, whatever the server says
                        (a compromised server still cannot reach past them; for a real guarantee
                        also set JT_IPAM_AUTO_UPDATE=0)
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import selectors
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

AGENT_VERSION = "1.17.4"
SERVER = os.environ.get("JT_IPAM_URL", "").rstrip("/")
KEY = os.environ.get("JT_IPAM_AGENT_KEY", "")
INTERVAL = int(os.environ.get("JT_IPAM_INTERVAL", "300"))
INSECURE = os.environ.get("JT_IPAM_INSECURE", "") in ("1", "true", "yes")
MAX_HOSTS = int(os.environ.get("JT_IPAM_MAX_HOSTS", "4096"))
AUTO_UPDATE = os.environ.get("JT_IPAM_AUTO_UPDATE", "1") not in ("0", "false", "no")
PING_WORKERS = 128
AGENT_PATH = os.path.realpath(__file__)

# 所有已知探測鍵；server 沒指定 probes 時，向下相容用 icmp。
ALL_PROBES = ("icmp", "tcp", "arp", "rdns", "netbios", "mdns", "dhcp", "os", "ports")
DEFAULT_PROBES = ("icmp",)

# tcp 探測掃的常見埠（也作為 alive 判定依據）
TCP_PROBE_PORTS = (22, 80, 443, 445, 3389, 8006)
# 定期 OS 偵測另外看的埠（只在沒開「連接埠」探測時補上）：RTSP 554／8554（攝影機）、9100／631／515（印表機）、
# 5060（VoIP）、5000／5001（NAS 管理頁）、8080／8443（設備網頁）、37777／34567（常見 NVR／DVR）
OS_PROBE_KIND_PORTS = (554, 8554, 9100, 631, 515, 5060, 5000, 5001, 8080, 8443, 37777, 34567)
TCP_PROBE_TIMEOUT = 1.0

# 每個探測在記憶體裡的「上次執行時間」：key = (subnet_id, probe) -> epoch seconds。
# 用 subnet 粒度節流（同一輪同子網的所有 host 一起跑某探測或一起跳過）。
_last_run: dict[tuple, float] = {}

# scan_once 把 server 回的 fast loop 寫在這，給 main 的 sleep 用（單元素 list 當可變參照）。
_CURRENT_FAST: list[int] = [0]


def _ctx() -> ssl.SSLContext | None:
    if not SERVER.startswith("https"):
        return None
    ctx = ssl.create_default_context()
    # 代理連回伺服器一律 TLS 1.2 以上（CodeQL #43）。Python 3.10 起預設就是，明寫出來不靠預設值
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _capabilities() -> list[str]:
    """回報本機實際能做的探測（送 X-Agent-Probes header 給 server）。

    icmp/tcp/rdns 一律支援；arp 需 neigh 表可讀；os/ports 需 PATH 上有 nmap；
    netbios 需 nmblookup/nbtscan、mdns 需 avahi-resolve（有才回報能力、才會實際查名）。
    不做需要憑證/社群字串的探測（如 SNMP）。
    """
    caps = ["icmp", "tcp", "rdns"]
    try:
        if _arp_table():
            caps.append("arp")
    except Exception:
        pass
    if shutil.which("nmap"):
        caps.extend(["os", "ports"])
    # NetBIOS / mDNS：有對應工具才回報能力（_netbios / _mdns 實際查名）
    if shutil.which("nmblookup") or shutil.which("nbtscan"):
        caps.append("netbios")
    if shutil.which("avahi-resolve"):
        caps.append("mdns")
    # DHCP discovery needs to bind UDP/68 (privileged) — report the capability only if we can.
    if _can_bind_dhcp_port():
        caps.append("dhcp")
    # 去重並維持 ALL_PROBES 順序
    seen = set(caps)
    return [p for p in ALL_PROBES if p in seen]


# 探測相依的外部工具（name, version-args）。server 端另有 probes/package 對照表（顯示用）。
_DEP_TOOLS = (
    ("python3", ["--version"]),
    ("ping", ["-V"]),
    ("ip", ["-V"]),
    ("nmap", ["--version"]),
    ("nmblookup", ["-V"]),
    ("nbtscan", []),         # 無可靠的版本旗標
    ("avahi-resolve", []),   # 無可靠的版本旗標
)


def _tool_version(path: str, args: list) -> str:
    if not args:
        return ""
    try:
        r = subprocess.run([path, *args], capture_output=True, text=True, timeout=4)
        txt = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", txt)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _tools_header() -> str:
    """相依工具盤點 → 緊湊字串 `name|installed(1/0)|version` 以分號相接（送 X-Agent-Tools）。"""
    parts = []
    for name, vargs in _DEP_TOOLS:
        path = shutil.which(name)
        ver = _tool_version(path, vargs) if path else ""
        parts.append(f"{name}|{1 if path else 0}|{ver}")
    return ";".join(parts)


def _req(method: str, path: str, body: dict | None = None,
         extra_headers: dict | None = None, timeout: float = 30) -> dict:
    url = f"{SERVER}{path}"
    data = json.dumps(body).encode() if body is not None else None
    # S310 is suppressed here and below: the scheme is validated once at startup
    # (main() rejects anything that is not http/https), and SERVER comes from the
    # agent's own config file, not from anything the network says.
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310
    req.add_header("X-Agent-Key", KEY)
    req.add_header("X-Agent-Version", AGENT_VERSION)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:  # noqa: S310
        return json.loads(resp.read().decode() or "{}")


def _get_bytes(path: str) -> bytes:
    req = urllib.request.Request(f"{SERVER}{path}", method="GET")  # noqa: S310
    req.add_header("X-Agent-Key", KEY)
    req.add_header("X-Agent-Version", AGENT_VERSION)
    with urllib.request.urlopen(req, timeout=30, context=_ctx()) as resp:  # noqa: S310
        return resp.read()


def _self_sha() -> str:
    try:
        with open(AGENT_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


def _children_of(pid: int, proc: str = "/proc") -> list:
    """PIDs whose parent is `pid` (Linux /proc). The name in /proc/<pid>/stat may itself contain
    ')' and spaces, so the fields are read after the LAST ')'."""
    out = []
    try:
        entries = os.listdir(proc)
    except OSError:
        return out
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc, name, "stat"), encoding="utf-8", errors="replace") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            if int(fields[1]) == pid:
                out.append(int(name))
        except (OSError, IndexError, ValueError):
            continue
    return out


# Self-update re-executes in place (os.execv keeps the PID), so probes the old program had
# running become children nobody waits for: when they finish they stay as zombies (seen in
# production: 8 nmap zombies left by an update). Children that already exist when this
# program starts can only be such leftovers; reap exactly those, never waitpid(-1), which
# would steal the exit status of a subprocess call that is still waiting for its child.
_INHERITED: list = _children_of(os.getpid())


def _reap_inherited() -> None:
    for pid in list(_INHERITED):
        try:
            done, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            done = pid
        except OSError:
            continue
        if done:
            _INHERITED.remove(pid)


def _maybe_self_update(server_sha: str | None) -> None:
    """If the server's agent.py differs from this copy, update self and re-exec."""
    if not AUTO_UPDATE or not server_sha:
        return
    if INSECURE or not SERVER.startswith("https://"):
        print(
            "[update] self-update disabled because the update channel is not authenticated",
            flush=True,
        )
        return
    if server_sha == _self_sha():
        return
    print("[update] server agent differs from local; downloading new version", flush=True)
    try:
        new = _get_bytes("/api/v1/scan-agents/agent.py")
        if hashlib.sha256(new).hexdigest() != server_sha:
            print("[update] downloaded sha mismatch; skip this round", flush=True)
            return
        tmp = AGENT_PATH + ".new"
        with open(tmp, "wb") as f:
            f.write(new)
        os.chmod(tmp, 0o755)
        os.replace(tmp, AGENT_PATH)
        print("[update] updated; re-executing new agent", flush=True)
        os.execv(sys.executable, [sys.executable, AGENT_PATH])
    except Exception as exc:  # noqa: BLE001 — never let update crash the agent
        print(f"[update] failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# 探測實作（每個都必須對單一 host 的失敗保持容忍，絕不可讓 loop 崩掉）           #
# --------------------------------------------------------------------------- #

def _ping(ip: str) -> bool:
    """icmp 探測：回 True 表示有回應。"""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


def _tcp_scan(ip: str) -> list[int]:
    """tcp 探測：嘗試連線常見埠，回傳成功連上的埠清單。"""
    open_ports: list[int] = []
    for port in TCP_PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=TCP_PROBE_TIMEOUT):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports


def _rdns(ip: str) -> tuple[str | None, bool]:
    """rdns 探測：反查 hostname → (名稱, DNS 是否明確說沒有)。

    只有 DNS 明確回答「沒有這筆 PTR」（HOST_NOT_FOUND＝NXDOMAIN、NO_DATA）才算沒有；伺服器會拿它
    清掉舊名。逾時、DNS 連不上、TRY_AGAIN 都不算 —— 那種時候清掉，全部名稱會跟著 DNS 故障一起消失。
    """
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return (host or None), False
    except socket.herror as exc:
        return None, exc.errno in (1, 4)      # HOST_NOT_FOUND / NO_DATA
    except Exception:
        return None, False


def _netbios(ip: str) -> str | None:
    """NetBIOS 名稱探測：nmblookup -A <ip> 取 <00> UNIQUE（非 <GROUP>）工作站名；或 nbtscan -q。"""
    nmb = shutil.which("nmblookup")
    if nmb:
        try:
            r = subprocess.run([nmb, "-A", ip], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                # 例： "    DESKTOP-ABC   <00> -         B <ACTIVE>"  → UNIQUE 機名（要）
                #      "    WORKGROUP     <00> - <GROUP> B <ACTIVE>"  → 群組（略過）
                if "<00>" in line and "<GROUP>" not in line:
                    name = line.split()[0].strip()
                    if name and name != ip:
                        return name
        except Exception:
            pass
    nbt = shutil.which("nbtscan")
    if nbt:
        try:
            r = subprocess.run([nbt, "-q", ip], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                # 例： "192.168.1.10   WORKGROUP\\DESKTOP-ABC   SHARING ..."
                if parts and parts[0] == ip and len(parts) >= 2:
                    nm = parts[1]
                    if "\\" in nm:
                        nm = nm.split("\\", 1)[1]
                    if nm and nm != "<unknown>":
                        return nm
        except Exception:
            pass
    return None


# ─────────────────── DHCP server discovery ───────────────────
# Sends one standard DHCPDISCOVER broadcast and collects every DHCPOFFER that comes
# back. Anything answering is handing out addresses on this segment; the server then
# compares that against the addresses marked as DHCP servers in IPAM, and whatever is
# left over is a rogue DHCP server.
#
# We do NOT accept the offered lease (no REQUEST is sent), so nothing is consumed.
# Some servers do reserve the offered address for a short while — that is inherent to
# asking the question at all, and is why this probe is off by default.

DHCP_MAGIC = b"\x63\x82\x53\x63"


def _can_bind_dhcp_port() -> bool:
    """Can we bind UDP/68? DHCP replies are sent there; without it we would miss them."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 68))
        s.close()
        return True
    except OSError:
        return False


def _dhcp_packet(xid: bytes, mac: bytes) -> bytes:
    """Build a minimal DHCPDISCOVER (RFC 2131)."""
    pkt = b"".join((
        b"\x01",                     # op: BOOTREQUEST
        b"\x01",                     # htype: ethernet
        b"\x06",                     # hlen
        b"\x00",                     # hops
        xid,
        b"\x00\x00",                 # secs
        b"\x80\x00",                 # flags: broadcast
        b"\x00" * 4 * 4,             # ciaddr / yiaddr / siaddr / giaddr
        mac + b"\x00" * 10,          # chaddr (16 bytes)
        b"\x00" * 64,                # sname
        b"\x00" * 128,               # file
        DHCP_MAGIC,
        b"\x35\x01\x01",            # option 53: DHCPDISCOVER
        b"\x37\x03\x01\x03\x06",    # option 55: request subnet/router/dns
        b"\xff",                     # end
    ))
    return pkt


def _dhcp_parse(data: bytes) -> dict | None:
    """Pull the interesting bits out of a DHCP reply. Returns None if it is not one."""
    if len(data) < 240 or data[236:240] != DHCP_MAGIC:
        return None
    out = {"offered_ip": socket.inet_ntoa(data[16:20]),
           "relay": socket.inet_ntoa(data[24:28]),
           "xid": data[4:8]}
    i = 240
    while i < len(data):
        opt = data[i]
        if opt == 255:                # end
            break
        if opt == 0:                  # pad
            i += 1
            continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if len(val) < ln:
            # Truncated option: stop here. Before 1.14.1 this raised (IndexError / OSError from
            # inet_ntoa) and ended the whole listening window, so any host on the segment could
            # hide a rogue DHCP server behind one malformed reply.
            break
        if opt == 53 and ln == 1:
            out["msg_type"] = val[0]
        elif opt == 54 and ln == 4:   # server identifier
            out["server_id"] = socket.inet_ntoa(val)
        elif opt == 1 and ln == 4:
            out["netmask"] = socket.inet_ntoa(val)
        elif opt == 3 and ln >= 4:
            out["router"] = socket.inet_ntoa(val[:4])
        i += 2 + ln
    return out


def _dhcp_discover(wait: float = 4.0) -> list:
    """Broadcast one DHCPDISCOVER, return every distinct server that answered.

    Listens for the whole window rather than stopping at the first reply — the entire
    point is to find the SECOND server answering on a segment that should only have one.
    """
    mac = os.urandom(6)
    mac = bytes([(mac[0] | 0x02) & 0xFE]) + mac[1:]   # locally administered, unicast
    xid = os.urandom(4)
    found = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", 68))
        sock.settimeout(0.5)
        sock.sendto(_dhcp_packet(xid, mac), ("255.255.255.255", 67))
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            info = _dhcp_parse(data)
            # Only our own transaction, and only offers (2 = DHCPOFFER)
            if not info or info.get("xid") != xid or info.get("msg_type") != 2:
                continue
            server_ip = info.get("server_id") or addr[0]
            if server_ip in found:
                continue
            found[server_ip] = {
                "server_ip": server_ip,
                "from_ip": addr[0],
                "offered_ip": info.get("offered_ip"),
                "router": info.get("router"),
                "netmask": info.get("netmask"),
                "via_relay": info.get("relay") not in (None, "0.0.0.0"),
            }
    except OSError as exc:
        print(f"[dhcp] discovery failed: {exc}", file=sys.stderr, flush=True)
    finally:
        if sock is not None:
            sock.close()
    return list(found.values())


def _mdns(ip: str) -> str | None:
    """mDNS 名稱探測：avahi-resolve -a <ip> 取 .local 主機名。"""
    av = shutil.which("avahi-resolve")
    if av:
        try:
            r = subprocess.run([av, "-a", ip], capture_output=True, text=True, timeout=5)
            out = (r.stdout or "").strip()
            if out:
                # 例： "192.168.1.10\tdesktop.local"
                parts = out.split()
                if len(parts) >= 2:
                    name = parts[-1].strip().rstrip(".")
                    if name and name != ip:
                        return name
        except Exception:
            pass
    return None


_ARP_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+([0-9a-f:]{17})", re.I)


def _arp_table() -> dict[str, str]:
    """Read ip->mac from `ip neigh` / /proc/net/arp."""
    out: dict[str, str] = {}
    try:
        r = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].count(".") == 3 and ":" in parts[4]:
                out[parts[0]] = parts[4].lower()
    except Exception:
        pass
    if not out:
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    c = line.split()
                    if len(c) >= 4 and c[3] != "00:00:00:00:00:00":
                        out[c[0]] = c[3].lower()
        except Exception:
            pass
    return out


# OS 推導：積極猜測（-O --osscan-guess）對裝置/BMC 常自信地誤判（HP NAS、OpenWrt…），
# 故只接受「通用 OS」猜測、排除裝置型號；有 banner/服務資訊時一律優先採信。
_OS_DEVICEY = re.compile(
    r"NAS|printer|\bWAP\b|router|webcam|camera|storage|switch|VoIP|media device|"
    r"game console|specialized|OpenWrt|P2000|firewall|access point|broadband|"
    r"bridge|load balancer|embedded", re.I)
_OS_OSY = re.compile(r"Linux|Windows|BSD|macOS|Mac OS|Solaris|Unix|Android|VMware|ESXi", re.I)


def _derive_os(text: str):
    """從 nmap -sV / smb-os-discovery / -O 輸出推出最可靠的 OS 字串。

    優先序（可靠 → 猜測）：SMB 探得的 Windows 版本 > SSH banner 發行版 > 綜合 Service Info OS
    > -O 精確匹配 > -O 系列 > 積極猜測（僅限通用 OS、排除裝置型號）。
    banner/服務資訊比 TCP/IP 堆疊指紋準得多，故一律優先；純猜測若是裝置型號寧回 None（顯示未知）。
    """
    m = re.search(r"smb-os-discovery:.*?\n\|\s*OS:\s*([^\n(]+)", text, re.S)
    if m:
        return m.group(1).strip()[:200]
    m = re.search(r"\d+/tcp\s+open\s+ssh\s+OpenSSH\s+\S+\s+(Debian|Ubuntu|Raspbian|FreeBSD)\b", text, re.I)
    if m:
        return m.group(1)
    m = re.search(r"Service Info:.*?\bOSs?:\s*([^;\n]+)", text)
    if m:
        return m.group(1).strip()[:200]
    m = re.search(r"OS details:\s*(.+)", text)
    if m:
        return m.group(1).strip()[:200]
    m = re.search(r"Running:\s*(.+)", text)
    if m:
        return m.group(1).strip()[:200]
    g = re.search(r"(?:Aggressive )?OS guesses:\s*(.+)", text)
    if g:
        top = g.group(1).split(",")[0].strip()[:200]
        if _OS_OSY.search(top) and not _OS_DEVICEY.search(top):
            return top
    return None


#: 定期 OS 偵測額外跑的腳本：都只是讀服務自己送出來的東西（banner、網頁標題、伺服器標頭、憑證），
#: 伺服器拿去比對 Recog 指紋庫（1.14.0 起）。與 IP 探測相比少了 ssh-hostkey、rdp-ntlm-info
_OS_SCRIPTS = "smb-os-discovery,banner,http-title,http-server-header,ssl-cert"
_OS_MAX_PORTS = 32
_OS_MAX_TEXT = 300


def _compact_nmap(parsed: dict) -> dict:
    """定期 OS 偵測要送回伺服器判讀的部分：埠數與每段文字都有上限，一台通常幾 KB。"""
    def cut(d) -> dict:  # noqa: ANN001
        return {k: (v or "")[:_OS_MAX_TEXT] for k, v in (d or {}).items()}
    ports = [{**p, "scripts": cut(p.get("scripts"))} for p in (parsed.get("ports") or [])[:_OS_MAX_PORTS]]
    return {"ports": ports, "os": (parsed.get("os") or [])[:3], "closed": int(parsed.get("closed") or 0),
            "host_scripts": cut(parsed.get("host_scripts")), "mac_vendor": parsed.get("mac_vendor"),
            "hostnames": (parsed.get("hostnames") or [])[:5]}


def _nmap_os_ports(ip: str, want_os: bool, want_ports: bool) -> dict:
    """os / ports 重量探測：有 nmap 才跑，回 {os_guess?, open_ports?, nmap?}。

    os 偵測需 root（-O），失敗就只回 ports；任何錯誤都回空 dict（略過）。
    `nmap`（1.14.0 起）：結構化結果，伺服器用 IP 探測同一套判讀（含 Recog）推 OS 與設備類型；
    `os_guess` 照舊附上（舊伺服器只認這個）。
    """
    result: dict = {}
    if not shutil.which("nmap"):
        return result
    if want_ports:
        port_args = ["--top-ports", "100"]
    else:
        # 沒開「連接埠」探測時只看幾個埠：OS 偵測至少要看得到最能說明設備類型的那幾個
        #（攝影機的 RTSP、印表機、VoIP、NAS、NVR），否則只剩 TCP/IP 指紋，攝影機會被判成一般主機
        ports = sorted(set(TCP_PROBE_PORTS) | set(OS_PROBE_KIND_PORTS)) if want_os else list(TCP_PROBE_PORTS)
        port_args = ["-p", ",".join(str(p) for p in ports)]
    try:
        v6 = ["-6"] if ipaddress.ip_address(ip).version == 6 else []     # 沒有 -6，IPv6 位址一定失敗
    except ValueError:
        v6 = []
    args = ["nmap", "-Pn", "-T4", "--host-timeout", "90s" if want_os else "30s", *v6, *port_args]
    xml_path = None
    if want_os:
        # -sV（服務/banner 偵測）+ smb-os-discovery 遠比純 TCP/IP 堆疊指紋（-O）可靠：
        # 裝置/BMC 用 -O 常被自信地誤判。_derive_os 綜合這些訊號、優先採信 banner。
        # --version-light：預設強度會對認不得的服務一連試幾十種探針、每種等好幾秒，一個慢服務（PVE 的 8006）
        # 就能拖過單台時限，nmap 會把這台的結果整筆丟掉（2026-10-04 正式環境）；常見服務輕量模式就認得
        args += ["-sV", "--version-light", "-O", "--osscan-guess",
                 "--script", _OS_SCRIPTS, "--script-timeout", "15s"]
        fd, xml_path = tempfile.mkstemp(prefix="jtipam-nmap-", suffix=".xml")
        os.close(fd)
        args += ["-oX", xml_path]
    args.append(ip)

    def _run(cmd: list) -> tuple:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120 if want_os else 60)
        parsed: dict = {}
        if xml_path:
            try:
                with open(xml_path, encoding="utf-8", errors="replace") as fh:
                    parsed = _parse_nmap_xml(fh.read())
            except OSError:
                pass
        return r.stdout or "", parsed

    def _has_data(parsed: dict) -> bool:
        return bool(parsed.get("ports") or parsed.get("os") or parsed.get("host_scripts"))

    try:
        text, parsed = _run(args)
        if want_os and not _has_data(parsed):
            # 還是拖過單台時限（或腳本卡住）：nmap 不留這台的任何結果。退回只做 OS 指紋（十幾秒），
            # 至少有 OS 與設備類型可判讀，不要整筆白跑
            text2, parsed2 = _run(["nmap", "-Pn", "-T4", "--host-timeout", "60s", *v6, *port_args,
                                   "-O", "--osscan-guess", "-oX", xml_path, ip])
            if _has_data(parsed2):
                text, parsed = text2, parsed2
        if _has_data(parsed):
            result["nmap"] = _compact_nmap(parsed)
        if want_ports:
            ports: list[int] = []
            for line in text.splitlines():
                m = re.match(r"^(\d+)/tcp\s+open", line.strip())
                if m:
                    ports.append(int(m.group(1)))
            if ports:
                result["open_ports"] = ports
        if want_os:
            og = _derive_os(text)
            if og:
                result["os_guess"] = og
    except Exception:
        return {}
    finally:
        if xml_path:
            try:
                os.unlink(xml_path)
            except OSError:
                pass
    return result


_chunk_pos: dict[str, int] = {}


# ── 獨立的 ISC DHCP Server（isc-dhcp-server）──────────────────────────────────
# 代理裝在 DHCP 主機上時，讀本機的 dhcpd.conf／dhcpd.leases，解析後只回報結構化資料
# （範圍、固定分配、租約）。ISC dhcpd 沒有能列出全部租約的 API（OMAPI 只能逐筆查），只能讀檔。
#
# 安全界線：
# - 檔案路徑只能在這台主機設定（環境變數），伺服器端改不了 —— 不然代理就成了「讀任意檔案」的管道
# - dhcpd.conf 裡常有 DDNS／OMAPI 金鑰：只取 subnet/range/host，key/zone/failover 等區塊一律不碰，
#   回報裡不會出現檔案原文
DHCPD_CONF_CANDIDATES = ("/etc/dhcp/dhcpd.conf", "/etc/dhcpd.conf", "/usr/local/etc/dhcpd.conf")
DHCPD_LEASES_CANDIDATES = ("/var/lib/dhcp/dhcpd.leases", "/var/lib/dhcpd/dhcpd.leases",
                           "/var/db/dhcpd.leases", "/var/db/dhcpd/dhcpd.leases")
DHCPD_MAX_FILE = 256 * 1024 * 1024       # 租約檔是日誌，dhcpd 每小時重寫一次；超過這麼大就不讀
DHCPD_MAX_INCLUDES = 50
DHCPD_MAX_POOLS = 5000
DHCPD_MAX_RESERVATIONS = 20000
DHCPD_MAX_LEASES = 50000
_DHCPD_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|#[^\n]*|[{};,]|[^\s{};,"#]+')


def _dhcpd_env_path(env: str, candidates: tuple) -> str:
    v = os.environ.get(env, "").strip()
    if v:
        return v
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]


def _dhcpd_tree(text: str) -> list:
    """dhcpd 設定／租約檔的語法樹：[(字詞串, 子節點或 None)]。字串去掉引號、註解略過。"""
    root: list = []
    stack = [root]
    cur: list = []
    for m in _DHCPD_TOKEN.finditer(text):
        tok = m.group(0)
        if tok.startswith("#"):
            continue
        if tok == ";":
            if cur:
                stack[-1].append((cur, None))
            cur = []
        elif tok == "{":
            node: tuple = (cur, [])
            stack[-1].append(node)
            stack.append(node[1])
            cur = []
        elif tok == "}":
            if cur:
                stack[-1].append((cur, None))
            cur = []
            if len(stack) > 1:
                stack.pop()
        elif tok.startswith('"'):
            cur.append(tok[1:-1])
        else:
            cur.append(tok)
    return root


def _dhcpd_ip4(v: str) -> str | None:
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return None
    return str(a) if a.version == 4 else None


def _dhcpd_mac(v: str) -> str | None:
    hexs = "".join(ch for ch in str(v).lower() if ch in "0123456789abcdef")
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)) if len(hexs) == 12 else None


def _dhcpd_host(label: str, kids: list) -> list:
    """host 區塊 → 固定分配（一個 fixed-address 一筆；寫主機名稱的要靠 DNS 才知道位址，不收）。"""
    mac = name = ddns = None
    addrs: list = []
    for words, sub in kids:
        if sub is not None or not words:
            continue
        k = words[0].lower()
        if k == "hardware" and len(words) >= 3:
            mac = _dhcpd_mac(words[2])
        elif k == "fixed-address":
            addrs = [w for w in words[1:] if w != ","]
        elif k == "option" and len(words) >= 3 and words[1].lower() == "host-name":
            name = words[2]
        elif k == "ddns-hostname" and len(words) >= 2:
            ddns = words[1]
    out = []
    for a in addrs:
        ip = _dhcpd_ip4(a)
        if ip:
            out.append({"ip": ip, "mac": mac, "hostname": name or ddns or label})
    return out


def _dhcpd_parse_conf(text: str, load_include=None) -> dict:  # noqa: ANN001
    """dhcpd.conf → {"pools": [...], "reservations": [...]}（只看 IPv4 的 subnet／range／host）。"""
    pools: list = []
    reservations: list = []
    seen_includes: set = set()

    def add_range(subnet: str | None, words: list) -> None:
        ips = [w for w in words if w.lower() != "dynamic-bootp"]
        start = _dhcpd_ip4(ips[0]) if ips else None
        end = _dhcpd_ip4(ips[1]) if len(ips) > 1 else start
        if not start or not end or subnet is None:
            return
        if ipaddress.ip_address(start) > ipaddress.ip_address(end):
            start, end = end, start
        if len(pools) < DHCPD_MAX_POOLS:
            pools.append({"subnet": subnet, "start": start, "end": end})

    def walk(nodes: list, subnet: str | None, depth: int) -> None:
        for words, kids in nodes:
            if not words:
                if kids:
                    walk(kids, subnet, depth)
                continue
            key = words[0].lower()
            if kids is None:
                if key == "range":
                    add_range(subnet, words[1:])
                elif key == "include" and len(words) >= 2 and load_include is not None:
                    path = words[1]
                    if depth < 5 and path not in seen_includes and len(seen_includes) < DHCPD_MAX_INCLUDES:
                        seen_includes.add(path)
                        inc = load_include(path)
                        if inc:
                            walk(_dhcpd_tree(inc), subnet, depth + 1)
                continue
            if key == "subnet" and len(words) >= 4 and words[2].lower() == "netmask":
                try:
                    net = ipaddress.ip_network(f"{words[1]}/{words[3]}", strict=False)
                except ValueError:
                    continue
                walk(kids, str(net), depth)
            elif key == "host" and len(words) >= 2:
                for r in _dhcpd_host(words[1], kids):
                    if len(reservations) < DHCPD_MAX_RESERVATIONS:
                        reservations.append(r)
            elif key in ("shared-network", "group", "pool"):
                walk(kids, subnet, depth)
            # 其他區塊（key、zone、failover、class、on commit…）不碰

    walk(_dhcpd_tree(text), None, 0)
    return {"pools": pools, "reservations": reservations}


def _dhcpd_time(words: list) -> tuple[bool, datetime | None]:
    """租約檔的時間：`4 2026/09/24 13:02:03`（UTC）、`epoch 1695520923`、`never`。
    回傳 (是否永不到期, 時間)。"""
    if not words:
        return False, None
    if words[0].lower() == "never":
        return True, None
    try:
        if words[0].lower() == "epoch" and len(words) >= 2:
            return False, datetime.fromtimestamp(int(words[1]), tz=timezone.utc)
        if len(words) >= 3:
            return False, datetime.strptime(f"{words[1]} {words[2]}", "%Y/%m/%d %H:%M:%S").replace(
                tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return False, None
    return False, None


def _dhcpd_parse_leases(text: str, now: datetime | None = None) -> dict:
    """dhcpd.leases → {"leases": [...目前有效的], "reservations": [...OMAPI 動態新增的 host]}。

    檔案是日誌：同一個位址後面的記錄蓋掉前面的。只有最後一筆是 `binding state active`、
    而且還沒到期（或永不到期）的才算。
    """
    now = now or datetime.now(timezone.utc)
    latest: dict = {}
    hosts: dict = {}
    for words, kids in _dhcpd_tree(text):
        if kids is None or not words:
            continue
        key = words[0].lower()
        if key == "lease" and len(words) >= 2:
            ip = _dhcpd_ip4(words[1])
            if not ip:
                continue
            info = {"state": None, "mac": None, "hostname": None, "never": False, "ends": None}
            for w, sub in kids:
                if sub is not None or not w:
                    continue
                k = w[0].lower()
                if k == "binding" and len(w) >= 3 and w[1].lower() == "state":
                    info["state"] = w[2].lower()
                elif k == "ends":
                    info["never"], info["ends"] = _dhcpd_time(w[1:])
                elif k == "hardware" and len(w) >= 3:
                    info["mac"] = _dhcpd_mac(w[2])
                elif k == "client-hostname" and len(w) >= 2:
                    info["hostname"] = w[1]
            latest.pop(ip, None)          # 維持「最後一次出現」的順序
            latest[ip] = info
        elif key == "host" and len(words) >= 2:
            flags = {w[0].lower() for w, sub in kids if sub is None and w}
            if "deleted" in flags:
                hosts.pop(words[1], None)
            else:
                hosts[words[1]] = _dhcpd_host(words[1], kids)
    leases = []
    for ip, info in latest.items():
        if info["state"] != "active":
            continue
        if not info["never"] and (info["ends"] is None or info["ends"] <= now):
            continue
        if len(leases) >= DHCPD_MAX_LEASES:
            break
        leases.append({"ip": ip, "mac": info["mac"], "hostname": info["hostname"],
                       "ends": info["ends"].isoformat() if info["ends"] else None})
    leases.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    reservations = [r for rs in hosts.values() for r in rs][:DHCPD_MAX_RESERVATIONS]
    return {"leases": leases, "reservations": reservations}


def _dhcpd_read(path: str) -> tuple[str | None, dict]:
    st = {"path": path, "ok": False, "error": None, "size": None, "mtime": None}
    try:
        info = os.stat(path)
        st["size"], st["mtime"] = info.st_size, int(info.st_mtime)
        if info.st_size > DHCPD_MAX_FILE:
            st["error"] = f"file too large ({info.st_size} bytes)"
            return None, st
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        st["ok"] = True
        return text, st
    except OSError as exc:
        st["error"] = f"{type(exc).__name__}: {exc.strerror or exc}"
        return None, st


def _dhcpd_collect(conf_path: str, leases_path: str, now: datetime | None = None) -> dict:
    """讀本機兩個檔、解析，回報結構化結果與檔案狀態（讀不到就說讀不到，不當成「沒有資料」）。"""
    base = os.path.dirname(conf_path)

    def load_include(p: str) -> str | None:
        full = p if os.path.isabs(p) else os.path.join(base, p)
        if not os.path.isfile(full):
            return None
        text, _st = _dhcpd_read(full)
        return text

    conf_text, conf_st = _dhcpd_read(conf_path)
    leases_text, leases_st = _dhcpd_read(leases_path)
    conf = _dhcpd_parse_conf(conf_text, load_include) if conf_text is not None else {
        "pools": [], "reservations": []}
    lease = _dhcpd_parse_leases(leases_text, now) if leases_text is not None else {
        "leases": [], "reservations": []}
    return {
        "pools": conf["pools"],
        "reservations": (conf["reservations"] + lease["reservations"])[:DHCPD_MAX_RESERVATIONS],
        "leases": lease["leases"],
        "files": {"conf": conf_st, "leases": leases_st},
    }


_DHCPD_STATE = {"last": 0.0, "running": False}
_DHCPD_LOCK = threading.Lock()


def _dhcpd_report_once(source_id: str) -> None:
    """讀本機 dhcpd 檔、回報（在背景執行緒跑：租約檔大時解析要幾秒，不能拖到上線偵測）。"""
    try:
        conf = _dhcpd_env_path("JT_IPAM_DHCPD_CONF", DHCPD_CONF_CANDIDATES)
        leases = _dhcpd_env_path("JT_IPAM_DHCPD_LEASES", DHCPD_LEASES_CANDIDATES)
        data = _dhcpd_collect(conf, leases)
        data["source_id"] = source_id
        r = _req("POST", "/api/v1/scan-agents/dhcpd-report", data, timeout=120)
        print(f"[dhcpd] pools={len(data['pools'])} reservations={len(data['reservations'])} "
              f"leases={len(data['leases'])} conf_ok={data['files']['conf']['ok']} "
              f"leases_ok={data['files']['leases']['ok']} -> {r.get('status', 'ok')}", flush=True)
    except Exception as exc:  # noqa: BLE001 — 下一輪再試
        print(f"[dhcpd] report failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    finally:
        with _DHCPD_LOCK:
            _DHCPD_STATE["running"] = False


def _dhcpd_maybe_report(cfg, now: float) -> None:  # noqa: ANN001
    """poll 回應帶了 `dhcpd`（伺服器上有 ISC DHCP 來源指到這台代理）才讀檔；沒有就什麼都不做。"""
    if not isinstance(cfg, dict) or not cfg.get("source_id"):
        return
    interval = max(60, int(cfg.get("interval_seconds") or 300))
    with _DHCPD_LOCK:
        if _DHCPD_STATE["running"] or now - _DHCPD_STATE["last"] < interval:
            return
        _DHCPD_STATE["running"], _DHCPD_STATE["last"] = True, now
    threading.Thread(target=_dhcpd_report_once, args=(str(cfg["source_id"]),),
                     name="jt-ipam-dhcpd", daemon=True).start()


def _subnet_chunk(subnet_id: str, cidr: str) -> tuple[list[str], int, dict]:
    """這輪要掃的位址、子網路總位址數、{chunk, rounds}。

    比單輪上限（MAX_HOSTS）大的子網路分段輪替：每輪掃下一段，掃完一遍從頭開始。以前是
    永遠只掃前 1024 個，後面的位址永遠不會被看到，畫面上也沒有任何提示。
    不為了算總數把整個大網段展開（/8 有一千六百萬個位址）。
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        return [], 0, {"chunk": 1, "rounds": 1}   # this build scans IPv4 only
    total = max(net.num_addresses - (2 if net.prefixlen < 31 else 0), 0)
    if total <= MAX_HOSTS:
        return [str(h) for h in net.hosts()], total, {"chunk": 1, "rounds": 1}
    rounds = -(-total // MAX_HOSTS)
    start = _chunk_pos.get(subnet_id, 0)
    if start >= total:
        start = 0
    first = int(net.network_address) + (1 if net.prefixlen < 31 else 0) + start
    count = min(MAX_HOSTS, total - start)
    hosts = [str(ipaddress.IPv4Address(first + i)) for i in range(count)]
    _chunk_pos[subnet_id] = start + count if start + count < total else 0
    return hosts, total, {"chunk": start // MAX_HOSTS + 1, "rounds": rounds}


def _due(subnet_id, probe: str, intervals: dict, fast: int, now: float) -> bool:
    """這個探測本輪是否該對此子網執行（依 per-probe cadence 節流）。

    輕量探測 cadence 預設等於 fast loop；重量探測（os/ports）用 intervals 指定的大週期。
    第一次（沒有 last_run 記錄）一律執行。
    """
    cadence = int(intervals.get(probe, fast) or fast)
    key = (subnet_id, probe)
    last = _last_run.get(key)
    if last is None:
        return True
    return (now - last) >= cadence


# 上線偵測（每輪都要跑完、立刻回報）與重量探測（對在線主機逐台查，丟給背景慢慢跑）分開。
# 以前全部串在一起、整輪跑完才回報：OS 指紋那一輪跑一個小時，這一小時內所有子網路的上線狀態
# 都沒有更新，連自動更新都卡住（正式環境 2026-09-28 實際發生）。
LIGHT_PROBES = ("icmp", "tcp", "arp", "dhcp")
HEAVY_WORKERS = int(os.environ.get("JT_IPAM_HEAVY_WORKERS", "16"))   # 背景同時查幾台
NMAP_WORKERS = int(os.environ.get("JT_IPAM_NMAP_WORKERS", "4"))      # 其中同時跑 nmap 的上限


def _split_probes(due: list[str]) -> tuple[list[str], list[str]]:
    """本輪到期的探測分成「上線偵測」與「重量探測」兩組（保持原本順序）。"""
    return [p for p in due if p in LIGHT_PROBES], [p for p in due if p not in LIGHT_PROBES]


class _HeavyQueue:
    """背景重量探測的待辦：同一台主機只排一次（還沒跑到又被排一次就合併探測項目）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, list[str]]] = {}

    def submit(self, subnet_id: str, ip: str, probes: list[str]) -> None:
        with self._lock:
            if ip in self._items:
                sid, old = self._items[ip]
                self._items[ip] = (sid, old + [p for p in probes if p not in old])
            else:
                self._items[ip] = (subnet_id, list(probes))

    def take(self, n: int) -> list[tuple[str, list[str]]]:
        with self._lock:
            keys = list(self._items)[:n]
            return [(k, self._items.pop(k)[1]) for k in keys]

    def pending(self) -> int:
        with self._lock:
            return len(self._items)


_HEAVY = _HeavyQueue()
_HEAVY_STATS: dict[str, float] = {"done": 0, "last_batch_s": 0.0}


NAME_PROBES = ("rdns", "netbios", "mdns")
HEAVY_FLUSH_S = 20.0     # 查完的結果最多等多久就先回報


def _heavy_names(ip: str, probes: list[str]) -> dict:
    """名稱查詢（反解／NetBIOS／mDNS）：幾秒內完成。"""
    item: dict = {"ip": ip, "alive": True, "liveness": False}
    probes_run: list[str] = []
    if "rdns" in probes:
        probes_run.append("rdns")
        rd, no_ptr = _rdns(ip)
        if rd:
            item["rdns"] = rd
        elif no_ptr:
            item["rdns"] = ""     # DNS 明確說沒有 → 伺服器清掉舊名（1.8.1 起）
    if "netbios" in probes:
        probes_run.append("netbios")
        nb = _netbios(ip)
        if nb:
            item["netbios"] = nb
    if "mdns" in probes:
        probes_run.append("mdns")
        md = _mdns(ip)
        if md:
            item["mdns"] = md
    item["probes_run"] = probes_run
    return item


def _heavy_nmap(ip: str, probes: list[str]) -> dict:
    """OS 指紋／連接埠（nmap）：每台可能要一分多鐘。"""
    want_os, want_ports = "os" in probes, "ports" in probes
    item: dict = {"ip": ip, "alive": True, "liveness": False}
    np = _nmap_os_ports(ip, want_os, want_ports)
    item["probes_run"] = [p for p in ("os", "ports") if p in probes]
    if np.get("os_guess"):
        item["os_guess"] = np["os_guess"]
    if np.get("open_ports"):
        item["open_ports"] = sorted(set(np["open_ports"]))
    if np.get("nmap"):
        item["nmap"] = np["nmap"]
    return item


def _heavy_probe_host(ip: str, probes: list[str]) -> dict:
    """對一台在線主機跑完所有重量探測，合成一筆。結果**不是上線證據**（liveness=False）：
    反解是 DNS 回答的，不是主機本身；排進佇列到真正跑到之間也可能隔了幾分鐘。"""
    item = _heavy_names(ip, probes)
    if "os" in probes or "ports" in probes:
        np = _heavy_nmap(ip, probes)
        item["probes_run"] = item["probes_run"] + np.pop("probes_run")
        item.update({k: v for k, v in np.items() if k in ("os_guess", "open_ports", "nmap")})
    return item


def _heavy_drain(q: _HeavyQueue, batch: int = 50) -> int:
    """把佇列裡的主機跑完。名稱查詢與 nmap 各用自己的工作池（nmap 很慢，不能讓它佔住名稱查詢），
    查完的結果累積到一批、或最多等 HEAVY_FLUSH_S 秒就先回報。回傳處理了幾台。"""
    done = 0
    buf: list[dict] = []
    last_flush = time.time()

    def flush() -> None:
        nonlocal buf, last_flush
        # 伺服器重啟（部署）的那幾秒會回 502：背景結果是花好幾分鐘跑出來的，丟了要等下一個週期
        # 才會重跑，所以隔幾秒再送，最多三次
        for attempt in range(3):
            if not buf:
                break
            try:
                _req("POST", "/api/v1/scan-agents/report", {"results": buf})
                break
            except Exception as exc:  # noqa: BLE001
                print(f"[heavy] report failed ({attempt + 1}/3): {type(exc).__name__}: {exc}",
                      file=sys.stderr, flush=True)
                if attempt < 2:
                    time.sleep(10 * (attempt + 1))
        buf = []
        last_flush = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, HEAVY_WORKERS)) as names_pool, \
            concurrent.futures.ThreadPoolExecutor(max_workers=max(1, NMAP_WORKERS)) as nmap_pool:
        while True:
            work = q.take(batch)
            if not work:
                break
            started = time.time()
            futs = []
            for ip, probes in work:
                if any(p in NAME_PROBES for p in probes):
                    futs.append(names_pool.submit(_heavy_names, ip, probes))
                if "os" in probes or "ports" in probes:
                    futs.append(nmap_pool.submit(_heavy_nmap, ip, probes))
            pending = set(futs)
            while pending:
                finished, pending = concurrent.futures.wait(pending, timeout=1.0)
                for f in finished:
                    try:
                        buf.append(f.result())
                    except Exception as exc:  # noqa: BLE001 -- 一台失敗不影響其他台
                        print(f"[heavy] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
                    if len(buf) >= batch:
                        flush()
                if buf and time.time() - last_flush >= HEAVY_FLUSH_S:
                    flush()
            flush()
            done += len(work)
            _HEAVY_STATS["done"] += len(work)
            _HEAVY_STATS["last_batch_s"] = round(time.time() - started, 1)
            print(f"[heavy] {len(work)} hosts in {_HEAVY_STATS['last_batch_s']}s, "
                  f"{q.pending()} still queued", flush=True)
    return done


def _heavy_loop() -> None:
    """背景執行緒：有待辦就跑，沒有就等。任何錯誤都不能讓它停掉（也不能影響上線偵測）。"""
    while True:
        try:
            if _HEAVY.pending():
                _heavy_drain(_HEAVY)
            else:
                time.sleep(2)
        except Exception as exc:  # noqa: BLE001
            print(f"[heavy] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            time.sleep(10)


def scan_once() -> None:
    _reap_inherited()
    cycle_started = time.time()
    caps = _capabilities()
    poll = _req("GET", "/api/v1/scan-agents/poll",
                extra_headers={"X-Agent-Probes": ",".join(caps),
                               "X-Agent-Tools": _tools_header(),
                               "X-Agent-Relay": _relay_header()})
    _relay_set_assigned(poll.get("relay_cidrs") or [], poll.get("relay_ports") or [], poll.get("relay_max") or 0)
    _maybe_self_update(poll.get("agent_sha"))
    subnets = poll.get("subnets") or []
    fast = int(poll.get("interval_seconds") or INTERVAL)
    _CURRENT_FAST[0] = fast  # 給 main 的 sleep 用
    intervals = poll.get("intervals") or {}
    ip_overrides = poll.get("ip_overrides") or {}
    # 「立刻執行一次」：server 要求強制本輪全跑 → 清掉各探測的上次執行時間（全部判定到期）
    if poll.get("force_scan"):
        _last_run.clear()
        print("[poll] force_scan: running all probes now", flush=True)
    print(f"[poll] agent={poll.get('agent')} subnets={len(subnets)} "
          f"fast={fast}s caps={','.join(caps)}", flush=True)
    # 獨立 ISC DHCP Server：伺服器指派了才讀本機 dhcpd 檔（背景執行，不佔這一輪的時間）
    _dhcpd_maybe_report(poll.get("dhcpd"), time.time())

    cap_set = set(caps)
    now = time.time()
    subnet_stats: list[dict] = []

    for s in subnets:
        cidr = s.get("cidr")
        if not cidr:
            continue
        sub_started = time.time()
        subnet_id = s.get("subnet_id")
        # server 要求的探測；缺/空 -> 向下相容用 icmp。再交集本機能力。
        requested = s.get("probes") or list(DEFAULT_PROBES)
        requested = [p for p in requested if p in ALL_PROBES]
        if not requested:
            requested = list(DEFAULT_PROBES)
        # 本輪實際對此子網要跑哪些探測（能力 ∩ 請求 ∩ cadence-due）
        due = [p for p in requested
               if p in cap_set and _due(subnet_id, p, intervals, fast, now)]
        # 標記這些探測本輪已跑（即使後面某 host 失敗，cadence 仍以本輪為準）
        for p in due:
            _last_run[(subnet_id, p)] = now

        if not due:
            print(f"  {cidr}: no probe due this cycle", flush=True)
            continue
        light, heavy = _split_probes(due)

        # DHCP 偵測是「對整個網段問一次」，不是逐台問 —— 它找的是誰在發 IP。
        dhcp_servers: list[dict] = []
        if "dhcp" in light:
            offers = _dhcp_discover()
            # 先問完再讀 arp 表：剛跟我們講過話的主機這時才會在表裡
            neigh = _arp_table() if offers else {}
            for srv in offers:
                srv["subnet_cidr"] = cidr
                srv["mac"] = neigh.get(srv["server_ip"])
                dhcp_servers.append(srv)
            print(f"  {cidr}: dhcp offers={len(dhcp_servers)}", flush=True)

        hosts, total_hosts, chunk = _subnet_chunk(str(subnet_id or cidr), cidr)
        if chunk["rounds"] > 1:
            print(f"  subnet {cidr} has {total_hosts} hosts -> scanning part {chunk['chunk']}/{chunk['rounds']} "
                  f"({hosts[0]}-{hosts[-1]})", flush=True)
        # arp 表用於 arp 探測，也順手在其他探測時補 mac。
        arp = _arp_table()

        icmp_alive: dict[str, bool] = {}
        if "icmp" in light:
            with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
                for ip, ok in zip(hosts, ex.map(_ping, hosts)):
                    icmp_alive[ip] = bool(ok)

        tcp_ports: dict[str, list[int]] = {}
        if "tcp" in light:
            with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
                for ip, ports in zip(hosts, ex.map(_tcp_scan, hosts)):
                    if ports:
                        tcp_ports[ip] = ports

        results: list[dict] = []
        for ip in hosts:
            # 套用 per-IP override：略過指定探測
            skip = set(ip_overrides.get(ip) or [])
            host_light = [p for p in light if p not in skip]
            host_heavy = [p for p in heavy if p not in skip]
            if not host_light and not host_heavy:
                continue

            alive = False
            item: dict = {"ip": ip}
            probes_run: list[str] = []
            if "icmp" in host_light:
                probes_run.append("icmp")
                if icmp_alive.get(ip):
                    alive = True
            if "tcp" in host_light:
                probes_run.append("tcp")
                ports = tcp_ports.get(ip) or []
                if ports:
                    alive = True
                    item["open_ports"] = sorted(set(ports))
            mac = arp.get(ip)
            if "arp" in host_light:
                probes_run.append("arp")
                if mac:
                    alive = True  # 在 neigh 表代表本子網有回應過
            if mac:
                item["mac"] = mac   # 即使沒跑 arp 探測，arp 表剛好有資料也順手補 mac
            # snmp 仍不實作（需社群字串/憑證，違反「不做需憑證探測」原則）
            if not alive:
                continue
            item["alive"] = True
            item["probes_run"] = probes_run
            results.append(item)
            # 重量探測只對在線主機、丟給背景跑，不佔住這一輪
            if host_heavy:
                _HEAVY.submit(subnet_id, ip, host_heavy)

        # 每個子網路做完就回報，不等其他子網路（大子網路或慢的子網路不會拖住別人）
        if results or dhcp_servers:
            payload: dict = {"results": results}
            if dhcp_servers:
                payload["dhcp_servers"] = dhcp_servers
            r = _req("POST", "/api/v1/scan-agents/report", payload)
            print(f"  {cidr}: probes={'+'.join(light) or '-'} alive={len(results)}/{len(hosts)} "
                  f"queued={'+'.join(heavy) or '-'} updated={r.get('updated')}", flush=True)
        subnet_stats.append({"cidr": cidr, "hosts": len(hosts), "total_hosts": total_hosts,
                             "alive": len(results), "truncated": False, **chunk,
                             "duration_s": round(time.time() - sub_started, 1)})

    # 整輪統計：負載顯示與超載通知用（耗時 ÷ 週期、背景待辦量）
    _req("POST", "/api/v1/scan-agents/report", {"results": [], "cycle": {
        "duration_s": round(time.time() - cycle_started, 1),
        "interval_s": fast,
        "subnets": subnet_stats,
        "heavy_backlog": _HEAVY.pending(),
        "heavy_done": int(_HEAVY_STATS["done"]),
        "heavy_last_batch_s": _HEAVY_STATS["last_batch_s"],
        "agent_version": AGENT_VERSION,
    }})


# ─────────────────── On-demand probe jobs (Tools page) ───────────────────
# The server cannot reach us: we only dial out. So on-demand probes arrive through a
# long-poll queue -- we ask for work, run it locally, and post the result back.
#
# SECURITY: we validate every job ourselves and never pass anything to a shell.
# The server is not trusted to have validated for us: if the server is compromised,
# this check is the last thing standing between it and arbitrary probing of the
# customer network. Only these read-only probe kinds are ever executed; identify runs a
# fixed, read-only script list defined in this file (see _IDENTIFY_SCRIPTS).
_JOB_KINDS = ("ping", "tcp", "traceroute", "rdns", "identify")
_JOB_MAX_TARGETS = 64
_JOB_MAX_PORTS = 64
_HOSTNAME_OK = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                          r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

def _job_valid_target(t: str) -> str | None:
    s = (t or "").strip()
    if not s or len(s) > 253:
        return None
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    return s if _HOSTNAME_OK.match(s) else None


def _job_run_ping(targets: list[str], count: int, timeout: float) -> list[dict]:
    out = []
    for t in targets:
        argv = ["ping", "-c", str(count), "-W", str(int(max(1, timeout))), t]
        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               timeout=count * timeout + 5)
            ok = r.returncode == 0
            out.append({"target": t, "alive": ok, "output": (r.stdout or "")[-2000:]})
        except Exception as exc:  # noqa: BLE001
            out.append({"target": t, "alive": False, "error": f"{type(exc).__name__}"})
    return out


def _job_run_tcp(targets: list[str], ports: list[int], timeout: float) -> list[dict]:
    out = []
    for t in targets:
        opened, closed = [], []
        for p in ports:
            try:
                with socket.create_connection((t, p), timeout=timeout):
                    opened.append(p)
            except Exception:  # noqa: BLE001
                closed.append(p)
        out.append({"target": t, "open": opened, "closed": closed})
    return out


def _job_run_traceroute(target: str, max_hops: int) -> dict:
    for tool in ("tracepath", "traceroute"):
        exe = shutil.which(tool)
        if not exe:
            continue
        argv = ([exe, "-m", str(max_hops), target] if tool == "traceroute"
                else [exe, "-m", str(max_hops), target])
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=max_hops * 3 + 10)
            return {"target": target, "tool": tool, "output": (r.stdout or "")[-8000:]}
        except Exception as exc:  # noqa: BLE001
            return {"target": target, "tool": tool, "error": f"{type(exc).__name__}"}
    return {"target": target, "error": "no traceroute tool available (tracepath/traceroute)"}


# identify（IP 詳細頁的「探測」）：只做唯讀、非侵入的識別 —— 服務版本、OS 指紋，加上固定一小組
# 讀取資訊用的 NSE 腳本（banner／HTTP 標題與伺服器標頭／TLS 憑證／SSH 主機金鑰／SMB 與 RDP 的
# 系統資訊）。清單寫死在這裡、不從伺服器收：後端被入侵也改不了代理會跑什麼。
_IDENTIFY_SCRIPTS = ("banner,http-title,http-server-header,ssl-cert,ssh-hostkey,"
                     "smb-os-discovery,rdp-ntlm-info")
_IDENTIFY_TIMEOUT = 300          # 秒；伺服器端的「領走未回報」門檻比這個長
_IDENTIFY_MAX_PORTS = 200
_IDENTIFY_MAX_TEXT = 600         # 每段腳本輸出最多保留幾個字元
_IDENTIFY_TOP_PORTS = 1000
# nmap 的前 1000 個常用埠不含這些，但它們最能說明「這是什麼設備」：PVE／PBS 網頁、WinRM、
# Intel AMT、HPE iLO、MikroTik Winbox／API、Docker／Kubernetes API、常見攝影機與 NVR 管理埠。
# 刻意不放工控協定（Modbus、S7 等）：老舊 PLC 可能被版本探測弄當。
_IDENTIFY_EXTRA_PORTS = (902, 2375, 2376, 5601, 5985, 5986, 6443, 8006, 8007, 8123, 8291, 8554,
                         8728, 8729, 9443, 10050, 10443, 16992, 16993, 17988, 17990, 34567, 37777)
_NMAP_SERVICES_PATHS = ("/usr/share/nmap/nmap-services", "/usr/local/share/nmap/nmap-services",
                        "/opt/homebrew/share/nmap/nmap-services")


def _identify_port_list(path: str | None = None, top: int = _IDENTIFY_TOP_PORTS) -> str | None:
    """前 N 個常用 TCP 埠（依 nmap-services 的頻率）＋補充清單，逗號分隔。

    nmap 的 `-p` 與 `--top-ports` 併用時是取交集而不是聯集，所以自己算。讀不到檔案回 None，
    呼叫端退回 `--top-ports`。
    """
    for p in ((path,) if path else _NMAP_SERVICES_PATHS):
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        ranked: list[tuple[float, int]] = []
        for line in lines:
            parts = line.split()
            if len(parts) < 3 or line.startswith("#") or not parts[1].endswith("/tcp"):
                continue
            try:
                ranked.append((float(parts[2]), int(parts[1][:-4])))
            except ValueError:
                continue
        if not ranked:
            continue
        ranked.sort(key=lambda x: (-x[0], x[1]))
        ports = {port for _, port in ranked[:top]} | set(_IDENTIFY_EXTRA_PORTS)
        return ",".join(str(x) for x in sorted(ports))
    return None


_MAX_SAN = 20


def _cert_data(sc) -> dict:  # noqa: ANN001 -- ElementTree element
    """ssl-cert 的結構化欄位：Subject／Issuer、有效期間、指紋、金鑰、SAN（1.17.4 起多了後四項）。

    文字輸出最多留 600 字，SAN 很長時到期日會被切掉；這裡不受影響。nmap 7.94 不給 SHA-256，
    從 PEM 自己算；PEM 本身不送回伺服器（只要指紋）。"""
    cert: dict = {}
    for part in ("subject", "issuer"):
        table = sc.find(f"table[@key='{part}']")
        if table is not None:
            cert[part] = {e.get("key"): (e.text or "")[:200] for e in table.findall("elem") if e.get("key")}
    val = sc.find("table[@key='validity']")
    if val is not None:
        for key, out_key in (("notBefore", "not_before"), ("notAfter", "not_after")):
            e = val.find(f"elem[@key='{key}']")
            if e is not None and e.text:
                cert[out_key] = e.text[:40]
    sha1 = sc.find("elem[@key='sha1']")
    if sha1 is not None and sha1.text:
        cert["sha1"] = sha1.text.strip().lower()[:64]
    pem = sc.find("elem[@key='pem']")
    if pem is not None and pem.text:
        body = "".join(ln for ln in pem.text.splitlines() if ln and not ln.startswith("-----"))
        try:
            cert["sha256"] = hashlib.sha256(base64.b64decode(body)).hexdigest()
        except Exception:  # noqa: BLE001 -- 指紋算不出來就不給，其餘照常
            pass
    pk = sc.find("table[@key='pubkey']")
    if pk is not None:
        t, b = pk.find("elem[@key='type']"), pk.find("elem[@key='bits']")
        if t is not None and t.text:
            cert["key_type"] = t.text[:20]
        if b is not None and (b.text or "").isdigit():
            cert["key_bits"] = int(b.text)
    for ext in sc.findall("table[@key='extensions']/table"):
        name = ext.find("elem[@key='name']")
        value = ext.find("elem[@key='value']")
        if name is not None and name.text == "X509v3 Subject Alternative Name" and value is not None:
            cert["san"] = [x.strip()[:200] for x in (value.text or "").split(",") if x.strip()][:_MAX_SAN]
    return cert


def _hostkey_data(sc) -> list:  # noqa: ANN001 -- ElementTree element
    """ssh-hostkey → [{type, bits, sha256}]。nmap 預設只給 MD5；OpenSSH 現在顯示的是 SHA256，
    從金鑰本體自己算，畫面才對得上 `ssh-keygen -lf`。金鑰本體不送回伺服器。"""
    keys = []
    for tb in sc.findall("table"):
        g = {e.get("key"): (e.text or "") for e in tb.findall("elem") if e.get("key")}
        if not g.get("key"):
            continue
        try:
            fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(g["key"])).digest()).decode().rstrip("=")
        except Exception:  # noqa: BLE001
            continue
        keys.append({"type": g.get("type", "")[:40], "bits": int(g["bits"]) if g.get("bits", "").isdigit() else None,
                     "sha256": fp})
    return keys[:8]


def _script_data(port) -> dict:  # noqa: ANN001 -- ElementTree element
    """腳本的結構化輸出裡伺服器要用的部分：ssl-cert（Subject／Issuer 各欄位、有效期間、指紋、金鑰、SAN）
    與 ssh-hostkey（SHA256 指紋）。"""
    out: dict = {}
    for sc in port.findall("script"):
        if sc.get("id") == "ssl-cert":
            cert = _cert_data(sc)
            if cert:
                out["ssl-cert"] = cert
        elif sc.get("id") == "ssh-hostkey":
            keys = _hostkey_data(sc)
            if keys:
                out["ssh-hostkey"] = keys
    return out


def _scripts_of(el) -> tuple[dict, list]:  # noqa: ANN001 -- ElementTree element
    """{腳本 id: 輸出（最多 _IDENTIFY_MAX_TEXT 字）}，以及被截斷的腳本 id（畫面要標出來）。"""
    texts, cut = {}, []
    for sc in el.findall("script"):
        sid = sc.get("id")
        if not sid:
            continue
        full = (sc.get("output") or "").strip()
        texts[sid] = full[:_IDENTIFY_MAX_TEXT]
        if len(full) > _IDENTIFY_MAX_TEXT:
            cut.append(sid)
    return texts, cut


def _parse_nmap_xml(text: str) -> dict:
    """nmap -oX 輸出 → {hostnames, mac, mac_vendor, ports[開著的], os[], host_scripts{}}。解析失敗回空結構。

    host_scripts：主機層腳本（smb-os-discovery 不掛在任何埠下，以前整段被丟掉）。
    ports[].script_data：ssl-cert 的完整 Subject／Issuer —— 文字輸出只有 CN／O／ST／C，
    伺服器端比對 Recog 的設備預設憑證要 OU、L 這些欄位。
    ports[].method／conf／devicetype（1.17.2 起）：nmap 怎麼認出這個服務。method="table" ＝沒有探針比中、
    服務名稱只是照埠號表寫的（9100 寫 jetdirect、554 寫 rtsp），伺服器不可以當成認出了服務；devicetype 是
    nmap-service-probes 的 d/ 欄位（這個服務通常跑在哪種設備上）。舊伺服器不認得這幾個欄位，照樣忽略。
    1.17.4 起：filtered（被過濾的埠數）、distance（跳數）、uptime（nmap 推估的開機時間）、host_found
    （輸出裡有沒有這台：沒有＝nmap 失敗或略過，不是「沒回應」）、timedout（單台時限到了、結果被丟掉）、
    ports[].truncated／host_scripts_truncated（輸出被截斷的腳本）。

    XML 是本機剛跑完的 nmap 產生的（不是從網路收來的文件），用標準函式庫解析即可。
    """
    # closed：回了 RST 的埠數 —— 有這個就代表主機活著，只是那些埠沒開；全部 filtered 又沒有 MAC 回應＝沒回應
    out: dict = {"hostnames": [], "mac": None, "mac_vendor": None, "ports": [], "os": [], "closed": 0,
                 "filtered": 0, "host_scripts": {}, "host_scripts_truncated": [], "distance": None, "uptime": None,
                 "host_found": False, "timedout": False}
    try:
        root = ET.fromstring(text)  # noqa: S314 -- local nmap output, not untrusted input
    except Exception:  # noqa: BLE001
        return out
    host = root.find("host")
    if host is None:
        return out
    out["host_found"] = True
    out["timedout"] = host.get("timedout") == "true"
    dist = host.find("distance")
    if dist is not None and (dist.get("value") or "").isdigit():
        out["distance"] = int(dist.get("value"))
    up = host.find("uptime")
    if up is not None and (up.get("seconds") or "").isdigit():
        out["uptime"] = {"seconds": int(up.get("seconds")), "lastboot": (up.get("lastboot") or "")[:60] or None}
    for a in host.findall("address"):
        if a.get("addrtype") == "mac":
            out["mac"], out["mac_vendor"] = a.get("addr"), a.get("vendor")
    out["hostnames"] = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]
    for ex in host.findall("ports/extraports"):
        if ex.get("state") in ("closed", "filtered"):
            out[ex.get("state")] += int(ex.get("count") or 0)
    for port in host.findall("ports/port"):
        st = port.find("state")
        if st is not None and st.get("state") in ("closed", "filtered"):
            out[st.get("state")] += 1
        if st is None or st.get("state") != "open":
            continue
        svc = port.find("service")
        g = (lambda k: (svc.get(k) if svc is not None else None) or "")
        scripts, cut = _scripts_of(port)
        out["ports"].append({
            "port": int(port.get("portid") or 0), "proto": port.get("protocol") or "tcp",
            "state": "open", "service": g("name"), "product": g("product"), "version": g("version"),
            "extrainfo": g("extrainfo"), "tunnel": g("tunnel"), "ostype": g("ostype"),
            "method": g("method"), "conf": g("conf"), "devicetype": g("devicetype"),
            "scripts": scripts, "truncated": cut,
            "script_data": _script_data(port),
        })
        if len(out["ports"]) >= _IDENTIFY_MAX_PORTS:
            break
    hs = host.find("hostscript")
    if hs is not None:
        out["host_scripts"], out["host_scripts_truncated"] = _scripts_of(hs)
    for m in host.findall("os/osmatch")[:5]:
        cls = m.find("osclass")
        out["os"].append({
            "name": m.get("name"), "accuracy": int(m.get("accuracy") or 0),
            "type": cls.get("type") if cls is not None else None,
            "vendor": cls.get("vendor") if cls is not None else None,
            "family": cls.get("osfamily") if cls is not None else None,
        })
    return out


def _job_run_identify(target: str, progress=None) -> dict:  # noqa: ANN001
    """對單一 IP 做識別：名稱查詢（反解／NetBIOS／mDNS）＋ nmap 服務版本與 OS 指紋。

    `progress`：每個階段開始時呼叫一次（{"stage": ...}），讓畫面看得到現在在做什麼。
    """
    started = time.time()

    def stage(name: str) -> None:
        if progress:
            try:
                progress({"stage": name, "elapsed": round(time.time() - started, 1)})
            except Exception:  # noqa: BLE001 -- 進度回報失敗不可以讓探測本身失敗
                pass

    stage("names")
    names = {"rdns": _rdns(target)[0], "netbios": _netbios(target), "mdns": _mdns(target)}
    if not shutil.which("nmap"):
        return {"target": target, "names": names, "nmap": {"available": False}}
    stage("scan")
    port_list = _identify_port_list()
    ports = ["-p", port_list] if port_list else ["--top-ports", str(_IDENTIFY_TOP_PORTS)]
    argv = ["nmap", "-Pn", "-sV", "--version-intensity", "5", *ports, "-T4",
            "--host-timeout", f"{_IDENTIFY_TIMEOUT - 30}s", "--script", _IDENTIFY_SCRIPTS]
    # IPv6 要 -6，不然 nmap 把位址當成解析不了的主機名稱（以前 IPv6 的探測一定失敗）
    if ipaddress.ip_address(target).version == 6:
        argv.append("-6")
    os_scan = hasattr(os, "geteuid") and os.geteuid() == 0
    if os_scan:
        argv += ["-O", "--osscan-guess"]      # OS 指紋要 raw socket（root）；沒有就只做服務版本
    argv += ["-oX", "-", target]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=_IDENTIFY_TIMEOUT)
        parsed = _parse_nmap_xml(r.stdout or "")
        nmap = {"available": True, **parsed, "exit": r.returncode, "os_scan": os_scan,
                "stderr": (r.stderr or "")[-_IDENTIFY_MAX_TEXT:] or None}
    except subprocess.TimeoutExpired:
        nmap = {"available": True, "os_scan": os_scan, "error": f"nmap timed out after {_IDENTIFY_TIMEOUT}s"}
    except Exception as exc:  # noqa: BLE001
        nmap = {"available": True, "os_scan": os_scan, "error": f"{type(exc).__name__}: {exc}"[:_IDENTIFY_MAX_TEXT]}
    return {"target": target, "names": names, "nmap": nmap, "elapsed": round(time.time() - started, 1)}


def _job_execute(kind: str, params: dict, progress=None) -> tuple[object, str | None]:  # noqa: ANN001
    """Run one job. Returns (result, error). Never raises."""
    if kind not in _JOB_KINDS:
        return None, f"unsupported probe: {kind}"
    raw = params.get("targets") or []
    items = raw if isinstance(raw, list) else re.split(r"[\s,]+", str(raw))
    targets = [x for x in (_job_valid_target(t) for t in items if t) if x]
    if not targets:
        return None, "no valid target"
    if len(targets) > _JOB_MAX_TARGETS:
        return None, f"too many targets (max {_JOB_MAX_TARGETS})"
    try:
        if kind == "ping":
            count = max(1, min(int(params.get("count") or 3), 10))
            timeout = max(0.5, min(float(params.get("timeout") or 2.0), 10.0))
            return _job_run_ping(targets, count, timeout), None
        if kind == "tcp":
            ports = [int(p) for p in (params.get("ports") or []) if 1 <= int(p) <= 65535]
            if not ports:
                return None, "no valid port"
            if len(ports) > _JOB_MAX_PORTS:
                return None, f"too many ports (max {_JOB_MAX_PORTS})"
            timeout = max(0.2, min(float(params.get("timeout") or 1.5), 10.0))
            return _job_run_tcp(targets, ports, timeout), None
        if kind == "traceroute":
            hops = max(1, min(int(params.get("max_hops") or 20), 30))
            return _job_run_traceroute(targets[0], hops), None
        if kind == "identify":
            # 代理自己也要擋：只接受單一 IP（不收主機名稱、不收多個目標）
            if len(targets) != 1:
                return None, "identify takes exactly one target"
            try:
                ipaddress.ip_address(targets[0])
            except ValueError:
                return None, "identify takes an IP address"
            return _job_run_identify(targets[0], progress), None
        return [{"target": t, "hostname": _rdns(t)[0]} for t in targets], None
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _job_runs_in_background(kind: str) -> bool:
    """identify 要跑好幾分鐘；放在工作佇列的執行緒上跑，這段期間其他工具探測會排不到
    （待辦兩分鐘沒被領就作廢）。其他種類幾秒內就結束，照順序跑即可。"""
    return kind == "identify"


def _job_run_and_report(job: dict) -> None:
    jid, kind = job.get("id"), str(job.get("kind"))

    def progress(p: dict) -> None:
        _req("POST", f"/api/v1/scan-agents/jobs/{jid}/progress", {"progress": p})

    result, error = _job_execute(kind, job.get("params") or {},
                                 progress=progress if kind == "identify" else None)
    try:
        _req("POST", f"/api/v1/scan-agents/jobs/{jid}/result", {"result": result, "error": error})
    except Exception as exc:  # noqa: BLE001
        print(f"[jobs] report failed: {type(exc).__name__}", file=sys.stderr, flush=True)


# ─────────────────── Console relay (issue #24 phase 2) ───────────────────
# The server cannot reach into this network; the agent dials out. For each console session the server
# hands out a `relay_open` job; the agent checks the target against ITS OWN rules, connects to it, then
# opens one outbound WebSocket per session to /api/v1/scan-agents/relay/<sid>/ws and moves bytes.
#
# Security: the server hands out the scope (assigned subnets, ports, session limit) only while the
# admin has relay switched on in the web UI; without a scope nothing is relayed. The target must be
# inside that scope (and inside the optional local pins). Loopback, link-local and multicast are always
# refused. JT_IPAM_RELAY=0 on this host refuses everything. A single-use ticket ties the WebSocket to
# this job.


def _relay_env_on(value) -> bool:
    """On unless the host owner explicitly says no: whether to relay is decided in the web UI."""
    return (value or "").strip().lower() not in ("0", "false", "no", "off")


RELAY_ENABLED = _relay_env_on(os.environ.get("JT_IPAM_RELAY"))
RELAY_PORTS_SPEC = os.environ.get("JT_IPAM_RELAY_PORTS", "")
_max_env = (os.environ.get("JT_IPAM_RELAY_MAX") or "").strip()
RELAY_MAX_LOCAL = max(1, min(int(_max_env), 64)) if _max_env.isdigit() else None
RELAY_CIDRS_SPEC = os.environ.get("JT_IPAM_RELAY_CIDRS", "")
RELAY_FRAME_MAX = 64 * 1024          # largest frame we accept from the server
RELAY_CHUNK = 64 * 1024              # largest frame we send
RELAY_CONNECT_TIMEOUT = 10.0
RELAY_KEEPALIVE = 25.0               # idle seconds before an application-level keepalive frame
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_RELAY_ASSIGNED: list = []           # networks the server says this agent is assigned to
_RELAY_PORTS: set = set()            # ports allowed in the web UI (from the server)
_RELAY_MAX = [0]                     # session limit set in the web UI (from the server)
_RELAY_ACTIVE = 0
_RELAY_LOCK = threading.Lock()
_TOKEN_OK = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SID_OK = re.compile(r"^[0-9a-f]{32}$")


def _parse_ports(spec: str) -> set:
    out: set = set()
    for tok in (spec or "").split(","):
        a, _, b = tok.strip().partition("-")
        if not a.isdigit() or (b and not b.isdigit()):
            continue
        lo, hi = int(a), int(b or a)
        if 1 <= lo <= hi <= 65535 and hi - lo < 256:
            out.update(range(lo, hi + 1))
    return out


def _parse_nets(spec) -> list:
    items = spec if isinstance(spec, list) else str(spec or "").split(",")
    nets = []
    for c in items:
        try:
            nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            continue
    return nets


RELAY_PORTS_LOCAL = _parse_ports(RELAY_PORTS_SPEC) if RELAY_PORTS_SPEC.strip() else None
RELAY_PINNED = _parse_nets(RELAY_CIDRS_SPEC) if RELAY_CIDRS_SPEC.strip() else None


def _relay_header() -> str:
    """Capabilities for X-Agent-Relay. Sent even when off, so the server can say *why* it cannot relay.
    ports / max are the host owner's local limits (empty / 0 = none, the web UI decides)."""
    ports = ",".join(str(p) for p in sorted(RELAY_PORTS_LOCAL or ()))
    return (f"enabled={1 if RELAY_ENABLED else 0};ports={ports};max={RELAY_MAX_LOCAL or 0};"
            f"pinned={1 if RELAY_PINNED is not None else 0}")


def _relay_set_assigned(cidrs: list, ports=None, max_sessions=None) -> None:
    """The scope the server currently allows (poll, or fresh in each relay job). Empty = relay nothing."""
    with _RELAY_LOCK:
        _RELAY_ASSIGNED[:] = _parse_nets(cidrs)
        if ports is not None:
            _RELAY_PORTS.clear()
            _RELAY_PORTS.update(int(p) for p in ports if str(p).isdigit() and 1 <= int(p) <= 65535)
        if max_sessions is not None:
            try:
                _RELAY_MAX[0] = max(0, min(int(max_sessions), 64))
            except (TypeError, ValueError):
                _RELAY_MAX[0] = 0


def _relay_limit() -> int:
    lim = _RELAY_MAX[0]
    return min(lim, RELAY_MAX_LOCAL) if RELAY_MAX_LOCAL else lim


def _relay_acquire() -> bool:
    global _RELAY_ACTIVE
    with _RELAY_LOCK:
        if _RELAY_ACTIVE >= _relay_limit():
            return False
        _RELAY_ACTIVE += 1
        return True


def _relay_release() -> None:
    global _RELAY_ACTIVE
    with _RELAY_LOCK:
        _RELAY_ACTIVE = max(0, _RELAY_ACTIVE - 1)


def _relay_target_ok(target: str, port: int) -> str | None:
    """None when allowed, else an error token. The agent decides for itself -- it does not take the
    server's word for the target."""
    if not RELAY_ENABLED:
        return "relay_disabled"
    with _RELAY_LOCK:
        ports = set(_RELAY_PORTS)
    if port not in ports or (RELAY_PORTS_LOCAL is not None and port not in RELAY_PORTS_LOCAL):
        return "relay_port_not_allowed"
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return "relay_target_not_allowed"
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return "relay_target_not_allowed"
    with _RELAY_LOCK:
        assigned = list(_RELAY_ASSIGNED)
    if not any(ip in n for n in assigned if n.version == ip.version):
        return "relay_target_not_allowed"
    if RELAY_PINNED is not None and not any(ip in n for n in RELAY_PINNED if n.version == ip.version):
        return "relay_target_not_allowed"
    return None


class _WSError(Exception):
    pass


def _ws_mask(payload: bytes, key: bytes) -> bytes:
    """XOR with the 4-byte key. Big-int XOR: fast enough for 64 KiB frames in pure Python."""
    n = len(payload)
    if not n:
        return b""
    m = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(m, "big")).to_bytes(n, "big")


def _ws_encode(opcode: int, payload: bytes) -> bytes:
    """One client frame (FIN set, masked as RFC 6455 requires of clients)."""
    n = len(payload)
    b1 = 0x80 | opcode
    if n < 126:
        head = struct.pack("!BB", b1, 0x80 | n)
    elif n < 65536:
        head = struct.pack("!BBH", b1, 0x80 | 126, n)
    else:
        head = struct.pack("!BBQ", b1, 0x80 | 127, n)
    key = os.urandom(4)
    return head + key + _ws_mask(payload, key)


def _ws_decode(buf: bytearray):
    """Take one complete server frame off the front of `buf` -> (opcode, payload), or None if more
    bytes are needed. Only the subset we use: no fragmentation, no masked server frames, no
    unknown opcodes, frames up to RELAY_FRAME_MAX. Anything else closes the session."""
    if len(buf) < 2:
        return None
    b1, b2 = buf[0], buf[1]
    fin, opcode, masked, n = b1 & 0x80, b1 & 0x0F, b2 & 0x80, b2 & 0x7F
    i = 2
    if n == 126:
        if len(buf) < 4:
            return None
        n = struct.unpack("!H", bytes(buf[2:4]))[0]
        i = 4
    elif n == 127:
        if len(buf) < 10:
            return None
        n = struct.unpack("!Q", bytes(buf[2:10]))[0]
        i = 10
    if masked:
        raise _WSError("masked frame from server")
    if not fin or opcode == 0:
        raise _WSError("fragmented frame")
    if opcode not in (0x1, 0x2, 0x8, 0x9, 0xA):
        raise _WSError(f"unexpected opcode {opcode}")
    if n > RELAY_FRAME_MAX:
        raise _WSError(f"frame too large ({n})")
    if len(buf) < i + n:
        return None
    payload = bytes(buf[i:i + n])
    del buf[:i + n]
    return opcode, payload


class _WS:
    def __init__(self, sock, rest: bytes = b"") -> None:
        self.sock = sock
        self.buf = bytearray(rest)
        self.closed = False

    def send(self, opcode: int, payload: bytes) -> None:
        self.sock.sendall(_ws_encode(opcode, payload))

    def read_frames(self) -> list:
        """Read what is available (the selector said readable) and return every complete frame."""
        data = self.sock.recv(65536)
        if not data:
            self.closed = True
            return []
        self.buf += data
        pending = getattr(self.sock, "pending", None)
        while pending is not None and pending():
            more = self.sock.recv(65536)
            if not more:
                break
            self.buf += more
        return self.buffered_frames()

    def buffered_frames(self) -> list:
        """Complete frames already in the buffer (e.g. one that arrived with the handshake reply)."""
        frames = []
        while True:
            f = _ws_decode(self.buf)
            if f is None:
                return frames
            frames.append(f)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.send(0x8, struct.pack("!H", 1000))
            except OSError:
                pass
        try:
            self.sock.close()
        except OSError:
            pass


def _ws_connect(path: str, headers: dict, timeout: float = RELAY_CONNECT_TIMEOUT) -> _WS:
    """Open a WebSocket to the jt-ipam server (same URL, TLS settings and CA as the rest of the agent)."""
    u = urllib.parse.urlsplit(SERVER)
    host = u.hostname or ""
    tls = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = _ctx().wrap_socket(raw, server_hostname=host) if tls else raw
        key = base64.b64encode(os.urandom(16)).decode()
        hosthdr = f"[{host}]" if ":" in host else host
        if u.port:
            hosthdr += f":{u.port}"
        lines = [f"GET {u.path.rstrip('/')}{path} HTTP/1.1", f"Host: {hosthdr}", "Upgrade: websocket",
                 "Connection: Upgrade", f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
                 f"X-Agent-Key: {KEY}", f"X-Agent-Version: {AGENT_VERSION}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                raise _WSError("server closed during handshake")
            resp += chunk
            if len(resp) > 16384:
                raise _WSError("handshake response too large")
        head, _, rest = resp.partition(b"\r\n\r\n")
        status, *hdr_lines = head.decode("latin-1").split("\r\n")
        parts = status.split(" ", 2)
        if len(parts) < 2 or parts[1] != "101":
            raise _WSError(f"handshake refused: {status[:80]}")
        hdrs = {}
        for line in hdr_lines:
            k, _, v = line.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        want = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()  # noqa: S324 -- RFC 6455 handshake
        if hdrs.get("sec-websocket-accept") != want:
            raise _WSError("bad Sec-WebSocket-Accept")
        sock.settimeout(120)
        return _WS(sock, rest)
    except BaseException:
        raw.close()
        raise


def _relay_report(jid, error=None) -> None:
    try:
        _req("POST", f"/api/v1/scan-agents/jobs/{jid}/result",
             {"result": None if error else {"relay": "open"}, "error": error})
    except Exception as exc:  # noqa: BLE001
        print(f"[relay] report failed: {type(exc).__name__}", file=sys.stderr, flush=True)


def _relay_pump(tsock, ws: _WS) -> str:
    """Move bytes until either side closes. Single thread, one selector over both sockets."""
    sel = selectors.DefaultSelector()
    sel.register(tsock, selectors.EVENT_READ, "target")
    sel.register(ws.sock, selectors.EVENT_READ, "ws")
    last_sent = time.monotonic()

    def handle(frames: list):
        for opcode, payload in frames:
            if opcode == 0x2:
                tsock.sendall(payload)
            elif opcode == 0x9:
                ws.send(0xA, payload)
            elif opcode == 0x8:
                return "server_closed"
            # 0x1 (server keepalive) and 0xA (pong) need nothing
        return None

    try:
        early = handle(ws.buffered_frames())
        if early:
            return early
        while True:
            wait = max(0.5, RELAY_KEEPALIVE - (time.monotonic() - last_sent))
            events = sel.select(wait)
            if not events and time.monotonic() - last_sent >= RELAY_KEEPALIVE:
                ws.send(0x1, b"ka")
                last_sent = time.monotonic()
            for key, _ in events:
                if key.data == "target":
                    data = tsock.recv(RELAY_CHUNK)
                    if not data:
                        return "target_closed"
                    ws.send(0x2, data)
                    last_sent = time.monotonic()
                    continue
                done = handle(ws.read_frames())
                if done or ws.closed:
                    return done or "server_closed"
    finally:
        sel.close()


def _relay_session(job: dict) -> None:
    """One console session. Never raises: relaying must not disturb scanning or probes."""
    jid = job.get("id")
    params = job.get("params") or {}
    target, sid, ticket = str(params.get("target") or ""), str(params.get("sid") or ""), str(params.get("ticket") or "")
    try:
        port = int(params.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not _SID_OK.match(sid) or not _TOKEN_OK.match(ticket):
        _relay_report(jid, "relay_ws_failed: malformed job")
        return
    # The job carries the scope the server allows right now: no waiting for the next poll after an
    # admin switches relay on in the web UI
    scope = params.get("scope")
    if isinstance(scope, dict):
        _relay_set_assigned(scope.get("cidrs") or [], scope.get("ports") or [], scope.get("max") or 0)
    err = _relay_target_ok(target, port)
    if err:
        _relay_report(jid, f"{err}: {target}:{port}")
        return
    if not _relay_acquire():
        _relay_report(jid, f"relay_busy: {_relay_limit()} sessions in use")
        return
    tsock = ws = None
    reason = "error"
    started = time.monotonic()
    try:
        try:
            tsock = socket.create_connection((target, port), timeout=RELAY_CONNECT_TIMEOUT)
            tsock.settimeout(None)
        except OSError as exc:
            _relay_report(jid, f"relay_connect_failed: {exc.strerror or exc}")
            return
        try:
            ws = _ws_connect(f"/api/v1/scan-agents/relay/{sid}/ws", {"X-Relay-Ticket": ticket})
        except Exception as exc:  # noqa: BLE001
            _relay_report(jid, f"relay_ws_failed: {type(exc).__name__}: {exc}")
            return
        _relay_report(jid)
        print(f"[relay] open {sid[:8]} -> {target}:{port}", flush=True)
        reason = _relay_pump(tsock, ws)
    except Exception as exc:  # noqa: BLE001
        reason = f"{type(exc).__name__}: {exc}"
    finally:
        for s in (ws, tsock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        _relay_release()
        if ws is not None:
            print(f"[relay] closed {sid[:8]} after {time.monotonic() - started:.0f}s ({reason})", flush=True)


def _jobs_loop() -> None:
    """Long-poll for on-demand probes. Runs in its own thread.

    Wrapped so that any failure here can never take the scanning loop down with it --
    the agent's primary job is scanning; this is an extra.
    """
    while True:
        try:
            resp = _req("GET", "/api/v1/scan-agents/jobs?wait=25") or {}
            for job in resp.get("jobs") or []:
                if str(job.get("kind")) == "relay_open":
                    # Console relay: long-lived, one thread per session (never blocks probes or scanning)
                    threading.Thread(target=_relay_session, args=(job,), name="jt-ipam-relay",
                                     daemon=True).start()
                    continue
                if _job_runs_in_background(str(job.get("kind"))):
                    threading.Thread(target=_job_run_and_report, args=(job,), daemon=True).start()
                else:
                    _job_run_and_report(job)
        except Exception as exc:  # noqa: BLE001
            print(f"[jobs] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            time.sleep(10)      # back off; do not hammer a server that is down


def main() -> int:
    if not SERVER or not KEY:
        print("ERROR: JT_IPAM_URL and JT_IPAM_AGENT_KEY environment variables are required",
              file=sys.stderr)
        return 2
    # Refuse anything that is not http(s). urllib happily opens file:, ftp: and
    # friends, so a mistyped JT_IPAM_URL would otherwise turn every poll into a
    # local file read -- with the agent key attached to it.
    if not SERVER.startswith(("https://", "http://")):
        print(f"ERROR: JT_IPAM_URL must start with https:// (or http://), got: {SERVER}",
              file=sys.stderr)
        return 2
    print(f"jt-ipam agent v{AGENT_VERSION} -> {SERVER}  fallback_interval={INTERVAL}s "
          f"insecure={INSECURE} auto_update={AUTO_UPDATE}", flush=True)
    # fast loop 由 server 的 interval_seconds 決定；poll 失敗時退回 env INTERVAL。
    sleep_for = INTERVAL
    # On-demand probe jobs run in a separate thread: scanning must not wait on them,
    # and a failure there must not stop scanning.
    threading.Thread(target=_jobs_loop, name="jt-ipam-jobs", daemon=True).start()
    # 重量探測（反解／NetBIOS／mDNS／OS 指紋）在背景跑，上線偵測每輪都能準時做完、立刻回報
    threading.Thread(target=_heavy_loop, name="jt-ipam-heavy", daemon=True).start()
    while True:
        try:
            scan_once()
            # scan_once 內已用 server 回的 interval_seconds；這裡再讀一次當下次 sleep。
        except Exception as exc:  # noqa: BLE001 — stay resilient, retry next round
            print(f"[error] {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        # 取最近一次 poll 拿到的 fast loop（存在模組層好讓 sleep 跟上）
        sleep_for = _CURRENT_FAST[0] or INTERVAL
        time.sleep(sleep_for)


if __name__ == "__main__":
    raise SystemExit(main())
