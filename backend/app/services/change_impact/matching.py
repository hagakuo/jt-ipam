"""位址比對：精確、CIDR 包含、起迄範圍、物件群組（遞迴、偵測循環）、文字線索（token 邊界）。

每種比對分開回報 match_kind，規則再依 match_kind 決定影響（規格 §5.3）：
- exact：值就是這個位址
- cidr_contains / range_contains：值是包含它的網段或範圍（新舊位址都在範圍內時不需要改）
- group_member：經由別名或位址物件（附群組路徑）
- text_hint：備註文字裡出現（只是線索，需人工確認）
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

Addr = ipaddress.IPv4Address | ipaddress.IPv6Address

ANY_VALUES = frozenset({"any", "*", "all", "0.0.0.0/0", "::/0"})


def norm_ip(text: Any) -> Addr | None:
    """位址字串（含 INET 物件、`位址/32`）→ 位址；不是單一位址回 None。"""
    if text is None:
        return None
    s = str(text).strip()
    if not s:
        return None
    if "/" in s:
        host = s.partition("/")[0]
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None
        if net.num_addresses != 1:
            return None
        s = host
    try:
        return ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return None


def value_match(value: Any, aip: Addr) -> str | None:
    """單一欄位值與位址：exact／cidr_contains／range_contains／None。涵蓋全部位址的值（any、/0）不算。"""
    s = str(value or "").strip()
    if not s or s.lower() in ANY_VALUES:
        return None
    try:
        if "-" in s and "/" not in s:
            lo_s, hi_s = (x.strip() for x in s.split("-", 1))
            lo, hi = ipaddress.ip_address(lo_s), ipaddress.ip_address(hi_s)
            if lo.version != aip.version or not (lo <= aip <= hi):
                return None
            return "exact" if lo == hi == aip else "range_contains"
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            if net.version != aip.version or net.prefixlen == 0 or aip not in net:
                return None
            return "exact" if net.num_addresses == 1 else "cidr_contains"
        a = ipaddress.ip_address(s.split("%", 1)[0])
        return "exact" if a == aip else None
    except (ValueError, TypeError):
        return None


def covers_both(value: Any, a: Addr, b: Addr) -> bool:
    """這個網段或範圍同時包含新舊兩個位址：改址不必動它（規格 §5.3）。"""
    return value_match(value, a) in ("cidr_contains", "range_contains") and \
        value_match(value, b) in ("cidr_contains", "range_contains")


# IPv4：前後不可以接數字或「.數字」（198.51.100.2 不可以比中 198.51.100.20 或 10.198.51.100.2）
_V4_TOKEN = re.compile(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9]|\.\d)")
# IPv6：十六進位與冒號組成、至少兩個冒號；前後不可以接十六進位字或冒號
_V6_TOKEN = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Fa-f:])")


def text_mentions(text: Any, targets: Iterable[Addr]) -> list[Addr]:
    """文字裡以完整 token 出現的目標位址（去重、依出現順序）。只比對單一位址，不比 CIDR。"""
    s = str(text or "")
    if not s:
        return []
    want = set(targets)
    hits: list[Addr] = []
    for m in _V4_TOKEN.finditer(s):
        a = norm_ip(m.group(1))
        if a is not None and a in want and a not in hits:
            hits.append(a)
    if ":" in s:
        for m in _V6_TOKEN.finditer(s):
            a = norm_ip(m.group(1))
            if a is not None and a in want and a not in hits:
                hits.append(a)
    return hits


@dataclass
class GroupHit:
    """一個群組／別名涵蓋目標位址的結果。path 由外而內：[群組, 子群組, …, 成員值]。"""
    name: str
    kind: str                       # exact / cidr_contains / range_contains（最內層成員的比對）
    path: list[str]
    member: str


@dataclass
class GroupResolution:
    hits: dict[str, GroupHit] = field(default_factory=dict)
    cycles: list[list[str]] = field(default_factory=list)
    unresolved: set[str] = field(default_factory=set)
    unknown_members: dict[str, list[str]] = field(default_factory=dict)
    depth_exceeded: set[str] = field(default_factory=set)


_UNKNOWN_MEMBER = re.compile(r"[a-z]", re.I)


def resolve_groups(groups: dict[str, list[str]], aip: Addr, *, depth: int = 16,
                   leaf_match: Callable[[str, Addr], str | None] = value_match,
                   is_group_ref: Callable[[str], bool] | None = None) -> GroupResolution:
    """把每個群組遞迴展開，找出哪些群組（直接或經由子群組）涵蓋 aip。

    - 成員若是另一個群組的名稱就往下展開；`visited` 擋循環並回報（規格 T04）
    - 超過 depth 層停止並回報
    - 成員不是位址、也不是已知群組（FQDN、URL、地理位置…）：記成語意不明，不當成沒有命中
    """
    res = GroupResolution()
    memo: dict[str, GroupHit | None] = {}

    def walk(name: str, trail: list[str]) -> tuple[GroupHit | None, bool]:
        """回 (命中, 是否完整)。途中遇到循環被截斷的結果不可以記住：從別的入口進來時可能命中
        （A 包 B、B 包 A，位址在 A 裡：從 A 進去時 B 被截斷，但 B 本身其實涵蓋這個位址）。"""
        if name in memo:
            return memo[name], True
        if name in trail:
            cyc = [*trail[trail.index(name):], name]
            if cyc not in res.cycles:
                res.cycles.append(cyc)
            return None, False
        if len(trail) >= depth:
            res.depth_exceeded.add(trail[0])
            return None, False
        best: GroupHit | None = None
        complete = True
        for raw in groups.get(name, []):
            m = str(raw).strip()
            if not m:
                continue
            if m in groups:
                sub, ok = walk(m, [*trail, name])
                complete = complete and ok
                if sub is not None and best is None:
                    best = GroupHit(name, sub.kind, [name, *sub.path], sub.member)
                continue
            kind = leaf_match(m, aip)
            if kind:
                if best is None or (kind == "exact" and best.kind != "exact"):
                    best = GroupHit(name, kind, [name, m], m)
                continue
            if norm_ip(m) is None and not _looks_like_net(m) and m.lower() not in ANY_VALUES:
                if is_group_ref is not None and is_group_ref(m):
                    res.unresolved.add(m)
                elif _UNKNOWN_MEMBER.search(m):
                    res.unknown_members.setdefault(name, []).append(m[:120])
        if complete or best is not None:
            memo[name] = best
        return best, complete or best is not None

    for g in groups:
        hit, _ = walk(g, [])
        if hit is not None:
            res.hits[g] = hit
    return res


def _looks_like_net(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        pass
    if "-" in s:
        try:
            lo, hi = s.split("-", 1)
            ipaddress.ip_address(lo.strip())
            ipaddress.ip_address(hi.strip())
            return True
        except ValueError:
            return False
    return False


def special_reason(a: Addr, net: ipaddress.IPv4Network | ipaddress.IPv6Network | None) -> str | None:
    """不可以當成改址目標的位址：多播、未指定、迴路、IPv4 的網路／廣播位址（/31、/32 例外）。"""
    if a.is_multicast:
        return "multicast"
    if a.is_unspecified:
        return "unspecified"
    if a.is_loopback:
        return "loopback"
    if isinstance(a, ipaddress.IPv6Address) and a.is_link_local:
        return "link_local_without_scope"
    if net is not None and a.version == 4 and net.prefixlen < 31:
        if a == net.network_address:
            return "network_address"
        if a == net.broadcast_address:
            return "broadcast_address"
    return None
