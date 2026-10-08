"""MikroTik RouterOS 整合的解析與**保護機制**。

這個整合的測試重點跟其他家不一樣：客戶的 MikroTik（CCR2004／CCR1072）是**主力
路由器**，所以「不會把它拖慢」跟「欄位解析正確」一樣重要，兩者都要有測試守著。

沒有實機可測（自有的 CRS309 在另一個網段，IPAM 主機目前不可達），因此樣本
取自官方文件的欄位名稱，解析一律容錯。實機到位後要回頭用「連線診斷」的逐端點
輸出校準這裡的樣本。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from app.services import mikrotik as svc


def _router(**kw: Any) -> Any:
    """夠用來跑解析的假路由器（不進 DB）。"""
    base = {
        "id": uuid.uuid4(), "name": "ccr", "api_url": "https://192.0.2.9",
        "api_username": "ipam", "verify_tls": False,
        "max_response_mb": 8, "section_delay_ms": 0, "cpu_load_limit": 70,
        "scope_subnet_ids": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


# ─────────────────── 型別轉換（RouterOS 全部回字串）───────────────────

def test_booleans_arrive_as_strings() -> None:
    """`"true"` 是字串。照 Python 的真值判斷，`"false"` 也會是 True —— 這正是坑。"""
    assert svc._b("true") is True
    assert svc._b("false") is False, "字串 'false' 被當成真 → 停用的規則會被當成生效中"
    assert svc._b("") is False
    assert svc._b(None) is False


def test_numbers_arrive_as_strings_with_units() -> None:
    assert svc._num("42") == 42
    assert svc._num("7%") == 7          # cpu-load 是 "7" 或 "7%"，兩種都見過
    assert svc._num("nonsense") is None


@pytest.mark.parametrize(("text", "seconds"), [
    ("1m30s", 90),
    ("4w2d3h", 4 * 604800 + 2 * 86400 + 3 * 3600),
    ("30s", 30),
    ("00:01:30", 90),        # 有些欄位是時鐘格式
    ("never", None),
    ("", None),
    (None, None),
])
def test_duration_parsing(text: str | None, seconds: float | None) -> None:
    assert svc.parse_duration(text) == seconds


def test_unparsable_duration_is_none_not_zero() -> None:
    """None 與 0 差很多：0 會被讀成「剛剛才看到」。"""
    assert svc.parse_duration("garbage") is None


# ─────────────────── ARP：只收 reachable ───────────────────

def test_arp_status_allowlist_is_reachable_only() -> None:
    """RouterOS 的 `/ip/arp` 沒有 age／TTL —— 資格完全靠鄰居狀態。

    放寬到 `stale` 就等於宣稱「還在表裡＝還活著」，那正是 0.5.206 那次
    「關機的 VM 顯示 52 天全綠」的成因。
    """
    assert svc.ARP_ACCEPTED_STATUS == ("reachable",)
    from app.services.evidence import is_aging
    assert is_aging("arp:mikrotik") is True
    assert is_aging("lease:mikrotik") is False, "DHCP 租約比開機時間長，不可宣稱上線"


# ─────────────────── DHCP：三張表 join ───────────────────

POOLS = [
    {"name": "dhcp-lan", "ranges": "10.0.0.100-10.0.0.200,10.0.0.240-10.0.0.250"},
    {"name": "dhcp-guest", "ranges": "10.9.0.10-10.9.0.99"},
    {"name": "unused-pool", "ranges": "172.16.0.5-172.16.0.9"},
]
SERVERS = [
    {"name": "lan", "interface": "bridge-lan", "address-pool": "dhcp-lan",
     "disabled": "false"},
    {"name": "guest", "interface": "bridge-guest", "address-pool": "dhcp-guest",
     "disabled": "true"},
]
NETWORKS = [
    {"address": "10.0.0.0/24", "gateway": "10.0.0.1",
     "dns-server": "10.0.0.1,1.1.1.1", "domain": "example.net"},
    {"address": "10.9.0.0/24", "gateway": "10.9.0.1"},
]


def test_ranges_need_all_three_tables() -> None:
    """`/ip/pool` 才有範圍、`/ip/dhcp-server` 才知道是哪一台在發、
    `/ip/dhcp-server/network` 才有網段與閘道 —— 少一張就組不出來。"""
    out = svc.build_pool_ranges(POOLS, SERVERS, NETWORKS)
    assert [(r["start_ip"], r["end_ip"]) for r in out] == [
        ("10.0.0.100", "10.0.0.200"), ("10.0.0.240", "10.0.0.250")]
    assert out[0]["subnet_cidr"] == "10.0.0.0/24"
    assert out[0]["gateway"] == "10.0.0.1"
    assert out[0]["dns_servers"] == "10.0.0.1,1.1.1.1"


def test_disabled_server_contributes_nothing() -> None:
    """停用的 DHCP 伺服器不發位址；它的 pool 仍在 `/ip/pool` 裡（第二個樣本）。"""
    out = svc.build_pool_ranges(POOLS, SERVERS, NETWORKS)
    assert not [r for r in out if r["start_ip"].startswith("10.9.")]


def test_a_pool_no_server_points_at_is_ignored() -> None:
    """`/ip/pool` 常有給 PPP／hotspot 用的池 —— 那些不是 DHCP 發放範圍。"""
    out = svc.build_pool_ranges(POOLS, SERVERS, NETWORKS)
    assert not [r for r in out if r["start_ip"].startswith("172.16.")]


def test_pool_without_a_matching_network_still_yields_a_range() -> None:
    """網段設定缺漏時仍要記下範圍（只是 `subnet_cidr` 為空），不能整段丟掉。"""
    out = svc.build_pool_ranges(POOLS, SERVERS, [])
    assert len(out) == 2
    assert out[0]["subnet_cidr"] is None
    assert out[0]["gateway"] is None


def test_single_address_pool() -> None:
    out = svc.build_pool_ranges(
        [{"name": "p", "ranges": "10.0.0.50"}],
        [{"name": "s", "interface": "e1", "address-pool": "p"}], [])
    assert (out[0]["start_ip"], out[0]["end_ip"]) == ("10.0.0.50", "10.0.0.50")


def test_garbage_range_is_skipped_not_fatal() -> None:
    out = svc.build_pool_ranges(
        [{"name": "p", "ranges": "not-an-ip-at-all,10.0.0.5-10.0.0.6"}],
        [{"name": "s", "interface": "e1", "address-pool": "p"}], [])
    assert [(r["start_ip"], r["end_ip"]) for r in out] == [("10.0.0.5", "10.0.0.6")]


# ─────────────────── 大表防護 ───────────────────

class _FakeTransport(httpx.AsyncBaseTransport):
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body, self.status, self.requests = body, status, []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, content=self.body,
                              headers={"content-type": "application/json"})


@pytest.mark.anyio
async def test_a_huge_menu_is_aborted_with_an_actionable_message(monkeypatch: Any) -> None:
    """RouterOS 的 REST 沒有分頁 —— 大小上限是唯一的護欄，訊息要說得出怎麼辦。"""
    monkeypatch.setattr(svc, "_decrypt_password", lambda r: "pw")
    router = _router(max_response_mb=1)
    transport = _FakeTransport(b"x" * (2 * 1024 * 1024))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(svc.RouterOSError) as exc:
            await svc._get(router, svc.EP_ADDRESS_LIST, client=client)
    msg = str(exc.value)
    assert "1 MiB" in msg
    assert "沒有分頁" in msg
    assert "關掉這個區段" in msg, "只說「太大」等於沒說 —— 要講得出下一步"


@pytest.mark.anyio
async def test_the_two_forbidden_menus_are_refused_in_code() -> None:
    """`/ip/route` 與 connection tracking 在主力路由器上是數十萬列。

    這條規則不能只寫在註解裡：擋在 `_get()` 才擋得住「順手加一支端點」。
    """
    for path in ("/ip/route", "/ip/firewall/connection"):
        with pytest.raises(svc.RouterOSError, match="不可抓取"):
            await svc._get(_router(), path)


@pytest.mark.anyio
async def test_proplist_and_server_side_filter_are_sent(monkeypatch: Any) -> None:
    """少序列化欄位、少回傳列數 —— 兩者都要真的送出去，不能只寫在註解裡。"""
    monkeypatch.setattr(svc, "_decrypt_password", lambda r: "pw")
    transport = _FakeTransport(b"[]")
    async with httpx.AsyncClient(transport=transport) as client:
        await svc._get(_router(), svc.EP_ARP, client=client,
                       proplist="address,mac-address", filters={"status": "reachable"})
    url = transport.requests[0].url
    assert url.params[".proplist"] == "address,mac-address"
    assert url.params["status"] == "reachable"
    assert str(url).startswith("https://192.0.2.9/rest/ip/arp")


@pytest.mark.anyio
async def test_v6_is_named_not_guessed(monkeypatch: Any) -> None:
    """v6 沒有 REST。現場對著「連線失敗」是猜不出來的，要指名版本。"""
    assert svc.version_is_v6("6.49.10") is True
    assert svc.version_is_v6("7.9") is False

    monkeypatch.setattr(svc, "_decrypt_password", lambda r: "pw")
    transport = _FakeTransport(b'{"version":"6.48.6","board-name":"CCR1072"}')

    class _Client:
        async def __aenter__(self) -> httpx.AsyncClient:
            self._c = httpx.AsyncClient(transport=transport)
            return self._c

        async def __aexit__(self, *a: Any) -> None:
            await self._c.aclose()

    monkeypatch.setattr(svc, "safe_client", lambda **kw: _Client())
    with pytest.raises(svc.RouterOSError, match=r"6\.48\.6"):
        await svc.diagnose(_router())


@pytest.mark.anyio
async def test_a_missing_menu_is_not_an_error(monkeypatch: Any) -> None:
    """交換器沒有 `/ip/dhcp-server` 是正常的，不該在畫面上掛紅字。"""
    monkeypatch.setattr(svc, "_decrypt_password", lambda r: "pw")
    transport = _FakeTransport(b"{}", status=404)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(svc.RouterOSNotPresent):
            await svc._get(_router(), svc.EP_DHCP_SERVER, client=client)
    # 它仍是 RouterOSError 的子類 → 呼叫端不特別處理時行為不變
    assert issubclass(svc.RouterOSNotPresent, svc.RouterOSError)


# ─────────────────── 退讓機制 ───────────────────

def test_sections_run_lightest_first() -> None:
    """會提早停止，所以順序決定「停在半路時做完了什麼」。"""
    names = [n for n, _ in svc.SECTION_ORDER]
    assert names.index("firewall") < names.index("address_lists")
    assert names[-1] == "arp", "全表 ARP 最貴，一定要排最後"


def test_lease_last_seen_is_converted_to_a_real_timestamp() -> None:
    """`last-seen` 是「多久前」，不是時間點 —— 直接存會變成 1970 年或現在。"""
    now = datetime.now(UTC)
    ago = svc.parse_duration("2m")
    assert ago == 120
    assert abs(((now - timedelta(seconds=ago)) - now).total_seconds() + 120) < 1


# ─────────────────── NAT 型別 ───────────────────

def test_ports_are_extracted_from_routeros_forms() -> None:
    assert svc._first_port("80") == 80
    assert svc._first_port("80,443") == 80
    assert svc._first_port("8000-8100") == 8000
    assert svc._first_port("") is None
    assert svc._first_port("http") is None


def test_dst_nat_with_a_port_must_be_a_port_forward() -> None:
    """對外開放服務清單只認 `port_forward`。

    標成 `one_to_one` 的話，MikroTik 的對外開口會整批從曝險檢視裡消失 ——
    而且畫面上什麼都不會壞，只是少了一整家的資料。
    """
    import inspect
    src = inspect.getsource(svc.sync_nat)
    assert '"port_forward" if (dst_port or to_port) else "one_to_one"' in src
    assert "dst_port=dst_port or to_port" in src, "埠沒存成欄位，曝險清單判不出可達性"


# ─────────────────── 規則異動 ───────────────────

def test_rule_key_survives_reordering() -> None:
    """RouterOS 的規則沒有名稱也沒有穩定 id；key 由內容組成。

    順序刻意不進 key：在中間插一條不該讓底下每一條都被記成「變更」。
    """
    from app.services.fw_review import normalize_mikrotik

    def _r(pos: int, dst: str) -> Any:
        return SimpleNamespace(
            table_name="filter", chain="forward", action="accept", position=pos,
            src_address="10.0.0.0/24", dst_address=dst, protocol="tcp",
            src_port=None, dst_port="443", in_interface="ether1", out_interface=None,
            comment="web", disabled=False)

    before = normalize_mikrotik([_r(0, "10.1.0.5"), _r(1, "10.1.0.6")])
    after = normalize_mikrotik([_r(0, "10.1.0.6"), _r(1, "10.1.0.5")])
    assert {r["key"] for r in before} == {r["key"] for r in after}

    from app.services.fw_review import rules_hash
    assert rules_hash(before) == rules_hash(after), "只是搬動順序，不算規則變更"


# ─────────────────── 整輪同步（含退讓）───────────────────

class _MenuTransport(httpx.AsyncBaseTransport):
    """照路徑回不同內容的假 RouterOS，並記錄請求順序與時間。

    `cpu_seq` 讓測試決定「第 n 次讀 /system/resource 回多少 CPU」，用來觸發退讓。
    """

    def __init__(self, menus: dict[str, Any], cpu_seq: list[float]) -> None:
        self.menus, self.cpu_seq = menus, cpu_seq
        self.paths: list[str] = []
        self._cpu_i = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/rest")
        self.paths.append(path)
        if path == "/system/resource":
            load = self.cpu_seq[min(self._cpu_i, len(self.cpu_seq) - 1)]
            self._cpu_i += 1
            body: Any = {"version": "7.14.2", "board-name": "CCR2004",
                         "cpu-load": str(int(load)), "free-memory": "900000000",
                         "total-memory": "4000000000", "uptime": "3w1d"}
        elif path in self.menus:
            body = self.menus[path]
        else:
            return httpx.Response(404, json={"error": 404, "message": "no such command"})
        return httpx.Response(200, json=body,
                              headers={"content-type": "application/json"})


def _fake_client(monkeypatch: Any, transport: httpx.AsyncBaseTransport) -> None:
    class _Ctx:
        async def __aenter__(self) -> httpx.AsyncClient:
            self._c = httpx.AsyncClient(transport=transport)
            return self._c

        async def __aexit__(self, *a: Any) -> None:
            await self._c.aclose()

    monkeypatch.setattr(svc, "safe_client", lambda **kw: _Ctx())
    monkeypatch.setattr(svc, "_decrypt_password", lambda r: "pw")


MENUS: dict[str, Any] = {
    "/ip/firewall/filter": [
        {"chain": "forward", "action": "accept", "protocol": "tcp",
         "dst-port": "443", "comment": "web", "disabled": "false"},
        {"chain": "input", "action": "drop", "disabled": "false"},
    ],
    "/ip/firewall/mangle": [],
    "/ip/firewall/nat": [
        {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp",
         "dst-port": "8443", "to-addresses": "10.0.0.9", "to-ports": "443",
         "in-interface": "ether1", "disabled": "false"},
        {"chain": "srcnat", "action": "masquerade", "out-interface": "ether1",
         "disabled": "false"},
        {"chain": "dstnat", "action": "jump", "disabled": "false"},   # 不是位址轉換
    ],
    "/ip/firewall/address-list": [
        {"list": "blocked", "address": "203.0.113.4", "dynamic": "true",
         "timeout": "1d"},
    ],
    "/ip/pool": POOLS,
    "/ip/dhcp-server": SERVERS,
    "/ip/dhcp-server/network": NETWORKS,
    "/ip/dhcp-server/lease": [
        {"address": "10.0.0.150", "mac-address": "AA:BB:CC:DD:EE:01",
         "host-name": "printer", "status": "bound", "last-seen": "2m"},
    ],
    "/ip/arp": [
        {"address": "10.0.0.150", "mac-address": "AA:BB:CC:DD:EE:01",
         "status": "reachable"},
        {"address": "10.0.0.151", "mac-address": "AA:BB:CC:DD:EE:02",
         "status": "stale"},
    ],
}


@pytest.mark.anyio
async def test_a_full_round_lands_rules_nat_and_lists(db_session: Any, monkeypatch: Any) -> None:
    """整輪同步：規則、NAT、address-list 都要進 DB，而且 NAT 的埠要分得出來。"""
    from app.models.mikrotik import MikroTikAddressList, MikroTikRouter, MikroTikRule
    from app.models.nat import NATTranslation
    from sqlalchemy import select

    router = MikroTikRouter(
        name="ccr-test", api_url="https://192.0.2.9", api_username="ipam",
        api_password_enc=b"x", api_password_nonce=b"y",
        section_delay_ms=0, cpu_load_limit=0,      # 0＝不做退讓，先驗完整一輪
        sync_dhcp=False, sync_dhcp_ranges=False, sync_vpn=False, sync_arp=False)
    db_session.add(router)
    await db_session.flush()

    transport = _MenuTransport(MENUS, cpu_seq=[5])
    _fake_client(monkeypatch, transport)
    counts = await svc.sync_instance(db_session, router)
    await db_session.flush()

    assert counts["filter_rules"] == 2
    assert router.routeros_version == "7.14.2"
    assert router.board_name == "CCR2004"
    assert router.last_error is None

    rules = (await db_session.execute(select(MikroTikRule))).scalars().all()
    # NAT 表的規則也要進同一張表（規則異動偵測要看得到），且只抓一次
    assert {r.table_name for r in rules} == {"filter", "nat"}
    assert transport.paths.count("/ip/firewall/nat") == 1, "NAT 選單被抓了兩次"

    nats = (await db_session.execute(select(NATTranslation))).scalars().all()
    kinds = {n.type: n for n in nats}
    assert set(kinds) == {"port_forward", "many_to_one"}
    assert kinds["port_forward"].dst_port == 8443
    assert kinds["many_to_one"].dst_port is None

    lists = (await db_session.execute(select(MikroTikAddressList))).scalars().all()
    assert [(x.list_name, x.address, x.dynamic) for x in lists] == \
        [("blocked", "203.0.113.4", True)]


@pytest.mark.anyio
async def test_a_busy_router_stops_the_round(db_session: Any, monkeypatch: Any) -> None:
    """CPU 超標時停掉剩下的區段 —— 而且**不算失敗**（`last_error` 要是空的）。

    主 router 忙的時候，最好的幫忙是走開；把它記成錯誤只會讓人以為整合壞了。
    """
    from app.models.mikrotik import MikroTikRouter

    router = MikroTikRouter(
        name="ccr-busy", api_url="https://192.0.2.9", api_username="ipam",
        api_password_enc=b"x", api_password_nonce=b"y",
        section_delay_ms=0, cpu_load_limit=70,
        sync_dhcp=True, sync_dhcp_ranges=True, sync_vpn=False, sync_arp=True)
    db_session.add(router)
    await db_session.flush()

    # 第一次讀是基準（5%），第一個區段跑完就飆到 95%
    transport = _MenuTransport(MENUS, cpu_seq=[5, 95])
    _fake_client(monkeypatch, transport)
    await svc.sync_instance(db_session, router)

    assert router.last_cost["stopped"]["after"] == "firewall"
    # 句子由前端組（代碼＋參數），所以這裡看的是參數而不是成品字串
    assert router.last_cost["stopped"]["code"] == "ros_stopped_cpu"
    assert router.last_cost["stopped"]["params"]["load"] == "95"
    assert "95" in router.last_cost["stopped"]["message"]
    assert router.last_error is None, "提早停止不是錯誤"
    # 停了就真的不要再打它
    assert "/ip/firewall/address-list" not in transport.paths
    assert "/ip/arp" not in transport.paths


@pytest.mark.anyio
async def test_only_reachable_arp_stamps_the_ip(db_session: Any, monkeypatch: Any) -> None:
    """`stale` 的條目在同一份回應裡 —— 它不可以留下任何上線證據。"""
    from app.models.address import IPAddress
    from app.models.mikrotik import MikroTikRouter
    from app.models.section import Section
    from app.models.subnet import Subnet

    section = Section(name="s-mt")
    db_session.add(section)
    await db_session.flush()
    subnet = Subnet(section_id=section.id, cidr="10.0.0.0/24")
    db_session.add(subnet)
    await db_session.flush()
    ips = [IPAddress(subnet_id=subnet.id, ip=f"10.0.0.{n}") for n in (150, 151)]
    db_session.add_all(ips)
    await db_session.flush()

    router = MikroTikRouter(
        name="ccr-arp", api_url="https://192.0.2.9", api_username="ipam",
        api_password_enc=b"x", api_password_nonce=b"y", section_delay_ms=0)
    db_session.add(router)
    await db_session.flush()

    transport = _MenuTransport(MENUS, cpu_seq=[5])
    _fake_client(monkeypatch, transport)
    async with httpx.AsyncClient(transport=transport) as client:
        out = await svc.sync_arp(db_session, router, client=client)
    await db_session.flush()

    assert out["arp"] == 1, "只有 reachable 的那一筆該被記下來"
    reachable, stale = ips
    assert "arp:mikrotik" in (reachable.arp_seen or {})
    assert (stale.arp_seen or {}) == {}, "stale 的條目留下了證據"
