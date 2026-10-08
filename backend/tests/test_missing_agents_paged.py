"""「未裝 Agent 的 IP」伺服器端分頁（2026-10-01 使用者同意；v0.6.56 大量資料測試的後續）。

大站台 5 萬筆缺口：以前整份清單（27～42 MB）一次回傳、瀏覽器裡篩選，點進頁籤要 8～10 秒、
主執行緒卡 2 秒。改成帶 `page` 時由後端篩選（區段／子網路／單位／上線狀態／關鍵字）並分頁，
篩選選項（facets）也由後端算 —— 規則與畫面上的燈號同一套（classify_liveness 對應前端的
classifyAddressLiveness）。不帶 `page` 維持原本的完整清單（API 相容）。
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.models.address import IPAddress
from app.models.customer import Customer
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import agent_scope
from app.services.agent_scope import classify_liveness


@pytest.fixture(autouse=True)
def _fresh_cache():
    agent_scope._CACHE.clear()
    yield
    agent_scope._CACHE.clear()


def _row(**kw):
    from types import SimpleNamespace
    base = {"last_seen_scanner": None, "last_seen_librenms": None, "last_seen_arp": None, "last_seen_wazuh": None,
                "last_seen_zabbix": None, "arp_seen": None, "exclude_from_ping": False, "subnet_scan_enabled": True}
    base.update(kw)
    return SimpleNamespace(**base)


def test_classify_liveness_matches_the_ip_list_lights() -> None:
    now = datetime.now(UTC)
    src = ["scanner", "librenms", "arp:opnsense"]
    c = lambda **kw: classify_liveness(_row(**kw), minutes=30, sources=src, now=now)  # noqa: E731
    assert c(last_seen_scanner=now - timedelta(minutes=5)) == "online"
    assert c(last_seen_scanner=now - timedelta(minutes=90)) == "stale"          # 30 分鐘 × 4 以內
    assert c(last_seen_scanner=now - timedelta(hours=5)) == "offline"
    assert c() == "offline"                                                      # 有掃描卻從沒看到
    assert c(exclude_from_ping=True) == "unknown"                                # 沒在探測 → 未知
    assert c(subnet_scan_enabled=False, last_seen_scanner=now - timedelta(days=3)) == "unknown"
    assert c(last_seen_wazuh=now) == "offline"                                   # 沒勾的來源不算
    assert c(arp_seen={"arp:opnsense": (now - timedelta(minutes=1)).isoformat()}) == "online"
    assert c(arp_seen={"lease:opnsense": now.isoformat()}) == "offline"          # 沒勾（租約不過期）


@pytest.fixture
async def gaps(db_session):
    """兩個區段、三個子網路、一個單位；每個 IP 都有主機名稱、都沒有 Wazuh 代理。"""
    now = datetime.now(UTC)
    cust = Customer(name=f"c-{uuid.uuid4().hex[:6]}")
    a, b = Section(name="sec-a"), Section(name="sec-b")
    db_session.add_all([cust, a, b])
    await db_session.flush()
    s1 = Subnet(section_id=a.id, cidr="198.51.100.0/24", scan_enabled=True)
    s2 = Subnet(section_id=a.id, cidr="203.0.113.0/24", customer_id=cust.id, scan_enabled=True)
    s3 = Subnet(section_id=b.id, cidr="192.0.2.0/24", scan_enabled=True)
    db_session.add_all([s1, s2, s3])
    await db_session.flush()
    rows = []
    for i in range(1, 121):
        rows.append({"subnet_id": s1.id, "ip": f"198.51.100.{i}", "hostname": f"pc-{i:03d}",
                     "last_seen_scanner": now if i % 2 else None})
    for i in range(1, 11):
        rows.append({"subnet_id": s2.id, "ip": f"203.0.113.{i}", "hostname": f"srv-{i}", "last_seen_scanner": None})
    for i in range(1, 6):
        rows.append({"subnet_id": s3.id, "ip": f"192.0.2.{i}", "hostname": f"lab-{i}", "last_seen_scanner": None})
    await db_session.execute(IPAddress.__table__.insert(), rows)
    await db_session.commit()
    return {"a": a, "b": b, "s1": s1, "s2": s2, "s3": s3, "cust": cust}


async def test_wazuh_missing_agents_paged_filters_and_facets(client, auth_headers, gaps) -> None:
    r = await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers, params={"page": 1, "page_size": 50})
    assert r.status_code == 200, r.text
    d = r.json()
    assert (d["total"], d["total_all"], len(d["items"])) == (135, 135, 50)
    assert d["items"][0]["ip"] == "192.0.2.1"                     # 依位址排序
    assert {"subnet_cidr", "section_name", "customer_name", "last_seen_scanner"} <= set(d["items"][0])
    assert [o["label"] for o in d["facets"]["sections"]] == ["sec-a", "sec-b"]
    assert {o["value"] for o in d["facets"]["statuses"]} == {"online", "offline"}
    assert [o["label"] for o in d["facets"]["customers"]] == [gaps["cust"].name]

    p3 = (await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers,
                           params={"page": 3, "page_size": 50})).json()
    assert len(p3["items"]) == 35

    one = (await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers, params={
        "page": 1, "page_size": 50, "section_id": str(gaps["a"].id)})).json()
    assert one["total"] == 130
    assert [o["label"] for o in one["facets"]["subnets"]] == ["198.51.100.0/24", "203.0.113.0/24"]  # 只列該區段的

    by_cust = (await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers, params={
        "page": 1, "customer_id": str(gaps["cust"].id)})).json()
    assert by_cust["total"] == 10                                  # 單位從子網路繼承

    online = (await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers, params={
        "page": 1, "page_size": 500, "status": "online"})).json()
    assert online["total"] == 60
    assert all(i["ip"].startswith("198.51.100.") for i in online["items"])

    q = (await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers, params={
        "page": 1, "q": "SRV-1"})).json()
    assert [i["hostname"] for i in q["items"]] == ["srv-1", "srv-10"]


async def test_without_page_the_full_list_is_kept(client, auth_headers, gaps) -> None:
    r = await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) == 135


async def test_ocs_missing_agents_paged(client, auth_headers, gaps) -> None:
    d = (await client.get("/api/v1/ocs/missing-agents", headers=auth_headers, params={
        "page": 1, "page_size": 20, "subnet_id": str(gaps["s3"].id)})).json()
    assert d["total"] == 5
    assert [i["ip"] for i in d["items"]] == [f"192.0.2.{i}" for i in range(1, 6)]


async def test_paged_status_is_the_same_rule_as_classify_liveness(client, auth_headers, db_session) -> None:
    """分頁路徑由資料庫先取「勾選來源裡最近的一次」（GREATEST＋arp_seen 取勾選的鍵），
    結果必須與逐列 classify_liveness 一模一樣 —— 否則頁籤上的燈號與篩選會和 IP 清單對不起來。"""
    from app.models.system_setting import SystemSetting
    from app.services.system_config import ONLINE_GRACE_KEY
    now = datetime.now(UTC)
    ago = lambda m: now - timedelta(minutes=m)  # noqa: E731
    db_session.add(SystemSetting(key=ONLINE_GRACE_KEY, value={
        "minutes": 30, "sources": ["scanner", "wazuh", "arp", "arp:opnsense"]}))
    sec = Section(name="sec-parity")
    db_session.add(sec)
    await db_session.flush()
    on = Subnet(section_id=sec.id, cidr="198.51.100.0/24", scan_enabled=True)
    off = Subnet(section_id=sec.id, cidr="203.0.113.0/24", scan_enabled=False)
    db_session.add_all([on, off])
    await db_session.flush()
    cases = [
        {"last_seen_scanner": ago(5)},
        {"last_seen_scanner": ago(90)},
        {"last_seen_scanner": ago(300)},
        {},
        {"exclude_from_ping": True},
        {"last_seen_librenms": ago(1)},                                                         # 沒勾的來源
        {"last_seen_scanner": ago(300), "last_seen_wazuh": ago(10)},                            # 取最近的
        {"last_seen_arp": ago(60)},
        {"arp_seen": {"arp:opnsense": ago(2).isoformat()}},
        {"arp_seen": {"lease:opnsense": ago(1).isoformat()}},                                   # 沒勾
        {"arp_seen": {"arp:opnsense": ago(500).isoformat(), "vpn:opnsense": ago(1).isoformat()}},
        {"arp_seen": {"arp:opnsense": "not-a-time"}, "last_seen_scanner": ago(100)},            # 壞值略過、不讓整頁失敗
        {"arp_seen": {"arp:opnsense": "2026-09-30T00:00:00"}},                                  # 沒時區 → 當 UTC
    ]
    ips = []
    for i, kw in enumerate(cases, start=1):
        for sn, net in ((on, "198.51.100"), (off, "203.0.113")):
            ips.append(IPAddress(subnet_id=sn.id, ip=f"{net}.{i}", hostname=f"h-{net}-{i}", **kw))
    db_session.add_all(ips)
    await db_session.commit()

    d = (await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers,
                          params={"page": 1, "page_size": 500})).json()
    got = {i["ip"]: i["status"] for i in d["items"]}
    src = ["scanner", "wazuh", "arp", "arp:opnsense"]
    for ipa in ips:
        ipa.subnet_scan_enabled = ipa.subnet_id == on.id
        want = classify_liveness(ipa, minutes=30, sources=src, now=datetime.now(UTC))
        assert got[str(ipa.ip)] == want, (ipa.ip, ipa.arp_seen, got[str(ipa.ip)], want)
    assert len(set(got.values())) == 4                                     # 四種狀態都有測到


async def test_cached_gaps_follow_data_changes(client, auth_headers, db_session, gaps) -> None:
    """翻頁不必每次重算（快取），但資料一變就要反映：裝了代理的消失、改名的搜得到。"""
    from app.models.wazuh import WazuhAgent, WazuhInstance
    from sqlalchemy import select, update
    url, params = "/api/v1/wazuh/missing-agents", {"page": 1, "page_size": 10}
    assert (await client.get(url, headers=auth_headers, params=params)).json()["total"] == 135
    first = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "192.0.2.1"))).scalar_one()
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://x",
                         api_user="u", api_password_enc=b"x", api_password_nonce=b"y")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(WazuhAgent(instance_id=inst.id, agent_id="001", jt_ipam_address_id=first.id, status="active"))
    await db_session.commit()
    d = (await client.get(url, headers=auth_headers, params=params)).json()
    assert d["total"] == 134
    assert d["items"][0]["ip"] == "192.0.2.2"

    await db_session.execute(update(IPAddress).where(IPAddress.ip == "192.0.2.3").values(hostname="renamed-box"))
    await db_session.commit()
    q = (await client.get(url, headers=auth_headers, params={"page": 1, "q": "renamed"})).json()
    assert [i["ip"] for i in q["items"]] == ["192.0.2.3"]


async def test_page_items_carry_current_per_source_times(client, auth_headers, db_session, gaps) -> None:
    """清單本身只取判斷用的欄位；各來源時間是翻到那一頁才抓 —— 內容要和資料庫一致。"""
    from sqlalchemy import update
    seen = datetime(2026, 9, 30, 8, 0, tzinfo=UTC)
    await db_session.execute(update(IPAddress).where(IPAddress.ip == "192.0.2.4").values(
        last_seen_librenms=seen, arp_seen={"arp:opnsense": seen.isoformat()}))
    await db_session.commit()
    d = (await client.get("/api/v1/wazuh/missing-agents", headers=auth_headers,
                          params={"page": 1, "subnet_id": str(gaps["s3"].id)})).json()
    row = next(i for i in d["items"] if i["ip"] == "192.0.2.4")
    assert row["last_seen_librenms"].startswith("2026-09-30T08:00:00")
    assert row["arp_seen"] == {"arp:opnsense": seen.isoformat()}
    assert row["section_id"] == str(gaps["b"].id)
    assert row["subnet_cidr"] == "192.0.2.0/24"


async def test_sorting_is_across_all_gaps_not_just_the_page(client, auth_headers, gaps) -> None:
    """分頁之後排序要由後端排整份缺口；在瀏覽器排只會排到當頁那 100 筆。"""
    url = "/api/v1/wazuh/missing-agents"

    async def first(**kw):
        d = (await client.get(url, headers=auth_headers, params={"page": 1, "page_size": 3, **kw})).json()
        return [i["ip"] for i in d["items"]]

    assert await first() == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert await first(order="desc") == ["203.0.113.10", "203.0.113.9", "203.0.113.8"]
    assert await first(sort="hostname") == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]      # lab-1 … 自然排序
    assert (await first(sort="hostname", order="desc"))[0] == "203.0.113.10"            # srv-10 排 srv-9 後面
    assert await first(sort="section", order="desc") == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]  # sec-b，同名次依位址
    assert (await first(sort="customer"))[0] == "203.0.113.1"                           # 有單位的在前、沒有的排最後
    assert (await first(sort="customer", order="desc"))[0] == "203.0.113.1"             # 反過來也是沒有值的在最後
    assert (await first(sort="status"))[0] == "198.51.100.1"                            # online 最前
    assert (await client.get(url, headers=auth_headers, params={"page": 1, "sort": "bogus"})).status_code == 422
