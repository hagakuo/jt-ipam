"""拓樸圖在超大規模環境（2026-09-29 超大規模測試抓到）。

5,000 台回報 FDB 的交換器時，推骨幹鏈路的那段把「每一對交換器 × 全部的埠」掃一遍，
拓樸頁讓後端單核跑滿十幾分鐘、整個服務卡住。改成只看 FDB 裡真的互相看得到的那幾對。

- 新寫法與舊寫法的結果要一模一樣（舊寫法留在這裡當參考答案，拿隨機拓樸比）
- 幾百台交換器時幾秒內算完
"""
from __future__ import annotations

import random
import time

from app.services.topology import uplink_pairs_from_fdb


def _reference(by_port, own_macs, switch_ids, visible, adjacency):
    """舊寫法（交換器數平方 × 埠數）——只當參考答案用。"""
    uplink_pairs: dict = {}
    for a in sorted(switch_ids):
        for b in sorted(switch_ids):
            if a >= b:
                continue
            pair = (a, b)
            if pair in adjacency or pair in uplink_pairs:
                continue
            if a not in visible or b not in visible:
                continue
            a_ports = [(p, m) for (s, p), m in by_port.items() if s == a and m & own_macs.get(b, set())]
            b_ports = [(p, m) for (s, p), m in by_port.items() if s == b and m & own_macs.get(a, set())]
            for pa, ma in a_ports:
                for pb, mb in b_ports:
                    if (ma - own_macs.get(b, set())) & (mb - own_macs.get(a, set())):
                        continue
                    uplink_pairs[pair] = (pa, pb)
                    break
                if pair in uplink_pairs:
                    break
    return uplink_pairs


def _random_topology(rng: random.Random, n_sw: int, n_ports: int, n_hosts: int):
    sws = [f"sw{i:03d}" for i in range(n_sw)]
    own = {sw: {f"own-{sw}"} for sw in sws}
    own[sws[0]].add(f"own2-{sws[0]}")                  # 一台交換器兩個自己的 MAC
    if n_sw > 3:
        own.setdefault("not-a-switch", set()).add(f"own-{sws[1]}")   # 同一個 MAC 兩個擁有者
    hosts = [f"h{i}" for i in range(n_hosts)]
    by_port: dict = {}
    for sw in sws:
        for p in range(n_ports):
            macs = set(rng.sample(hosts, rng.randint(0, min(6, n_hosts))))
            pool = [m for o in sws if o != sw for m in own[o]]
            if pool and rng.random() < 0.35:
                macs |= set(rng.sample(pool, min(len(pool), rng.randint(1, 3))))
            if macs:
                by_port[(sw, f"p{p}")] = macs
    switch_ids = {sw for sw, _ in by_port}
    visible = {sw for sw in sws if rng.random() < 0.9} | {"not-a-switch"}
    adjacency = {tuple(sorted(rng.sample(sws, 2))) for _ in range(rng.randint(0, 3))}
    return by_port, own, switch_ids, visible, adjacency


def test_same_result_as_the_reference_on_random_topologies() -> None:
    rng = random.Random(47)
    for _ in range(200):
        args = _random_topology(rng, rng.randint(2, 12), rng.randint(1, 6), rng.randint(0, 20))
        assert uplink_pairs_from_fdb(*args) == _reference(*args)


def test_hundreds_of_switches_finish_quickly() -> None:
    """800 台交換器、每台 24 埠：舊寫法要掃三十幾萬對 × 兩萬個埠；新寫法只看真的互相看得到的。"""
    n, ports = 800, 24
    sws = [f"sw{i:04d}" for i in range(n)]
    own = {sw: {f"own-{sw}"} for sw in sws}
    by_port: dict = {}
    for i, sw in enumerate(sws):
        for p in range(ports):
            by_port[(sw, f"ge-0/0/{p}")] = {f"host-{i}-{p}-{k}" for k in range(3)}
        # 串成一條骨幹：往下一台的埠看得到下一台，往上一台的埠看得到上一台
        if i + 1 < n:
            by_port[(sw, "xe-0/1/0")] = {f"own-{sws[i + 1]}"}
        if i > 0:
            by_port[(sw, "xe-0/1/1")] = {f"own-{sws[i - 1]}"}
    started = time.monotonic()
    pairs = uplink_pairs_from_fdb(by_port, own, set(sws), set(sws), set())
    assert time.monotonic() - started < 5
    assert len(pairs) == n - 1
    assert pairs[(sws[0], sws[1])] == ("xe-0/1/0", "xe-0/1/1")


async def test_an_unfiltered_graph_over_the_limit_asks_for_a_filter(db_session) -> None:
    """兩萬台裝置畫不出來也看不懂：超過上限就不建圖，回傳裝置數讓畫面請使用者先篩選。"""
    from app.models.device import Device
    from app.services.topology import build_topology

    for i in range(5):
        db_session.add(Device(name=f"topo-cap-{i}", type="server"))
    await db_session.commit()
    g = await build_topology(db_session, max_devices=3)
    assert g["nodes"] == [] and g["edges"] == []
    assert g["too_large"] == {"devices": 5, "limit": 3}
    g = await build_topology(db_session, max_devices=10)
    assert "too_large" not in g
    assert len(g["nodes"]) >= 5


async def test_ai_topology_tool_says_the_graph_is_too_large(db_session, admin_user, monkeypatch) -> None:
    from app.mcp import tools
    from app.models.device import Device
    from app.services import topology as topo

    monkeypatch.setattr(topo, "MAX_TOPOLOGY_DEVICES", 2)
    for i in range(3):
        db_session.add(Device(name=f"topo-ai-{i}", type="server"))
    await db_session.commit()
    out = await tools.get_topology(db_session, user=admin_user)
    assert out["too_large"]["devices"] == 3
    assert "subnet_cidr" in out["hint"]
