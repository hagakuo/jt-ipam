"""OCS 同步在超大規模下（2026-09-30 大量資料測試；客戶實際規模 5,000 台）。

以前每張對到的網卡各查一次 IP、再各查一次裝置：5,000 台一輪就是上萬次查詢。
改成每頁（200 台）先把會用到的 IP 與裝置整批載入。
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.models.address import IPAddress
from app.models.device import Device
from app.models.section import Section
from app.models.subnet import Subnet
from sqlalchemy import event, select

from tests.test_ocs_integration import _FakeResp

N = 400


def _mac(i: int) -> str:
    return f"00:00:5e:00:{i // 256:02x}:{i % 256:02x}"


async def _seed(db):
    sec = Section(name=f"ocs-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sn = Subnet(section_id=sec.id, cidr="10.70.0.0/16")
    db.add(sn)
    await db.flush()
    devs = [Device(name=f"pc-{i}") for i in range(N)]
    db.add_all(devs)
    await db.flush()
    db.add_all([IPAddress(subnet_id=sn.id, ip=f"10.70.{i // 256}.{i % 256}", mac=_mac(i), device_id=devs[i].id)
                for i in range(N)])
    await db.commit()


def _pages():
    comps = {str(i + 1): {
        "hardware": {"NAME": f"pc-{i}", "OSNAME": "Windows", "OSCOMMENTS": "Windows 11 Pro",
                     "LASTDATE": "2026-09-29 08:00:00"},
        "networks": [{"MACADDR": _mac(i), "VIRTUALDEV": 0, "IPADDRESS": f"10.70.{i // 256}.{i % 256}"}],
        "bios": [{"SSN": f"SN-{i}", "SMODEL": "OptiPlex", "SMANUFACTURER": "Dell Inc."}],
    } for i in range(N)}
    keys = list(comps)
    return [{k: comps[k] for k in keys[p:p + 200]} for p in range(0, N, 200)]


async def test_full_sync_does_not_query_per_computer(monkeypatch, db_session) -> None:
    import app.services.ocs as ocs

    db_session.autoflush = False
    await _seed(db_session)
    pages = _pages()

    class _C:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *e):
            return False

    async def fake_request(method, url, *, client=None, headers=None, verify=True, **extra):
        if "lastupdate" in url:
            return _FakeResp(404, None)
        start = int(url.split("start=")[1])
        idx = start // 200
        return _FakeResp(200, pages[idx] if idx < len(pages) else {})
    monkeypatch.setattr(ocs, "safe_client", lambda *a, **k: _C())
    monkeypatch.setattr(ocs, "safe_request", fake_request)
    srv = SimpleNamespace(
        id=uuid.uuid4(), name="ocs", source_type="rest", base_url="https://192.0.2.10",
        verify_tls=False, api_username=None, api_password_enc=None, api_password_nonce=None,
        sync_bios=True, stale_after_days=30, last_incremental_epoch=None, detected_version=None,
        last_sync_at=None, last_success_at=None, last_error=None, last_cost=None, scope_subnet_ids=None)

    counts = []
    for _round in range(2):
        n = {"q": 0}
        conn = await db_session.connection()

        def _c(*_a, _n=n, **_k):
            _n["q"] += 1
        event.listen(conn.sync_connection, "before_cursor_execute", _c)
        try:
            out = await ocs.sync_instance(db_session, srv)
            await db_session.commit()
        finally:
            event.remove(conn.sync_connection, "before_cursor_execute", _c)
        counts.append(n["q"])
        assert out["computers"] == N
        assert out["matched_ips"] == N
    assert counts[1] < 40, f"第二輪查了 {counts[1]} 次（{N} 台）"
    assert counts[0] < 80, f"第一輪查了 {counts[0]} 次（{N} 台）"
    dev = (await db_session.execute(select(Device).where(Device.name == "pc-7"))).scalar_one()
    assert dev.serial == "SN-7"
    ip = (await db_session.execute(select(IPAddress).where(IPAddress.ip == "10.70.0.7"))).scalar_one()
    assert ip.os_ocs == "Windows 11 Pro"
    assert ip.hostname == "pc-7"
