"""DNS 伺服器上刪掉的記錄，同步後要跟著消失（使用者回報，2026-09-26）。

198.51.100.139 換了主機、A 記錄在 DNS 伺服器上刪了、手動同步過，jt-ipam 仍顯示舊名：
dns_sync 從不刪 dns_records，也從不清 dns 這個來源的主機名稱觀測。
"""
from __future__ import annotations

from app.models.address import IPAddress
from app.models.dns import DNSRecord, DNSServer
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import dns_sync
from app.services.dns.base import DNSAdapterError, DNSRecordOp, DNSZoneInfo
from app.services.hostname import apply_observation
from sqlalchemy import select


class _Adapter:
    def __init__(self, zones: dict):
        self.zones = zones          # name -> list[DNSRecordOp] | Exception

    async def list_zones(self):
        return [DNSZoneInfo(name=z, kind="forward") for z in self.zones]

    async def list_records(self, zone):
        v = self.zones[zone]
        if isinstance(v, Exception):
            raise v
        return list(v)

    async def close(self):
        return None


def _patch(monkeypatch, zones):
    async def _get(_s, _srv):
        return _Adapter(zones)
    monkeypatch.setattr(dns_sync, "get_adapter", _get)


async def _setup(db):
    sec = Section(name="dns-stale")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.139")
    db.add(ip)
    srv = DNSServer(name="dc-a", type="powerdns")
    db.add(srv)
    await db.flush()
    return ip, srv


async def _records(db, srv) -> set[str]:
    from app.models.dns import DNSZone
    return set((await db.execute(select(DNSRecord.name).join(DNSZone).where(
        DNSZone.server_id == srv.id))).scalars().all())


async def test_a_record_deleted_on_the_server_disappears_with_its_hostname(db_session, monkeypatch):
    ip, srv = await _setup(db_session)
    await apply_observation(db_session, ip=ip, source="manual", hostname="new-host")
    others = [DNSRecordOp(name=f"h{i}", type="A", value=f"198.51.100.{i}") for i in range(1, 4)]
    _patch(monkeypatch, {"example.com": [DNSRecordOp(name="old-host", type="A", value="198.51.100.139"), *others]})
    await dns_sync.pull_server(db_session, srv)
    await db_session.refresh(ip)
    assert "old-host" in await _records(db_session, srv)

    # 伺服器上刪掉了 → 再同步一次：記錄與名稱都要消失，名稱回到手動填的
    _patch(monkeypatch, {"example.com": others})
    await dns_sync.pull_server(db_session, srv)
    await db_session.refresh(ip)
    assert "old-host" not in await _records(db_session, srv)
    assert ip.hostname == "new-host"
    assert srv.last_error is None


async def test_a_failed_zone_keeps_its_records_and_says_so(db_session, monkeypatch):
    ip, srv = await _setup(db_session)
    _patch(monkeypatch, {"example.com": [DNSRecordOp(name="web", type="A", value="198.51.100.139")]})
    await dns_sync.pull_server(db_session, srv)
    _patch(monkeypatch, {"example.com": DNSAdapterError("timeout")})
    await dns_sync.pull_server(db_session, srv)
    await db_session.refresh(ip)
    assert "web" in await _records(db_session, srv), "讀取失敗不代表伺服器上刪了"
    assert ip.hostname == "web"
    assert "timeout" in (srv.last_error or ""), "部分失敗要看得出來"


async def test_an_empty_read_of_a_populated_zone_is_not_trusted(db_session, monkeypatch):
    ip, srv = await _setup(db_session)
    recs = [DNSRecordOp(name=f"h{i}", type="A", value=f"198.51.100.{i}") for i in range(1, 8)]
    _patch(monkeypatch, {"example.com": recs})
    await dns_sync.pull_server(db_session, srv)
    _patch(monkeypatch, {"example.com": []})
    await dns_sync.pull_server(db_session, srv)
    assert len(await _records(db_session, srv)) == 7
    assert "empty read" in (srv.last_error or "")
