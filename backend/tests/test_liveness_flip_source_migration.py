"""#49 的舊資料修正：只在沒有 LibreNMS 整合的站台，把上線／失聯記錄的來源改成 system。"""
from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

from app.models.address import IPAddress
from app.models.ip_change_log import IPChangeLog
from app.models.librenms import LibreNMSInstance
from app.models.section import Section
from app.models.subnet import Subnet
from sqlalchemy import select, text

_MIG = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0174_liveness_flip_source.py"


def _fix_sql() -> str:
    spec = importlib.util.spec_from_file_location("m0174", _MIG)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FIX_SQL


async def _rows(db):
    sec = Section(name=f"m74-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.7")
    db.add(ip)
    await db.flush()
    for ev, f, src in (("offline", "effective_status", "librenms"), ("online", "effective_status", "librenms"),
                       ("arp_changed", "mac", "librenms"), ("online", "effective_status", "scanner")):
        db.add(IPChangeLog(ip_id=ip.id, subnet_id=sub.id, ip_text="198.51.100.7", event_type=ev, field=f,
                           source=src))
    await db.commit()


async def _sources(db):
    return sorted((e, f, s) for e, f, s in (await db.execute(
        select(IPChangeLog.event_type, IPChangeLog.field, IPChangeLog.source))).all())


async def test_sites_without_librenms_get_system(db_session) -> None:
    await _rows(db_session)
    await db_session.execute(text(_fix_sql()))
    await db_session.commit()
    assert await _sources(db_session) == [
        ("arp_changed", "mac", "librenms"),                 # 不是上線狀態的不動
        ("offline", "effective_status", "system"),
        ("online", "effective_status", "scanner"),          # 本來就對的不動
        ("online", "effective_status", "system"),
    ]


async def test_sites_with_librenms_are_left_alone(db_session) -> None:
    await _rows(db_session)
    db_session.add(LibreNMSInstance(name="lnms", api_url="https://librenms.example",
                                    api_token_enc=b"x", api_token_nonce=b"y"))
    await db_session.commit()
    before = await _sources(db_session)
    await db_session.execute(text(_fix_sql()))
    await db_session.commit()
    assert await _sources(db_session) == before
