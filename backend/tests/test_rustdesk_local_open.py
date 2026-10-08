"""「用本機的 RustDesk 客戶端軟體開啟」也留稽核（使用者 2026-10-05）。

rustdesk:// 網址交給使用者電腦上的客戶端，連線在客戶端與對方之間、不經過 jt-ipam，以前完全沒有紀錄 ——
「調查」的遠端連線記錄只列得出網頁連線。按下去時記一筆（誰、什麼時候、對哪個 IP、哪個 RustDesk ID）。
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.address import IPAddress
from app.models.audit import AuditLog
from app.models.permission import Permission
from app.models.rustdesk import RustDeskPeer, RustDeskServer
from app.models.section import Section
from app.models.subnet import Subnet

pytestmark = pytest.mark.anyio
PEER = "123456789"


async def _setup(db, *, rustdesk_enabled: bool = True, matched: bool = True):
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.21", rustdesk_enabled=rustdesk_enabled)
    db.add(ip)
    await db.flush()
    srv = RustDeskServer(name=f"rd-{uuid.uuid4().hex[:6]}", public_key="K" * 43 + "=")
    db.add(srv)
    await db.flush()
    db.add(RustDeskPeer(server_id=srv.id, rustdesk_id=PEER, online=True,
                        address_id=ip.id if matched else None, match_status="matched" if matched else "no_ip"))
    await db.commit()
    return ip, srv


async def _audits(db, ip_id):
    return (await db.execute(select(AuditLog.action, AuditLog.diff).where(
        AuditLog.object_type == "ip", AuditLog.object_id == ip_id))).all()


async def test_local_open_is_audited(client, auth_headers, db_session) -> None:
    ip, srv = await _setup(db_session)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/local-open", headers=auth_headers)
    assert r.status_code == 204, r.text
    rows = [(a, d) for a, d in await _audits(db_session, ip.id) if a == "rustdesk.local_client_open"]
    assert len(rows) == 1
    assert rows[0][1]["peer_id"] == PEER
    assert rows[0][1]["server"] == srv.name


async def test_local_open_needs_the_same_rights_as_the_button(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    ip, _srv = await _setup(db_session)
    u = User(username=f"u-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@t.local", display_name="U",
             password_hash=hash_password("TestPassword2026!"), auth_provider="local", is_active=True)
    db_session.add(u)
    await db_session.flush()
    db_session.add(Permission(object_type="subnet", object_id=ip.subnet_id, principal_type="user",
                              principal_id=u.id, level="read"))
    await db_session.commit()
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/local-open",
                          headers={"Authorization": f"Bearer {issue_access_token(u)}"})
    assert r.status_code == 403
    assert not [a for a, _ in await _audits(db_session, ip.id) if a == "rustdesk.local_client_open"]


async def test_local_open_without_rustdesk_on_the_ip(client, auth_headers, db_session) -> None:
    ip, _srv = await _setup(db_session, rustdesk_enabled=False)
    r = await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/local-open", headers=auth_headers)
    assert r.status_code == 403
    ip2, _ = await _setup(db_session, matched=False)
    r = await client.post(f"/api/v1/addresses/{ip2.id}/rustdesk/local-open", headers=auth_headers)
    assert r.status_code == 404


async def test_investigate_lists_local_client_opens(client, auth_headers, db_session, admin_user) -> None:
    from app.services.investigate import collect_dossier
    ip, _srv = await _setup(db_session)
    await client.post(f"/api/v1/addresses/{ip.id}/rustdesk/local-open", headers=auth_headers)
    d = await collect_dossier(db_session, user=admin_user, ip="198.51.100.21")
    assert [c["kind"] for c in d["console_sessions"]] == ["rustdesk_local"]
