"""OS 來源：Wazuh 用產品名稱、RustDesk 也是來源（排最後）（使用者 2026-10-06）。

實機：同一台 Windows 11，OCS 與 RustDesk 都說 Windows 11 Pro，Wazuh 卻顯示「windows 10.0.26200.9457」——
我們只向 Wazuh 拿了 os.platform／os.version，沒拿它本來就有的 os.name。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.core.os_fingerprint import wazuh_os_display
from app.models.address import IPAddress
from app.models.rustdesk import RustDeskPeer
from app.models.section import Section
from app.models.subnet import Subnet
from app.models.wazuh import WazuhAgent, WazuhInstance


def test_wazuh_display_prefers_the_product_name() -> None:
    assert wazuh_os_display("Microsoft Windows 11 Pro", "windows", "10.0.26200.9457") == "Microsoft Windows 11 Pro"


def test_windows_build_22000_and_later_is_windows_11_when_no_name() -> None:
    assert wazuh_os_display(None, "windows", "10.0.26200.9457") == "Windows 11 10.0.26200.9457"
    assert wazuh_os_display("", "windows", "10.0.22000.1") == "Windows 11 10.0.22000.1"
    # Windows 10 與非 Windows 照舊
    assert wazuh_os_display(None, "windows", "10.0.19045.4529") == "windows 10.0.19045.4529"
    assert wazuh_os_display(None, "ubuntu", "24.04") == "ubuntu 24.04"
    assert wazuh_os_display(None, None, None) is None


async def _ip(db, addr: str) -> IPAddress:
    sec = Section(name=f"sec-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip=addr)
    db.add(ip)
    await db.flush()
    return ip


async def _rd_peer(db, ip: IPAddress, os_name: str) -> None:
    from tests.test_rustdesk import _server
    srv = await _server(db)
    db.add(RustDeskPeer(server_id=srv.id, rustdesk_id=uuid.uuid4().hex[:9], address_id=ip.id,
                        match_status="matched", online=True, os_name=os_name,
                        last_online_at=datetime.now(UTC)))
    await db.flush()


async def test_rustdesk_is_an_os_source_ranked_last(db_session) -> None:
    from app.services import os_precedence
    assert os_precedence.DEFAULT_ORDER[-1] == "rustdesk"
    ip = await _ip(db_session, "198.51.100.61")
    await _rd_peer(db_session, ip, "Windows 11 Pro")
    eff = await os_precedence.effective_os(db_session, ip)
    assert eff["os_source"] == "rustdesk" and eff["os_guess"] == "Windows 11 Pro"
    # 有別的來源時 RustDesk 排最後
    ip.os_guess = "Microsoft Windows 10 (92%)"
    await db_session.flush()
    eff = await os_precedence.effective_os(db_session, ip)
    assert eff["os_source"] == "scanner"


async def test_unmatched_rustdesk_peer_is_not_used(db_session) -> None:
    from app.services import os_precedence
    from tests.test_rustdesk import _server
    ip = await _ip(db_session, "198.51.100.62")
    srv = await _server(db_session)
    db_session.add(RustDeskPeer(server_id=srv.id, rustdesk_id="900000062", candidate_address_id=ip.id,
                                match_status="ambiguous", online=True, os_name="Windows 11 Pro"))
    await db_session.flush()
    eff = await os_precedence.effective_os(db_session, ip)
    assert eff["os_source"] is None


async def test_wazuh_candidate_uses_the_product_name(db_session) -> None:
    from app.services import os_precedence
    ip = await _ip(db_session, "198.51.100.63")
    inst = WazuhInstance(name=f"wz-{uuid.uuid4().hex[:6]}", api_url="https://192.0.2.30:55000", api_user="u",
                         api_password_enc=b"x", api_password_nonce=b"x")
    db_session.add(inst)
    await db_session.flush()
    db_session.add(WazuhAgent(instance_id=inst.id, agent_id="063", name="laptop-07", ip="198.51.100.63",
                              status="active", os_platform="windows", os_version="10.0.26200.9457",
                              os_name="Microsoft Windows 11 Pro", last_keep_alive=datetime.now(UTC),
                              last_seen_at=datetime.now(UTC), jt_ipam_address_id=ip.id))
    await db_session.flush()
    eff = await os_precedence.effective_os(db_session, ip)
    assert eff["os_source"] == "wazuh" and eff["os_guess"] == "Microsoft Windows 11 Pro"


def test_rustdesk_os_strings_are_tidied_like_the_ui() -> None:
    """跟前端 utils/rustdeskOs.ts 同一套規則：「Linux 24.04 Ubuntu」→「Ubuntu 24.04」（使用者 2026-10-07）。"""
    from app.services.rustdesk import os_display
    assert os_display("ubuntu / Linux 24.04 Ubuntu") == "Ubuntu 24.04"
    assert os_display("debian / Linux 12 Debian") == "Debian 12"
    assert os_display("windows / Windows 11 Pro - 11 (26200)") == "Windows 11 Pro"
    assert os_display("macos / MacOS 15.7.5") == "MacOS 15.7.5"
    assert os_display("Windows 10 Pro") == "Windows 10 Pro"
    assert os_display("") is None and os_display(None) is None


async def test_rustdesk_os_source_uses_the_tidy_string(db_session) -> None:
    from app.services import os_precedence
    ip = await _ip(db_session, "198.51.100.64")
    await _rd_peer(db_session, ip, "ubuntu / Linux 24.04 Ubuntu")
    eff = await os_precedence.effective_os(db_session, ip)
    assert eff["os_source"] == "rustdesk" and eff["os_guess"] == "Ubuntu 24.04"
    assert eff["os_family"] in ("ubuntu", "linux")
