"""LibreNMS ARP sync compatibility tests."""

from __future__ import annotations

from app.models.address import IPAddress
from app.models.librenms import ARPEntry, LibreNMSDevice, LibreNMSInstance
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import librenms as lib
from sqlalchemy import func, select


async def test_sync_arp_uses_global_resources_endpoint(db_session, monkeypatch):
    """Current LibreNMS exposes ARP at /resources/ip/arp/all, not per-device."""
    sec = Section(name="lnms-arp-sec")
    db_session.add(sec)
    await db_session.flush()
    sub = Subnet(section_id=sec.id, cidr="192.83.194.0/24")
    db_session.add(sub)
    inst = LibreNMSInstance(
        name="lnms-arp-test",
        api_url="https://librenms.example",
        api_token_enc=b"x",
        api_token_nonce=b"y",
    )
    db_session.add(inst)
    await db_session.flush()
    dev = LibreNMSDevice(
        instance_id=inst.id,
        legacy_device_id=2,
        hostname="192.83.194.254",
        sysname="nz-c6807_vss.nkmu.edu.tw",
        primary_ip="192.83.194.254",
        status="up",
    )
    db_session.add(dev)
    ip = IPAddress(subnet_id=sub.id, ip="192.83.194.254", state="active")
    db_session.add(ip)
    await db_session.commit()

    async def fake_api_get(_instance, path, *, timeout=30.0):  # noqa: ANN001
        assert path == "/api/v0/resources/ip/arp/all"
        return {
            "status": "ok",
            "arp": [{
                "device_id": 2,
                "port_id": 443,
                "mac_address": "70db98821b00",
                "ipv4_address": "192.83.194.254",
                "context_name": "",
            }, {
                "device_id": 2,
                "port_id": 443,
                "mac_address": "70db98821b00",
                "ipv4_address": "192.83.194.254",
                "context_name": "",
            }],
        }

    monkeypatch.setattr(lib, "_api_get", fake_api_get)

    seen, inserted, updated, filled = await lib.sync_arp(db_session, inst)
    await db_session.commit()

    assert (seen, inserted, updated, filled) == (1, 1, 0, 1)
    arp = (await db_session.execute(select(ARPEntry))).scalar_one()
    assert str(arp.ip) == "192.83.194.254"
    assert str(arp.mac) == "70:db:98:82:1b:00"
    assert arp.device_id == dev.id
    row = (await db_session.execute(
        select(IPAddress).where(func.host(IPAddress.ip) == "192.83.194.254")
    )).scalar_one()
    assert str(row.mac) == "70:db:98:82:1b:00"
    assert row.last_seen_librenms is not None
