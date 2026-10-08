"""DHCP 集區的使用率：算「範圍內已被佔用的位址數」。

「已用」的定義刻意包含**有租約**與**手動登記在池內**兩種：使用者關心的是
「還有多少位址可以發出去」，而不是「DHCP 伺服器自己記了幾筆」。有人把固定 IP
設在池的範圍裡（常見的設定失誤）也會吃掉可用量，那正是要看見的事。
"""
from __future__ import annotations

from app.models.address import IPAddress
from app.models.dhcp import DHCPPoolRange
from app.models.section import Section
from app.models.subnet import Subnet


async def _subnet(session, cidr: str = "198.51.100.0/24") -> Subnet:
    sec = Section(name=f"pool-{cidr}")
    session.add(sec)
    await session.flush()
    sub = Subnet(section_id=sec.id, cidr=cidr)
    session.add(sub)
    await session.flush()
    return sub


async def test_counts_only_addresses_inside_the_range(db_session):
    from app.services.dhcp_usage import pool_usage

    sub = await _subnet(db_session)
    for last, in_lease in ((100, True), (101, True), (5, True)):   # .5 在池外
        db_session.add(IPAddress(subnet_id=sub.id, ip=f"198.51.100.{last}",
                                 in_dhcp_lease=in_lease))
    db_session.add(DHCPPoolRange(source_type="opnsense", source_id=sub.id,
                                 source_name="lan", subnet_cidr="198.51.100.0/24",
                                 start_ip="198.51.100.100", end_ip="198.51.100.199"))
    await db_session.flush()

    (pool, used, size), = await pool_usage(db_session)
    assert size == 100, "範圍大小是 .100–.199＝100 個位址"
    assert used == 2, "池外的 .5 不算"


async def test_manually_assigned_addresses_inside_the_pool_count_as_used(db_session):
    """把固定 IP 設在池範圍內是常見的設定失誤，它確實吃掉了可發放的量。"""
    from app.services.dhcp_usage import pool_usage

    sub = await _subnet(db_session, "203.0.113.0/24")
    db_session.add(IPAddress(subnet_id=sub.id, ip="203.0.113.150", in_dhcp_lease=False))
    db_session.add(DHCPPoolRange(source_type="mikrotik", source_id=sub.id,
                                 source_name="dhcp1", subnet_cidr="203.0.113.0/24",
                                 start_ip="203.0.113.100", end_ip="203.0.113.199"))
    await db_session.flush()
    (_, used, size), = await pool_usage(db_session)
    assert (used, size) == (1, 100)


async def test_broken_range_does_not_explode(db_session):
    """同步到一半或設定錯的範圍（起 > 迄、非法位址）不該讓整輪告警爆掉。"""
    from app.services.dhcp_usage import pool_usage

    sub = await _subnet(db_session, "192.0.2.0/24")
    db_session.add(DHCPPoolRange(source_type="x", source_id=sub.id, source_name="bad",
                                 subnet_cidr="192.0.2.0/24",
                                 start_ip="192.0.2.200", end_ip="192.0.2.100"))
    db_session.add(DHCPPoolRange(source_type="x", source_id=sub.id, source_name="junk",
                                 subnet_cidr="192.0.2.0/24",
                                 start_ip="not-an-ip", end_ip="192.0.2.100"))
    await db_session.flush()
    for _, used, size in await pool_usage(db_session):
        assert size == 0 and used == 0
