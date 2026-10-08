"""異常偵測「類型或 OS 突變」（2026-10-01，Recog 的其他用途 ②）。

依據是掃描代理定期偵測寫下的異動記錄（services/device_identity）。印表機突然變成 Windows 主機，
可能是 IP 被別台機器拿去用、設備被換掉，或有人冒用。判讀在兩個答案之間搖擺（A→B→A）不報。
"""
from __future__ import annotations

import uuid

from app.models.address import IPAddress
from app.models.section import Section
from app.models.subnet import Subnet
from app.services.anomaly import detect_identity_changes
from app.services.device_identity import apply_summary


async def _ip(db, *, anomaly: bool = True, last: int = 9) -> IPAddress:
    sec = Section(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr=f"198.51.{last}.0/24", anomaly_enabled=anomaly)
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip=f"198.51.{last}.20", hostname="printer-2f")
    db.add(ip)
    await db.commit()
    return ip


async def _see(db, ip, kind: str, os_text: str) -> None:
    await apply_summary(db, ip, {"device_type": kind, "os": os_text})
    await db.commit()


async def test_a_printer_that_became_a_windows_box_is_reported(db_session) -> None:
    ip = await _ip(db_session)
    await _see(db_session, ip, "printer", "HP embedded")
    await _see(db_session, ip, "windows", "Microsoft Windows 10")
    out = await detect_identity_changes(db_session)
    assert len(out) == 1
    row = out[0]
    assert row["ip"] == "198.51.9.20"
    assert {(c["field"], c["old"], c["new"]) for c in row["shifts"]} >= {("device_kind", "printer", "windows")}


async def test_flip_flopping_judgement_is_not_a_change(db_session) -> None:
    """A→B→A：判讀搖擺，不是設備換了。（隔超過十分鐘的來回才會留下兩筆記錄，這裡直接寫記錄模擬）"""
    from datetime import UTC, datetime, timedelta

    from app.models.ip_change_log import IPChangeLog
    ip = await _ip(db_session, last=10)
    await _see(db_session, ip, "camera", "Linux 3.x")
    t0 = datetime.now(UTC) - timedelta(hours=3)
    for i, (old, new) in enumerate((("camera", "server"), ("server", "camera"))):
        db_session.add(IPChangeLog(ip_id=ip.id, subnet_id=ip.subnet_id, ip_text="198.51.10.20",
                                   event_type="kind_changed", field="device_kind", old_value=old,
                                   new_value=new, source="scanner", created_at=t0 + timedelta(hours=i)))
    await db_session.commit()
    assert await detect_identity_changes(db_session) == []


async def test_ignored_ips_and_subnets_without_anomaly_detection_are_skipped(db_session) -> None:
    ip = await _ip(db_session, last=11)
    await _see(db_session, ip, "printer", "HP embedded")
    await _see(db_session, ip, "server", "Linux 5.x")
    ip.anomaly_ignore = ["identity_changes"]                 # 例如雙系統開機的機器
    await db_session.commit()
    assert await detect_identity_changes(db_session) == []

    other = await _ip(db_session, anomaly=False, last=12)
    await _see(db_session, other, "printer", "HP embedded")
    await _see(db_session, other, "server", "Linux 5.x")
    assert await detect_identity_changes(db_session) == []


async def test_ai_tool_can_list_them(db_session, admin_user) -> None:
    from app.mcp.tools import TOOLS
    ip = await _ip(db_session, last=13)
    await _see(db_session, ip, "camera", "Linux 3.x")
    await _see(db_session, ip, "windows", "Microsoft Windows 11")
    res = await TOOLS["list_anomalies"]["fn"](db_session, user=admin_user, kind="identity_changes")
    text = str(res)
    assert "198.51.13.20" in text
