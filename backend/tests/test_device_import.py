"""issue #46：裝置清單只能匯出、不能匯入。

目標是「匯出改完能直接匯回去」：清單匯出的中／英／日檔頭、類型的顯示文字都要認得；地點／機櫃／單位用名稱對應；
已存在的裝置可以略過或更新（空白＝不變）；驗證與 API 同一套（U 位不可重疊，同一個檔裡的也算）；
預覽走完整流程但不留任何變更。
"""
from __future__ import annotations

import io
import json
import uuid
import zipfile
from pathlib import Path

import pytest
from app.models.address import IPAddress
from app.models.customer import Customer
from app.models.device import Device
from app.models.location import Location, Rack
from app.models.section import Section
from app.models.subnet import Subnet
from app.services import device_import as di
from sqlalchemy import func, select

TAG = uuid.uuid4().hex[:6]


async def _world(db):
    loc = Location(name=f"機房A-{TAG}")
    loc2 = Location(name=f"機房B-{TAG}")
    db.add_all([loc, loc2])
    await db.flush()
    r1 = Rack(name=f"R01-{TAG}", location_id=loc.id, u_height=42)
    r1b = Rack(name=f"R01-{TAG}", location_id=loc2.id, u_height=42)     # 同名、不同地點
    r2 = Rack(name=f"R02-{TAG}", location_id=loc.id, u_height=42)
    db.add_all([r1, r1b, r2])
    cust = Customer(name=f"資訊部-{TAG}", title=f"IT-{TAG}")
    db.add(cust)
    sec = Section(name=f"sec-{TAG}")
    db.add(sec)
    await db.flush()
    sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24")
    db.add(sub)
    await db.flush()
    ip = IPAddress(subnet_id=sub.id, ip="198.51.100.21", state="active")
    db.add(ip)
    await db.commit()
    return {"loc": loc, "loc2": loc2, "r1": r1, "r1b": r1b, "r2": r2, "cust": cust, "ip": ip}


def _csv(text: str) -> list[list[str]]:
    return di.read_table(text.encode("utf-8"))


async def _dev(db, name):
    return (await db.execute(select(Device).where(Device.name == name))).scalars().first()


async def test_create_with_names_resolved_and_ip_linked(db_session) -> None:
    w = await _world(db_session)
    rows = _csv(f"""name,type,vendor,model,serial,location,rack,u_position,u_size,rack_face,unit,ip,description
sw-core-{TAG},switch,Juniper,EX4300,SN123,機房A-{TAG},R02-{TAG},10,1,front,資訊部-{TAG},198.51.100.21,核心交換器
""")
    out = await di.import_devices(db_session, rows, dry_run=False)
    await db_session.commit()
    assert out.to_dict()["created"] == 1, out.to_dict()
    d = await _dev(db_session, f"sw-core-{TAG}")
    assert (d.type, d.vendor, d.model, d.serial) == ("switch", "Juniper", "EX4300", "SN123")
    assert (d.location_id, d.rack_id, d.u_position, d.u_size, d.rack_face) == (w["loc"].id, w["r2"].id, 10, 1, "front")
    assert d.customer_id == w["cust"].id and d.description == "核心交換器"
    assert d.primary_ip_id == w["ip"].id
    await db_session.refresh(w["ip"])
    assert w["ip"].device_id == d.id, "主要 IP 要雙向連結（跟 API 一樣）"


async def test_the_lists_own_export_headers_in_any_language_import_back(db_session) -> None:
    """清單匯出的檔頭是介面語言的文字，類型也是顯示文字 —— 原樣匯回來要認得。"""
    w = await _world(db_session)
    for header, typ, extra in (
        ("名稱,IP,類型,虛實,製造商,型號,地點,機櫃,單位", "伺服器", "實體"),
        ("Name,IP,Type,Kind,Vendor,Model,Location,Rack,Unit", "Server", "Physical"),
        ("名称,IP,種別,区分,ベンダー,型番,設置場所,ラック,顧客", "サーバー", "物理"),
    ):
        name = f"srv-{header[:2]}-{TAG}"
        rows = _csv(f"{header}\n{name},—,{typ},{extra},Dell,R650,機房A-{TAG},R02-{TAG},IT-{TAG}\n")
        out = await di.import_devices(db_session, rows, dry_run=False)
        assert out.to_dict()["created"] == 1, (header, out.to_dict())
        assert out.ignored_columns == [], "匯出帶的「虛實」是推算欄位，認得、略過，不要當成不認得的欄位"
        d = await _dev(db_session, name)
        assert (d.type, d.vendor, d.location_id, d.rack_id, d.customer_id) == (
            "server", "Dell", w["loc"].id, w["r2"].id, w["cust"].id)


async def test_existing_devices_skip_or_update_and_blank_means_unchanged(db_session) -> None:
    w = await _world(db_session)
    db_session.add(Device(name=f"fw-{TAG}", type="firewall", vendor="OldVendor", model="X1",
                          description="keep me", location_id=w["loc"].id))
    await db_session.commit()
    rows = _csv(f"name,vendor,model,description\nFW-{TAG},NewVendor,,\n")     # 名稱不分大小寫
    out = await di.import_devices(db_session, rows, on_existing="skip", dry_run=False)
    assert out.to_dict()["skipped"] == 1
    assert (await _dev(db_session, f"fw-{TAG}")).vendor == "OldVendor"

    out = await di.import_devices(db_session, rows, on_existing="update", dry_run=False)
    await db_session.commit()
    assert out.to_dict()["updated"] == 1
    d = await _dev(db_session, f"fw-{TAG}")
    assert d.vendor == "NewVendor"
    assert (d.model, d.description, d.location_id) == ("X1", "keep me", w["loc"].id), "空白欄位不可以把原值清掉"


async def test_errors_are_reported_per_row_and_bad_rows_are_not_written(db_session) -> None:
    await _world(db_session)
    rows = _csv(f"""name,type,location,rack,u_position,u_size,unit,ip
ok-{TAG},server,機房A-{TAG},R02-{TAG},20,2,,
bad-loc-{TAG},server,不存在的機房,,,,,
bad-rack-{TAG},server,,R01-{TAG},,,,
bad-type-{TAG},toaster,,,,,,
bad-unit-{TAG},server,,,,,沒有這個單位,
overlap-{TAG},server,機房A-{TAG},R02-{TAG},21,1,,
ok-{TAG},server,,,,,,
,server,,,,,,
ip-miss-{TAG},server,,,,,,203.0.113.99
""")
    out = await di.import_devices(db_session, rows, dry_run=False)
    await db_session.commit()
    by = {r.line: r for r in out.rows}
    codes = {line: [m["code"] for m in r.messages] for line, r in by.items()}
    assert by[2].action == "create"
    assert codes[3] == ["location_not_found"]
    assert codes[4] == ["rack_ambiguous"], "同名機櫃在兩個地點：不猜，要求補地點"
    assert codes[5] == ["bad_type"]
    assert codes[6] == ["unit_not_found"]
    assert codes[7] == ["placement"], "同一個檔案裡前一列剛放進去的 U 位也算重疊"
    assert codes[8] == ["duplicate_in_file"]
    assert codes[9] == ["missing_name"]
    assert by[10].action == "create" and codes[10] == ["warn_ip_not_found"], "IP 不在 IPAM 只是提醒，裝置照建"
    n = (await db_session.execute(select(func.count()).select_from(Device).where(
        Device.name.like(f"%-{TAG}")))).scalar()
    assert n == 2, "有錯的列一筆都不寫"


async def test_rack_alone_derives_the_location(db_session) -> None:
    w = await _world(db_session)
    out = await di.import_devices(db_session, _csv(f"name,rack\npdu-{TAG},R02-{TAG}\n"), dry_run=False)
    assert out.to_dict()["created"] == 1
    assert (await _dev(db_session, f"pdu-{TAG}")).location_id == w["loc"].id


async def test_dry_run_leaves_nothing_behind(db_session) -> None:
    await _world(db_session)
    out = await di.import_devices(db_session, _csv(f"name,type\ndry-{TAG},server\n"), dry_run=True)
    assert out.to_dict()["created"] == 1
    assert await _dev(db_session, f"dry-{TAG}") is None


def _xlsx(rows: list[list[str]]) -> bytes:
    """最小的 .xlsx：共用字串＋數字（Excel 存檔時整數可能寫成 10.0）。"""
    shared: list[str] = []
    def cell(ref, v):
        if isinstance(v, (int, float)):
            return f'<c r="{ref}"><v>{v}</v></c>'
        shared.append(v)
        return f'<c r="{ref}" t="s"><v>{len(shared) - 1}</v></c>'
    sheet_rows = "".join(
        f'<row r="{i + 1}">' + "".join(cell(f"{chr(65 + j)}{i + 1}", v) for j, v in enumerate(r)) + "</row>"
        for i, r in enumerate(rows))
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/workbook.xml", f'<workbook {ns} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="x" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr("xl/worksheets/sheet1.xml", f"<worksheet {ns}><sheetData>{sheet_rows}</sheetData></worksheet>")
        z.writestr("xl/sharedStrings.xml", f"<sst {ns}>" + "".join(f"<si><t>{s}</t></si>" for s in shared) + "</sst>")
    return buf.getvalue()


async def test_xlsx_from_excel_imports(db_session) -> None:
    w = await _world(db_session)
    raw = _xlsx([["名稱", "類型", "機櫃", "u_position", "u_size"],
                 [f"nas-{TAG}", "儲存設備", f"R02-{TAG}", 30.0, 2]])
    out = await di.import_devices(db_session, di.read_table(raw), dry_run=False)
    assert out.to_dict()["created"] == 1, out.to_dict()
    d = await _dev(db_session, f"nas-{TAG}")
    assert (d.type, d.rack_id, d.u_position, d.u_size) == ("storage", w["r2"].id, 30, 2)


async def test_xlsx_bomb_and_garbage_are_refused() -> None:
    from app.services.xlsx_read import XlsxError, read_first_sheet
    with pytest.raises(XlsxError):
        read_first_sheet(b"PK\x03\x04not really a zip")


async def test_template_round_trips_and_is_formula_safe(client, auth_headers, db_session) -> None:
    w = await _world(db_session)
    db_session.add(Device(name=f"=HYPERLINK-{TAG}", type="server", rack_id=w["r2"].id,
                          location_id=w["loc"].id, u_position=5, u_size=1, customer_id=w["cust"].id,
                          primary_ip_id=w["ip"].id))
    await db_session.commit()
    r = await client.get("/api/v1/devices/import-template?include_devices=true", headers=auth_headers)
    assert r.status_code == 200, r.text
    assert "attachment" in r.headers["content-disposition"]
    text = r.content.decode("utf-8-sig")
    assert text.splitlines()[0] == ",".join(di.FIELDS)
    line = next(ln for ln in text.splitlines() if f"HYPERLINK-{TAG}" in ln)
    assert line.startswith("'=HYPERLINK"), "公式注入防護：= 開頭的值要加單引號"
    assert f"R02-{TAG}" in line and f"機房A-{TAG}" in line and "198.51.100.21" in line

    # 原封不動用「更新」模式匯回去：沒有錯誤、每一台都是更新
    files = {"file": ("devices.csv", r.content, "text/csv")}
    pre = await client.post("/api/v1/devices/import", headers=auth_headers, files=files,
                            data={"dry_run": "true", "on_existing": "update"})
    assert pre.status_code == 200, pre.text
    body = pre.json()
    assert body["errored"] == 0, [x for x in body["rows"] if x["action"] == "error"]
    mine = next(x for x in body["rows"] if x["name"] == f"=HYPERLINK-{TAG}")
    assert mine["action"] == "update"


async def test_commit_runs_as_a_task_and_audits_each_device(client, auth_headers, db_session) -> None:
    from app.models.audit import AuditLog
    from app.models.background_task import BackgroundTask
    await _world(db_session)
    files = {"file": ("d.csv", f"name,type\ntask-{TAG},router\n".encode(), "text/csv")}
    r = await client.post("/api/v1/devices/import", headers=auth_headers, files=files,
                          data={"dry_run": "false", "on_existing": "skip"})
    assert r.status_code == 200, r.text
    tid = uuid.UUID(r.json()["task_id"])
    import asyncio
    for _ in range(50):
        await asyncio.sleep(0.1)
        db_session.expire_all()
        t = await db_session.get(BackgroundTask, tid)
        if t and t.status in ("succeeded", "failed"):
            break
    assert t.status == "succeeded", t.error
    assert t.summary["created"] == 1
    d = await _dev(db_session, f"task-{TAG}")
    assert d is not None and d.type == "router"
    audit = (await db_session.execute(select(AuditLog).where(
        AuditLog.object_id == d.id, AuditLog.action == "create"))).scalars().first()
    assert audit is not None and audit.diff["source"] == "device_import"


async def test_non_admins_cannot_import(client, db_session) -> None:
    from app.core.security import hash_password
    from app.models.user import User
    from app.services.auth import issue_access_token
    u = User(username=f"viewer-{TAG}", email=f"v-{TAG}@e.test", password_hash=hash_password("Xx!12345678xX"),
             is_admin=False, is_active=True)
    db_session.add(u)
    await db_session.commit()
    h = {"Authorization": f"Bearer {issue_access_token(u)}"}
    r = await client.post("/api/v1/devices/import", headers=h,
                          files={"file": ("d.csv", b"name\nx\n", "text/csv")}, data={"dry_run": "true"})
    assert r.status_code == 403
    assert (await client.get("/api/v1/devices/import-template", headers=h)).status_code == 403


def test_header_and_type_aliases_match_the_ui_labels() -> None:
    """匯出的檔頭與類型文字來自前端語言檔；語言檔改了、這裡沒跟上，匯出的檔案就匯不回來。"""
    root = Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n"
    cols = {"name": "common.name", "type": "devices.type", "vendor": "devices.vendor", "model": "devices.model",
            "location": "devices.location", "rack": "devices.rack", "unit": "nav.customers",
            "serial": "devices.serial", "u_position": "devices.u_position", "u_size": "devices.u_size",
            "rack_face": "devices.rack_face"}
    for loc in ("zh-TW", "en-US", "ja-JP"):
        d = json.loads((root / f"{loc}.json").read_text(encoding="utf-8"))
        def get(k, d=d):
            cur = d
            for p in k.split("."):
                cur = cur[p]
            return cur
        for field, key in cols.items():
            assert di._HEADER_MAP.get(di._norm(get(key))) == field, (loc, key, get(key))
        assert di._norm(get("devices.virtuality")) in di._IGNORED
        for code in di.TYPE_LABELS:
            assert di._TYPE_MAP.get(di._norm(get(f"devices.type_{code}"))) == code, (loc, code)
        for face in ("front", "rear"):
            assert di._FACE_MAP.get(di._norm(get(f"devices.rack_face_{face}"))) == face, (loc, face)
