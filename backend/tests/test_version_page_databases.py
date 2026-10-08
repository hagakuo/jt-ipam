"""版本頁的「選用相依」也要列出下載來的資料庫：MAC 製造商（OUI）與 GeoIP。

由來（2026-10-06 使用者）：選用相依裡有 Recog，同樣是下載來的 OUI 卻不在 ——
OUI 表是空的時候，IP 清單、MAC 歷程、異常偵測的製造商欄全部空白，卻沒有地方講。
GeoIP 要管理員自己的 MaxMind 帳號，沒設定是正常狀態：列出來但不發警告（opt_in）。
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from app.models.oui import OUIVendor


async def _tools(client, auth_headers) -> dict:
    r = await client.get("/api/v1/system/version", headers=auth_headers)
    assert r.status_code == 200, r.text
    return r.json()["host"]["optional_tools"]


async def test_oui_is_listed_and_reports_missing_when_the_table_is_empty(client, auth_headers):
    oui = (await _tools(client, auth_headers))["oui"]
    assert oui["present"] is False
    assert "manuf" in oui["package"]
    assert "MAC" in oui["used_by"]
    # 缺了要進警告：不可以標成備用或選擇性設定
    assert not oui.get("fallback")
    assert not oui.get("opt_in")


async def test_oui_present_shows_the_last_update_date(client, auth_headers, db_session):
    db_session.add(OUIVendor(prefix="00005E", short_name="IANA", name="ICANN, IANA Department",
                             source="wireshark", updated_at=datetime(2026, 10, 1, 3, 0, tzinfo=UTC)))
    await db_session.commit()
    oui = (await _tools(client, auth_headers))["oui"]
    assert oui["present"] is True
    assert oui["version"] == "2026-10-01"


@pytest.fixture
def geoip_dir(tmp_path, monkeypatch):
    from app.services import geoip
    monkeypatch.setattr(geoip, "DB_DIR", tmp_path)
    return tmp_path


async def test_geoip_not_configured_is_listed_without_a_warning(client, auth_headers, geoip_dir):
    g = (await _tools(client, auth_headers))["geoip"]
    assert g["present"] is False
    assert g["opt_in"] is True          # 要自己的 MaxMind 帳號：沒設定是正常的
    assert "MaxMind" in g["package"]
    assert g["version"] is None


async def test_geoip_local_database_shows_its_date(client, auth_headers, geoip_dir):
    p = geoip_dir / "GeoLite2-City.mmdb"
    p.write_bytes(b"x")
    ts = datetime(2026, 9, 30, 12, 0, tzinfo=UTC).timestamp()
    os.utime(p, (ts, ts))
    g = (await _tools(client, auth_headers))["geoip"]
    assert g["present"] is True
    assert g["version"] == "2026-09-30"


async def test_geoip_web_service_credentials_count_as_present(client, auth_headers, db_session, geoip_dir):
    from app.services import geoip
    await geoip.set_geoip_config(db_session, account_id="123456", license_key="test-key")
    g = (await _tools(client, auth_headers))["geoip"]
    assert g["present"] is True
    assert g["version"] == "web service"
