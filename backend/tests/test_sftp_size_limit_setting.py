"""SFTP 單檔上下傳上限可以在系統設定改（使用者要求，2026-09-26）。

原本寫死 100 MB：要下載一個 6 GB 的 ISO 只看到「檔案超過 100 MB 上限」，而且沒有地方能改。
預設維持 100 MB（這個功能的本意是設定檔與紀錄）；放大是管理者自己的決定。
上限的上界是防手殘，不是能力限制：後端本來就是逐塊串流、不會整個檔案放進記憶體。
"""
from __future__ import annotations

import pytest
from app.services.sftp import MAX_FILE_BYTES, SftpError, check_size
from app.services.system_config import (
    SFTP_MAX_FILE_MB_DEFAULT,
    SFTP_MAX_FILE_MB_LIMIT,
    get_sftp_max_file_mb,
    set_sftp_max_file_mb,
)

MB = 1024 * 1024


def test_check_size_uses_the_given_limit() -> None:
    assert check_size(2048 * MB, what="download", max_bytes=4096 * MB) == 2048 * MB
    with pytest.raises(SftpError) as exc:
        check_size(4097 * MB, what="download", max_bytes=4096 * MB)
    assert exc.value.code == "sftp_download_too_large"
    assert exc.value.params["max"] == 4096
    # 沒給上限時維持原本的 100 MB
    assert MAX_FILE_BYTES == 100 * MB
    with pytest.raises(SftpError):
        check_size(MAX_FILE_BYTES + 1, what="upload")


async def test_default_is_100_mb_and_it_can_be_changed(db_session) -> None:
    assert SFTP_MAX_FILE_MB_DEFAULT == 100
    assert await get_sftp_max_file_mb(db_session) == 100
    assert await set_sftp_max_file_mb(db_session, mb=8192) == 8192
    assert await get_sftp_max_file_mb(db_session) == 8192


async def test_other_console_settings_survive(db_session) -> None:
    """同一把設定底下還有剪貼簿與引擎 —— 要合併，不能整包換掉。"""
    from app.services.system_config import get_rdp_engine, set_rdp_engine
    await set_rdp_engine(db_session, engine="guacd")
    await set_sftp_max_file_mb(db_session, mb=500)
    assert await get_rdp_engine(db_session) == "guacd"
    assert await get_sftp_max_file_mb(db_session) == 500


@pytest.mark.parametrize("bad", [0, -1, SFTP_MAX_FILE_MB_LIMIT + 1])
async def test_out_of_range_values_are_refused(db_session, bad) -> None:
    with pytest.raises(ValueError):
        await set_sftp_max_file_mb(db_session, mb=bad)


async def test_a_broken_stored_value_falls_back_to_the_default(db_session) -> None:
    """壞掉的設定值不可以讓 SFTP 整個不能用（例如被手動改成字串）。"""
    from app.models.system_setting import SystemSetting
    from app.services.system_config import CONSOLE_SECURITY_KEY
    db_session.add(SystemSetting(key=CONSOLE_SECURITY_KEY, value={"sftp_max_file_mb": "lots"}))
    await db_session.commit()
    assert await get_sftp_max_file_mb(db_session) == SFTP_MAX_FILE_MB_DEFAULT


async def test_endpoint_round_trip_and_omitted_means_keep(client, auth_headers) -> None:
    r = await client.get("/api/v1/system/console-security", headers=auth_headers)
    assert r.json()["sftp_max_file_mb"] == 100
    r = await client.put("/api/v1/system/console-security", headers=auth_headers,
                         json={"rdp_engine": "aardwolf", "sftp_max_file_mb": 10240})
    assert r.status_code == 200, r.text
    assert r.json()["sftp_max_file_mb"] == 10240
    # 舊版頁面沒有這個欄位：按儲存不可以把它改回預設
    r = await client.put("/api/v1/system/console-security", headers=auth_headers,
                         json={"rdp_engine": "aardwolf"})
    assert r.json()["sftp_max_file_mb"] == 10240
    r = await client.put("/api/v1/system/console-security", headers=auth_headers,
                         json={"rdp_engine": "aardwolf", "sftp_max_file_mb": 0})
    assert r.status_code == 422
