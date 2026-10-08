"""四類補上的告警：DHCP 集區、跳板主機金鑰、憑證來源、以及兩個原本關不掉的通知。

共同的設計與前一批相同：狀態類的只在「開始」與「恢復」時發（`services/state_alert`），
而且逐項可在通知發送設定關掉。
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta


# ── DHCP 集區快用完 ────────────────────────────────────────────────────────
async def test_dhcp_pool_exhaustion_is_reported(db_session, admin_user):
    """集區用完＝新機器接上去拿不到位址，而且症狀是「網路壞了」不是「IPAM 有問題」。"""
    from app.services.capacity_alert import check_dhcp_pools

    class _Pool:
        def __init__(self, used, size):
            self.id = "66666666-6666-6666-6666-666666666666"
            self.source_name = "opnsense-lan"
            self.subnet_cidr = "198.51.100.0/24"
            self.start_ip, self.end_ip = "198.51.100.100", "198.51.100.199"
            self._used, self._size = used, size

    # 95% 已用 → 要通知（門檻 90）
    assert await check_dhcp_pools(db_session, [(_Pool(95, 100), 95, 100)],
                                  threshold_pct=90) == 1
    # 持續滿著不再吵
    assert await check_dhcp_pools(db_session, [(_Pool(96, 100), 96, 100)],
                                  threshold_pct=90) == 0
    # 降回門檻以下 → 說一聲
    assert await check_dhcp_pools(db_session, [(_Pool(50, 100), 50, 100)],
                                  threshold_pct=90) == 1


async def test_empty_pool_is_not_a_division_by_zero(db_session, admin_user):
    """size 為 0 的集區（設定錯誤／同步到一半）不該讓整輪告警爆掉。"""
    from app.services.capacity_alert import check_dhcp_pools

    class _Pool:
        id = "77777777-7777-7777-7777-777777777777"
        source_name = "broken"
        subnet_cidr = None
        start_ip = end_ip = "0.0.0.0"

    assert await check_dhcp_pools(db_session, [(_Pool(), 0, 0)], threshold_pct=90) == 0


# ── 跳板主機的金鑰改變 ─────────────────────────────────────────────────────
async def test_jump_host_key_change_alerts(db_session, admin_user):
    """指紋變了是中間人攻擊的訊號 —— 原本只有在有人連線時才會擋下來，
    沒人連的時候完全沒人知道。"""
    from app.services.capacity_alert import check_jump_host_keys

    class _JH:
        def __init__(self, fp):
            self.id = "88888888-8888-8888-8888-888888888888"
            self.name = "jump-a"
            self.enabled = True
            self.host, self.port = "198.51.100.9", 22
            self.host_key_fingerprint = fp

    pinned = "SHA256:AAAA"
    async def probe_same(host, port=22, timeout=None):
        return {"fingerprint": pinned}
    async def probe_changed(host, port=22, timeout=None):
        return {"fingerprint": "SHA256:BBBB"}

    assert await check_jump_host_keys(db_session, [_JH(pinned)], probe=probe_same) == 0
    assert await check_jump_host_keys(db_session, [_JH(pinned)], probe=probe_changed) == 1


async def test_unreachable_jump_host_is_not_a_key_change(db_session, admin_user):
    """連不到不等於金鑰換了 —— 把它報成中間人攻擊會讓人不再相信這則告警。"""
    from app.services.capacity_alert import check_jump_host_keys

    class _JH:
        id = "99999999-9999-9999-9999-999999999999"
        name = "jump-down"
        enabled = True
        host, port = "198.51.100.10", 22
        host_key_fingerprint = "SHA256:AAAA"

    async def probe_fail(host, port=22, timeout=None):
        raise OSError("connection refused")

    assert await check_jump_host_keys(db_session, [_JH()], probe=probe_fail) == 0


async def test_unpinned_jump_host_is_skipped(db_session, admin_user):
    """還沒釘選指紋的跳板沒有比較基準，不能拿來報警。"""
    from app.services.capacity_alert import check_jump_host_keys

    class _JH:
        id = "aaaaaaaa-9999-9999-9999-999999999999"
        name = "jump-new"
        enabled = True
        host, port = "198.51.100.11", 22
        host_key_fingerprint = None

    async def probe(host, port=22, timeout=None):
        return {"fingerprint": "SHA256:CCCC"}

    assert await check_jump_host_keys(db_session, [_JH()], probe=probe) == 0


# ── 憑證來源抓取失敗 ───────────────────────────────────────────────────────
async def test_cert_fetch_failure_alerts(db_session, admin_user):
    """抓不到新版憑證 = 到期當天才會發現。"""
    from app.services.capacity_alert import check_cert_sources

    class _Cert:
        def __init__(self, err):
            self.id = "bbbbbbbb-9999-9999-9999-999999999999"
            self.name = "wildcard.example.com"
            self.last_fetch_error = err

    assert await check_cert_sources(db_session, [_Cert("SFTP auth failed")]) == 1
    assert await check_cert_sources(db_session, [_Cert("SFTP auth failed")]) == 0
    assert await check_cert_sources(db_session, [_Cert(None)]) == 1


# ── 原本關不掉的兩個通知 ───────────────────────────────────────────────────
def test_previously_ungated_notifications_are_in_the_matrix():
    """稽核鏈驗證失敗與失聯 IP 原本直接推通知，設定頁上沒有對應的列 ——
    使用者收得到卻關不掉。"""
    from app.services.system_config import NOTIFY_EVENTS

    keys = {k for k, _, _ in NOTIFY_EVENTS}
    assert "audit.chain_broken" in keys
    assert "ip.stale" in keys
    assert "dhcp.pool_exhausted" in keys
    assert "jump_host.key_changed" in keys
    assert "cert.fetch_failed" in keys
