"""三類新的告警：整合同步失敗、代理失聯、系統健康。

共同點是「東西壞了卻沒人知道」—— 資料早就在資料庫裡（`last_error`、`last_seen_at`、
系統診斷的檢查結果），只是要有人主動去點才看得到。實務上沒有人每天點。

三類都走同一套狀態轉換（`services/state_alert`）：只在開始與恢復時發。
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta


async def test_integration_failure_alerts_and_recovers(db_session, admin_user):
    from app.models.notification import Notification
    from app.services.health_alert import check_integration_health
    from sqlalchemy import func, select

    async def count() -> int:
        return (await db_session.execute(
            select(func.count()).select_from(Notification))).scalar_one()

    class _Inst:
        def __init__(self, err):
            self.id = "11111111-1111-1111-1111-111111111111"
            self.name = "monitor-a"
            self.last_error = err

    broken = [("librenms", _Inst("401 Unauthorized"))]
    # 第一次失敗只記著（偶發逾時不吵人）
    assert await check_integration_health(db_session, broken, threshold=2) == 0
    before = await count()
    # 連續失敗 → 發一次
    assert await check_integration_health(db_session, broken, threshold=2) == 1
    assert await count() > before
    # 持續壞著不再發
    mid = await count()
    assert await check_integration_health(db_session, broken, threshold=2) == 0
    assert await count() == mid
    # 恢復 → 再發一次
    ok = [("librenms", _Inst(None))]
    assert await check_integration_health(db_session, ok, threshold=2) == 1


async def test_agent_offline_uses_its_own_last_seen(db_session, admin_user):
    """代理失聯看的是它自己回報的時間，不是我們檢查的時間。"""
    from app.services.health_alert import check_agent_health

    now = datetime.now(UTC)

    class _Agent:
        def __init__(self, seen):
            self.id = "22222222-2222-2222-2222-222222222222"
            self.name = "agent-a"
            self.enabled = True
            self.last_seen_at = seen

    fresh = [("scan", _Agent(now - timedelta(minutes=3)))]
    stale = [("scan", _Agent(now - timedelta(hours=6)))]
    assert await check_agent_health(db_session, fresh, max_age_minutes=30, threshold=1) == 0
    assert await check_agent_health(db_session, stale, max_age_minutes=30, threshold=1) == 1


async def test_agent_that_never_reported_is_not_an_alert(db_session, admin_user):
    """剛建好、還沒裝上去的代理不是「失聯」—— 那會讓每個新代理都先發一則假警報。"""
    from app.services.health_alert import check_agent_health

    class _Agent:
        id = "33333333-3333-3333-3333-333333333333"
        name = "agent-new"
        enabled = True
        last_seen_at = None

    assert await check_agent_health(db_session, [("scan", _Agent())],
                                    max_age_minutes=30, threshold=1) == 0


async def test_disabled_agent_is_not_an_alert(db_session, admin_user):
    from app.services.health_alert import check_agent_health

    class _Agent:
        id = "44444444-4444-4444-4444-444444444444"
        name = "agent-off"
        enabled = False
        last_seen_at = datetime.now(UTC) - timedelta(days=5)

    assert await check_agent_health(db_session, [("scan", _Agent())],
                                    max_age_minutes=30, threshold=1) == 0


async def test_system_health_alerts_only_on_bad(db_session, admin_user):
    """`warn` 不吵人：診斷頁上一半的項目長期是 warn（沒裝 traceroute 之類），
    那些不是「出事了」。只有 bad 值得半夜叫人。"""
    from app.services.health_alert import check_system_health

    class _Check:
        def __init__(self, key, status, title="x", detail="", fix=""):
            self.key, self.status, self.title = key, status, title
            self.detail, self.fix = detail, fix

    warns = [_Check("icmp", "warn")]
    assert await check_system_health(db_session, warns, threshold=1) == 0

    bads = [_Check("disk", "bad", title="磁碟空間不足", detail="剩 2%", fix="清理或擴充磁碟")]
    assert await check_system_health(db_session, bads, threshold=1) == 1
    # 修好之後要說一聲（同一項還在，只是狀態變成 ok）
    fixed = [_Check("disk", "ok", title="磁碟空間")]
    assert await check_system_health(db_session, fixed, threshold=1) == 1


async def test_a_check_that_disappears_is_not_announced_as_recovered(db_session, admin_user):
    """檢查項目整個不見時，我們**不知道**它好了沒 —— 不能因此宣稱「已恢復」。

    這種情況會發生在檢查本身出錯、或某個設定讓那一項不再適用。沉默是誠實的，
    謊報恢復不是。"""
    from app.services.health_alert import check_system_health

    class _Check:
        def __init__(self, key, status, title="x"):
            self.key, self.status, self.title = key, status, title
            self.detail = self.fix = ""

    assert await check_system_health(
        db_session, [_Check("backup", "bad", title="備份")], threshold=1) == 1
    # 下一輪那一項不見了 → 不發任何通知
    assert await check_system_health(db_session, [_Check("icmp", "ok")], threshold=1) == 0


async def test_notifications_respect_the_matrix(db_session, admin_user):
    """三類都要能在通知發送設定頁關掉。"""
    from app.models.system_setting import SystemSetting
    from app.services.health_alert import check_integration_health
    from app.services.system_config import NOTIFY_MATRIX_KEY

    db_session.add(SystemSetting(
        key=NOTIFY_MATRIX_KEY,
        value={"integration.sync_failed": {"in_app": False, "email": False}}))
    await db_session.flush()

    class _Inst:
        id = "55555555-5555-5555-5555-555555555555"
        name = "mon9"
        last_error = "boom"

    broken = [("librenms", _Inst())]
    await check_integration_health(db_session, broken, threshold=1)
    from app.models.notification import Notification
    from sqlalchemy import func, select
    n = (await db_session.execute(
        select(func.count()).select_from(Notification))).scalar_one()
    assert n == 0, "關掉了就不該發"


def test_the_alert_list_covers_every_integration_that_syncs():
    """健康告警的整合清單要與實際會同步的整合一致。

    少列一個，那個整合壞掉時就永遠不會有人知道 —— 而且畫面上完全看不出少了誰。
    這是「新增整合要跟進所有功能」那條規矩的一部分（tests/test_integration_coverage.py
    守的是同一件事，這裡守的是同步腳本裡的這一份清單）。
    """
    from pathlib import Path

    src = (Path(__file__).resolve().parents[2] / "scripts" / "jt-ipam-sync.py").read_text()
    block = src.split("for kind, model in (")[1].split("):")[0]
    for model in ("LibreNMSInstance", "WazuhInstance", "ZabbixInstance", "AdGuardInstance",
                  "ProxmoxInstance", "ESXiInstance", "OPNsenseFirewall", "PfSenseFirewall",
                  "FortiGateFirewall", "PaloAltoFirewall", "MikroTikRouter",
                  "WindowsDhcpServer", "DNSServer"):
        assert model in block, f"{model} 不在健康告警的清單裡 —— 它壞掉時不會有人知道"


async def test_cert_agents_get_a_much_longer_grace_than_scan_agents(db_session, admin_user):
    """兩種代理的回報頻率差兩個數量級，不能共用一個門檻。

    掃描代理是常駐長輪詢（預設 300 秒一輪）；憑證代理是 systemd timer，
    安裝腳本的預設是 **daily**。用 30 分鐘判憑證代理，等於每天把每一台都報一次 ——
    實機上就是這樣發生的：17 台憑證代理在同一輪全部被誤報。
    """
    from datetime import UTC, datetime, timedelta

    from app.services.health_alert import check_agent_health

    now = datetime.now(UTC)

    class _Agent:
        def __init__(self, seen):
            self.id = f"cert-{seen}"
            self.name = "host-x"
            self.enabled = True
            self.last_seen_at = seen

    # 19 小時前回報的憑證代理：每日排程下完全正常
    assert await check_agent_health(
        db_session, [("cert", _Agent(now - timedelta(hours=19)))], threshold=1) == 0
    # 同樣的時間差，掃描代理就是失聯
    assert await check_agent_health(
        db_session, [("scan", _Agent(now - timedelta(hours=19)))], threshold=1) == 1
    # 憑證代理連續兩天沒來才算
    assert await check_agent_health(
        db_session, [("cert", _Agent(now - timedelta(days=3)))], threshold=1) == 1
