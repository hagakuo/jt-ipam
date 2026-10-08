"""異常偵測的通知可以逐類別決定。

原本整個異常偵測只有一列 `anomaly.detected`：要嘛十種發現全部通知、要嘛全部不通知。
實務上這十種的份量差很多 —— 「非法 DHCP 伺服器」是要立刻處理的事，
「失聯 IP」比較像每週整理一次的清單。混在一起的結果是使用者為了不被吵而整類關掉，
於是真正要緊的那幾種也一起消失。

守的重點是**升級不會改變既有行為**：已經把異常通知打開 Email 的站台，
升級之後每一類都要維持開著，而不是被重設成預設值。
"""
from __future__ import annotations

from app.services.system_config import ANOMALY_EVENTS


async def test_every_category_has_its_own_event(db_session):
    from app.services.system_config import get_notification_matrix

    m = await get_notification_matrix(db_session)
    for ev in ANOMALY_EVENTS:
        assert ev in m, f"{ev} 不在通知矩陣裡＝那一類永遠用不到自己的設定"


async def test_the_old_single_row_is_gone_from_the_ui_list(db_session):
    """留著一列講不出作用的總開關，只會讓人猜它與逐類別設定誰說了算。"""
    from app.services.system_config import NOTIFY_EVENTS

    keys = [k for k, _, _ in NOTIFY_EVENTS]
    assert "anomaly.detected" not in keys


async def test_existing_setting_carries_over(db_session):
    """升級前把異常通知的 Email 打開過 → 升級後十類都還是開著。"""
    from app.models.system_setting import SystemSetting
    from app.services.system_config import NOTIFY_MATRIX_KEY, get_notification_matrix

    # 模擬舊資料：只有 anomaly.detected，而且被改成 email=True
    db_session.add(SystemSetting(
        key=NOTIFY_MATRIX_KEY,
        value={"anomaly.detected": {"in_app": False, "email": True}},
    ))
    await db_session.flush()

    m = await get_notification_matrix(db_session)
    for ev in ANOMALY_EVENTS:
        assert m[ev] == {"in_app": False, "email": True}, f"{ev} 沒有沿用舊設定"


async def test_per_category_setting_wins_over_the_legacy_value(db_session):
    from app.models.system_setting import SystemSetting
    from app.services.system_config import NOTIFY_MATRIX_KEY, get_notification_matrix

    db_session.add(SystemSetting(
        key=NOTIFY_MATRIX_KEY,
        value={
            "anomaly.detected": {"in_app": True, "email": True},
            "anomaly.ghost_ips": {"in_app": False, "email": False},
        },
    ))
    await db_session.flush()
    m = await get_notification_matrix(db_session)
    assert m["anomaly.ghost_ips"] == {"in_app": False, "email": False}
    assert m["anomaly.ip_conflicts"] == {"in_app": True, "email": True}


async def test_notifications_respect_the_per_category_switch(db_session, admin_user):
    """關掉某一類就真的不發，其他類不受影響 —— 否則這個設定只是裝飾。"""
    from app.models.system_setting import SystemSetting
    from app.services.anomaly import notify_new_findings
    from app.services.system_config import NOTIFY_MATRIX_KEY

    db_session.add(SystemSetting(
        key=NOTIFY_MATRIX_KEY,
        value={"anomaly.ip_conflicts": {"in_app": False, "email": False},
               "anomaly.rogue_dhcp": {"in_app": True, "email": False}},
    ))
    await db_session.flush()

    sent = await notify_new_findings(db_session, {
        "ip_conflicts": [{"ip": "198.51.100.20"}],
        "rogue_dhcp": [{"server_ip": "198.51.100.30"}],
    })
    assert sent == 1, "只有沒被關掉的那一類該發"


async def test_manual_scan_does_not_call_old_findings_new(db_session, admin_user):
    """手動掃描報的是「當下全部」，排程報的才是「新增」。

    兩者原本共用同一個翻譯鍵（`{類別}：新增 {count} 筆`），於是人按下「執行掃描」
    會收到「新增 3 筆」—— 那 3 筆可能躺在那裡好幾個月了。收件者據此判斷要不要
    立刻處理，說錯了就是把舊帳當成新事故。
    """
    from sqlalchemy import select

    from app.models.notification import Notification
    from app.services.anomaly import _notify_categories

    findings = {"ip_conflicts": [{"ip": "198.51.100.20"}, {"ip": "198.51.100.21"}]}
    assert await _notify_categories(db_session, findings, only_new=False) == 1
    await db_session.flush()

    n = (await db_session.execute(select(Notification))).scalars().one()
    assert n.title_key == "notif.anom_now", "手動掃描不該用「新增」那句"
    assert n.params["count"] == 2


async def test_scheduled_run_reports_new_and_total(db_session, admin_user):
    """排程那句是「新增 N 筆（共 M 筆）」—— 兩個數字都要帶到。

    `total` 原本沒放進 params，翻譯句子裡的 `{total}` 永遠是空的。
    """
    from sqlalchemy import select

    from app.models.notification import Notification
    from app.services.anomaly import _notify_categories

    first = {"ip_conflicts": [{"ip": "198.51.100.20"}]}
    assert await _notify_categories(db_session, first, only_new=True) == 1

    both = {"ip_conflicts": [{"ip": "198.51.100.20"}, {"ip": "198.51.100.21"}]}
    assert await _notify_categories(db_session, both, only_new=True) == 1
    await db_session.flush()

    rows = (await db_session.execute(
        select(Notification).order_by(Notification.created_at))).scalars().all()
    latest = rows[-1]
    assert latest.title_key == "notif.anom_new"
    assert latest.params["count"] == 1, "第二次只有一筆是新的"
    assert latest.params["total"] == 2, "總數要一起帶，否則「共 M 筆」是空的"


async def test_every_category_points_at_a_label_key(db_session):
    """十一個類別都要有類別名稱的鍵。

    `mac_flapping` 曾經指著 `notif.anom_mac_flapping` —— 那個鍵三個語言檔裡都沒有，
    於是通知標題在畫面上顯示成鍵名本身。這種漏接不會報錯，只會醜在使用者眼前。
    """
    import json
    import pathlib

    from app.services.anomaly import _NOTIFY_CATEGORIES

    root = pathlib.Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n"
    for loc in ("zh-TW", "en-US", "ja-JP"):
        msgs = json.loads((root / f"{loc}.json").read_text())
        for _key, _label, lkey, _tab in _NOTIFY_CATEGORIES:
            node: object = msgs
            for part in lkey.split("."):
                assert isinstance(node, dict) and part in node, f"{loc} 缺 {lkey}"
                node = node[part]
            assert isinstance(node, str) and node


async def test_legacy_notification_keys_stay_translatable():
    """舊的 `notif.anom_*` 不可以從語言檔刪掉。

    已經發出去的通知存在資料庫，`title_key` 欄位還指著那些鍵。刪掉之後，歷史通知
    在畫面上會顯示成鍵的原文（`notif.anom_ghost`）—— 不報錯，只是醜在那裡。
    這幾個鍵沒有新的使用者，靠註解提醒不住，所以用測試釘著。
    """
    import json
    import pathlib

    legacy = ["notif.anom_ip_conflict", "notif.anom_mac_drift", "notif.anom_ghost",
              "notif.anom_unauthorized", "notif.anom_rogue_dhcp", "notif.anom_exposure",
              "notif.anom_dangling_dns", "notif.anom_dup_ip", "notif.anom_changes",
              "notif.anom_fw_rot", "notif.anom_mac_flapping"]
    root = pathlib.Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n"
    for loc in ("zh-TW", "en-US", "ja-JP"):
        msgs = json.loads((root / f"{loc}.json").read_text())
        for key in legacy:
            node: object = msgs
            for part in key.split("."):
                assert isinstance(node, dict) and part in node, f"{loc} 少了舊鍵 {key}"
                node = node[part]
            assert isinstance(node, str) and node
