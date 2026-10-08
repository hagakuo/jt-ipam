"""狀態類告警：只在「開始」與「恢復」時發。

新接進通知的三類（整合同步失敗、代理失聯、系統健康）與 IP 申請那種「事件」不同：
它們描述的是**持續的狀態**。整合每 5 分鐘同步一次，token 過期的那台會**每輪都失敗** ——
每輪發一次通知，一天就是 288 則，使用者第二天就會把整類關掉，然後真正的新問題也一起消失。

所以這裡只在狀態轉換時發：`ok → 壞掉` 發一次，`壞掉 → ok` 再發一次（恢復也要說，
否則沒有人知道問題已經沒了，只能自己去點）。中間持續壞著不發。

另外要有「連續失敗幾次才算壞掉」的緩衝：整合偶爾逾時一次是常態，
第一次失敗就吵人的話，這個功能會在一週內被關掉。
"""
from __future__ import annotations


async def test_first_failure_is_buffered(db_session):
    """偶發的一次失敗不吵人 —— 但要記著它。"""
    from app.services.state_alert import observe

    r = await observe(db_session, key="integration:librenms:x", failing=True, threshold=2)
    assert r is None, "第一次失敗就通知的話，偶爾逾時一次也會吵人"


async def test_alert_fires_once_it_is_persistent(db_session):
    from app.services.state_alert import observe

    await observe(db_session, key="integration:librenms:y", failing=True, threshold=2)
    r = await observe(db_session, key="integration:librenms:y", failing=True, threshold=2)
    assert r == "down", "連續失敗達到門檻要發一次"


async def test_no_repeat_while_it_stays_broken(db_session):
    """壞著不動的東西不該每輪再講一次 —— 那正是通知被關掉的原因。"""
    from app.services.state_alert import observe

    for _ in range(2):
        await observe(db_session, key="integration:librenms:z", failing=True, threshold=2)
    for _ in range(10):
        assert await observe(db_session, key="integration:librenms:z",
                             failing=True, threshold=2) is None


async def test_recovery_is_announced_once(db_session):
    """恢復也要說 —— 否則沒人知道問題已經沒了。"""
    from app.services.state_alert import observe

    for _ in range(2):
        await observe(db_session, key="agent:scan:a", failing=True, threshold=2)
    assert await observe(db_session, key="agent:scan:a", failing=False, threshold=2) == "up"
    # 恢復之後持續正常，不該再發
    for _ in range(5):
        assert await observe(db_session, key="agent:scan:a", failing=False, threshold=2) is None


async def test_recovering_before_the_threshold_says_nothing(db_session):
    """還沒吵過的東西恢復了，也不用特地講一次「它好了」。"""
    from app.services.state_alert import observe

    await observe(db_session, key="agent:scan:b", failing=True, threshold=2)
    assert await observe(db_session, key="agent:scan:b", failing=False, threshold=2) is None


async def test_keys_are_independent(db_session):
    from app.services.state_alert import observe

    for _ in range(2):
        await observe(db_session, key="integration:a", failing=True, threshold=2)
    assert await observe(db_session, key="integration:b", failing=True, threshold=2) is None


async def test_state_is_pruned_when_the_thing_disappears(db_session):
    """整合被刪掉之後，它的狀態不該永遠留在設定裡長大。"""
    from app.services.state_alert import observe, prune_missing

    for _ in range(2):
        await observe(db_session, key="integration:gone", failing=True, threshold=2)
        await observe(db_session, key="integration:stays", failing=True, threshold=2)
    removed = await prune_missing(db_session, prefix="integration:", alive={"integration:stays"})
    assert removed == 1
    # 被清掉的那個再出現時要當成新的問題重新計數
    assert await observe(db_session, key="integration:gone", failing=True, threshold=2) is None
