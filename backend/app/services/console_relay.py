"""主控台經由掃描代理中繼（issue #24 階段二）：跨 worker 的協調（Redis）。

整條路徑：

    瀏覽器 ⇄ worker B（主控台，不改）── open_route(ViaAgent) ──┐
                                                              │ ① 發單次票證、派 relay_open 工作給代理
                                                              │ ② BLPOP relay:ready:{sid}（最多 15 秒）
    guacd / asyncssh ──TCP──▶ 127.0.0.1:P（開在 worker A）◀────┘ ③ 拿到 P，之後與直連完全相同
                               ▲
    worker A：/scan-agents/relay/{sid}/ws ◀──(WSS，代理撥出)── 掃描代理 ──TCP──▶ 目標

**為什麼監聽埠開在 worker A**：正式機有好幾個 uvicorn worker，代理的 WebSocket 與使用者的主控台
可能落在不同 worker。埠開在收到代理連線的那一個，就只有一段本機轉發，不必在 worker 之間再搬一次。
埠號經 Redis 交給 worker B；兩個 worker 在同一台機器上，127.0.0.1 彼此都連得到。

這個模組只管 Redis 上的三樣東西：單次票證、就緒通知、逐台代理的同時連線計數。
"""
from __future__ import annotations

import hmac
import json
import secrets
import time
import uuid
from typing import Any

from app.core.rate_limit import _redis_client
from app.core.tickets import take_once

#: 票證壽命：代理要在這段時間內領工作並撥回來（領工作的長輪詢最多 1 秒延遲，加上握手）
TICKET_TTL = 30
#: worker B 等「就緒」最多幾秒
READY_TIMEOUT = 15
#: 同時連線計數裡，多久沒清掉就當成殘留（worker 當掉時 finally 沒跑到）
SLOT_STALE_SECONDS = 12 * 3600


def _ticket_key(sid: str) -> str:
    return f"relay:ticket:{sid}"


def _ready_key(sid: str) -> str:
    return f"relay:ready:{sid}"


def _slots_key(agent_id: uuid.UUID | str) -> str:
    return f"relay:active:{agent_id}"


def new_session_id() -> str:
    return uuid.uuid4().hex


async def issue_ticket(sid: str, *, agent_id: uuid.UUID, target: str, port: int,
                       user_id: uuid.UUID | None, kind: str) -> str:
    """發一張單次票證（30 秒）。代理撥回來時要同時帶上代理金鑰與這張票。"""
    ticket = secrets.token_urlsafe(32)
    payload = {"ticket": ticket, "agent_id": str(agent_id), "target": target, "port": int(port),
               "user_id": str(user_id) if user_id else None, "kind": kind, "issued_at": time.time()}
    await _redis_client().set(_ticket_key(sid), json.dumps(payload), ex=TICKET_TTL)
    return ticket


async def redeem_ticket(sid: str, ticket: str, *, agent_id: uuid.UUID) -> dict[str, Any] | None:
    """取出並刪除票證；票不對、或不是發給這台代理的 → None。同一張票只有第一次拿得到。"""
    raw = await take_once(_redis_client(), _ticket_key(sid))
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict) or not hmac.compare_digest(str(data.get("ticket", "")), ticket or ""):
        return None
    if data.get("agent_id") != str(agent_id):
        return None
    return data


async def discard_ticket(sid: str) -> None:
    await _redis_client().delete(_ticket_key(sid))


async def push_ready(sid: str, payload: dict[str, Any]) -> None:
    """worker A（或回報錯誤的代理工作）通知 worker B：`{"port": P}` 或 `{"error": 代碼, "reason": …}`。"""
    r = _redis_client()
    await r.rpush(_ready_key(sid), json.dumps(payload))
    await r.expire(_ready_key(sid), READY_TIMEOUT + 30)


#: 單次 BLPOP 最多等幾秒。redis-py 8 的 socket 逾時預設 5 秒：單次等 15 秒會先丟 TimeoutError
#: （實機驗證時撞到；假 Redis 的單元測試看不出來），所以每次只等 1 秒、迴圈到 READY_TIMEOUT
BLPOP_STEP = 1


async def wait_ready(sid: str, timeout: float = READY_TIMEOUT) -> dict[str, Any] | None:
    """worker B 等就緒通知；逾時回 None。"""
    deadline = time.monotonic() + timeout
    got = None
    while got is None:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        got = await _redis_client().blpop([_ready_key(sid)], timeout=max(1, min(BLPOP_STEP, int(left) or 1)))
    try:
        data = json.loads(got[1])
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


async def acquire_slot(agent_id: uuid.UUID, sid: str, limit: int) -> bool:
    """逐台代理的同時中繼數；超過上限回 False。殘留（worker 當掉沒清）的會自動回收。"""
    r = _redis_client()
    key = _slots_key(agent_id)
    now = time.time()
    await r.zremrangebyscore(key, 0, now - SLOT_STALE_SECONDS)
    if int(await r.zcard(key)) >= max(1, int(limit)):
        return False
    await r.zadd(key, {sid: now})
    await r.expire(key, SLOT_STALE_SECONDS)
    # 併發時可能兩個同時通過檢查：加完再數一次，超過就退回自己這一筆
    if int(await r.zcard(key)) > max(1, int(limit)):
        await r.zrem(key, sid)
        return False
    return True


async def release_slot(agent_id: uuid.UUID, sid: str) -> None:
    await _redis_client().zrem(_slots_key(agent_id), sid)


async def active_count(agent_id: uuid.UUID) -> int:
    r = _redis_client()
    key = _slots_key(agent_id)
    await r.zremrangebyscore(key, 0, time.time() - SLOT_STALE_SECONDS)
    return int(await r.zcard(key))
