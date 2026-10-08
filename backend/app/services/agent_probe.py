"""工具探測工作的建立、領取與回報（後端側）。

這裡是整個功能的安全核心：它決定「代理會被要求做什麼」。因此所有驗證都集中在
`validate_params()`，代理端再獨立驗一次（不可只信後端 —— 後端被入侵時代理是最後一道閘）。
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_probe_job import (
    PROBE_KINDS,
    STATUS_DONE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    AgentProbeJob,
)

# 沒被領走的工作多久作廢。代理離線時工作會堆積，上線後一次補跑一堆過期探測沒有意義，
# 而且會讓使用者以為是「剛剛那次」的結果。
JOB_TTL = timedelta(minutes=2)
# 領走但沒回報（代理當掉／被 kill）多久視為失敗，才不會永遠卡在 running
CLAIM_TTL = timedelta(minutes=5)
# identify（服務版本＋OS 指紋）本身可能跑到四、五分鐘，要給它更長的時間才算卡住
CLAIM_TTL_BY_KIND = {"identify": timedelta(minutes=9)}
# 進度只是幾行狀態，不是結果：超過就拒收，免得被當成另一條傳大量資料的管道
MAX_PROGRESS_BYTES = 8192
MAX_TARGETS = 64
MAX_PORTS = 64
MAX_PENDING_PER_AGENT = 20

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                          r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")


class ProbeJobError(ValueError):
    """參數不合法（回 400，不建立工作）。"""


def _valid_target(t: str) -> str:
    """目標必須是 IP 或合法主機名稱。

    這是防注入的第一道：即使代理端一律用陣列傳參數、不經過 shell，仍然不接受
    奇怪的字串進到子行程的 argv —— 少一層可被玩的地方。
    """
    s = (t or "").strip()
    if not s or len(s) > 253:
        raise ProbeJobError(f"invalid target: {t!r}")
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(s):
        raise ProbeJobError(f"invalid target: {t!r}")
    return s


def _valid_ports(raw: Any) -> list[int]:
    ports: list[int] = []
    items = raw if isinstance(raw, list) else str(raw or "").replace(",", " ").split()
    for p in items:
        try:
            n = int(p)
        except (TypeError, ValueError) as exc:
            raise ProbeJobError(f"invalid port: {p!r}") from exc
        if not 1 <= n <= 65535:
            raise ProbeJobError(f"port out of range: {n}")
        ports.append(n)
    if not ports:
        raise ProbeJobError("no ports given")
    if len(ports) > MAX_PORTS:
        raise ProbeJobError(f"too many ports (max {MAX_PORTS})")
    return ports


def validate_params(kind: str, params: dict[str, Any]) -> dict[str, Any]:
    """把使用者輸入正規化成代理能安全執行的形狀；不合法就拒絕建立工作。"""
    if kind not in PROBE_KINDS:
        raise ProbeJobError(f"unsupported probe: {kind!r}")

    raw_targets = params.get("targets") or params.get("target") or ""
    items = raw_targets if isinstance(raw_targets, list) else \
        [t for t in re.split(r"[\s,]+", str(raw_targets)) if t]
    if not items:
        raise ProbeJobError("no target given")
    if len(items) > MAX_TARGETS:
        raise ProbeJobError(f"too many targets (max {MAX_TARGETS})")
    targets = [_valid_target(t) for t in items]

    out: dict[str, Any] = {"targets": targets}
    if kind == "ping":
        out["count"] = max(1, min(int(params.get("count") or 3), 10))
        out["timeout"] = max(0.5, min(float(params.get("timeout") or 2.0), 10.0))
    elif kind == "tcp":
        out["ports"] = _valid_ports(params.get("ports"))
        out["timeout"] = max(0.2, min(float(params.get("timeout") or 1.5), 10.0))
    elif kind == "traceroute":
        if len(targets) != 1:
            raise ProbeJobError("traceroute takes exactly one target")
        out["max_hops"] = max(1, min(int(params.get("max_hops") or 20), 30))
    elif kind == "identify":
        # 只能對 jt-ipam 裡的單一 IP：不接受主機名稱（名稱可能解析到別處）、不接受多個目標
        if len(targets) != 1:
            raise ProbeJobError("identify takes exactly one target")
        try:
            ipaddress.ip_address(targets[0])
        except ValueError as exc:
            raise ProbeJobError("identify takes an IP address, not a host name") from exc
    return out


async def create_job(
    session: AsyncSession, *, agent_id: uuid.UUID, kind: str,
    params: dict[str, Any], requested_by: uuid.UUID | None,
) -> AgentProbeJob:
    """建立一筆待辦。超過待辦上限就拒絕 —— 代理離線時使用者連按會堆積。"""
    clean = validate_params(kind, params)
    pending = list((await session.execute(
        select(AgentProbeJob.id).where(
            AgentProbeJob.agent_id == agent_id,
            AgentProbeJob.status == STATUS_PENDING,
            AgentProbeJob.expires_at > datetime.now(UTC),
        ).limit(MAX_PENDING_PER_AGENT + 1)
    )).scalars().all())
    if len(pending) >= MAX_PENDING_PER_AGENT:
        raise ProbeJobError("too many pending jobs for this agent")

    job = AgentProbeJob(
        agent_id=agent_id, kind=kind, params=clean, status=STATUS_PENDING,
        requested_by=requested_by, expires_at=datetime.now(UTC) + JOB_TTL,
    )
    session.add(job)
    await session.flush()
    return job


async def expire_stale(session: AsyncSession) -> int:
    """把過期的待辦與卡住的 running 收掉。每次領取／查詢時順手跑，不另開排程。"""
    now = datetime.now(UTC)
    # 探測（identify）在「作業」頁有對應的一筆，作廢時要跟著更新 —— 先把會被收掉的挑出來
    ident_ttl = CLAIM_TTL_BY_KIND["identify"]
    doomed = list((await session.execute(select(AgentProbeJob).where(
        AgentProbeJob.kind == "identify",
        ((AgentProbeJob.status == STATUS_PENDING) & (AgentProbeJob.expires_at <= now))
        | ((AgentProbeJob.status == STATUS_RUNNING) & (AgentProbeJob.claimed_at <= now - ident_ttl)),
    ))).scalars().all())
    r1 = await session.execute(
        update(AgentProbeJob)
        .where(AgentProbeJob.status == STATUS_PENDING, AgentProbeJob.expires_at <= now)
        .values(status=STATUS_EXPIRED, finished_at=now,
                error="沒有代理在時限內領取（代理可能離線）"))
    slow = tuple(CLAIM_TTL_BY_KIND)
    r2 = await session.execute(
        update(AgentProbeJob)
        .where(AgentProbeJob.status == STATUS_RUNNING,
               AgentProbeJob.kind.notin_(slow),  # bounded: slow probe kinds
               AgentProbeJob.claimed_at <= now - CLAIM_TTL)
        .values(status=STATUS_FAILED, finished_at=now, error="代理領取後未回報結果"))
    n = int(r1.rowcount or 0) + int(r2.rowcount or 0)
    for kind, ttl in CLAIM_TTL_BY_KIND.items():
        r = await session.execute(
            update(AgentProbeJob)
            .where(AgentProbeJob.status == STATUS_RUNNING, AgentProbeJob.kind == kind,
                   AgentProbeJob.claimed_at <= now - ttl)
            .values(status=STATUS_FAILED, finished_at=now, error="代理領取後未回報結果"))
        n += int(r.rowcount or 0)
    if doomed:
        from app.services.identify_tasks import on_expired
        for j in doomed:
            await session.refresh(j)
        await on_expired(session, doomed)
    return n


async def claim_jobs(
    session: AsyncSession, *, agent_id: uuid.UUID, limit: int = 5,
) -> list[AgentProbeJob]:
    """代理領取待辦。`FOR UPDATE SKIP LOCKED` 讓同一代理的多個行程不會重複領。"""
    await expire_stale(session)
    now = datetime.now(UTC)
    rows = list((await session.execute(
        select(AgentProbeJob)
        .where(AgentProbeJob.agent_id == agent_id,
               AgentProbeJob.status == STATUS_PENDING,
               AgentProbeJob.expires_at > now)
        .order_by(AgentProbeJob.created_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )).scalars().all())
    for j in rows:
        j.status = STATUS_RUNNING
        j.claimed_at = now
    if any(j.kind == "identify" for j in rows):
        from app.services.identify_tasks import on_claimed
        await on_claimed(session, rows)
    return rows


#: 使用者取消的工作：記成失敗並寫明原因（代理晚到的回報因為狀態已不是 running 會被忽略）
CANCELLED_ERROR = "使用者取消"


async def cancel_job(session: AsyncSession, job: AgentProbeJob) -> bool:
    """取消還在等待或執行中的工作（2026-10-07：部署重啟時代理的回報掉了，探測要等 9 分鐘才會逾時）。
    代理那邊的 nmap 會照跑完，但結果回來時這筆已經不是 running，不會被寫回。已經結束的回 False。"""
    if job.status not in (STATUS_PENDING, STATUS_RUNNING):
        return False
    job.status = STATUS_FAILED
    job.error = CANCELLED_ERROR
    job.finished_at = datetime.now(UTC)
    _scrub_ticket(job)
    if job.kind == "identify":
        from app.services.identify_tasks import on_cancelled
        await on_cancelled(session, job)
    return True


async def finish_job(
    session: AsyncSession, *, agent_id: uuid.UUID, job_id: uuid.UUID,
    result: Any = None, error: str | None = None,
) -> bool:
    """代理回報結果。**必須驗 agent_id**：代理只能結束自己領到的工作。"""
    job = (await session.execute(
        select(AgentProbeJob).where(
            AgentProbeJob.id == job_id, AgentProbeJob.agent_id == agent_id)
    )).scalars().first()
    if job is None or job.status not in (STATUS_RUNNING, STATUS_PENDING):
        return False
    job.status = STATUS_FAILED if error else STATUS_DONE
    job.result = result if isinstance(result, dict) else {"items": result}
    job.error = (error or "")[:2000] or None
    job.finished_at = datetime.now(UTC)
    if job.kind == "identify":
        from app.services.identify_tasks import on_finished
        await on_finished(session, job)
    if job.kind == RELAY_KIND:
        await _relay_finished(job, error)
    return True


# ─────────────────── 主控台中繼（issue #24 階段二）───────────────────
#: 中繼工作的種類。**刻意不在 PROBE_KINDS 裡**：工具頁的探測 API 走 validate_params，
#: 因此使用者不可能自己派出中繼工作；只有 console_route 經由 create_relay_job 會建。
RELAY_KIND = "relay_open"


async def create_relay_job(
    session: AsyncSession, *, agent_id: uuid.UUID, sid: str, ticket: str,
    target: str, port: int, requested_by: uuid.UUID | None, scope: dict[str, Any] | None = None,
) -> AgentProbeJob:
    """請代理開一條中繼。目標只會是 IP 記錄的位址（呼叫端推導，不接受使用者輸入）。
    `scope`：網頁上當下允許的範圍（relay_scope），代理收到就更新，不必等下一輪 poll。"""
    ipaddress.ip_address(target)                    # 只接受 IP 字面值
    if not 1 <= int(port) <= 65535:
        raise ProbeJobError("invalid port")
    params: dict[str, Any] = {"sid": sid, "ticket": ticket, "target": target, "port": int(port)}
    if scope is not None:
        params["scope"] = scope
    job = AgentProbeJob(
        agent_id=agent_id, kind=RELAY_KIND, status=STATUS_PENDING, requested_by=requested_by,
        params=params,
        # 使用者在等，代理領不到就不必留：比一般探測的 2 分鐘短很多
        expires_at=datetime.now(UTC) + timedelta(seconds=30),
    )
    session.add(job)
    await session.flush()
    return job


def _scrub_ticket(job: AgentProbeJob) -> None:
    """票證只在派工作時有用；用完就從資料庫擦掉（單次、30 秒，但沒必要留在工作紀錄裡）。"""
    if isinstance(job.params, dict) and "ticket" in job.params:
        job.params = {k: v for k, v in job.params.items() if k != "ticket"}


async def cancel_relay_job(session: AsyncSession, job_id: uuid.UUID | None) -> None:
    """worker B 等不到就緒時收掉還沒被領的中繼工作（代理晚到也不會再開）。"""
    if job_id is None:
        return
    job = await session.get(AgentProbeJob, job_id)
    if job is None:
        return
    _scrub_ticket(job)
    if job.status == STATUS_PENDING:
        job.status = STATUS_EXPIRED
        job.finished_at = datetime.now(UTC)
        job.error = "等待代理回應逾時"


async def _relay_finished(job: AgentProbeJob, error: str | None) -> None:
    """代理回報中繼的結果。成功時就緒通知由收到代理 WebSocket 的 worker 送；失敗要馬上告訴等待的那一邊，
    不讓使用者乾等 15 秒。代理的錯誤格式是「代號: 原因」。"""
    sid = (job.params or {}).get("sid") if isinstance(job.params, dict) else None
    _scrub_ticket(job)
    if not error or not sid:
        return
    from app.services import console_relay
    token, _, reason = str(error).partition(":")
    await console_relay.push_ready(str(sid), {"error": token.strip(), "reason": reason.strip()[:200]})


async def update_progress(
    session: AsyncSession, *, agent_id: uuid.UUID, job_id: uuid.UUID, progress: dict[str, Any],
) -> bool:
    """代理回報執行中的進度。只收自己領到、還在跑的工作（跟 finish_job 同一道驗證）。"""
    job = (await session.execute(
        select(AgentProbeJob).where(
            AgentProbeJob.id == job_id, AgentProbeJob.agent_id == agent_id)
    )).scalars().first()
    if job is None or job.status != STATUS_RUNNING:
        return False
    job.progress = progress
    if job.kind == "identify":
        from app.services.identify_tasks import on_progress
        await on_progress(session, job)
    return True
