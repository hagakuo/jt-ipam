"""AI 巡檢的查詢與操作端點。

**整支端點都限管理員**（`require_admin`），包含只是看發現的那幾支。

原本「看發現」只需要 `require_global_read`，但這個功能已經放在管理區、跟其它管理功能
並列。權限跟位置對不起來的話，會出現「選單看不到、直接打網址卻進得去」——
那是最糟的一種：看起來有管控，實際上沒有。

理由不只是位置：巡檢結論是模型對整個環境的推測，會點名到哪些網段沒有監測、哪些管理
介面放在一般網段 —— 那等於一份跨部門的弱點清單，不該給只被指派特定物件的帳號看。

執行巡檢時取樣仍**以發起者的可見範圍為準**（見 `services/ai_audit._collect`），
就算是管理員也一樣。
"""

from __future__ import annotations

import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.models.ai_finding import AIFinding
from app.schemas.base import StrictModel
from app.services.ai_audit import CATEGORIES, SEVERITIES, latest_summary, run_audit
from app.services.background_tasks import spawn_task

router = APIRouter(prefix="/ai-audit", tags=["ai-audit"])


def _out(f: AIFinding) -> dict[str, Any]:
    return {
        "id": str(f.id), "run_id": str(f.run_id),
        "severity": f.severity, "category": f.category,
        "title": f.title, "detail": f.detail, "recommendation": f.recommendation,
        "evidence": f.evidence,
        "object_type": f.object_type,
        "object_id": str(f.object_id) if f.object_id else None,
        "status": f.status,
        # 哪個模型寫的：巡檢是推測，換模型後要能分辨哪幾條出自哪一個
        "model": f.model,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


@router.get("/summary", dependencies=[Depends(require_admin)])
async def summary(session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    """儀表板用的摘要：未處理發現的嚴重度分佈與最後執行時間。"""
    return await latest_summary(session)


@router.get("/findings", dependencies=[Depends(require_admin)])
async def list_findings(
    session: Annotated[AsyncSession, Depends(get_session)],
    status: Annotated[str, Query(pattern="^(open|dismissed|all)$")] = "open",
    severity: Annotated[str | None, Query(max_length=16)] = None,
    category: Annotated[str | None, Query(max_length=48)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    stmt = select(AIFinding)
    count_stmt = select(func.count()).select_from(AIFinding)
    if status != "all":
        stmt = stmt.where(AIFinding.status == status)
        count_stmt = count_stmt.where(AIFinding.status == status)
    if severity in SEVERITIES:
        stmt = stmt.where(AIFinding.severity == severity)
        count_stmt = count_stmt.where(AIFinding.severity == severity)
    # 認不得的分類就當沒篩（比照 severity）—— 舊網址帶著已淘汰的分類進來時，
    # 寧可回全部也不要整頁 422
    if category in CATEGORIES:
        stmt = stmt.where(AIFinding.category == category)
        count_stmt = count_stmt.where(AIFinding.category == category)
    total = (await session.execute(count_stmt)).scalar_one()
    rows = (await session.execute(
        stmt.order_by(AIFinding.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return {"items": [_out(f) for f in rows], "total": total,
            "page": page, "page_size": page_size}


@router.post("/run", dependencies=[Depends(require_admin)])
async def run_now(
    user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """排一次巡檢到背景執行，馬上回一個作業 ID。

    **不是同步等它跑完**：巡檢動輒十幾分鐘，綁在 HTTP 請求上的話，使用者一離開頁面
    就整個消失，連跑到一半的結果都拿不回來（實際發生過）。改成背景作業之後，關掉分頁、
    切到別頁都不影響，回來再看進度就好。
    """
    # 409 而不是排隊：兩次同時跑會互相拖死同一台 LLM，排隊只是把問題延後。
    # 判斷依據是「作業列有沒有還沒跑完的」，不是程序內的鎖 —— 作業是非同步啟動的，
    # 連按兩次時第一個還沒拿到鎖，用鎖判斷會漏掉，於是多出一筆立刻失敗的作業，
    # 而狀態查詢會看到那筆失敗的、把真正在跑的那個蓋掉。
    if await _active_run(session) is not None:
        raise HTTPException(status_code=409, detail="已經有一次巡檢正在執行")

    user_id = user.id

    async def _runner(sess: AsyncSession, task: Any) -> dict[str, Any]:
        from app.models.user import User as _User
        principal = await sess.get(_User, user_id)
        if principal is None:
            raise RuntimeError("發起者已不存在")

        last_write = [0.0]
        last_mark: list[Any] = [None]

        async def _progress(ev: dict[str, Any]) -> None:
            # 進度寫進作業列，前端用 poll 讀 —— 這樣才跟「人有沒有開著頁面」無關。
            # 但不能每個事件都寫 DB（模型每 200 字回報一次），節流到每秒最多一次。
            now = time.monotonic()
            # 換階段／換批次一定要寫：那是最值得看的一刻，被節流吃掉的話畫面會停在上一段
            mark = (ev.get("stage"), ev.get("batch"), ev.get("phase"))
            changed = mark != last_mark[0]
            last_mark[0] = mark
            if not changed and now - last_write[0] < 1.0:
                return
            last_write[0] = now
            task.progress = _percent(ev)
            task.summary = {"live": ev}
            await sess.commit()

        result = await run_audit(sess, principal, progress=_progress)
        await append_audit(
            sess,
            actor_user_id=str(user_id),
            actor_ip=None, actor_user_agent=None,
            object_type="ai_audit", object_id=None, action="run",
            diff={"run_id": str(result.run_id), "findings": result.findings,
                  "error": result.error},
            request_id=None,
        )
        await sess.commit()
        if result.error and result.findings == 0:
            # 沒跑成不能標成成功 —— 「沒發現問題」跟「沒跑成」差很多
            raise RuntimeError(result.error)
        return {"run_id": str(result.run_id), "findings": result.findings,
                "error": result.error}

    task = await spawn_task(
        session=session, kind="ai_audit.run",
        actor_user_id=user.id, trigger="manual", runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status}


async def _active_run(session: AsyncSession) -> Any:
    """還沒跑完的巡檢作業（有的話回那一列）。"""
    from app.models.background_task import BackgroundTask
    return (await session.execute(
        select(BackgroundTask).where(
            BackgroundTask.kind == "ai_audit.run",
            BackgroundTask.status.in_(("pending", "running")),
        ).limit(1)
    )).scalar_one_or_none()


def _percent(ev: dict[str, Any]) -> int:
    """把階段事件換算成百分比。分析佔絕大多數 —— 時間也確實都花在那。"""
    stage = ev.get("stage")
    if stage == "collecting":
        return 2
    if stage == "saving":
        return 98
    if stage == "done":
        return 100
    total = ev.get("total") or 0
    if not total:
        return 2
    return min(99, int(2 + (ev.get("current", 0) / total) * 95))


@router.get("/status", dependencies=[Depends(require_admin)])
async def run_status(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """最近一次巡檢作業的狀態（給頁面顯示進度用）。

    有這支，重新整理或切走再回來都還看得到現況 —— 進度存在作業列，不在瀏覽器裡。
    """
    from app.models.background_task import BackgroundTask
    # 正在跑的優先；沒有才回最近一次的結果。倒過來的話，執行中卻顯示上一次的失敗，
    # 使用者會以為這次也掛了。
    row = await _active_run(session)
    if row is None:
        row = (await session.execute(
            select(BackgroundTask).where(BackgroundTask.kind == "ai_audit.run")
            .order_by(BackgroundTask.queued_at.desc()).limit(1)
        )).scalar_one_or_none()
    if row is None:
        return {"task": None}
    return {"task": {
        "id": str(row.id), "status": row.status, "progress": row.progress,
        "summary": row.summary, "error": row.error,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }}


class _DismissIn(StrictModel):
    ids: list[uuid.UUID]


@router.post("/dismiss", dependencies=[Depends(require_admin)])
async def dismiss(
    payload: _DismissIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """把發現標為已忽略（不刪除 —— 留著才看得出哪些被判斷為誤報）。"""
    from datetime import UTC, datetime
    rows = (await session.execute(
        select(AIFinding).where(AIFinding.id.in_(payload.ids))
    )).scalars().all()
    for f in rows:
        f.status = "dismissed"
        f.dismissed_by = user.id
        f.dismissed_at = datetime.now(UTC)
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ai_audit", object_id=None, action="dismiss",
        diff={"count": len(rows)},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return {"dismissed": len(rows)}


@router.delete("/findings", dependencies=[Depends(require_admin)])
async def clear_findings(
    user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """清空整份發現清單，讓下一次巡檢從頭report。

    這裡是**刪除**，不是「全部忽略」，兩者結果完全相反：忽略會留下指紋，往後每一次巡檢
    遇到同一件事都自動忽略 —— 用忽略實作「清除」，等於把這些發現永久封住，而使用者想要
    的是清掉之後重新分析一次。

    連同已忽略的一起刪：那些記錄正是「不要再報這件事」的依據，留著就等於沒清。
    """
    from sqlalchemy import delete as _delete
    n = int(await session.scalar(select(func.count()).select_from(AIFinding)) or 0)
    await session.execute(_delete(AIFinding))
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ai_audit", object_id=None, action="clear",
        diff={"count": n},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return {"deleted": n}


@router.post("/restore", dependencies=[Depends(require_admin)])
async def restore(
    payload: _DismissIn, user: CurrentUser, request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """把已忽略的發現放回未處理。

    忽略是一個按了就影響往後每一次巡檢的動作（同指紋的發現之後都會自動忽略），
    所以一定要能反悔 —— 沒有回復的路，誤按一下就永久看不到那類問題了。
    """
    rows = (await session.execute(
        select(AIFinding).where(AIFinding.id.in_(payload.ids))
    )).scalars().all()
    for f in rows:
        f.status = "open"
        f.dismissed_by = None
        f.dismissed_at = None
    await append_audit(
        session,
        actor_user_id=str(user.id),
        actor_ip=request.client.host if request.client else None,
        actor_user_agent=request.headers.get("user-agent"),
        object_type="ai_audit", object_id=None, action="restore",
        diff={"count": len(rows)},
        request_id=getattr(request.state, "request_id", None),
    )
    await session.commit()
    return {"restored": len(rows)}
