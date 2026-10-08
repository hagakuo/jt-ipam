"""裝置匯入與匯入範本（issue #46，admin only）。

獨立一支 router、並在 devices 之前掛上：devices 有 `GET /devices/{device_id}`，路徑參數不限格式，
放在後面的話 `/devices/import-template` 會先被它吃掉、回 422。

- 預覽（dry_run=true）：同步回每一列的結果（新增／更新／略過／錯誤＋原因），完整跑過驗證後還原，不寫入
- 實際匯入：背景作業（作業頁看得到），每台裝置各寫一筆稽核，另有一筆整批的摘要
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.db import get_session
from app.core.ui_error import ui_detail
from app.services import device_import as svc

router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(require_admin)])

MAX_UPLOAD = 16 * 1024 * 1024


@router.get("/import-template")
async def import_template(
    session: Annotated[AsyncSession, Depends(get_session)],
    include_devices: bool = False,
) -> Response:
    """匯入範本（CSV，標準欄名）。include_devices=true 時帶出全部現有裝置，改完用「更新」模式匯回來。"""
    body = await svc.template_csv(session, include_devices=include_devices)
    name = "devices-import.csv" if include_devices else "devices-import-template.csv"
    return Response(content=body.encode("utf-8"), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _parse(raw: bytes) -> list[list[str]]:
    from app.services.xlsx_read import XlsxError
    try:
        return svc.read_table(raw)
    except UnicodeDecodeError as exc:
        raise HTTPException(400, detail=ui_detail("device_import_encoding", "CSV 必須是 UTF-8",
                                                  reason=str(exc))) from exc
    except XlsxError as exc:
        raise HTTPException(400, detail=ui_detail("device_import_bad_xlsx", "無法讀取這個 Excel 檔",
                                                  reason=str(exc))) from exc


@router.post("/import")
async def import_devices(
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    file: Annotated[UploadFile, File()],
    dry_run: Annotated[bool, Form()] = True,
    on_existing: Annotated[Literal["skip", "update"], Form()] = "skip",
) -> dict[str, Any]:
    raw = await file.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, detail=ui_detail("device_import_too_large", "檔案太大（上限 16 MB）"))
    rows = _parse(raw)

    if dry_run:
        outcome = await svc.import_devices(session, rows, on_existing=on_existing, dry_run=True)
        return {"dry_run": True, **outcome.to_dict()}

    from app.services.background_tasks import spawn_task

    actor_id = str(user.id)
    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)
    filename = file.filename

    async def _runner(sess: AsyncSession, _task: Any) -> dict[str, Any]:
        async def audit(obj: Any, action: str, diff: dict[str, Any]) -> None:
            await append_audit(sess, actor_user_id=actor_id, actor_ip=actor_ip, actor_user_agent=actor_ua,
                               object_type="device", object_id=str(obj.id), action=action, diff=diff,
                               request_id=request_id)

        outcome = await svc.import_devices(sess, rows, on_existing=on_existing, dry_run=False, audit=audit)
        summary = outcome.to_dict()
        await append_audit(sess, actor_user_id=actor_id, actor_ip=actor_ip, actor_user_agent=actor_ua,
                           object_type="device", object_id=None, action="csv_import",
                           diff={k: summary[k] for k in ("total", "created", "updated", "skipped", "errored")}
                           | {"filename": filename, "on_existing": on_existing},
                           request_id=request_id)
        await sess.commit()
        return {k: v for k, v in summary.items() if k != "rows"} | {
            "errors": [r for r in summary["rows"] if r["action"] == "error"][:50]}

    task = await spawn_task(session=session, kind="device.csv_import", target_type=None, target_id=None,
                            target_label=filename or "devices", actor_user_id=user.id, runner=_runner)
    return {"dry_run": False, "task_id": str(task.id), "status": task.status}
