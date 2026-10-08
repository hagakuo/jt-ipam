"""系統匯出／匯入（跨機搬移）—— 管理區獨立功能。

全部端點 require_admin。匯出把整台的設定與資料序列化成一份密碼保護的 JSON 匯出檔；
匯入可在另一台 jt-ipam 還原（保留 UUID → 外鍵與機密皆自動成立），並支援向下相容舊版匯出檔。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import CurrentUser, require_admin
from app.core.audit import append_audit
from app.core.config import get_settings
from app.core.db import get_session
from app.core.ui_error import detail_of, ui_detail
from app.models.background_task import BackgroundTask
from app.schemas.system_transfer import ExportRequest, ImportApplyRequest
from app.services.system_transfer import crypto, exporter, importer, registry, streaming
from app.version import __version__

router = APIRouter(prefix="/system/transfer", tags=["system-transfer"],
                   dependencies=[Depends(require_admin)])

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MAX_UPLOAD = 512 * 1024 * 1024  # 512 MiB 上限，擋超大檔耗盡記憶體


def _spool_dir() -> Path:
    d = Path(get_settings().upload_dir).parent / "transfer"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def _contained(base: Path, name: str) -> Path:
    """組出來的路徑解析後必須還在 base 底下（第二道防線；第一道是檔名只接受 UUID）。"""
    root = os.path.realpath(base)
    full = os.path.realpath(os.path.join(root, name))
    if not full.startswith(root + os.sep):
        raise HTTPException(status_code=400, detail="invalid token")
    return Path(full)


def _safe_path(name: str) -> Path:
    """只接受 <uuid>.json；擋路徑穿越。"""
    stem = name[:-5] if name.endswith(".json") else name
    if not _UUID_RE.match(stem):
        raise HTTPException(status_code=400, detail="invalid token")
    return _contained(_spool_dir(), f"{stem}.json")


def _cleanup_old(keep_hours: int = 48) -> None:
    """清掉 spool 內超過 keep_hours 的舊檔（best-effort）。"""
    import time
    cutoff = time.time() - keep_hours * 3600
    try:
        for f in _spool_dir().glob("*.json"):
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
    except OSError:
        pass


class _TooLarge(Exception):
    pass


def _save_upload(src: Any, dest: Path) -> None:
    """把上傳檔（starlette 超過 1 MB 就放在暫存檔）逐段複製到暫存目錄，超過上限就停。"""
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    size = 0
    with os.fdopen(fd, "wb") as out:
        while chunk := src.read(1 << 20):
            size += len(chunk)
            if size > _MAX_UPLOAD:
                raise _TooLarge
            out.write(chunk)


def _load_inner(path: Path, passphrase: str) -> dict[str, Any]:
    return crypto.open_envelope(json.loads(path.read_bytes().decode("utf-8")), passphrase)


async def _schema_version(session: AsyncSession) -> str | None:
    try:
        row = (await session.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))).first()
        return row[0] if row else None
    except Exception:
        return None


# ────────────────────────────────── schema ──────────────────────────────────
@router.get("/schema")
async def get_schema(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """回可選分類 + 各分類目前列數（供匯出 UI 勾選）。"""
    counts: dict[str, int] = {}
    for cat in registry.SCOPES:
        total = 0
        for name in registry.tables_for_scope([cat]):
            if name == registry.ENCRYPTED_SECRETS_TABLE:
                continue
            table = registry.table_by_name(name)
            n = (await session.execute(select(func.count()).select_from(table))).scalar_one()
            total += int(n or 0)
        counts[cat] = total
    return {
        "scopes": list(registry.SCOPES),
        "default_scope": list(registry.DEFAULT_SCOPE),
        "counts": counts,
        "schema_version": await _schema_version(session),
        "app_version": __version__,
    }


# ────────────────────────────────── export ──────────────────────────────────
@router.post("/export")
async def start_export(
    payload: ExportRequest,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    scope = [s for s in payload.scope if s in registry.SCOPES]
    if not scope:
        raise HTTPException(status_code=422, detail=ui_detail("xfer_scope_empty", "scope 需至少含一個有效分類"))
    _cleanup_old()
    schema_version = await _schema_version(session)
    passphrase = payload.passphrase
    actor_id = user.id
    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)

    async def _runner(sess: AsyncSession, task: BackgroundTask) -> dict[str, Any]:
        import secrets as _rng
        # 串流：邊讀邊壓縮、封套分段寫檔（整份組在記憶體裡的話，大型站台會吃掉好幾 GB）
        raw, counts = await exporter.export_compressed(sess, scope)
        metadata = {
            "app_version": __version__,
            "schema_version": schema_version,
            "scope": scope,
            "exported_at": datetime.now(UTC).isoformat(),
        }
        path = _spool_dir() / f"{task.id}.json"
        # 一建立就是 0600（先寫再 chmod 的話，中間有一段時間是依 umask 的權限）
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            size = crypto.write_sealed(f, raw, passphrase, metadata=metadata, rng=_rng)
        del raw
        await append_audit(
            sess, actor_user_id=str(actor_id), actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="system", object_id=None, action="export",
            diff={"scope": scope, "counts": counts, "bytes": size},
            request_id=request_id,
        )
        return {"filename": f"jt-ipam-export-{task.id}.json", "bytes": size,
                "counts": counts, "scope": scope}

    from app.services.background_tasks import spawn_task
    task = await spawn_task(
        session=session, kind="system.export", target_type="system",
        target_label=",".join(scope), actor_user_id=actor_id, runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status}


@router.get("/export/{task_id}/download")
async def download_export(
    task_id: uuid.UUID,
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FileResponse:
    task = await session.get(BackgroundTask, task_id)
    if task is None or task.kind != "system.export":
        raise HTTPException(status_code=404, detail="export task not found")
    if task.status != "succeeded":
        raise HTTPException(status_code=409, detail=f"export not ready (status={task.status})")
    path = _contained(_spool_dir(), f"{task_id}.json")
    if not path.exists():
        raise HTTPException(status_code=410, detail="export file expired")
    fname = (task.summary or {}).get("filename") or f"jt-ipam-export-{task_id}.json"
    return FileResponse(path, media_type="application/json", filename=fname)


# ────────────────────────────────── import ──────────────────────────────────
@router.post("/import/analyze")
async def analyze_import(
    _user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    file: UploadFile = File(...),
    passphrase: str = Form(...),
) -> dict[str, Any]:
    """驗證上傳的匯出檔＋密碼，回來源版本／各表列數／相容性警告（不寫任何資料）。

    上傳直接寫進暫存目錄、再逐段解密驗證（streaming.scan），不把整份檔案讀進記憶體 ——
    以前 27 MB 的匯出檔光分析就要好幾百 MB（2026-10-01）。
    """
    _cleanup_old()
    token = uuid.uuid4()
    path = _spool_dir() / f"{token}.json"
    try:
        await asyncio.to_thread(_save_upload, file.file, path)
    except _TooLarge as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(status_code=413, detail=ui_detail("xfer_file_too_large", "檔案過大")) from exc
    try:
        scanned = await asyncio.to_thread(streaming.scan, path, passphrase)
        meta = scanned.metadata
        if scanned.counts is not None:
            counts_all = scanned.counts
        else:                                   # 沒有 counts 的檔案（目前沒有任何一版這樣寫）：整份載入算
            inner = await asyncio.to_thread(_load_inner, path, passphrase)
            counts_all = {t: len(rows) for t, rows in (inner.get("tables") or {}).items()}
            counts_all[registry.ENCRYPTED_SECRETS_TABLE] = len(inner.get("central_secrets") or [])
    except crypto.TransferCryptoError as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=detail_of(exc, "xfer_bad_file")) from exc

    target_schema = await _schema_version(session)
    # 結構化（code/params/message）而不是現成句子：這些警告會顯示在畫面上，
    # 伺服器組好的中文在英文與日文介面上翻不動。message 是沒有翻譯時的退路。
    warnings: list[dict[str, Any]] = []
    if meta.get("schema_version") and target_schema and meta["schema_version"] != target_schema:
        warnings.append(ui_detail(
            "xfer_warn_schema_mismatch",
            f"匯出檔 schema 版本（{meta['schema_version']}）與本機（{target_schema}）不同；"
            "多數情況仍可匯入，缺漏欄位會吃預設。",
            source=meta["schema_version"], target=target_schema,
        ))
    known = set(registry.all_tablenames())
    unknown = [t for t in counts_all if t not in known]
    if unknown:
        warnings.append(ui_detail(
            "xfer_warn_unknown_tables",
            f"匯出檔含本機未知的資料表（將略過）：{', '.join(sorted(unknown))}",
            tables=", ".join(sorted(unknown)),
        ))

    counts = {t: n for t, n in counts_all.items() if t != registry.ENCRYPTED_SECRETS_TABLE}
    counts_central = counts_all.get(registry.ENCRYPTED_SECRETS_TABLE, 0)

    return {
        "token": str(token),
        "metadata": meta,
        "target_schema_version": target_schema,
        "counts": counts,
        "central_secrets": counts_central,
        "warnings": warnings,
    }


@router.post("/import/apply")
async def apply_import_ep(
    payload: ImportApplyRequest,
    user: CurrentUser,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """套用先前 analyze 暫存的匯入檔。dry_run 同步回預覽；正式匯入走背景作業。"""
    path = _safe_path(payload.token)
    if not path.exists():
        raise HTTPException(status_code=410, detail=ui_detail("xfer_staging_expired", "匯入暫存檔已過期，請重新上傳分析"))
    try:
        scanned = await asyncio.to_thread(streaming.scan, path, payload.passphrase)
    except crypto.TransferCryptoError as exc:
        raise HTTPException(status_code=400, detail=ui_detail("xfer_bad_passphrase", "密碼錯誤或檔案損毀")) from exc
    passphrase = payload.passphrase

    mode = payload.mode
    actor_id = user.id
    actor_ip = request.client.host if request.client else None
    actor_ua = request.headers.get("user-agent")
    request_id = getattr(request.state, "request_id", None)

    if payload.dry_run:
        report = await importer.import_file(
            session, path, passphrase, mode=mode, dry_run=True, actor_user_id=actor_id, scanned=scanned,
        )
        return {"dry_run": True, "report": report}

    async def _runner(sess: AsyncSession, _task: BackgroundTask) -> dict[str, Any]:
        report = await importer.import_file(
            sess, path, passphrase, mode=mode, dry_run=False, actor_user_id=actor_id, scanned=scanned,
        )
        await append_audit(
            sess, actor_user_id=str(actor_id), actor_ip=actor_ip, actor_user_agent=actor_ua,
            object_type="system", object_id=None, action="import",
            diff={"mode": mode, "tables": {k: v for k, v in report["tables"].items()}},
            request_id=request_id,
        )
        # 匯入完清掉暫存檔
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return report

    from app.services.background_tasks import spawn_task
    task = await spawn_task(
        session=session, kind="system.import", target_type="system",
        target_label=mode, actor_user_id=actor_id, runner=_runner,
    )
    return {"task_id": str(task.id), "status": task.status, "dry_run": False}
