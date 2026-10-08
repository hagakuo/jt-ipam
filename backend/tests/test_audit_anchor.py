"""稽核鏈的定期驗證與外部錨定。

這組測試的核心是證明一件事：**雜湊鏈抓不到尾端截斷，錨定抓得到**。
如果沒有這個對照，「我們有雜湊鏈」這句話在稽核場合會被高估。
"""
from __future__ import annotations

import json
import uuid

import pytest
from app.core.audit import append_audit, verify_chain
from app.models.audit import AuditLog
from app.services.audit_anchor import append_anchor, read_last_anchor, verify_and_anchor
from sqlalchemy import delete, func, select


async def _as_table_owner(session, on: bool) -> None:
    """模擬「有資料表擁有者權限的人」：停用／恢復只能新增的觸發器（migration 0149）。

    應用程式層任何路徑都改不動稽核記錄；這組測試要證明的是**更高權限的人**動了手腳時，
    雜湊鏈與外部錨定仍然抓得到。同一個交易內停用、竄改、恢復，不會漏到別的測試。
    """
    from sqlalchemy import text
    verb = "DISABLE" if on else "ENABLE"
    await session.execute(text(f"ALTER TABLE audit_logs {verb} TRIGGER audit_logs_append_only"))


async def _write_audits(session, n: int) -> None:
    for i in range(n):
        await append_audit(
            session, actor_user_id=None, actor_ip=None, actor_user_agent=None,
            object_type="test", object_id=None, action=f"act-{i}",
            diff={"i": i}, request_id=str(uuid.uuid4()),
        )
    await session.flush()


@pytest.mark.anyio
async def test_tail_truncation_is_invisible_to_the_chain_alone(db_session, tmp_path) -> None:
    """先證明問題存在：砍掉最後幾筆，`verify_chain` 仍然回「完整」。

    這正是我們需要外部錨定的理由 —— 沒有這一支測試，下一個人會以為鏈本身就夠了。
    """
    await _write_audits(db_session, 5)
    ok, _ = await verify_chain(db_session)
    assert ok is True

    last_two = list((await db_session.execute(
        select(AuditLog.id).order_by(AuditLog.id.desc()).limit(2))).scalars().all())
    await _as_table_owner(db_session, True)
    await db_session.execute(delete(AuditLog).where(AuditLog.id.in_(last_two)))
    await db_session.flush()
    await _as_table_owner(db_session, False)

    ok_after, bad = await verify_chain(db_session)
    assert ok_after is True, "尾端截斷竟被鏈抓到了？那這個模組的前提要重寫"
    assert bad is None


@pytest.mark.anyio
async def test_anchor_detects_tail_truncation(db_session, tmp_path) -> None:
    """錨定之後再砍尾端 → 必須抓到。"""
    path = tmp_path / "anchors.jsonl"
    await _write_audits(db_session, 5)

    first = await verify_and_anchor(db_session, path=path)
    assert first["ok"] is True
    anchored_id = first["anchored_to"]

    await _as_table_owner(db_session, True)
    await db_session.execute(delete(AuditLog).where(AuditLog.id >= anchored_id))
    await db_session.flush()
    await _as_table_owner(db_session, False)

    second = await verify_and_anchor(db_session, path=path)
    assert second["ok"] is False
    assert second["reason"] == "anchored_row_missing", second
    assert "尾端截斷" in second["detail"]


@pytest.mark.anyio
async def test_anchor_detects_content_tampering(db_session, tmp_path) -> None:
    """被錨定的那一筆內容被改（雜湊變了）→ 抓到。"""
    path = tmp_path / "anchors.jsonl"
    await _write_audits(db_session, 3)
    res = await verify_and_anchor(db_session, path=path)
    row = (await db_session.execute(
        select(AuditLog).where(AuditLog.id == res["anchored_to"]))).scalars().one()
    await _as_table_owner(db_session, True)
    row.this_hash = bytes(32)
    await db_session.flush()
    await _as_table_owner(db_session, False)

    after = await verify_and_anchor(db_session, path=path)
    assert after["ok"] is False
    assert after["reason"] == "anchored_hash_changed"


@pytest.mark.anyio
async def test_mid_chain_tamper_still_detected(db_session, tmp_path) -> None:
    """中間竄改仍由鏈本身抓到（增量驗證不能因此漏掉）。"""
    path = tmp_path / "anchors.jsonl"
    await _write_audits(db_session, 3)
    await verify_and_anchor(db_session, path=path)     # 錨定到第 3 筆

    await _write_audits(db_session, 3)                 # 再寫 3 筆
    mid = list((await db_session.execute(
        select(AuditLog).order_by(AuditLog.id.asc()))).scalars().all())[4]
    await _as_table_owner(db_session, True)
    mid.action = "tampered"                            # 改內容但不改雜湊
    await db_session.flush()
    await _as_table_owner(db_session, False)

    res = await verify_and_anchor(db_session, path=path)
    assert res["ok"] is False
    assert res["reason"] == "chain_broken"
    assert str(mid.id) in res["detail"]


@pytest.mark.anyio
async def test_incremental_verification_starts_from_anchor(db_session, tmp_path) -> None:
    """增量驗證：錨定之後只驗新的部分（否則每輪都要重走整條鏈）。"""
    path = tmp_path / "anchors.jsonl"
    await _write_audits(db_session, 4)
    first = await verify_and_anchor(db_session, path=path)
    assert first["anchored_from"] is None              # 第一次沒有起點

    await _write_audits(db_session, 2)
    second = await verify_and_anchor(db_session, path=path)
    assert second["ok"] is True
    assert second["anchored_from"] == first["anchored_to"], "沒有從上次錨定處接續"
    assert second["count"] == 6


@pytest.mark.anyio
async def test_anchor_file_is_appended_not_replaced(db_session, tmp_path) -> None:
    """錨定檔是逐行附加的歷史，不是只留最後一筆 —— 歷史本身就是證據。"""
    path = tmp_path / "anchors.jsonl"
    await _write_audits(db_session, 2)
    await verify_and_anchor(db_session, path=path)
    await _write_audits(db_session, 1)
    await verify_and_anchor(db_session, path=path)

    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["count"] == 2
    assert json.loads(lines[1])["count"] == 3


def test_corrupt_anchor_line_does_not_break_reading(tmp_path) -> None:
    """錨定檔壞了一行不該讓整個機制停擺（讀不到就當首次錨定）。"""
    path = tmp_path / "anchors.jsonl"
    path.write_text('{"audit_id": 1, "this_hash": "aa", "count": 1}\n'
                    "this is not json\n"
                    '{"audit_id": 2, "this_hash": "bb", "count": 2}\n', encoding="utf-8")
    last = read_last_anchor(path)
    assert last is not None
    assert last["audit_id"] == 2


def test_missing_anchor_file_is_not_an_error(tmp_path) -> None:
    assert read_last_anchor(tmp_path / "nope.jsonl") is None


def test_append_creates_parent_directory(tmp_path) -> None:
    path = tmp_path / "nested" / "dir" / "anchors.jsonl"
    append_anchor({"audit_id": 1, "this_hash": "aa", "count": 1}, path)
    assert path.exists()


@pytest.mark.anyio
async def test_deleted_rows_shrink_count_is_flagged(db_session, tmp_path) -> None:
    """總數變少一定有問題 —— 稽核記錄只增不減。"""
    path = tmp_path / "anchors.jsonl"
    await _write_audits(db_session, 4)
    res = await verify_and_anchor(db_session, path=path)
    # 刪掉中間一筆但保留被錨定的那筆 → 走 count 這條檢查
    mid = list((await db_session.execute(
        select(AuditLog.id).order_by(AuditLog.id.asc()))).scalars().all())[1]
    await _as_table_owner(db_session, True)
    await db_session.execute(delete(AuditLog).where(AuditLog.id == mid))
    await db_session.flush()
    await _as_table_owner(db_session, False)
    assert int(await db_session.scalar(
        select(func.count()).select_from(AuditLog)) or 0) < res["count"]

    after = await verify_and_anchor(db_session, path=path)
    assert after["ok"] is False
    assert after["reason"] in ("count_shrank", "chain_broken")


@pytest.mark.anyio
async def test_chain_failure_alert_is_deduped(db_session, tmp_path) -> None:
    """斷鏈告警每 5 分鐘重發一次就是洗版；同一種失敗一段時間內只發一次。"""
    from app.models.user import User
    from app.services.audit_anchor import notify_chain_failure

    admin = User(username=f"a-{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@example.com",
                 password_hash="x", is_admin=True, is_active=True)
    db_session.add(admin)
    await db_session.flush()

    res = {"ok": False, "reason": "anchored_row_missing", "detail": "尾端截斷"}
    first = await notify_chain_failure(db_session, res)
    await db_session.flush()
    assert first >= 1, "第一次一定要發出去"

    second = await notify_chain_failure(db_session, res)
    await db_session.flush()
    assert second == 0, "同一種失敗在去重視窗內不該重發"

    # 視窗外要再發一次 —— 去重不能變成「只通知一次就永遠靜音」
    third = await notify_chain_failure(db_session, res, dedup_hours=0)
    assert third >= 1


@pytest.mark.anyio
async def test_baseline_starts_verification_after_a_known_legacy_break(
    db_session, tmp_path, monkeypatch,
) -> None:
    """舊版寫入端 bug 留下的斷點，只能劃線之後才開始驗 —— 但那條線要留下痕跡。"""
    from app.models.audit import AuditLog

    await _write_audits(db_session, 3)
    ids = list((await db_session.execute(
        select(AuditLog.id).order_by(AuditLog.id.asc()))).scalars().all())
    # 人工製造一個舊斷點：第 2 筆的 prev_hash 指向錯的地方
    broken = (await db_session.execute(
        select(AuditLog).where(AuditLog.id == ids[1]))).scalars().one()
    await _as_table_owner(db_session, True)
    broken.prev_hash = bytes(32)
    await db_session.flush()
    await _as_table_owner(db_session, False)

    path = tmp_path / "anchors.jsonl"
    assert (await verify_and_anchor(db_session, path=path))["ok"] is False

    # 劃線在斷點那一筆之後 → 之後的段落是完整的
    monkeypatch.setenv("JT_IPAM_AUDIT_CHAIN_BASELINE_ID", str(ids[1]))
    res = await verify_and_anchor(db_session, path=path)
    assert res["ok"] is True
    assert res["baseline_id"] == ids[1]
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[-1])["baseline_id"] == ids[1]


@pytest.mark.anyio
async def test_missing_baseline_row_is_a_failure(db_session, tmp_path, monkeypatch) -> None:
    """基準線那一筆被刪掉 → 不可以當成沒事，那正是要偵測的情況。"""
    await _write_audits(db_session, 2)
    monkeypatch.setenv("JT_IPAM_AUDIT_CHAIN_BASELINE_ID", "999999999")
    res = await verify_and_anchor(db_session, path=tmp_path / "a.jsonl")
    assert res["ok"] is False
    assert res["reason"] == "baseline_row_missing"


@pytest.mark.anyio
async def test_chain_is_verified_in_batches_across_boundaries(db_session, monkeypatch) -> None:
    """一批一批驗（2026-09-30：以前整條鏈一次載進記憶體，上百萬筆會吃掉好幾 GB）。
    批次邊界不可以讓鏈斷掉，也不可以漏掉邊界上的竄改；增量驗證與 limit 照常。"""
    from app.core import audit as audit_core

    monkeypatch.setattr(audit_core, "_VERIFY_BATCH", 3)
    await _write_audits(db_session, 10)
    assert await verify_chain(db_session) == (True, None)
    ids = list((await db_session.execute(select(AuditLog.id).order_by(AuditLog.id))).scalars().all())
    first = (await db_session.execute(select(AuditLog).where(AuditLog.id == ids[2]))).scalar_one()
    assert await verify_chain(db_session, after_id=ids[2], expected_prev=first.this_hash) == (True, None)
    assert await verify_chain(db_session, limit=4) == (True, None)

    await _as_table_owner(db_session, True)
    from sqlalchemy import update
    await db_session.execute(update(AuditLog).where(AuditLog.id == ids[6]).values(action="tampered"))
    await db_session.flush()
    await _as_table_owner(db_session, False)
    db_session.expire_all()
    assert await verify_chain(db_session) == (False, ids[6])     # 落在第三批的第一筆
