"""套用匯出包的 inner payload 到目標機。

- 保留來源 UUID → 外鍵與機密 AAD 自動成立。
- merge：依主鍵 upsert（ON CONFLICT DO UPDATE），冪等。
- replace：先反相依序清空 in-scope 表（保護目前登入的 admin 那列，避免自斷 session），再 upsert。
- 每列包 SAVEPOINT（begin_nested）做錯誤隔離，單列失敗只計數不中斷整批。
- dry_run：全程照跑但最後 rollback，不落地（回預覽計數）。
- 向下相容：只寫「目標表存在的欄位」；匯出包多出的未知欄位忽略、缺的欄位吃預設。
"""

from __future__ import annotations

import base64
import datetime as _dt
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Date, DateTime, LargeBinary, Time, delete, select
from sqlalchemy import and_ as sa_and
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.types import Uuid as GenericUUID

from app.services.system_transfer import registry, secrets


@dataclass
class TableResult:
    inserted: int = 0
    updated: int = 0
    skipped: int = 0
    errored: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "inserted": self.inserted, "updated": self.updated,
            "skipped": self.skipped, "errored": self.errored,
            "errors": self.errors[:20],
        }


def _coerce(table, row: dict[str, Any]) -> dict[str, Any]:
    """依目標表欄位型別轉換值；只保留目標表存在的欄位（向下相容關鍵）。"""
    # 舊版匯出檔的機櫃占寬是 `rack_side`（full/left/right），新版是 rack_slot/rack_slot_span
    # （issue #31）。不轉的話半 U 裝置會被當成整 U 還原，匯入後就會彼此重疊。
    if table.name == "devices" and "rack_side" in row and "rack_slot" not in row:
        from app.services.rack import legacy_side_to_slots
        slot, span = legacy_side_to_slots(row.get("rack_side"))
        row = {**row, "rack_slot": slot, "rack_slot_span": span}
    cols = table.columns
    out: dict[str, Any] = {}
    for name, val in row.items():
        if name not in cols:
            continue  # 未知欄位（新版匯出→舊實例）忽略
        col = cols[name]
        if val is None:
            out[name] = None
            continue
        ctype = col.type
        if isinstance(ctype, LargeBinary):
            out[name] = base64.b64decode(val) if isinstance(val, str) else val
        elif isinstance(ctype, (DateTime, Date, Time)):
            out[name] = _parse_temporal(val)
        elif isinstance(ctype, (PGUUID, GenericUUID)):
            out[name] = uuid.UUID(val) if isinstance(val, str) else val
        else:
            out[name] = val
    return out


def _parse_temporal(val: Any) -> Any:
    if not isinstance(val, str):
        return val
    try:
        return _dt.datetime.fromisoformat(val)
    except ValueError:
        try:
            return _dt.date.fromisoformat(val)
        except ValueError:
            return val


def deferred_fk_columns(name: str) -> set[str]:
    """這張表裡「指向還沒建立的那一列」的外鍵欄位。

    匯入照外鍵相依序逐表寫入，但有些欄位是往後指的：`devices.primary_ip_id` 指向排在
    後面的 `ip_addresses`，`sections.parent_id` / `subnets.master_subnet_id` /
    `device_ports.peer_port_id` 則是指向同一張表的其他列（同表內誰先誰後由匯出順序決定）。
    寫到那一列時目標還不存在 → 外鍵違反 → **整列進不去**。

    客戶回報的「裝置少了一半」就是這個：設了主要 IP 的裝置全部失敗、沒設的照常匯入，
    看起來像隨機掉資料。所以這些欄位先留空，等所有表都寫完再回頭補上（見 `_apply_deferred`）。

    只延後**可為空**的欄位 —— 不可為空的往後指外鍵無法先留空，那種結構要靠調整相依序解決；
    目前 metadata 裡沒有這種欄位。
    """
    table = registry.table_by_name(name)
    order = registry.all_tablenames()
    idx = {n: i for i, n in enumerate(order)}
    here = idx.get(name, -1)
    out: set[str] = set()
    for fk in table.foreign_keys:
        ref = fk.column.table.name
        if idx.get(ref, -1) >= here and fk.parent.nullable:
            out.add(fk.parent.name)
    return out


async def _apply_deferred(
    session: AsyncSession, pending: list[tuple[str, dict[str, Any], dict[str, Any]]],
) -> tuple[int, list[str]]:
    """所有表寫完後，把先前留空的往後指外鍵補回去。"""
    fixed, errors = 0, []
    for name, pk, values in pending:
        table = registry.table_by_name(name)
        try:
            async with session.begin_nested():
                cond = sa_and(*[table.c[k] == v for k, v in pk.items()])
                await session.execute(table.update().where(cond).values(**values))
            fixed += 1
        except Exception as exc:
            if len(errors) < 20:
                errors.append(f"{name} pk={pk}: {type(exc).__name__}: {exc}")
    return fixed, errors


def _pk_cols(table) -> list[str]:
    return [c.name for c in table.primary_key.columns]


async def _existing_pks(session: AsyncSession, table) -> set:
    pk = list(table.primary_key.columns)
    if not pk:
        return set()
    result = await session.execute(select(*pk))
    if len(pk) == 1:
        return {r[0] for r in result.all()}
    return {tuple(r) for r in result.all()}


def _pk_value(table, coerced: dict[str, Any]):
    pk = _pk_cols(table)
    vals = tuple(coerced.get(c) for c in pk)
    return vals[0] if len(vals) == 1 else vals


class _TableImporter:
    """一張表的匯入：`start()` → 一批一批 `feed()` → `result`。

    串流匯入（apply_import_stream）一次只拿到一批列；整份在記憶體裡的舊路徑（_import_table）
    就是一次餵完。兩條路寫入的方式完全一樣。
    """

    def __init__(self, session: AsyncSession, name: str, *, mode: str,
                 pending: list[tuple[str, dict[str, Any], dict[str, Any]]] | None) -> None:
        self.session, self.name, self.mode, self.pending = session, name, mode, pending
        self.table = registry.table_by_name(name)
        self.result = TableResult()
        self.existing: set = set()
        self.pk_cols = _pk_cols(self.table)
        self.deferred = deferred_fk_columns(name) if pending is not None else set()

    async def start(self) -> None:
        if self.mode != "replace":
            self.existing = await _existing_pks(self.session, self.table)

    async def feed(self, rows: list[dict[str, Any]]) -> None:
        name, table, res, pk_cols = self.name, self.table, self.result, self.pk_cols
        prepared: list[tuple[dict[str, Any], dict[str, Any], bool]] = []
        for raw in rows:
            raw = dict(raw)
            sec = raw.pop("__secrets__", None)
            try:
                coerced = _coerce(table, raw)
                if name == "system_settings":
                    coerced["value"] = secrets.transform_settings_in(coerced.get("key"), coerced.get("value"))
                secrets.apply_column_secrets(name, coerced, sec)
                secrets.apply_envelope_secrets(name, coerced, sec)
                # 往後指的外鍵先留空，等全部寫完再補（否則整列會因為外鍵違反而消失）。
                # 這裡是把欄位整個拿掉而不是填 None：merge 模式下 upsert 就不會把目標端
                # 既有的值蓋成空的。
                if self.deferred:
                    hold = {c: coerced.pop(c) for c in self.deferred if c in coerced}
                    hold = {c: v for c, v in hold.items() if v is not None}
                    if hold and self.pending is not None:
                        self.pending.append((name, {c: coerced[c] for c in pk_cols}, hold))
                prepared.append((coerced, raw, _pk_value(table, coerced) in self.existing))
            except Exception as exc:
                _record_error(res, name, raw, exc)

        # 一批一次寫（2026-09-30 大量資料測試：以前每一列一個 SAVEPOINT＋重新編譯一次 INSERT，
        # 43 萬列的匯入要跑幾十分鐘）。欄位組合相同的列用同一個語句 executemany；
        # 整批失敗才退回逐列，壞掉的那幾列照樣報得出來、其他列照寫。
        for i in range(0, len(prepared), _IMPORT_BATCH):
            groups: dict[tuple[str, ...], list[tuple[dict[str, Any], dict[str, Any], bool]]] = {}
            for item in prepared[i:i + _IMPORT_BATCH]:
                groups.setdefault(tuple(item[0]), []).append(item)
            for cols, items in groups.items():
                stmt = _upsert_stmt(table, cols, pk_cols)
                try:
                    async with self.session.begin_nested():
                        await self.session.execute(stmt, [c for c, _r, _u in items])
                except Exception:
                    for coerced, raw, is_update in items:
                        try:
                            async with self.session.begin_nested():
                                await self.session.execute(stmt, [coerced])
                        except Exception as exc:
                            _record_error(res, name, raw, exc)
                            continue
                        _count(res, is_update)
                    continue
                for _c, _r, is_update in items:
                    _count(res, is_update)


async def _import_table(
    session: AsyncSession, name: str, rows: list[dict[str, Any]], *, mode: str,
    pending: list[tuple[str, dict[str, Any], dict[str, Any]]] | None = None,
) -> TableResult:
    imp = _TableImporter(session, name, mode=mode, pending=pending)
    await imp.start()
    await imp.feed(rows)
    return imp.result


#: 匯入一批幾列
_IMPORT_BATCH = 1000


def _upsert_stmt(table: Any, cols: tuple[str, ...], pk_cols: list[str]) -> Any:
    stmt = pg_insert(table)
    update_cols = {c: stmt.excluded[c] for c in cols if c not in pk_cols}
    if update_cols:
        return stmt.on_conflict_do_update(index_elements=pk_cols, set_=update_cols)
    return stmt.on_conflict_do_nothing(index_elements=pk_cols)


def _count(res: TableResult, is_update: bool) -> None:
    if is_update:
        res.updated += 1
    else:
        res.inserted += 1


def _record_error(res: TableResult, name: str, raw: dict[str, Any], exc: Exception) -> None:
    res.errored += 1
    if len(res.errors) < 20:
        res.errors.append(f"{name} pk={raw.get('id', raw.get('key', '?'))}: {type(exc).__name__}: {exc}")


#: 匯出包裡就算有、也永遠不匯入的表（值是寫進報告的理由）。
#: 稽核記錄是**這台機器**的雜湊鏈：別台的歷史接不進來，同 id 的 upsert 會覆寫本機記錄，
#: 取代模式的清空會整段刪掉 —— 三種都會讓鏈斷掉（資料庫層也另有觸發器拒絕改寫）。
#: 匯出包裡的那份稽核記錄仍然是來源機器的完整備份，要查就看匯出檔本身。
NEVER_IMPORT: dict[str, str] = {
    "audit_logs": "append-only hash chain of this machine; never imported (the export file keeps the source copy)",
}


async def _wipe(session: AsyncSession, names: list[str], *, protect_user_id: uuid.UUID | None) -> None:
    """反相依序清空 in-scope 表；users 表保留目前登入 admin 那列。每表獨立 SAVEPOINT。"""
    for name in reversed(names):
        table = registry.table_by_name(name)
        try:
            async with session.begin_nested():
                stmt = delete(table)
                if name == "users" and protect_user_id is not None:
                    stmt = stmt.where(table.c.id != protect_user_id)
                await session.execute(stmt)
        except Exception:
            pass


async def apply_import(
    session: AsyncSession,
    inner: dict[str, Any],
    *,
    mode: str = "merge",
    dry_run: bool = False,
    scope: list[str] | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """套用匯入。回 report dict（各表計數 + 中央機密計數 + mode/dry_run）。"""
    if mode not in ("merge", "replace"):
        raise ValueError(f"unknown import mode: {mode!r}")
    tables_in = inner.get("tables") or {}
    central_in = inner.get("central_secrets") or []
    # 決定要處理哪些表：交集（匯出包有的 ∩ 相依序）；scope 未給則用匯出包內全部表
    ordered = registry.all_tablenames()
    present = [n for n in ordered if n in tables_in and n not in NEVER_IMPORT]

    report: dict[str, Any] = {"mode": mode, "dry_run": dry_run, "tables": {}}
    skipped = {n: NEVER_IMPORT[n] for n in NEVER_IMPORT if n in tables_in}
    if skipped:
        report["skipped"] = skipped

    if mode == "replace":
        await _wipe(session, present, protect_user_id=actor_user_id)

    pending: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for name in present:
        res = await _import_table(session, name, tables_in[name], mode=mode, pending=pending)
        report["tables"][name] = res.as_dict()

    if pending:
        fixed, errors = await _apply_deferred(session, pending)
        report["deferred_refs"] = {"fixed": fixed, "total": len(pending), "errors": errors}

    # 中央機密（encrypted_secrets）：以目標金鑰重加密後 upsert
    if central_in:
        report["central_secrets"] = await _import_central(session, central_in, mode=mode)

    if dry_run:
        await session.rollback()
    else:
        await session.commit()
    return report


async def _import_central(session: AsyncSession, entries: list[dict[str, Any]], *, mode: str) -> dict[str, Any]:
    table = registry.table_by_name(registry.ENCRYPTED_SECRETS_TABLE)
    res = TableResult()
    pk_cols = ["object_type", "object_id", "field", "key_id"]  # 業務唯一鍵（UniqueConstraint）
    for entry in entries:
        built = secrets.import_central_row(entry)
        if built is None:
            res.skipped += 1
            continue
        try:
            built["object_id"] = uuid.UUID(str(built["object_id"]))
            async with session.begin_nested():
                stmt = pg_insert(table).values(**built)
                stmt = stmt.on_conflict_do_update(
                    index_elements=pk_cols,
                    set_={"ciphertext": stmt.excluded.ciphertext, "nonce": stmt.excluded.nonce},
                )
                await session.execute(stmt)
            res.inserted += 1
        except Exception as exc:
            res.errored += 1
            if len(res.errors) < 20:
                res.errors.append(f"encrypted_secrets {entry.get('object_type')}: {type(exc).__name__}: {exc}")
    return res.as_dict()


async def apply_import_stream(
    session: AsyncSession,
    events: Any,
    *,
    counts: dict[str, int],
    mode: str = "merge",
    dry_run: bool = False,
    actor_user_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """與 apply_import 相同的匯入，但資料一批一批來（`streaming.iter_events`），不整份放進記憶體。

    匯入要照**本機**的外鍵相依序逐表寫。檔案裡的表若照這個順序排（同版或相鄰版本的匯出都是），
    每張表邊讀邊寫；某張表比它前面的表還早出現，才先把那張表暫存在記憶體，輪到它時再寫。
    `counts`（第一趟 `streaming.scan` 從檔案結尾取得）決定有哪些表 —— 取代模式只清空這些表，
    所以一定要有；沒有 counts 的檔案請走整份載入的 apply_import（每一版的匯出都有寫 counts）。

    **呼叫前必須已經用 `streaming.scan` 驗證過檔案**：取代模式一開始就清空資料表。
    第二趟結尾若標籤不符（檔案在兩趟之間被換掉），這裡會丟出例外，呼叫端不提交、整個還原。
    """
    if mode not in ("merge", "replace"):
        raise ValueError(f"unknown import mode: {mode!r}")
    ordered = registry.all_tablenames()
    in_file = set(counts) - {registry.ENCRYPTED_SECRETS_TABLE}
    present = [n for n in ordered if n in in_file and n not in NEVER_IMPORT]
    rank = {n: i for i, n in enumerate(present)}

    report: dict[str, Any] = {"mode": mode, "dry_run": dry_run, "tables": {}}
    skipped = {n: NEVER_IMPORT[n] for n in NEVER_IMPORT if n in counts}

    if mode == "replace":
        await _wipe(session, present, protect_user_id=actor_user_id)

    pending: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    done: set[str] = set()
    seen: set[str] = set()
    held: dict[str, list[dict[str, Any]]] = {}
    central: list[dict[str, Any]] = []

    def ready(name: str) -> bool:
        return all(p in done for p in present[:rank[name]])

    async def run_held() -> None:
        progressed = True
        while progressed:
            progressed = False
            for name in [n for n in present if n in held]:
                if ready(name):
                    imp = _TableImporter(session, name, mode=mode, pending=pending)
                    await imp.start()
                    await imp.feed(held.pop(name))
                    report["tables"][name] = imp.result.as_dict()
                    done.add(name)
                    progressed = True

    current: _TableImporter | None = None
    holding: str | None = None
    for ev in events:
        kind = ev[0]
        if kind == "table":
            name = ev[1]
            seen.add(name)
            if name in NEVER_IMPORT:
                skipped[name] = NEVER_IMPORT[name]
            if name not in rank:
                continue                                 # 本機沒有這張表（或永不匯入）：略過
            if ready(name):
                current = _TableImporter(session, name, mode=mode, pending=pending)
                await current.start()
            else:
                holding = name
                held[name] = []
        elif kind == "rows":
            name = ev[1]
            if current is not None and current.name == name:
                await current.feed(ev[2])
            elif holding == name:
                held[name].extend(ev[2])
        elif kind == "end":
            name = ev[1]
            if current is not None and current.name == name:
                report["tables"][name] = current.result.as_dict()
                done.add(name)
                current = None
            elif holding == name:
                holding = None
            await run_held()
        elif kind == "key" and ev[1] == "central_secrets" and isinstance(ev[2], list):
            central = ev[2]

    # 讀完了（標籤也驗過了）：counts 說有、但檔案裡其實沒有的表視同空表，讓排在後面的暫存表能寫
    done |= {n for n in present if n not in seen}
    await run_held()
    for name in [n for n in present if n in held]:      # 理論上不會到這裡；保險起見照順序寫完
        imp = _TableImporter(session, name, mode=mode, pending=pending)
        await imp.start()
        await imp.feed(held.pop(name))
        report["tables"][name] = imp.result.as_dict()

    if skipped:
        report["skipped"] = skipped
    if pending:
        fixed, errors = await _apply_deferred(session, pending)
        report["deferred_refs"] = {"fixed": fixed, "total": len(pending), "errors": errors}
    if central:
        report["central_secrets"] = await _import_central(session, central, mode=mode)

    if dry_run:
        await session.rollback()
    else:
        await session.commit()
    return report


async def import_file(
    session: AsyncSession,
    path: Any,
    passphrase: str,
    *,
    mode: str = "merge",
    dry_run: bool = False,
    actor_user_id: uuid.UUID | None = None,
    scanned: Any = None,
) -> dict[str, Any]:
    """從匯出檔匯入（上傳端點、背景作業與 CLI 共用）：先驗證，再串流匯入。

    `scanned` 是已經做過的 `streaming.scan` 結果（分析步驟做過就不必再做一次）。
    驗證在執行緒裡跑：解密＋解壓整份檔案要好幾秒，不該卡住事件迴圈。
    """
    import asyncio
    import json
    from pathlib import Path

    from app.services.system_transfer import crypto, streaming

    if scanned is None:
        scanned = await asyncio.to_thread(streaming.scan, path, passphrase)
    if scanned.counts is None:
        # 沒有 counts 的檔案（目前沒有任何一版這樣寫）：照舊整份載入
        def _load() -> dict[str, Any]:
            return crypto.open_envelope(json.loads(Path(path).read_bytes().decode("utf-8")), passphrase)
        inner = await asyncio.to_thread(_load)
        return await apply_import(session, inner, mode=mode, dry_run=dry_run, actor_user_id=actor_user_id)
    return await apply_import_stream(
        session, streaming.iter_events(path, passphrase), counts=scanned.counts,
        mode=mode, dry_run=dry_run, actor_user_id=actor_user_id,
    )
