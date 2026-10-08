"""CLI：全系統匯出／匯入（跨機搬移）。

與管理區 UI 共用同一 service 層（app.services.system_transfer），供 headless 搬移／自動化用。

用法：
    # 匯出（互動式輸入密碼；或 --passphrase-stdin 從 stdin 讀一行）
    python -m app.cli.system_transfer export \
        --scope settings,users_rbac,core,integrations \
        --out /path/backup.json --passphrase-stdin

    # 匯入（先預覽再套用；replace 會清空 in-scope 表）
    python -m app.cli.system_transfer import --file backup.json --mode merge --dry-run
    python -m app.cli.system_transfer import --file backup.json --mode merge

OWASP A07：密碼只從 TTY / stdin 讀，不接受命令列參數（避免留在 shell history）。

註：終端輸出一律英文（比照 app.cli.bootstrap，客戶終端可能非中文環境）。
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import secrets as _rng
import sys
from datetime import UTC, datetime

from sqlalchemy import text

from app.core.db import SessionLocal
from app.services.system_transfer import crypto, exporter, importer, registry, streaming
from app.version import __version__


def _read_passphrase(from_stdin: bool, *, confirm: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    pw = getpass.getpass("Passphrase: ")
    if confirm:
        pw2 = getpass.getpass("Confirm:    ")
        if pw != pw2:
            print("[error] passphrases do not match", file=sys.stderr)
            raise SystemExit(1)
    return pw


async def _schema_version() -> str | None:
    async with SessionLocal() as session:
        try:
            row = (await session.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))).first()
            return row[0] if row else None
        except Exception:
            return None


async def _build(scope: list[str]) -> tuple[bytes, dict[str, int], str | None]:
    """串流匯出（邊讀邊壓縮）：回 (gzip 後的 inner JSON, 各表筆數, schema 版本)。"""
    schema_version = await _schema_version()
    async with SessionLocal() as session:
        raw, counts = await exporter.export_compressed(session, scope)
    return raw, counts, schema_version


def _export(scope: list[str], out: str, passphrase: str) -> int:
    bad = [s for s in scope if s not in registry.SCOPES]
    if bad:
        print(f"[error] unknown scope(s): {', '.join(bad)}", file=sys.stderr)
        print(f"        valid: {', '.join(registry.SCOPES)}", file=sys.stderr)
        return 1
    raw, counts, schema_version = asyncio.run(_build(scope))
    import os
    # 一建立就是 0600（先寫再 chmod 的話，中間有一段時間是依 umask 的權限）
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        size = crypto.write_sealed(
            f, raw, passphrase,
            metadata={
                "app_version": __version__, "schema_version": schema_version,
                "scope": scope, "exported_at": datetime.now(UTC).isoformat(),
            },
            rng=_rng,
        )
    print(f"[ok] exported {sum(counts.values())} rows across {len(counts)} tables "
          f"→ {out} ({size} bytes)")
    for name, n in sorted(counts.items()):
        if n:
            print(f"       {name}: {n}")
    return 0


async def _apply(file: str, passphrase: str, scanned: streaming.ScanResult, mode: str, dry_run: bool) -> dict:
    async with SessionLocal() as session:
        return await importer.import_file(session, file, passphrase, mode=mode, dry_run=dry_run,
                                          scanned=scanned)


def _import(file: str, mode: str, dry_run: bool, passphrase: str) -> int:
    # 先逐段驗證（密碼、完整性），再串流匯入 —— 不把整份檔案讀進記憶體
    try:
        scanned = streaming.scan(file, passphrase)
    except crypto.TransferCryptoError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[error] cannot read {file}: {exc}", file=sys.stderr)
        return 1
    meta = scanned.metadata

    print(f"[info] source app_version={meta.get('app_version')} schema={meta.get('schema_version')} "
          f"scope={','.join(meta.get('scope') or [])}")
    try:
        report = asyncio.run(_apply(file, passphrase, scanned, mode, dry_run))
    except crypto.TransferCryptoError as exc:          # 兩趟之間檔案被換掉：交易已還原
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    tag = "DRY-RUN (nothing written)" if dry_run else "APPLIED"
    print(f"[ok] import {tag}  mode={mode}")
    tot = {"inserted": 0, "updated": 0, "skipped": 0, "errored": 0}
    for name, r in sorted(report["tables"].items()):
        for k in tot:
            tot[k] += r.get(k, 0)
        if any(r.get(k) for k in tot):
            print(f"       {name}: +{r['inserted']} ~{r['updated']} skip{r['skipped']} err{r['errored']}")
    # 這裡只有筆數（加密機密一律不會出現在報告裡）；先轉成數字再印，記錄工具也看得出不是機密內容
    counts = report.get("central_secrets") or {}
    if counts:
        n_ins, n_skip, n_err = (int(counts.get(k, 0)) for k in ("inserted", "skipped", "errored"))
        print(f"       encrypted_secrets: +{n_ins} skip{n_skip} err{n_err}")
    print(f"[total] inserted={tot['inserted']} updated={tot['updated']} "
          f"skipped={tot['skipped']} errored={tot['errored']}")
    return 1 if tot["errored"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="jt-ipam-transfer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_exp = sub.add_parser("export", help="Export system config + data to an encrypted file")
    p_exp.add_argument("--scope", default=",".join(registry.DEFAULT_SCOPE),
                       help=f"comma-separated categories (default: {','.join(registry.DEFAULT_SCOPE)}; "
                            f"valid: {','.join(registry.SCOPES)})")
    p_exp.add_argument("--out", required=True, help="output file path")
    p_exp.add_argument("--passphrase-stdin", action="store_true",
                       help="read passphrase from stdin (one line); otherwise prompt")

    p_imp = sub.add_parser("import", help="Import a previously exported file into this instance")
    p_imp.add_argument("--file", required=True, help="export file path")
    p_imp.add_argument("--mode", choices=("merge", "replace"), default="merge",
                       help="merge=upsert by id (default); replace=wipe in-scope tables first")
    p_imp.add_argument("--dry-run", action="store_true", help="preview counts, write nothing")
    p_imp.add_argument("--passphrase-stdin", action="store_true",
                       help="read passphrase from stdin (one line); otherwise prompt")

    args = parser.parse_args(argv)

    if args.cmd == "export":
        pw = _read_passphrase(args.passphrase_stdin, confirm=True)
        if len(pw) < 8:
            print("[error] passphrase must be ≥ 8 characters", file=sys.stderr)
            return 1
        scope = [s.strip() for s in args.scope.split(",") if s.strip()]
        return _export(scope, args.out, pw)

    if args.cmd == "import":
        pw = _read_passphrase(args.passphrase_stdin, confirm=False)
        return _import(args.file, args.mode, args.dry_run, pw)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
