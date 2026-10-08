"""Recog 指紋資料庫的 CLI —— 安裝／升級腳本、每週排程（jt-ipam-recog-refresh.timer）與離線站台用。

    python -m app.cli.recog update            # 沒裝就裝；有新版就換；已是最新只記錄檢查時間
    python -m app.cli.recog update --force    # 同一版也重新下載匯入
    python -m app.cli.recog update --file recog-content-3.2.0.zip   # 離線：用手上的發佈檔
    python -m app.cli.recog status

選用元件：失敗時回非零、印出原因，但**不會**動到已安裝的那一版；安裝腳本只警告、不中斷。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from pathlib import Path

from app.core.db import SessionLocal, engine
from app.services import recog


async def _update(force: bool, file: str | None, version: str | None) -> int:
    async with SessionLocal() as session:
        if file:
            path = Path(file)
            try:
                data = await asyncio.to_thread(path.read_bytes)
            except OSError as exc:
                print(f"error\tcannot read {file}: {exc}")
                return 1
            ver = version or recog.version_from_filename(path.name) or f"local-{hashlib.sha256(data).hexdigest()[:8]}"
            try:
                res = await recog.install_bundle(session, data, version=ver, source=f"file:{path.name}")
            except recog.RecogError as exc:
                await session.rollback()
                print(f"error\t{exc}")
                return 1
            await session.commit()
            print(f"updated\t{res['release']}\t{res['fingerprints']} fingerprints ({res['skipped']} skipped)")
            return 0
        res = await recog.check_and_update(session, force=force)
        await session.commit()
        # 作業頁看得到這次檢查（每週 timer 跑的就是這裡；已是最新也算一次成功的檢查）
        from app.services.background_tasks import record_refresh
        await record_refresh(session, "recog.refresh", ok=res["status"] != "error", error=res.get("error"),
                             summary={k: res.get(k) for k in ("status", "release", "previous", "latest",
                                                               "databases", "fingerprints", "skipped")})
    if res["status"] == "error":
        print(f"error\t{res['error']}" + (f"\t(installed: {res['release']})" if res.get("release") else ""))
        return 1
    if res["status"] == "updated":
        print(f"updated\t{res.get('previous') or '-'} -> {res['release']}\t"
              f"{res['fingerprints']} fingerprints ({res['skipped']} skipped)")
    else:
        print(f"up_to_date\t{res['release']}")
    return 0


async def _status() -> int:
    async with SessionLocal() as session:
        st = await recog.status(session)
    if not st["installed"]:
        print("not_installed" + (f"\tlast error: {st['error']}" if st.get("error") else ""))
        return 1
    print(f"installed\t{st['release']}\t{st['fingerprints']} fingerprints\tchecked {st.get('checked_at') or '-'}"
          + (f"\tlast error: {st['error']}" if st.get("error") else ""))
    return 0


async def _run(coro) -> int:
    try:
        return await coro
    finally:
        # 短命腳本用 async engine：不 dispose 的話，結束時連線池的清理會噴例外或卡住
        try:
            await engine.dispose()
        except Exception as exc:  # 收尾失敗不可以蓋掉主要結果
            print(f"warning\tengine dispose failed: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli.recog", description="Recog fingerprint database")
    sub = ap.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("update", help="install or update from GitHub (or from --file)")
    up.add_argument("--force", action="store_true", help="re-import even if the installed release is the latest")
    up.add_argument("--file", help="install from a downloaded recog-content-*.zip (offline hosts)")
    up.add_argument("--version", help="release name to record with --file (default: taken from the file name)")
    sub.add_parser("status", help="show the installed release")
    args = ap.parse_args(argv)
    if args.cmd == "update":
        return asyncio.run(_run(_update(args.force, args.file, args.version)))
    return asyncio.run(_run(_status()))


if __name__ == "__main__":
    sys.exit(main())
