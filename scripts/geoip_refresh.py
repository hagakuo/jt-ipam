#!/usr/bin/env python3
"""GeoIP mmdb 排程更新：由 jt-ipam-geoip-refresh.timer 每日觸發。

依系統設定的 auto_update + frequency 判斷是否到期，到期才向 MaxMind 下載。
（與 scripts/oui_refresh.py 同套路：自帶 async session，讀 backend.env。）
"""
from __future__ import annotations

import asyncio
import sys


async def _main() -> int:
    from app.core.db import SessionLocal, engine
    from app.services.background_tasks import record_refresh
    from app.services.geoip import maybe_scheduled_update, update_outcome

    try:
        async with SessionLocal() as session:
            result = await maybe_scheduled_update(session)
            print(f"[geoip_refresh] {result}")
            if not isinstance(result, dict) or result.get("skipped"):
                return 0        # 沒開自動更新或還沒到期：跟沒輪到的整合一樣，不留作業記錄
            ok, err = update_outcome(result)
            await record_refresh(session, "geoip.refresh", ok=ok, summary=result, error=err)
            # 有錯誤回非零，讓 systemd 標記失敗
            return 0 if ok else 1
    finally:
        # 短命腳本要放掉連線池，否則結束時的清理會讓 systemd 把每次都記成失敗（見 jt-ipam-sync.py）
        await engine.dispose()


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
