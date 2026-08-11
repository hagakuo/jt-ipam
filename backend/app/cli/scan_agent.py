"""掃描代理的 CLI —— 給安裝腳本在 jt-ipam 主機上自動建立「本機代理」用。

為什麼需要這支：掃描一律要有代理，而全新安裝時還沒有任何登入者可以去 UI 按「新增代理」
取得金鑰。安裝腳本需要一個不必登入、可重複執行的方式拿到金鑰。

`ensure-local` 是**冪等**的：
- 本機代理已存在且金鑰還在 → 什麼都不做，回報 `exists`（不重發金鑰，免得把跑著的代理踢掉）
- 已存在但沒有金鑰（早期資料）→ 重發一把
- 不存在 → 建立並印出金鑰

金鑰只在建立／重發當下印出一次（資料庫只存 SHA-256）。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import secrets
import socket
import subprocess
import sys

from sqlalchemy import select

from app.core import scan_probes
from app.core.db import SessionLocal
from app.models.scan_agent import ScanAgent


def _key_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _own_addresses() -> set[str]:
    """這台主機自己的 IP（含 loopback）—— 用來認出「已經裝在本機的那個代理」。"""
    addrs = {"127.0.0.1", "::1"}
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"],  # noqa: S607 - 固定指令、無使用者輸入
                             capture_output=True, text=True, timeout=5, check=False).stdout
        for line in out.splitlines():
            parts = line.split()
            if "inet" in parts or "inet6" in parts:
                for i, tok in enumerate(parts):
                    if tok in ("inet", "inet6") and i + 1 < len(parts):
                        addrs.add(parts[i + 1].split("/")[0])
    except Exception:  # 拿不到就只用 loopback，不要因此中斷安裝
        pass
    return addrs


async def _ensure_local(name: str | None) -> int:
    agent_name = (name or socket.gethostname() or "local").strip()[:128]
    async with SessionLocal() as session:
        existing = (await session.execute(
            select(ScanAgent).where(ScanAgent.is_local.is_(True)).order_by(ScanAgent.created_at)
        )).scalars().first()

        # 還沒有標記過，但這台上其實早就手動裝了一個代理（升級的站台幾乎都是這樣）：
        # 認領它，不要再建第二個 —— 兩個代理搶同一批子網路只會讓人一頭霧水。
        if existing is None:
            mine = _own_addresses()
            adopted = (await session.execute(
                select(ScanAgent).where(ScanAgent.last_source_ip.in_(mine))
                .order_by(ScanAgent.created_at)
            )).scalars().first()
            if adopted is not None:
                adopted.is_local = True
                await session.commit()
                print(f"adopted\t{adopted.name}")
                return 0

        if existing is not None and existing.enroll_key_hash:
            # 已經有金鑰就不重發：重發會讓正在跑的代理當場失效
            print(f"exists\t{existing.name}")
            return 0

        raw_key = secrets.token_urlsafe(32)
        if existing is not None:
            existing.enroll_key_hash = _key_hash(raw_key)
            obj = existing
        else:
            # 同名的非本機代理已存在時退讓，避免撞到 name 的唯一鍵
            clash = (await session.execute(
                select(ScanAgent).where(ScanAgent.name == agent_name)
            )).scalars().first()
            if clash is not None:
                agent_name = f"{agent_name}-local"
            obj = ScanAgent(
                name=agent_name,
                description="jt-ipam 主機本機代理（安裝時自動建立）",
                enabled=True,
                is_local=True,
                enroll_key_hash=_key_hash(raw_key),
                enabled_probes=list(scan_probes.DEFAULT_AGENT_PROBES),
            )
            session.add(obj)
        await session.commit()
        print(f"created\t{obj.name}\t{raw_key}")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="jt-ipam scan agent CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ensure = sub.add_parser("ensure-local",
                            help="create the local scan agent if missing; print its key once")
    ensure.add_argument("--name", default=None, help="agent name (default: hostname)")
    args = ap.parse_args()
    if args.cmd == "ensure-local":
        return asyncio.run(_ensure_local(args.name))
    return 2


if __name__ == "__main__":
    sys.exit(main())
