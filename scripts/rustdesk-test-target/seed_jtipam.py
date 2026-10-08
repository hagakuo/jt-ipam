"""把 RustDesk 測試靶接到一個拋棄式的 jt-ipam 開發資料庫（只接受名稱以 _e2e 或 _test 結尾的資料庫）。

正式環境是 RustDesk 代理回報裝置、jt-ipam 自己對應到 IP 記錄；測試靶沒有代理，所以直接寫這幾筆：
- RustDesk 伺服器「rdtest」：公鑰、開放網頁連線、hbbs 位址（中繼位址留空＝hbbs 主機＋21117）
- 一筆 IP 記錄（RFC 5737 文件範圍 198.51.100.77）開啟 RustDesk 連線
- 受控端的 RustDesk ID 對應到這筆 IP（match_status = matched）

用法（在 backend 目錄）：
    set -a; . ../.dev.env; set +a
    POSTGRES_DB=jt_ipam_rd_e2e .venv/bin/python ../scripts/rustdesk-test-target/seed_jtipam.py \\
        --peer-id 123456789 --key '<伺服器公鑰>' --hbbs 172.18.0.2 [--transport ws]
重跑會更新同一批資料。
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))


def _guard() -> None:
    name = os.environ.get("POSTGRES_DB", "")
    if not name.endswith(("_e2e", "_test")):
        raise SystemExit(f"POSTGRES_DB={name!r}：只能對 *_e2e／*_test 的拋棄式資料庫跑")
    # 發版 e2e 共用的那一個不行：這裡建的 198.51.100.0/24 會跟 seed_e2e 的子網路重複，
    # 下拉選單出現兩個同名選項，好幾個 spec 跟著失敗（2026-10-05 踩過）
    if name == "jt_ipam_e2e":
        raise SystemExit("POSTGRES_DB=jt_ipam_e2e 是發版 e2e 共用的資料庫，請另建一個（例如 jt_ipam_rd_e2e）")


async def seed(peer_id: str, key: str, hbbs: str, transport: str) -> None:
    from sqlalchemy import select

    from app.core.db import SessionLocal
    from app.models.address import IPAddress
    from app.models.rustdesk import RustDeskPeer, RustDeskServer
    from app.models.section import Section
    from app.models.subnet import Subnet

    async with SessionLocal() as s:
        sec = (await s.execute(select(Section).where(Section.name == "rdtest"))).scalars().first()
        if sec is None:
            sec = Section(name="rdtest", description="RustDesk 測試靶")
            s.add(sec)
            await s.flush()
        sub = (await s.execute(select(Subnet).where(Subnet.section_id == sec.id))).scalars().first()
        if sub is None:
            sub = Subnet(section_id=sec.id, cidr="198.51.100.0/24", description="RustDesk 測試靶")
            s.add(sub)
            await s.flush()
        ip = (await s.execute(select(IPAddress).where(IPAddress.subnet_id == sub.id))).scalars().first()
        if ip is None:
            ip = IPAddress(subnet_id=sub.id, ip="198.51.100.77", hostname="rdtest-client", state="active")
            s.add(ip)
        ip.rustdesk_enabled = True
        await s.flush()
        srv = (await s.execute(select(RustDeskServer).where(RustDeskServer.name == "rdtest"))).scalars().first()
        if srv is None:
            srv = RustDeskServer(name="rdtest")
            s.add(srv)
        srv.public_key = key
        srv.web_enabled = True
        srv.web_file_transfer = True      # 附錄 J：網頁檔案傳輸（正式站台預設關）
        srv.hbbs_host = hbbs
        srv.relay_host = None
        srv.transport = transport
        srv.enabled = True
        srv.description = "RustDesk 測試靶（scripts/rustdesk-test-target）"
        await s.flush()
        for old in (await s.execute(select(RustDeskPeer).where(RustDeskPeer.server_id == srv.id))).scalars():
            if old.rustdesk_id != peer_id:
                await s.delete(old)
        peer = (await s.execute(select(RustDeskPeer).where(
            RustDeskPeer.server_id == srv.id, RustDeskPeer.rustdesk_id == peer_id))).scalars().first()
        if peer is None:
            peer = RustDeskPeer(server_id=srv.id, rustdesk_id=peer_id)
            s.add(peer)
        peer.online = True
        peer.address_id = ip.id
        peer.match_status = "matched"
        peer.hostname = "rdtest-client"
        await s.commit()
        print(f"ip_id={ip.id} server_id={srv.id} peer={peer_id}")


def main() -> None:
    _guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("--peer-id", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--hbbs", required=True, help="後端連 hbbs 用的位址（可帶 :埠）")
    ap.add_argument("--transport", choices=("tcp", "ws"), default="tcp")
    a = ap.parse_args()
    asyncio.run(seed(a.peer_id, a.key, a.hbbs, a.transport))


if __name__ == "__main__":
    main()
