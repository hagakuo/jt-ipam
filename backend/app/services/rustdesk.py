"""RustDesk Server（開源版）整合：專用代理的金鑰、寫入代理的回報、把 ID 保守地對應到 IP 記錄、組連線網址。

**對應規則（不確定就不對應，寧可少對也不要對錯）**
hbbs 存的 IP 是那台客戶端最後一次註冊時、hbbs 看到的來源位址。它可能是：
- 內網真實位址（RustDesk 伺服器在內網、客戶端直連）→ 可以用
- NAT 回流後的防火牆位址（客戶端用對外網域連回來）→ 所有客戶端看起來是同一個 IP，不能用
- 公網位址（家裡、分公司）→ 不在管理網段，不能用
- 舊位址（客戶端離線很久，DHCP 早就把位址發給別台）→ 不能用

所以要同時符合：登記 IP 只落在一筆 IP 記錄（重疊網段不猜）、這個 ID 最近 7 天內被 jt-ipam 看到上線、
同一個登記 IP 不超過 2 個 ID（2 個時只對應唯一上線的那個）。
"""
from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import String, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.core.sqlin import in_values
from app.models.address import IPAddress
from app.models.encrypted_secret import EncryptedSecret
from app.models.rustdesk import (
    PEER_DELETE_RESULTS,
    RustDeskPeer,
    RustDeskPeerDelete,
    RustDeskServer,
)

STALE_FACTOR = 3
#: 客戶端每 15 秒送一次心跳（只送給設了 API 伺服器的客戶端）；這段時間內收過就算在線，hbbs 說離線也一樣。
#: hbbs 的線上狀態只看 30 秒內有沒有 UDP 註冊：UDP 掉包、走 TCP／WebSocket 連 hbbs 的客戶端都會被說成離線
HEARTBEAT_FRESH = timedelta(seconds=45)

# ── 專用代理（agent/jt_ipam_rustdesk_agent.py）─────────────────────────────────

AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"
AGENT_FILE = AGENT_DIR / "jt_ipam_rustdesk_agent.py"
AGENT_INSTALLER = AGENT_DIR / "jt-ipam-rustdesk-agent-installer.sh"
#: 代理多久問一次設定。只是一個很小的 GET 等級請求；短一點「立即同步」「測試」才等得下去
AGENT_POLL_SECONDS = 10
#: 超過這麼久沒輪詢 ＝ 代理離線（畫面與「測試」用）
AGENT_OFFLINE_AFTER = timedelta(seconds=AGENT_POLL_SECONDS * 6)
#: 「測試」沒有在這段時間內拿到結果就算逾時（代理離線、卡住）
TEST_TIMEOUT = timedelta(seconds=60)
_SECRET_TYPE, _SECRET_FIELD = "rustdesk_server", "agent_key"


_OS_TAIL = re.compile(r"\s+-\s+[\d.]+\s*\(\d+\)\s*$")
_LINUX_DETAIL = re.compile(r"^linux\s+(\d[\w.-]*)\s+(.+)$", re.I)
_LINUX_NO_VERSION = re.compile(r"^linux\s+(\D.*)$", re.I)


def os_display(raw: str | None) -> str | None:
    """客戶端回報的作業系統字串 → 給人看的寫法（跟前端 utils/rustdeskOs.ts 同一套規則）。

    「windows / Windows 11 Pro - 11 (26200)」→「Windows 11 Pro」；「ubuntu / Linux 24.04 Ubuntu」→「Ubuntu 24.04」
    （Linux 的原文是「Linux <版本> <發行版>」，使用者 2026-10-07 指出順序怪）。
    """
    if not raw or not str(raw).strip():
        return None
    plat, sep, rest = str(raw).partition(" / ")
    detail = _OS_TAIL.sub("", (rest if sep else plat)).strip()
    m = _LINUX_DETAIL.match(detail)
    if m:
        return f"{m.group(2).strip()} {m.group(1)}"
    n = _LINUX_NO_VERSION.match(detail)
    if n:
        return n.group(1).strip()
    return detail or None


def new_agent_key() -> str:
    return secrets.token_urlsafe(32)


def agent_key_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _key_aad(server_id: uuid.UUID) -> bytes:
    # 與 system_transfer 的 central_secret_aad 同一個格式：搬到別台後解得開
    return f"{_SECRET_TYPE}:{server_id}:{_SECRET_FIELD}".encode()


async def save_agent_key(session: AsyncSession, server: RustDeskServer, raw: str) -> None:
    """金鑰只存雜湊給代理認證；明文加密另存，讓管理員之後還能再看到安裝指令。"""
    server.agent_key_hash = agent_key_hash(raw)
    enc, nonce = encrypt_secret(raw, aad=_key_aad(server.id))
    row = (await session.execute(select(EncryptedSecret).where(
        EncryptedSecret.object_type == _SECRET_TYPE, EncryptedSecret.object_id == server.id,
        EncryptedSecret.field == _SECRET_FIELD))).scalar_one_or_none()
    if row is None:
        session.add(EncryptedSecret(object_type=_SECRET_TYPE, object_id=server.id, field=_SECRET_FIELD,
                                    ciphertext=enc, nonce=nonce))
    else:
        row.ciphertext, row.nonce = enc, nonce


async def load_agent_key(session: AsyncSession, server_id: uuid.UUID) -> str | None:
    row = (await session.execute(select(EncryptedSecret).where(
        EncryptedSecret.object_type == _SECRET_TYPE, EncryptedSecret.object_id == server_id,
        EncryptedSecret.field == _SECRET_FIELD))).scalar_one_or_none()
    if row is None:
        return None
    return decrypt_secret(row.ciphertext, row.nonce, aad=_key_aad(server_id)).decode("utf-8")


async def delete_agent_key(session: AsyncSession, server_id: uuid.UUID) -> None:
    await session.execute(delete(EncryptedSecret).where(
        EncryptedSecret.object_type == _SECRET_TYPE, EncryptedSecret.object_id == server_id))


def agent_sha() -> str:
    try:
        return hashlib.sha256(AGENT_FILE.read_bytes()).hexdigest()
    except OSError:
        return ""


def agent_latest_version() -> str | None:
    try:
        m = re.search(r'^AGENT_VERSION\s*=\s*"([0-9][^"]*)"', AGENT_FILE.read_text(encoding="utf-8"), re.M)
    except OSError:
        return None
    return m.group(1) if m else None
#: 最近幾天內被看到上線，才拿它的登記 IP 對應 IP 記錄
MATCH_FRESH = timedelta(days=7)
#: 同一個登記 IP 有這麼多個以上的 ID ＝ NAT 回流
NAT_SHARED = 3


def _parse_created(value: str | None) -> datetime | None:
    """hbbs 的 created_at 是 SQLite current_timestamp（UTC，'YYYY-MM-DD HH:MM:SS'）。"""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace(" ", "T"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def connect_uri(server: RustDeskServer, rustdesk_id: str) -> str:
    """叫出使用者電腦上 RustDesk 客戶端的網址。**不放密碼**（會留在瀏覽器歷程與作業系統的處理程式紀錄）。

    有設客戶端用的伺服器位址就帶 `<id>@<位址>?key=<公鑰>`，客戶端不用事先設定這台伺服器；
    沒設就只帶 ID，客戶端用它自己設定的伺服器。
    """
    if server.client_address:
        uri = f"rustdesk://connect/{rustdesk_id}@{server.client_address}"
        return f"{uri}?key={server.public_key}" if server.public_key else uri
    return f"rustdesk://connect/{rustdesk_id}"


async def ingest_report(session: AsyncSession, server: RustDeskServer, report: dict[str, Any],
                        now: datetime | None = None) -> dict[str, Any]:
    """寫入代理的回報。資料庫讀不到就說讀不到、不清資料；查不到線上狀態就保留上一次的。"""
    now = now or datetime.now(UTC)
    db = (report.get("files") or {}).get("db") or {}
    db_ok, truncated = bool(db.get("ok")), bool(db.get("truncated"))
    online_ok = bool(report.get("online_ok"))
    server.last_report_at = now
    server.file_status = {"db": {k: db.get(k) for k in ("path", "ok", "error", "truncated")}}
    if report.get("version"):
        server.server_version = str(report["version"])[:32]
    if report.get("public_key"):
        server.public_key = str(report["public_key"])

    problems: list[str] = []
    if not db_ok:
        problems.append(f"{db.get('path') or 'db_v2.sqlite3'}: {db.get('error') or 'not readable'}")
    if not online_ok and report.get("peers"):
        problems.append(f"online status: {report.get('online_error') or 'query failed'}")
    if truncated:
        problems.append("too many devices: only the first part was read; nothing was removed")
    server.last_error = "; ".join(problems) or None

    if not db_ok:
        await session.flush()
        return {"peers": None, "online": None, "matched": None, "error": server.last_error}

    existing = {p.rustdesk_id: p for p in (await session.execute(
        select(RustDeskPeer).where(RustDeskPeer.server_id == server.id))).scalars().all()}
    seen: set[str] = set()
    for row in report.get("peers") or []:
        rid = str(row["id"])
        if rid in seen:
            continue
        seen.add(rid)
        p = existing.get(rid)
        if p is None:
            p = RustDeskPeer(server_id=server.id, rustdesk_id=rid)
            session.add(p)
            existing[rid] = p
        p.registered_ip = row.get("ip") or None
        p.first_registered_at = _parse_created(row.get("created_at"))
        if online_ok and row.get("online") is not None:
            # 兩個訊號合併：hbbs 說在線，或剛剛還收到心跳。以前只信 hbbs，在線的裝置每 5 分鐘被改成離線、
            # 下一個心跳又改回上線（使用者 2026-10-06：「明明都在線上，有時會變離線」）
            beat = p.last_heartbeat_at is not None and now - p.last_heartbeat_at <= HEARTBEAT_FRESH
            p.online = bool(row["online"]) or beat
            if row["online"]:
                p.last_online_at = now
    removed = 0
    if not truncated:
        gone = [p.id for rid, p in existing.items() if rid not in seen and p.id is not None]
        if gone:
            removed = (await session.execute(delete(RustDeskPeer).where(in_values(RustDeskPeer.id, gone)))).rowcount
        existing = {rid: p for rid, p in existing.items() if rid in seen}
    await session.flush()

    matched = await _match(session, list(existing.values()), now)
    await _report_hostnames(session, server, list(existing.values()), complete=not truncated)
    online = sum(1 for p in existing.values() if p.online)
    server.last_summary = {"peers": len(existing), "online": online, "matched": matched,
                           "removed": removed, "online_ok": online_ok, "truncated": truncated}
    await session.flush()
    return {"peers": len(existing), "online": online, "matched": matched, "removed": removed,
            "error": server.last_error}


# 常見的預設主機名稱：很多台同名，拿來比對只會配錯
GENERIC_HOSTNAMES = frozenset({
    "localhost", "ubuntu", "debian", "raspberrypi", "desktop", "laptop", "pc", "user", "admin", "root",
    "linux", "windows", "computer", "rustdesk", "kali", "fedora", "centos", "archlinux", "android",
    "iphone", "ipad", "macbook", "mac", "host", "server", "workstation", "none", "unknown",
})


def _short_host(name: str | None) -> str | None:
    """主機名稱正規化成可比對的短名；常見預設名與太短的回 None（不拿來比）。"""
    if not name:
        return None
    s = name.strip().lower().split(".")[0]
    if len(s) < 3 or s in GENERIC_HOSTNAMES:
        return None
    return s


def _ip_str(v: Any) -> str | None:
    return str(v).split("/")[0] if v else None


def _usable_hostname(name: str | None) -> str | None:
    """客戶端自報的名稱要當 IP 的主機名稱時：不收空白、控制字元、太長的，也不收常見的預設名。"""
    s = (name or "").strip()
    if not s or len(s) > 253 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in s):
        return None
    return s if _short_host(s) else None


async def _report_hostnames(session: AsyncSession, server: RustDeskServer, peers: list[RustDeskPeer], *,
                            complete: bool) -> dict[str, Any]:
    """已對應到 IP 記錄的裝置，把客戶端回報的主機名稱報給主機名稱多來源機制（來源 `rustdesk`）。

    優先序預設排最後（客戶端自己說的、誰都能改自己電腦的名字），所以只在其他來源都沒有名稱時才會顯示；
    裝置不再對應（換了位址、離線太久）時，下一輪完整回報就收回。
    """
    from app.services.hostname_reports import HostnameRun, enabled_peers

    names: dict[uuid.UUID, str] = {}
    for p in peers:
        if p.match_status == "matched" and p.address_id and (hn := _usable_hostname(p.hostname)):
            names[p.address_id] = hn
    run = HostnameRun(session, source="rustdesk", origin=f"rustdesk:{server.id}",
                      peers=await enabled_peers(session, RustDeskServer))
    if names:
        for ip in (await session.execute(select(IPAddress).where(in_values(IPAddress.id, list(names))))).scalars():
            run.report(ip, names[ip.id])
    return await run.finish(complete=complete)


async def _match(session: AsyncSession, peers: list[RustDeskPeer], now: datetime) -> int:
    """多訊號對應（使用者 2026-10-04：「要多個條件比對」）。

    IP 訊號找候選記錄：心跳的來源位址（內網直連、當下的真實位址）優先於 hbbs 的登記 IP；
    主機名稱用來確認或否決：相符 → 依據多一項；不符而且只有登記 IP 可以判斷 → 不關聯（conflict，多半是 DHCP
    位址換了主人）；心跳剛從那個位址送來時以位址為準，名稱不同不擋；
    IP 對不上、只有主機名稱唯一相符 → 只給建議（hostname_only），不關聯。
    """
    from app.models.device import Device

    # 「同一個登記 IP 有幾個 ID」只算最近看過上線的：hbbs 永遠留著舊註冊（2023 年那時的 DHCP 主人重裝過幾次
    # RustDesk 就留下幾個 ID），算進去會讓整個位址變成「多台共用」（2026-10-05 正式環境：一個位址有 6 個、另一個有 4 個）
    reg_by_ip: dict[str, list[RustDeskPeer]] = defaultdict(list)
    for p in peers:
        if p.registered_ip and (p.online or (p.last_online_at is not None and now - p.last_online_at <= MATCH_FRESH)):
            reg_by_ip[_ip_str(p.registered_ip) or ""].append(p)
    want_ips = ({_ip_str(p.registered_ip) for p in peers if p.registered_ip}
                | {_ip_str(p.report_ip) for p in peers if p.report_ip}) - {None}
    records: dict[str, list[tuple[uuid.UUID, str | None, uuid.UUID | None]]] = defaultdict(list)
    if want_ips:
        for addr_id, ip, hostname, device_id in (await session.execute(
                select(IPAddress.id, IPAddress.ip, IPAddress.hostname, IPAddress.device_id)
                .where(in_values(IPAddress.ip, [x for x in want_ips if x])))).all():
            records[_ip_str(ip) or ""].append((addr_id, hostname, device_id))
    device_ids = {d for recs in records.values() for _a, _h, d in recs if d}
    device_names: dict[uuid.UUID, str] = {}
    if device_ids:
        device_names = {d: n for d, n in (await session.execute(
            select(Device.id, Device.name).where(in_values(Device.id, list(device_ids))))).all()}

    # 只有主機名稱可比時的候選：IP 記錄的短名、裝置名稱（取主要 IP）
    hosts = {h for p in peers if (h := _short_host(p.hostname))}
    by_host: dict[str, set[uuid.UUID]] = defaultdict(set)
    if hosts:
        short = func.lower(func.split_part(IPAddress.hostname, ".", 1))
        for addr_id, h in (await session.execute(
                select(IPAddress.id, short).where(in_values(short, list(hosts), type_=String())))).all():
            by_host[h].add(addr_id)
        dname = func.lower(Device.name)
        for primary, h in (await session.execute(
                select(Device.primary_ip_id, dname).where(in_values(dname, list(hosts), type_=String()),
                                                          Device.primary_ip_id.is_not(None)))).all():
            by_host[h].add(primary)

    matched = 0
    for p in peers:
        status, addr, evidence, candidate = _decide(p, reg_by_ip, records, device_names, by_host, now)
        p.match_status, p.address_id, p.match_evidence, p.candidate_address_id = status, addr, evidence, candidate
        matched += addr is not None
    return matched


def _reg_ip_signal(p: RustDeskPeer, reg_by_ip: dict[str, list[RustDeskPeer]], now: datetime) -> tuple[str | None, str]:
    """hbbs 登記 IP 能不能當證據；不能的話回原因（給 match_status 用）。"""
    if not p.registered_ip:
        return None, "no_ip"
    ip = _ip_str(p.registered_ip) or ""
    sharing = reg_by_ip.get(ip, [])
    if len(sharing) >= NAT_SHARED:
        return None, "shared"
    if len(sharing) == 2:
        live = [x for x in sharing if x.online]
        if len(live) != 1 or live[0] is not p:
            return None, "ambiguous"
    if p.last_online_at is None:
        return None, "not_seen_online"
    if now - p.last_online_at > MATCH_FRESH:
        return None, "stale"
    return ip, ""


def _decide(
    p: RustDeskPeer,
    reg_by_ip: dict[str, list[RustDeskPeer]],
    records: dict[str, list[tuple[uuid.UUID, str | None, uuid.UUID | None]]],
    device_names: dict[uuid.UUID, str],
    by_host: dict[str, set[uuid.UUID]],
    now: datetime,
) -> tuple[str, uuid.UUID | None, list[str] | None, uuid.UUID | None]:
    reg_ip, reg_reason = _reg_ip_signal(p, reg_by_ip, now)
    rep_ip = _ip_str(p.report_ip) if (p.report_ip and p.report_ip_at
                                       and now - p.report_ip_at <= MATCH_FRESH) else None

    def unique(ip: str | None) -> tuple[tuple[uuid.UUID, str | None, uuid.UUID | None] | None, str]:
        if not ip:
            return None, ""
        recs = records.get(ip) or []
        if not recs:
            return None, "unmanaged"
        if len(recs) > 1:
            return None, "ambiguous"                    # 重疊網段：兩個單位各有一筆
        return recs[0], ""

    rec_rep, rep_reason = unique(rep_ip)
    rec_reg, reg_reason2 = unique(reg_ip)
    chosen, evidence = None, []
    if rec_rep is not None:
        chosen = rec_rep
        evidence.append("report_ip")
        if rec_reg is not None and rec_reg[0] == rec_rep[0]:
            evidence.append("registered_ip")
    elif rec_reg is not None:
        chosen = rec_reg
        evidence.append("registered_ip")

    host = _short_host(p.hostname)
    if chosen is not None:
        addr_id, rec_hostname, device_id = chosen
        names = {n for n in (_short_host(rec_hostname),
                             _short_host(device_names.get(device_id)) if device_id else None) if n}
        if host and names:
            if host in names:
                evidence.append("hostname")
            elif "report_ip" not in evidence:
                # 只有登記 IP（可能是舊的）而名稱不同：位址多半已經換了主人，不關聯。
                # 心跳剛從這個位址送來就以位址為準：名稱不同只是 IP 記錄寫的名稱不一樣（例如 desk-22 對 ws-ud22）
                return "conflict", None, sorted(evidence), None
        return "matched", addr_id, sorted(evidence), None

    reason = rep_reason or reg_reason2 or reg_reason or "no_ip"
    if host:
        cands = by_host.get(host) or set()
        if len(cands) == 1:
            return "hostname_only", None, ["hostname"], next(iter(cands))
    return reason, None, None, None


async def mark_stale_rustdesk(session: AsyncSession, now: datetime | None = None) -> int:
    """被動等代理回報：代理停了、被移走、主機關機時不會有任何錯誤冒出來。
    超過回報間隔 3 倍沒收到回報 → 寫 last_error；收到回報時 ingest 會重寫。"""
    now = now or datetime.now(UTC)
    n = 0
    for srv in (await session.execute(select(RustDeskServer).where(
            RustDeskServer.enabled.is_(True), RustDeskServer.agent_key_hash.is_not(None)))).scalars().all():
        since = srv.last_report_at or srv.created_at
        if since is not None and (now - since).total_seconds() > srv.report_interval_seconds * STALE_FACTOR:
            minutes = int((now - since).total_seconds() // 60)
            msg = (f"no report from the RustDesk agent for {minutes} min "
                   f"(expected every {srv.report_interval_seconds // 60 or 1} min)")
            if srv.last_error != msg:
                srv.last_error = msg
                n += 1
    return n


# ── 客戶端回報（docs/SPEC_RUSTDESK_API_zh-TW.md）──────────────────────────────

#: 告警類型 → 是否是暴力破解的直接訊號（通知用較高嚴重度）
ALARM_BRUTE_FORCE = frozenset({1, 2, 6})
#: 同一台、同一類告警，這段時間內只通知一次
ALARM_NOTIFY_QUIET = timedelta(minutes=10)
#: 稽核保留天數（與 jt-ipam 自己的稽核記錄分開管理）
AUDIT_RETENTION = timedelta(days=400)


def _valid_ip(v: Any) -> str | None:
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return None if ip.is_loopback else str(ip)


async def ingest_events(session: AsyncSession, server: RustDeskServer, payload: dict[str, Any],
                        now: datetime | None = None) -> dict[str, Any]:
    """寫入代理轉送的客戶端回報。代理已在本機比對過 uuid；這裡只收、不再驗證身分。"""
    from sqlalchemy.dialects.postgresql import insert

    from app.models.rustdesk import RustDeskAuditEvent

    now = now or datetime.now(UTC)
    server.last_events_at = now
    dropped = {k: int(v) for k, v in (payload.get("dropped") or {}).items() if int(v or 0) > 0}
    if dropped:
        acc = dict(server.events_dropped or {})
        for k, v in dropped.items():
            acc[k] = int(acc.get(k, 0)) + v
        server.events_dropped = acc

    events = payload.get("events") or []
    ids = {str(e["id"]) for e in events}
    peers = {p.rustdesk_id: p for p in (await session.execute(
        select(RustDeskPeer).where(RustDeskPeer.server_id == server.id,
                                   in_values(RustDeskPeer.rustdesk_id, list(ids))))).scalars().all()} if ids else {}

    def peer(rid: str) -> RustDeskPeer:
        p = peers.get(rid)
        if p is None:   # 代理還沒讀到 hbbs 資料庫裡的新裝置；下一輪讀資料庫時會補上登記 IP
            p = RustDeskPeer(server_id=server.id, rustdesk_id=rid, online=False, match_status="no_ip")
            session.add(p)
            peers[rid] = p
        return p

    rematch = False
    stored = {"heartbeat": 0, "sysinfo": 0, "audit": 0, "duplicate": 0}
    alarms: list[tuple[uuid.UUID, dict[str, Any]]] = []
    for e in events:
        kind, rid, at = e["kind"], str(e["id"]), e["at"]
        if at.tzinfo is None:
            at = at.replace(tzinfo=UTC)
        at = min(at, now)                 # 代理的時鐘超前時不讓「最後上線」跑到未來
        src = _valid_ip(e.get("src_ip"))
        if kind in ("heartbeat", "sysinfo"):
            p = peer(rid)
            if src and (_ip_str(p.report_ip) != src):
                rematch = True
            if src:
                p.report_ip, p.report_ip_at = src, max(at, p.report_ip_at) if p.report_ip_at else at
            if p.last_online_at is None or at > p.last_online_at:
                p.last_online_at = at
            p.online = True
            if kind == "heartbeat":
                p.last_heartbeat_at = max(at, p.last_heartbeat_at) if p.last_heartbeat_at else at
                p.active_conns = e.get("conns")
                stored["heartbeat"] += 1
            else:
                if (e.get("hostname") or None) != p.hostname:
                    rematch = True
                p.hostname = e.get("hostname") or None
                p.username = e.get("username") or None
                p.os_name = e.get("os") or None
                p.cpu = e.get("cpu") or None
                p.memory = (e.get("memory") or None) and str(e["memory"])[:64]
                p.client_version = (e.get("version") or None) and str(e["version"])[:32]
                p.sysinfo_at = at
                stored["sysinfo"] += 1
            continue

        row: dict[str, Any] = {"server_id": server.id, "kind": kind, "rustdesk_id": rid, "nonce": e.get("nonce"),
                               "occurred_at": at, "src_ip": src, "conn_id": e.get("conn_id"),
                               "verified": e.get("verified") is not False}
        if kind == "conn":
            row.update(action=e.get("action"), ip=_valid_ip(e.get("ip")), peer_id=e.get("peer_id"),
                       peer_name=e.get("peer_name"), conn_type=e.get("type"), session_id=e.get("session_id"),
                       detail={k: e.get(k) for k in ("primary_auth", "two_factor", "conn_audit_ref")
                               if e.get(k) is not None} or None)
        elif kind == "file":
            row.update(ip=_valid_ip(e.get("ip")), peer_id=e.get("peer_id"), peer_name=e.get("peer_name"),
                       detail={"direction": e.get("type"), "path": e.get("path"), "is_file": e.get("is_file"),
                               "num": e.get("num"), "files": e.get("files") or []})
        elif kind == "alarm":
            info = e.get("info") or {}
            row.update(alarm_type=e.get("typ"), ip=_valid_ip(info.get("ip")),
                       peer_id=(str(info["id"])[:100] if info.get("id") else None),
                       peer_name=(str(info["name"])[:255] if info.get("name") else None),
                       detail={str(k)[:64]: (v if isinstance(v, (int, float, bool)) or v is None else str(v)[:512])
                               for k, v in list(info.items())[:20]})
        elif kind == "note":
            row.update(session_id=e.get("session_id"), detail={"note": e.get("note")})
        stmt = insert(RustDeskAuditEvent).values(**row)
        if row["nonce"]:
            stmt = stmt.on_conflict_do_nothing(index_elements=["server_id", "nonce"],
                                               index_where=RustDeskAuditEvent.nonce.is_not(None))
        new_id = (await session.execute(stmt.returning(RustDeskAuditEvent.id))).scalar_one_or_none()
        if new_id is None:
            stored["duplicate"] += 1
            continue
        stored["audit"] += 1
        if kind == "alarm":
            alarms.append((new_id, row))
    await session.flush()

    for new_id, row in alarms:
        await _maybe_notify_alarm(session, server, new_id, row)
    if rematch:
        all_peers = list((await session.execute(
            select(RustDeskPeer).where(RustDeskPeer.server_id == server.id))).scalars().all())
        await _match(session, all_peers, now)
        await _report_hostnames(session, server, all_peers, complete=True)
        await session.flush()
    return stored


async def _maybe_notify_alarm(session: AsyncSession, server: RustDeskServer, new_id: uuid.UUID,
                              row: dict[str, Any]) -> None:
    from sqlalchemy import and_

    from app.models.rustdesk import RustDeskAuditEvent
    from app.services.health_alert import _notify

    earlier = (await session.execute(select(RustDeskAuditEvent.id).where(and_(
        RustDeskAuditEvent.server_id == server.id, RustDeskAuditEvent.kind == "alarm",
        RustDeskAuditEvent.rustdesk_id == row["rustdesk_id"],
        RustDeskAuditEvent.alarm_type == row["alarm_type"],
        RustDeskAuditEvent.id != new_id,
        RustDeskAuditEvent.occurred_at >= row["occurred_at"] - ALARM_NOTIFY_QUIET,
        RustDeskAuditEvent.occurred_at <= row["occurred_at"])).limit(1))).first()
    if earlier is not None:
        return
    p = (await session.execute(select(RustDeskPeer).where(
        RustDeskPeer.server_id == server.id, RustDeskPeer.rustdesk_id == row["rustdesk_id"]))).scalars().first()
    device = row["rustdesk_id"]
    if p is not None and (p.hostname or p.address_id):
        device = f"{p.hostname or ''} ({row['rustdesk_id']})".strip()
    typ = row["alarm_type"]
    ip = row.get("ip") or "?"
    peer_id = row.get("peer_id") or "?"
    labels = {0: "來源 IP 不在允許清單", 1: "密碼錯誤累計超過 30 次", 2: "一分鐘內密碼錯誤 6 次",
              6: "同一個 IPv6 前綴錯誤次數過多", 7: "終端機登入退避", 8: "終端機登入並行過多",
              9: "工作階段越權", 10: "對方 ID 不在允許清單"}
    known = typ in labels
    await _notify(
        session, event="rustdesk.alarm",
        title=f"RustDesk 告警：{device}",
        body=f"{labels.get(typ, f'告警類型 {typ}')}：來源 {ip}（對方 ID {peer_id}）",
        link="/rustdesk?tab=audit",
        severity="error" if typ in ALARM_BRUTE_FORCE else "warning",
        title_key="notif.rustdesk_alarm",
        body_key=f"notif.rustdesk_alarm_{typ}" if known else "notif.rustdesk_alarm_other",
        params={"device": device, "ip": ip, "peer": peer_id, "typ": typ})


async def prune_audit(session: AsyncSession, now: datetime | None = None) -> int:
    from app.models.rustdesk import RustDeskAuditEvent
    now = now or datetime.now(UTC)
    res = await session.execute(delete(RustDeskAuditEvent).where(
        RustDeskAuditEvent.occurred_at < now - AUDIT_RETENTION))
    return int(res.rowcount or 0)


# ── Key 設錯（代理讀 hbbr／hbbs 日誌）────────────────────────────────────────────
# Key 錯的客戶端照樣註冊（顯示「就緒」）、照樣回報、同一區網的直接連線也正常，只有走中繼時被 hbbr 拒絕；
# 網頁連線一定走中繼，看起來就像網頁連線壞了（2026-10-05 實機：兩個字母大小寫顛倒）。

KEY_PROBLEM_WINDOW = timedelta(days=30)      # 這麼久沒再被拒就不再標（可能早就改好、只是沒再走過中繼）


def key_problem(p: RustDeskPeer, now: datetime | None = None) -> dict[str, Any] | None:
    """{at, scope, count}：最近被拒、而且之後沒有通過過中繼；否則 None。"""
    now = now or datetime.now(UTC)
    if p.key_fail_at is None or p.key_fail_at < now - KEY_PROBLEM_WINDOW:
        return None
    if p.key_ok_at is not None and p.key_ok_at > p.key_fail_at:
        return None
    return {"at": p.key_fail_at, "scope": p.key_fail_scope, "count": p.key_fail_count or 1}


def key_problem_clause(now: datetime | None = None) -> Any:
    """與 key_problem() 同一個判斷的 SQL 版（清單篩選用）。"""
    from sqlalchemy import and_, or_
    now = now or datetime.now(UTC)
    return and_(RustDeskPeer.key_fail_at.is_not(None), RustDeskPeer.key_fail_at >= now - KEY_PROBLEM_WINDOW,
                or_(RustDeskPeer.key_ok_at.is_(None), RustDeskPeer.key_ok_at <= RustDeskPeer.key_fail_at))


async def ingest_key_checks(session: AsyncSession, server: RustDeskServer, kc: dict[str, Any],
                            now: datetime | None = None) -> dict[str, int]:
    """代理送來的 Key 檢查結果記到裝置上。日誌只有 IP，所以同一台伺服器上只有一個裝置在那個 IP
    （登記 IP 或回報 IP）才記；NAT 後面好幾台共用一個 IP 時分不出是誰，不猜。"""
    now = now or datetime.now(UTC)
    fails = kc.get("fails") or []
    oks = kc.get("ok") or []
    ips = {_valid_ip(x["ip"]) for x in [*fails, *oks]} - {None}
    if not ips:
        return {"flagged": 0, "cleared": 0, "ambiguous": 0}
    from sqlalchemy import Text, or_
    peers = list((await session.execute(select(RustDeskPeer).where(
        RustDeskPeer.server_id == server.id,
        or_(in_values(func.host(RustDeskPeer.registered_ip), sorted(ips), type_=Text()),
            in_values(func.host(RustDeskPeer.report_ip), sorted(ips), type_=Text()))))).scalars().all())
    by_ip: dict[str, set[uuid.UUID]] = defaultdict(set)
    by_id = {p.id: p for p in peers}
    for p in peers:
        for v in (p.registered_ip, p.report_ip):
            ip = _ip_str(v)
            if ip in ips:
                by_ip[ip].add(p.id)

    def only(ip_raw: str) -> RustDeskPeer | None:
        ids = by_ip.get(_valid_ip(ip_raw) or "", set())
        return by_id[next(iter(ids))] if len(ids) == 1 else None

    def at(v: datetime) -> datetime:
        return min(v if v.tzinfo else v.replace(tzinfo=UTC), now)

    counts = {"flagged": 0, "cleared": 0, "ambiguous": 0}
    for o in oks:
        p = only(o["ip"])
        if p is not None:
            t = at(o["last"])
            p.key_ok_at = max(t, p.key_ok_at) if p.key_ok_at else t
            if p.key_fail_at is not None and p.key_ok_at > p.key_fail_at:
                counts["cleared"] += 1
    for f in fails:
        p = only(f["ip"])
        if p is None:
            counts["ambiguous"] += 1
            continue
        t = at(f["last"])
        resolved = p.key_fail_at is None or (p.key_ok_at is not None and p.key_ok_at > p.key_fail_at)
        p.key_fail_count = int(f["n"]) if resolved else (p.key_fail_count or 0) + int(f["n"])
        if p.key_fail_at is None or t >= p.key_fail_at:
            p.key_fail_at, p.key_fail_scope = t, f["scope"]
        counts["flagged"] += 1
    return counts


async def key_refused_since(session: AsyncSession, server_id: Any, peer_id: str,
                            since: datetime) -> datetime | None:
    """網頁連線用：這台受控端在 since 之後因為 Key 被中繼拒絕過（而且之後沒有通過）→ 被拒的時間。"""
    p = (await session.execute(select(RustDeskPeer).where(
        RustDeskPeer.server_id == server_id, RustDeskPeer.rustdesk_id == peer_id))).scalars().first()
    if p is None or p.key_fail_scope != "relay":
        return None
    kp = key_problem(p)
    return kp["at"] if kp is not None and kp["at"] >= since else None


async def matched_peer(session: AsyncSession, address_id: uuid.UUID) -> tuple[RustDeskPeer, RustDeskServer] | None:
    """對應到這個 IP 的 RustDesk 裝置（有好幾台伺服器時取最近上線的）。IP 詳細資料與網頁連線用同一個選法，
    畫面上顯示的 ID 就是網頁連線會連的那一台。"""
    row = (await session.execute(
        select(RustDeskPeer, RustDeskServer).join(RustDeskServer, RustDeskServer.id == RustDeskPeer.server_id)
        .where(RustDeskPeer.address_id == address_id, RustDeskPeer.match_status == "matched")
        .order_by(RustDeskPeer.online.desc(), RustDeskPeer.last_online_at.desc().nulls_last())
        .limit(1))).first()
    return (row[0], row[1]) if row is not None else None


def web_problem(srv: RustDeskServer) -> str | None:
    """這台伺服器能不能走相容 RustDesk 的網頁連線；不能的話回錯誤代碼（errors.<code> 有翻譯）。"""
    if not srv.enabled:
        return "rd_web_server_disabled"
    if not srv.web_enabled:
        return "rd_web_disabled"
    if not srv.public_key:
        return "rd_web_no_key"           # 驗 hbbs 簽章（規格 6.1）一定要有公鑰
    if not ((srv.hbbs_host or "").strip() or (srv.agent_source_ip or "").strip()):
        return "rd_web_no_address"
    return None


def file_problem(srv: RustDeskServer) -> str | None:
    """這台伺服器能不能走網頁檔案傳輸（規格附錄 J.6）：沿用網頁連線的中繼，所以網頁連線要先能用，
    再加上「允許網頁檔案傳輸」（預設關）。不能的話回錯誤代碼（errors.<code> 有翻譯）。"""
    return web_problem(srv) or (None if srv.web_file_transfer else "rd_file_disabled")


def file_limits(srv: RustDeskServer) -> dict[str, int]:
    """上傳上限（位元組）。後端看不到檔案內容，由瀏覽器照著擋（J.6）。"""
    return {"max_file_bytes": int(srv.web_file_max_file_mb) * 1024 * 1024,
            "max_total_bytes": int(srv.web_file_max_total_mb) * 1024 * 1024}


async def elsewhere_on_device(session: AsyncSession, ip: IPAddress, *, user: Any) -> list[dict[str, Any]]:
    """這個 IP 沒有 RustDesk 裝置時：同一台裝置的其他 IP 上有沒有。

    一台電腦兩張網卡時，RustDesk 只會從其中一個位址連出去，也就只對應得到那一個；另一個 IP 的畫面
    要講清楚「對應在哪」，不然看起來像選項不見了。只認「兩筆 IP 掛在同一台裝置上」，
    主機名稱相同不算（DHCP 回收後舊名字還留著）。使用者看不到的子網路不列，免得從提示知道位址。
    """
    if ip.device_id is None:
        return []
    from app.models.subnet import Subnet
    from app.services.permission import visible_ids
    q = (select(RustDeskPeer.rustdesk_id, IPAddress.id, IPAddress.ip, IPAddress.rustdesk_enabled)
         .join(IPAddress, IPAddress.id == RustDeskPeer.address_id)
         .join(Subnet, Subnet.id == IPAddress.subnet_id)
         .where(IPAddress.device_id == ip.device_id, IPAddress.id != ip.id,
                RustDeskPeer.match_status == "matched", Subnet.archived_at.is_(None))
         .order_by(RustDeskPeer.online.desc(), RustDeskPeer.last_online_at.desc().nulls_last()))
    vis = await visible_ids(session, user=user, object_type="subnet", required="read")
    if vis is not None:
        if not vis:
            return []
        q = q.where(in_values(IPAddress.subnet_id, vis))
    out: list[dict[str, Any]] = []
    seen: set[uuid.UUID] = set()
    for rid, aid, addr, enabled in (await session.execute(q.limit(10))).all():
        if aid in seen:
            continue
        seen.add(aid)
        out.append({"address_id": str(aid), "ip": str(addr).split("/")[0], "rustdesk_id": rid,
                    "enabled": bool(enabled)})
    return out


async def for_address(session: AsyncSession, address_id: uuid.UUID) -> dict[str, Any] | None:
    """IP 詳細資料用：對應到這個 IP 的 RustDesk ID（有好幾台伺服器時取最近上線的）。"""
    row = await matched_peer(session, address_id)
    if row is None:
        return None
    p, srv = row
    return {"id": p.rustdesk_id, "online": p.online, "last_online_at": p.last_online_at,
            "last_heartbeat_at": p.last_heartbeat_at,
            "server_id": srv.id, "server_name": srv.name, "connect_uri": connect_uri(srv, p.rustdesk_id),
            # 相容 RustDesk 的網頁連線可不可用（伺服器設定面）；有沒有權限由呼叫端再收斂
            "web_available": web_problem(srv) is None,
            # 網頁檔案傳輸可不可用（伺服器設定面；附錄 J.6）；有沒有權限同樣由呼叫端再收斂
            "file_available": file_problem(srv) is None,
            # 客戶端回報的系統資訊（有開回報才有）與對應依據
            "hostname": p.hostname, "os": p.os_name, "username": p.username, "version": p.client_version,
            "evidence": p.match_evidence or [],
            # 這台的 Key 設錯（中繼拒絕過它、之後沒通過）：網頁連線與外網連線都會失敗
            "key_problem": key_problem(p)}


# ── 刪除舊註冊（0182）──────────────────────────────────────────────────────────
# hbbs 永遠留著每一個註冊過的 ID；開源版沒有管理 API，由 RustDesk 主機上的代理代為刪除。
# 兩邊都同意才會動到 RustDesk 的資料：網頁上的 allow_peer_delete，以及主機端以 --allow-delete 安裝的代理
# （輪詢時回報 capabilities.delete）。刪之前代理在主機上再查一次線上狀態，上線中的不刪。

#: 每次輪詢最多帶給代理幾筆（一次最多可以要求 500 筆，分幾輪做完）
PEER_DELETE_BATCH = 200
#: 等待中的請求超過這麼久沒被代理取走就算失敗（代理離線、被移走）
PEER_DELETE_EXPIRE = timedelta(days=1)
#: 已結束的請求保留多久（稽核記錄另有永久的一份）
PEER_DELETE_RETENTION = timedelta(days=180)
PEER_DELETE_EXPIRED_DETAIL = "expired: the RustDesk agent did not take this request within 24 hours"


def delete_capability(server: RustDeskServer) -> tuple[bool, str | None]:
    """代理最近一次輪詢回報的寫入能力：(做得到嗎, 做不到的原因)。舊版代理不回報 → (False, None)。"""
    caps = (server.agent_status or {}).get("capabilities")
    if not isinstance(caps, dict):
        return False, None
    return bool(caps.get("delete")), (str(caps["delete_reason"]) if caps.get("delete_reason") else None)


async def expire_peer_deletes(session: AsyncSession, server_id: uuid.UUID | None = None,
                              now: datetime | None = None) -> int:
    """超過一天還沒被代理取走的請求 → failed（逾時）；結束超過保留天數的請求刪掉。回傳逾時的筆數。"""
    now = now or datetime.now(UTC)
    scope = [RustDeskPeerDelete.server_id == server_id] if server_id is not None else []
    res = await session.execute(update(RustDeskPeerDelete).where(
        RustDeskPeerDelete.status == "pending", RustDeskPeerDelete.requested_at < now - PEER_DELETE_EXPIRE, *scope)
        .values(status="failed", detail=PEER_DELETE_EXPIRED_DETAIL, finished_at=now))
    await session.execute(delete(RustDeskPeerDelete).where(
        RustDeskPeerDelete.finished_at.is_not(None), RustDeskPeerDelete.finished_at < now - PEER_DELETE_RETENTION,
        *scope))
    return int(res.rowcount or 0)


async def cancel_pending_deletes(session: AsyncSession, server_id: uuid.UUID, detail: str,
                                 now: datetime | None = None) -> int:
    """網頁上關掉「刪除舊註冊」時，還在等的請求一併取消（不可以等之後重新打開時才被執行）。"""
    res = await session.execute(update(RustDeskPeerDelete).where(
        RustDeskPeerDelete.server_id == server_id, RustDeskPeerDelete.status == "pending")
        .values(status="cancelled", detail=detail[:500], finished_at=now or datetime.now(UTC)))
    return int(res.rowcount or 0)


async def pending_delete_jobs(session: AsyncSession, server: RustDeskServer) -> list[dict[str, Any]]:
    """輪詢要帶給代理的工作：只有網頁上允許、伺服器啟用時才有；先排的先做。"""
    if not (server.enabled and server.allow_peer_delete):
        return []
    rows = (await session.execute(
        select(RustDeskPeerDelete.id, RustDeskPeerDelete.rustdesk_id)
        .where(RustDeskPeerDelete.server_id == server.id, RustDeskPeerDelete.status == "pending")
        .order_by(RustDeskPeerDelete.requested_at, RustDeskPeerDelete.id).limit(PEER_DELETE_BATCH))).all()
    return [{"req_id": rid, "rustdesk_id": pid} for rid, pid in rows]


async def apply_delete_results(session: AsyncSession, server: RustDeskServer, results: list[dict[str, Any]],
                               now: datetime | None = None) -> dict[str, Any]:
    """寫入代理的結果。只認這台伺服器、還在等的請求（重送、別台的、已逾時或已取消的一律略過）；
    刪掉了的裝置在 jt-ipam 這邊也一起刪（不用等下一次回報）。回傳各結果的 RustDesk ID 與略過的筆數。"""
    now = now or datetime.now(UTC)
    by_id = {r["req_id"]: r for r in results if r.get("status") in PEER_DELETE_RESULTS}
    out: dict[str, list[str]] = {s: [] for s in PEER_DELETE_RESULTS}
    stale = len(results) - len(by_id)
    if by_id:
        rows = (await session.execute(select(RustDeskPeerDelete).where(
            in_values(RustDeskPeerDelete.id, list(by_id)), RustDeskPeerDelete.server_id == server.id,
            RustDeskPeerDelete.status == "pending"))).scalars().all()
        stale += len(by_id) - len(rows)
        for row in rows:
            r = by_id[row.id]
            row.status = r["status"]
            row.detail = str(r["detail"])[:500] if r.get("detail") else None
            row.finished_at = now
            out[row.status].append(row.rustdesk_id)
    if out["deleted"]:
        await session.execute(delete(RustDeskPeer).where(
            RustDeskPeer.server_id == server.id, in_values(RustDeskPeer.rustdesk_id, out["deleted"])))
    await session.flush()
    return {**out, "stale": stale}
