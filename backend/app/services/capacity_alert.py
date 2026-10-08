"""容量與資安面的告警：DHCP 集區、跳板主機金鑰、憑證來源。

三者的共同點與 `health_alert` 一樣：資料早就有，只是沒有人會主動去點。
狀態轉換一律走 `services/state_alert`（只在開始與恢復時發）。

**子網路使用率刻意不在這裡**：那是規劃用的數字，慢慢逼近門檻是常態，做成通知只會
變成每天一則「還是很滿」。DHCP 集區不同 —— 集區用完的當下，新接上來的機器直接拿不到
位址，而現場看到的症狀是「網路壞了」，不會有人聯想到 IPAM。
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.health_alert import _notify
from app.services.state_alert import observe, prune_missing

log = logging.getLogger(__name__)

EVENT_DHCP = "dhcp.pool_exhausted"
EVENT_JUMP_KEY = "jump_host.key_changed"
EVENT_CERT_FETCH = "cert.fetch_failed"


async def check_dhcp_pools(
    session: AsyncSession, pools: list[tuple[Any, int, int]], *,
    threshold_pct: int = 90, threshold: int = 1,
) -> int:
    """DHCP 集區使用率。`pools` 是 (集區, 已用數, 總數)。"""
    sent = 0
    alive: set[str] = set()
    for pool, used, size in pools:
        key = f"dhcp:{pool.id}"
        alive.add(key)
        # size 0 = 設定錯誤或同步到一半。不是「滿了」，也不能拿來除
        pct = (used * 100 // size) if size > 0 else 0
        change = await observe(session, key=key,
                               failing=size > 0 and pct >= threshold_pct,
                               threshold=threshold)
        if change is None:
            continue
        sent += 1
        # 網段與範圍之間要有分隔 —— 少了它會黏成「192.0.2.0/24192.0.2.150」，
        # 讀的人得自己找界線在哪
        scope = f"{pool.subnet_cidr} " if pool.subnet_cidr else ""
        where = f"{pool.source_name}（{scope}{pool.start_ip}–{pool.end_ip}）"
        _p = {"where": where, "used": used, "size": size, "pct": pct}
        if change == "down":
            await _notify(
                session, event=EVENT_DHCP,
                title=f"DHCP 集區快用完：{where}",
                body=(f"已用 {used}/{size}（{pct}%）。集區用完之後新接上來的機器會直接"
                      f"拿不到位址，而現場看到的症狀是「網路壞了」。"),
                link="/subnets", severity="error",
                title_key="notif.dhcp_pool_full", body_key="notif.dhcp_pool_full_body",
                params=_p)
        else:
            await _notify(
                session, event=EVENT_DHCP,
                title=f"DHCP 集區已回到門檻以下：{where}",
                body=f"目前 {used}/{size}（{pct}%）。", link="/subnets", severity="info",
                title_key="notif.dhcp_pool_ok", body_key="notif.dhcp_pool_ok_body",
                params=_p)
    await prune_missing(session, prefix="dhcp:", alive=alive)
    return sent


async def check_jump_host_keys(
    session: AsyncSession, hosts: list[Any], *,
    probe: Callable[..., Awaitable[dict[str, str]]] | None = None,
    threshold: int = 1,
) -> int:
    """跳板主機的 host key 是否還是釘選的那一把。

    原本只有在有人開主控台時才會擋下來 —— **沒人連的時候完全沒人知道**，
    而那正是中間人攻擊最想要的狀態。

    兩個刻意的排除：
    - **連不到不算金鑰改變**：跳板重開機、網路不通都會連不到，報成中間人攻擊
      會讓人不再相信這則告警（真的發生時也被當成雜訊）。
    - **還沒釘選指紋的不檢查**：沒有比較基準。
    """
    if probe is None:
        from app.services.ssh_tunnel import fetch_host_key as probe  # type: ignore[assignment]
    sent = 0
    alive: set[str] = set()
    for jh in hosts:
        if not getattr(jh, "enabled", True) or not jh.host_key_fingerprint:
            continue
        key = f"jumpkey:{jh.id}"
        alive.add(key)
        try:
            info = await probe(jh.host, jh.port or 22, timeout=10.0)
        except Exception as exc:
            # 連不到：不改變狀態，也不通知。但要留下原因 ——
            # 否則現場只會看到「這台跳板從來沒被檢查過」，查不出是為什麼。
            log.info("jump host key probe skipped (%s): %s", jh.name, exc)
            continue
        actual = str(info.get("fingerprint") or "")
        change = await observe(session, key=key,
                               failing=bool(actual) and actual != jh.host_key_fingerprint,
                               threshold=threshold)
        if change is None:
            continue
        sent += 1
        if change == "down":
            await _notify(
                session, event=EVENT_JUMP_KEY,
                title=f"跳板主機的金鑰改變了：{jh.name}",
                body=(f"釘選的是 {jh.host_key_fingerprint}，現在拿到的是 {actual}。"
                      f"可能是重灌或換機，也可能是連線遭到攔截 —— 確認之前，"
                      f"經由這台跳板的主控台都會被擋下來。"),
                link="/jump-hosts", severity="error",
                title_key="notif.jump_key_changed", body_key="notif.jump_key_changed_body",
                params={"name": jh.name, "pinned": jh.host_key_fingerprint, "actual": actual})
        else:
            await _notify(
                session, event=EVENT_JUMP_KEY,
                title=f"跳板主機的金鑰恢復為釘選值：{jh.name}",
                body="指紋又與釘選的一致了。", link="/jump-hosts", severity="info",
                title_key="notif.jump_key_restored", body_key="notif.jump_key_restored_body",
                params={"name": jh.name})
    await prune_missing(session, prefix="jumpkey:", alive=alive)
    return sent


async def check_cert_sources(
    session: AsyncSession, certs: list[Any], *, threshold: int = 1,
) -> int:
    """憑證的 URL/SFTP 來源抓取失敗。

    抓不到新版本不會有任何症狀 —— 直到憑證到期那天。這是最需要提前講的一類。
    """
    sent = 0
    alive: set[str] = set()
    for cert in certs:
        key = f"certsrc:{cert.id}"
        alive.add(key)
        change = await observe(session, key=key,
                               failing=bool(getattr(cert, "last_fetch_error", None)),
                               threshold=threshold)
        if change is None:
            continue
        sent += 1
        if change == "down":
            await _notify(
                session, event=EVENT_CERT_FETCH,
                title=f"憑證來源抓取失敗：{cert.name}",
                body=(f"{str(cert.last_fetch_error)[:300]}\n"
                      f"抓不到新版本不會有任何症狀，直到憑證到期那天。"),
                link="/certificates", severity="error",
                title_key="notif.cert_fetch_failed", body_key="notif.cert_fetch_failed_body",
                params={"name": cert.name, "reason": str(cert.last_fetch_error)[:300]})
        else:
            await _notify(
                session, event=EVENT_CERT_FETCH,
                title=f"憑證來源已恢復：{cert.name}",
                body="又抓得到了。", link="/certificates", severity="info",
                title_key="notif.cert_fetch_ok", body_key="notif.cert_fetch_ok_body",
                params={"name": cert.name})
    await prune_missing(session, prefix="certsrc:", alive=alive)
    return sent
