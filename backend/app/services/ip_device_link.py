"""依網卡 MAC 把 IP 掛回它所屬的裝置。

由來（2026-08-06 實機）：一台雙網卡機器的第二個 IP 沒有 `device_id`，於是裝置頁的
「IP 清單」只列得出一筆，AI 巡檢也據此把它報成「重複的 IP 紀錄」。但那個 MAC 就寫在
該裝置的 eth1 連接埠上 —— 系統手上早就有答案，只是沒去用。

**前提（已對實機查證，不是假設）**：`device_ports.mac_address` 存的是埠**自身**的硬體
位址（LibreNMS 寫 `ifPhysAddress`、Proxmox 寫網卡設定），不是該埠學習到的 MAC。若是
後者，這套比對會把主機的 IP 掛到交換器上 —— 整個方向就反了。

**這不是新哲學**：LibreNMS 同步建立裝置時，本來就會把主要 IP 掛上去（規則同樣是
「只在空的時候掛」）。這裡補的是第二張以後的網卡，並且守門比那條更嚴，因為證據較弱
（MAC 推論 vs 來源系統直接指明）。

**十條「不猜」的規則**（沒有一條是「猜得聰明一點」）：
 1. 已經有裝置關聯 → 永不覆寫
 2. 同一個 MAC 對到多台裝置 → 不猜（複製的 VM、重複建立的裝置）
 3. 從不移除既有關聯，只填空的
 4. 這個 IP 的裝置欄被人手動改過（含清空）→ 不再插手。少了這條，使用者清掉掛錯的
    關聯之後下一輪又會被掛回去，系統與人對打而人永遠贏不了
 5. MAC 屬於協定保留的共用範圍（VRRP / HSRP / 文件用）→ 依定義會出現在多台機器上
 6. MAC 格式不合或非單播（長度不足、全零、廣播、多播位元）→ `device_ports.mac_address`
    是 VARCHAR 且可手動編輯，"N/A" 正規化後會變成 "a"，非空、會被當成有效的鍵
 7. 主機名稱明確指向另一台裝置 → 兩條獨立線索打架時不猜
 8. 跨單位衝突（IP 的單位與裝置的單位兩邊都有值且不同）→ 多單位共管環境
 9. 封存的子網路 → 已經不再使用，補關聯只是製造雜訊
10. 未開啟或不在指定的子網路範圍內 → 預設關閉，由管理員明確開啟

**殘留風險（刻意不解）**：關聯掛上後不再重新評估，網卡日後換到別台機器會靜靜變錯。
根治要靠事後偵測（異常偵測比對「裝置關聯 vs 主機名稱」），而不是在寫入端疊更多猜測。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address import IPAddress
from app.models.device import Device
from app.models.ip_change_log import IPChangeLog
from app.models.physical import DevicePort
from app.models.subnet import Subnet
from app.services.arp_precedence import normalize_mac

# 每 N 筆放掉一次鎖。整批放在同一個交易裡會跟同時在跑的整合同步互鎖 ——
# reindex 就是這樣在實機上撞到 deadlock 的，同樣的錯不犯第二次。
_BATCH = 25

# 協定保留、依定義會出現在多台機器上的 MAC 前綴
_SHARED_PREFIXES = (
    "00005e0001",   # VRRP（IPv4 虛擬路由器）
    "00005e0002",   # VRRP（IPv6）
    "00000c07ac",   # HSRP
    "00005e0053",   # RFC 7042 文件用範圍
)


@dataclass
class LinkStats:
    """回報做了什麼、以及**沒做什麼**。

    只回成功數的話，「全部被守門擋下」看起來會跟「沒事可做」一模一樣 —— 這個專案
    在別處已經吃過這種虧（reindex 回 0/0/0）。
    """

    linked: int = 0
    skipped_ambiguous: int = 0
    skipped_manual: int = 0
    skipped_invalid_mac: int = 0
    skipped_hostname_mismatch: int = 0
    skipped_customer: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> str:
        return (f"linked={self.linked} ambiguous={self.skipped_ambiguous} "
                f"manual={self.skipped_manual} invalid_mac={self.skipped_invalid_mac} "
                f"hostname={self.skipped_hostname_mismatch} customer={self.skipped_customer}")


def is_linkable_mac(raw: object) -> bool:
    """能不能拿這個 MAC 當作「某張實體網卡」的識別。

    正規化只挑十六進位字元，所以任何字串都可能產出非空結果（"N/A" → "a"）。
    要求正好 12 個字元，並排除全零、廣播、多播位元與協定保留範圍。
    """
    m = normalize_mac(raw)
    if len(m) != 12:
        return False
    if m in ("000000000000", "ffffffffffff"):
        return False
    if int(m[0:2], 16) & 1:            # 多播位元：永遠不是網卡的單播位址
        return False
    return not m.startswith(_SHARED_PREFIXES)


def _label(name: str | None) -> str:
    """取第一段並轉小寫：`srv-01-storage.example.test` → `srv-01-storage`。"""
    return (name or "").strip().split(".")[0].lower()


def hostname_contradicts(hostname: str | None, device_name: str | None) -> bool:
    """主機名稱是否明確指向另一台裝置。

    沒有主機名稱＝沒有第二條線索，不算矛盾（不能因為缺資料就拒絕）。
    一方是另一方的首碼就算相符 —— 實機上第二張網卡常叫 `srv-01-storage`，
    那是同一台機器的儲存網介面，不是矛盾。
    """
    h, d = _label(hostname), _label(device_name)
    if not h or not d:
        return False
    return not (h.startswith(d) or d.startswith(h))


async def link_by_port_mac(
    session: AsyncSession,
    *,
    dry_run: bool = False,
    scope_subnet_ids: list[str] | None = None,
) -> LinkStats:
    """把沒有裝置關聯、但 MAC 唯一對應到某台裝置連接埠的 IP 掛上去。

    `dry_run=True` 只計算不寫入，並在 `samples` 附上明細 —— 這是會改資料的作業，
    要能先看會動到什麼再決定。
    """
    stats = LinkStats()

    # ── 埠 MAC → 裝置。用集合而不是 dict：dict 的後者會無聲蓋掉前者，
    #    而「同一個 MAC 對到多台」正是最需要被看見的情況。
    by_mac: dict[str, set[uuid.UUID]] = {}
    for dev_id, raw in (await session.execute(
        select(DevicePort.device_id, DevicePort.mac_address)
        .where(DevicePort.mac_address.isnot(None))
    )).all():
        if not is_linkable_mac(raw):
            continue
        by_mac.setdefault(normalize_mac(raw), set()).add(dev_id)
    unique = {m: next(iter(d)) for m, d in by_mac.items() if len(d) == 1}
    ambiguous = {m for m, d in by_mac.items() if len(d) > 1}
    # 這裡刻意**不**提前 return：就算一個可用的埠 MAC 都沒有，仍要跑完候選 IP，
    # 才數得出「因為 MAC 無效而跳過幾筆」。少了那個數字，「全部被擋下」看起來
    # 會跟「沒事可做」一模一樣 —— 這個專案已經在別處吃過這種虧。

    devices = {i: (n, c) for i, n, c in (await session.execute(
        select(Device.id, Device.name, Device.customer_id))).all()}

    # ── 候選 IP：沒有裝置、有 MAC、不在封存的子網路裡，並可限定範圍。
    #    只取需要的欄位，不載入整個 ORM 物件（每 5 分鐘一次的作業要能撐得住規模）。
    q = (
        select(IPAddress.id, IPAddress.ip, IPAddress.mac, IPAddress.hostname,
               IPAddress.customer_id, IPAddress.subnet_id, Subnet.customer_id)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .where(IPAddress.device_id.is_(None), IPAddress.mac.isnot(None),
               Subnet.archived_at.is_(None))
    )
    if scope_subnet_ids is not None:
        q = q.where(IPAddress.subnet_id.in_(scope_subnet_ids))
    rows = (await session.execute(q)).all()
    if not rows:
        return stats

    # ── 人手動改過裝置欄的 IP：一次查完，不要逐筆打 DB
    touched = set((await session.execute(
        select(IPChangeLog.ip_id).where(
            IPChangeLog.field == "device_id",
            IPChangeLog.source != "system",
        ).distinct()
    )).scalars().all())

    from app.services.ip_history import log_change

    pending = 0
    for ip_id, ip_val, mac, hostname, ip_cust, _subnet_id, sub_cust in rows:
        m = normalize_mac(mac)
        if not is_linkable_mac(mac):
            stats.skipped_invalid_mac += 1
            continue
        if m in ambiguous:
            stats.skipped_ambiguous += 1
            continue
        dev_id = unique.get(m)
        if not dev_id:
            continue
        if ip_id in touched:
            stats.skipped_manual += 1
            continue
        dev_name, dev_cust = devices.get(dev_id, (None, None))
        if hostname_contradicts(hostname, dev_name):
            stats.skipped_hostname_mismatch += 1
            continue
        # 單位常常掛在子網路而不是逐筆 IP 上 —— 往上找才擋得到真正的跨單位。
        # 只在兩邊都有值且不同時才擋：多單位站台初期大量物件沒填單位，
        # 嚴格比對會讓功能完全不動。
        eff_cust = ip_cust or sub_cust
        if eff_cust and dev_cust and eff_cust != dev_cust:
            stats.skipped_customer += 1
            continue

        stats.linked += 1
        if len(stats.samples) < 200:
            stats.samples.append({"ip": str(ip_val), "hostname": hostname,
                                  "device": dev_name})
        if dry_run:
            continue

        ipa = await session.get(IPAddress, ip_id)
        if ipa is None or ipa.device_id is not None:
            continue
        ipa.device_id = dev_id
        # 留痕：使用者看到裝置欄突然有值，要查得到何時、依據什麼掛上的
        await log_change(
            session, ip=ipa, event_type="edited", field="device_id",
            old=None, new=str(dev_id), source="system",
            note="matched a device port MAC",
        )
        pending += 1
        if pending % _BATCH == 0:
            await session.commit()
    if not dry_run and pending:
        await session.commit()
    return stats
