#!/usr/bin/env python3
"""定時同步腳本：跑所有 enabled 的 OPNsense / Wazuh / LibreNMS / AdGuard / Proxmox 實例。

由 systemd timer 觸發；每次只跑那些 last_sync_at 距現在已經超過
sync_interval_seconds 的實例（避免短時間內重複跑）。

用法：
    sudo -u jtipam env $(cat /etc/jt-ipam/backend.env | xargs) \\
        /opt/jt-ipam/backend/.venv/bin/python /opt/jt-ipam/scripts/jt-ipam-sync.py

退出碼：
    0 — 全部成功（或沒到時間）
    1 — 至少一個實例 sync 失敗（last_error 已寫回 DB；syslog 也會看到）
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import UTC, datetime, timedelta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("jt-ipam-sync")


async def _run() -> int:
    from app.core.db import SessionLocal
    from app.models.adguard import AdGuardInstance
    from app.models.dns import DNSServer
    from app.models.esxi import ESXiInstance
    from app.models.firewall import OPNsenseFirewall
    from app.models.fortigate import FortiGateFirewall
    from app.models.mikrotik import MikroTikRouter
    from app.models.ocs import OcsServer
    from app.models.paloalto import PaloAltoFirewall
    from app.models.librenms import LibreNMSInstance
    from app.models.pfsense import PfSenseFirewall
    from app.models.virt import ProxmoxInstance, VirtCluster
    from app.models.wazuh import WazuhInstance
    from app.models.zabbix import ZabbixInstance
    from app.models.windows_dhcp import WindowsDhcpServer
    from app.models.dhcp_standalone import IscDhcpServer, KeaDhcpServer
    from app.models.rustdesk import RustDeskServer
    from app.services import adguard as adguard_svc
    from app.services import fortigate as fortigate_svc
    from app.services import mikrotik as mikrotik_svc
    from app.services import ocs as ocs_svc
    from app.services import paloalto as paloalto_svc
    from app.services import librenms as librenms_svc
    from app.services import opnsense_firewall as fw_svc
    from app.services import pfsense as pfsense_svc
    from app.services import proxmox as proxmox_svc
    from app.services import wazuh as wazuh_svc
    from app.services import zabbix as zabbix_svc
    from app.services import windows_dhcp as windows_dhcp_svc
    from app.services import kea_dhcp as kea_dhcp_svc
    from app.services import dhcp_standalone as dhcp_standalone_svc
    from app.services import rustdesk as rustdesk_svc
    from app.services.background_tasks import upsert_scheduled_task as _hb
    from app.services.dns.factory import get_adapter as _dns_adapter  # noqa: F401
    from app.services.dns_sync import pull_server
    from sqlalchemy import select

    failed = 0

    async with SessionLocal() as session:
        now = datetime.now(UTC)

        # ── OPNsense ──
        fws = (
            await session.execute(
                select(OPNsenseFirewall).where(OPNsenseFirewall.enabled.is_(True))
            )
        ).scalars().all()
        for fw in fws:
            interval = timedelta(seconds=fw.sync_interval_seconds)
            if fw.last_sync_at and fw.last_sync_at + interval > now:
                continue
            name = fw.name
            try:
                results = await fw_svc.sync_all_for_firewall(session, fw)
                await session.commit()
                log.info("opnsense %s: %d mappings", name, len(results))
                await _hb(session, kind="opnsense.sync", target_type="opnsense_firewall",
                          target_id=fw.id, target_label=name, ok=True,
                          summary={"mappings": len(results)})
            except Exception as exc:
                # 失敗的 transaction 先 rollback，否則接著的 commit 會二次爆 → 中斷整輪 sync
                await session.rollback()
                fw.last_error = str(exc)
                await session.commit()
                log.error("opnsense %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="opnsense.sync", target_type="opnsense_firewall",
                          target_id=fw.id, target_label=name, ok=False, error=str(exc))

        # ── pfSense ──
        pfws = (
            await session.execute(
                select(PfSenseFirewall).where(PfSenseFirewall.enabled.is_(True))
            )
        ).scalars().all()
        for fw in pfws:
            interval = timedelta(seconds=fw.sync_interval_seconds)
            if fw.last_sync_at and fw.last_sync_at + interval > now:
                continue
            name = fw.name
            try:
                counts = await pfsense_svc.sync_instance(session, fw)
                await session.commit()
                log.info("pfsense %s: %s", name, counts)
                await _hb(session, kind="pfsense.sync", target_type="pfsense_firewall",
                          target_id=fw.id, target_label=name, ok=True,
                          summary=counts if isinstance(counts, dict) else {"result": str(counts)})
            except Exception as exc:
                await session.rollback()
                fw.last_error = str(exc)
                await session.commit()
                log.error("pfsense %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="pfsense.sync", target_type="pfsense_firewall",
                          target_id=fw.id, target_label=name, ok=False, error=str(exc))


        # ── ESXi / vCenter ──
        for inst in (await session.execute(
            select(ESXiInstance).where(ESXiInstance.enabled.is_(True))
        )).scalars().all():
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                from app.services import esxi as esxi_svc
                summary = await esxi_svc.sync_instance(session, inst)
                await session.commit()
                log.info("esxi %s: %s", name, summary)
                await _hb(session, kind="esxi.sync", target_type="esxi_instance",
                          target_id=inst.id, target_label=name, ok=True, summary=summary)
            except Exception as exc:
                # 先 rollback 再寫 last_error：不 rollback 會二次爆、連鎖中斷整輪
                await session.rollback()
                inst.last_error = str(exc)[:2000]
                await session.commit()
                log.error("esxi %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="esxi.sync", target_type="esxi_instance",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))
        # ── Wazuh ──
        wzs = (
            await session.execute(
                select(WazuhInstance).where(WazuhInstance.enabled.is_(True))
            )
        ).scalars().all()
        for inst in wzs:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await wazuh_svc.sync_agents(session, inst)
                # SCA（資安組態評估）：用同一組 API 憑證，失敗不影響 agent 同步本身
                try:
                    n = await wazuh_svc.sync_sca(session, inst)
                    if n and isinstance(summary, dict):
                        summary["sca"] = n
                except Exception as exc:
                    log.warning("wazuh %s sca: %s", inst.name, exc)
                await session.commit()
                log.info("wazuh %s: %s", name, summary)
                await _hb(session, kind="wazuh.sync", target_type="wazuh_instance",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("wazuh %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="wazuh.sync", target_type="wazuh_instance",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── Zabbix ──
        zbxs = (
            await session.execute(
                select(ZabbixInstance).where(ZabbixInstance.enabled.is_(True))
            )
        ).scalars().all()
        for inst in zbxs:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await zabbix_svc.sync_instance(session, inst)
                await session.commit()
                log.info("zabbix %s: %s", name, summary)
                await _hb(session, kind="zabbix.sync", target_type="zabbix_instance",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)[:2000]
                await session.commit()
                log.error("zabbix %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="zabbix.sync", target_type="zabbix_instance",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── LibreNMS ──
        lns = (
            await session.execute(
                select(LibreNMSInstance).where(LibreNMSInstance.enabled.is_(True))
            )
        ).scalars().all()
        for inst in lns:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await librenms_svc.sync_instance(session, inst)
                await session.commit()
                log.info("librenms %s: %s", name, summary)
                # sync_instance 回的是 SyncSummary 物件：以前這裡只收 dict，排程同步在背景作業頁的摘要一直是空的
                # （手動同步才有）；依 ARP 建立了幾筆、沒建的原因也因此看不到
                await _hb(session, kind="librenms.sync", target_type="librenms_instance",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary.to_dict() if hasattr(summary, "to_dict")
                          else (summary if isinstance(summary, dict) else None))
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("librenms %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="librenms.sync", target_type="librenms_instance",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── ARP 過期清除（每輪一次，與 instance 是否到期無關）──
        # arp_entries 只新增不回收，靠這裡刪掉超過保留天數的舊紀錄（含孤兒 row）。
        try:
            from app.core.config import get_settings
            pruned = await librenms_svc.prune_stale_arp(
                session, max_age_days=get_settings().arp_retention_days,
            )
            await session.commit()
            if pruned:
                log.info("arp prune: removed %d stale entries", pruned)
        except Exception as exc:
            await session.rollback()
            log.error("arp prune failed: %s", exc)

        # ── 健康告警：整合同步失敗／代理失聯／系統檢查（每輪一次）──
        # 這三類資料早就在資料庫裡（last_error / last_seen_at / 系統診斷），只是要有人
        # 主動去點才看得到 —— 實務上沒有人每天點。只在「開始」與「恢復」時發，
        # 中間持續壞著不再吵（見 services/state_alert）。
        try:
            from app.models.certificate import CertAgent
            from app.models.scan_agent import ScanAgent
            from app.services.health_alert import (
                check_agent_health,
                check_integration_health,
                check_system_health,
            )
            from app.services.self_check import run_checks

            insts: list = []
            # 這份清單要**與上面實際會同步的整合一致** —— 少列一個，那個整合壞掉時
            # 就永遠不會有人知道，而且畫面上完全看不出少了誰。
            for kind, model in (
                ("librenms", LibreNMSInstance), ("wazuh", WazuhInstance),
                ("zabbix", ZabbixInstance), ("adguard", AdGuardInstance),
                ("proxmox", ProxmoxInstance), ("esxi", ESXiInstance),
                ("opnsense", OPNsenseFirewall), ("pfsense", PfSenseFirewall),
                ("fortigate", FortiGateFirewall), ("paloalto", PaloAltoFirewall),
                ("mikrotik", MikroTikRouter), ("windows_dhcp", WindowsDhcpServer),
                ("kea_dhcp", KeaDhcpServer), ("isc_dhcp", IscDhcpServer),
                ("rustdesk", RustDeskServer),
                ("ocs", OcsServer),
                ("dns", DNSServer),
            ):
                rows = (await session.execute(
                    select(model).where(model.enabled.is_(True)))).scalars().all()
                insts.extend((kind, r) for r in rows)
            await check_integration_health(session, insts)

            agents: list = []
            for kind, model in (("scan", ScanAgent), ("cert", CertAgent)):
                rows = (await session.execute(select(model))).scalars().all()
                agents.extend((kind, r) for r in rows)
            await check_agent_health(session, agents)

            await check_system_health(session, (await run_checks(session)).checks)
            await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("health alerts failed: %s", exc)

        # ── 容量與資安告警：DHCP 集區／跳板金鑰／憑證來源（每輪一次）──
        # 跳板金鑰是這三個裡面最重要的：指紋改變是中間人攻擊的訊號，而原本只有
        # 「有人開主控台」時才會被擋下來 —— 沒人連的時候完全沒人知道。
        try:
            from app.models.certificate import Certificate
            from app.models.dhcp import DHCPPoolRange
            from app.models.jump_host import JumpHost
            from app.services.capacity_alert import (
                check_cert_sources,
                check_dhcp_pools,
                check_jump_host_keys,
            )
            from app.services.dhcp_usage import pool_usage

            pools = await pool_usage(session)
            await check_dhcp_pools(session, pools)

            jhs = (await session.execute(
                select(JumpHost).where(JumpHost.enabled.is_(True)))).scalars().all()
            await check_jump_host_keys(session, list(jhs))

            # `source_type` 是 NOT NULL、沒設來源時是字串 'none' —— 用 is_not(None)
            # 會把每一張憑證都撈進來，包含根本沒有自動抓取的那些。
            certs = (await session.execute(
                select(Certificate).where(Certificate.source_type != "none")
            )).scalars().all()
            await check_cert_sources(session, list(certs))
            await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("capacity/security alerts failed: %s", exc)

        # ── 疑似暴力破解（每輪一次）──
        # 單一使用者忘記密碼被鎖不是資安事件；**多個帳號同時處於鎖定中**才是形狀。
        try:
            from app.models.user import User
            from app.services.security_alert import check_lockouts

            locked = (await session.execute(
                select(User).where(User.locked_until.is_not(None)))).scalars().all()
            await check_lockouts(session, list(locked))
            await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("brute force check failed: %s", exc)

        # ── FDB 過期清除（每輪一次）──
        # 與 ARP 同樣是只新增不回收的表，但保留期限長得多（預設一年）：
        # 這張表的價值就是「那台機器以前接在哪個埠」，砍太快等於把查案依據丟掉。
        # 注意：**保留 ≠ 採信** —— 推導「目前接在哪個埠」時只會用近期仍在的條目
        # （見 librenms.current_fdb_cutoff），舊的只留著給人查。
        try:
            from app.core.config import get_settings as _gs
            pruned_fdb = await librenms_svc.prune_stale_fdb(
                session, max_age_days=_gs().fdb_retention_days,
            )
            await session.commit()
            if pruned_fdb:
                log.info("fdb prune: removed %d stale entries", pruned_fdb)
        except Exception as exc:
            await session.rollback()
            log.error("fdb prune failed: %s", exc)

        # ── 冷卻紀錄回收 ──
        # 只增不刪會無限累積；到期後仍多留一段時間，因為「這位址上一手是誰」
        # 最常在冷卻剛結束那幾天被問到。
        try:
            from app.services.ip_lifecycle import purge_expired
            removed = await purge_expired(session)
            await session.commit()
            if removed:
                log.info("cooldown purge: removed %d expired rows", removed)
        except Exception as exc:
            await session.rollback()
            log.error("cooldown purge failed: %s", exc)

        # ── AdGuard ──
        ags = (
            await session.execute(
                select(AdGuardInstance).where(AdGuardInstance.enabled.is_(True))
            )
        ).scalars().all()
        for inst in ags:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await adguard_svc.sync_instance(session, inst)
                await session.commit()
                log.info("adguard %s: %s", name, summary)
                await _hb(session, kind="adguard.sync", target_type="adguard_instance",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("adguard %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="adguard.sync", target_type="adguard_instance",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── FortiGate（Beta；FortiOS REST API 唯讀）──
        fgs = (
            await session.execute(
                select(FortiGateFirewall).where(FortiGateFirewall.enabled.is_(True))
            )
        ).scalars().all()
        for inst in fgs:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await fortigate_svc.sync_instance(session, inst)
                await session.commit()
                log.info("fortigate %s: %s", name, summary)
                await _hb(session, kind="fortigate.sync", target_type="fortigate_firewall",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("fortigate %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="fortigate.sync", target_type="fortigate_firewall",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── Palo Alto（Beta；PAN-OS REST + XML 唯讀）──
        pas = (
            await session.execute(
                select(PaloAltoFirewall).where(PaloAltoFirewall.enabled.is_(True))
            )
        ).scalars().all()
        for inst in pas:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await paloalto_svc.sync_instance(session, inst)
                await session.commit()
                log.info("paloalto %s: %s", name, summary)
                await _hb(session, kind="paloalto.sync", target_type="paloalto_firewall",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                # 先 rollback 再寫 last_error —— 不 rollback 會二次爆並中斷整輪
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("paloalto %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="paloalto.sync", target_type="paloalto_firewall",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── MikroTik RouterOS（v7 REST 唯讀）──
        # ⚠️ 這一家的同步間隔預設是 900 秒（其他整合 300）：客戶的 MikroTik 是主力
        # 路由器，服務本身也會在 CPU 超標時停掉本輪剩下的區段（見 services/mikrotik.py）。
        mts = (
            await session.execute(
                select(MikroTikRouter).where(MikroTikRouter.enabled.is_(True))
            )
        ).scalars().all()
        for inst in mts:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await mikrotik_svc.sync_instance(session, inst)
                await session.commit()
                log.info("mikrotik %s: %s", name, summary)
                await _hb(session, kind="mikrotik.sync", target_type="mikrotik_router",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                # 先 rollback 再寫 last_error —— 不 rollback 會二次爆並中斷整輪
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("mikrotik %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="mikrotik.sync", target_type="mikrotik_router",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── OCS Inventory NG（端點資產盤點；唯讀 REST，只比不建）──
        ocs_servers = (
            await session.execute(
                select(OcsServer).where(OcsServer.enabled.is_(True))
            )
        ).scalars().all()
        for inst in ocs_servers:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await ocs_svc.sync_instance(session, inst)
                await session.commit()
                log.info("ocs %s: %s", name, summary)
                await _hb(session, kind="ocs.sync", target_type="ocs_server",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("ocs %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="ocs.sync", target_type="ocs_server",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── Windows DHCP Server（Beta；WinRM 唯讀拉 scope/租約）──
        wdhcps = (
            await session.execute(
                select(WindowsDhcpServer).where(WindowsDhcpServer.enabled.is_(True))
            )
        ).scalars().all()
        for inst in wdhcps:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await windows_dhcp_svc.sync_instance(session, inst)
                await session.commit()
                log.info("windows_dhcp %s: %s", name, summary)
                await _hb(session, kind="windows_dhcp.sync", target_type="windows_dhcp_server",
                          target_id=inst.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("windows_dhcp %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="windows_dhcp.sync", target_type="windows_dhcp_server",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── 獨立 Kea DHCP Server（issue #45；JSON 控制 API 唯讀拉範圍／保留／租約）──
        keas = (
            await session.execute(
                select(KeaDhcpServer).where(KeaDhcpServer.enabled.is_(True))
            )
        ).scalars().all()
        for inst in keas:
            interval = timedelta(seconds=inst.sync_interval_seconds)
            if inst.last_sync_at and inst.last_sync_at + interval > now:
                continue
            name = inst.name
            try:
                summary = await kea_dhcp_svc.sync_instance(session, inst)
                await session.commit()
                log.info("kea_dhcp %s: %s", name, summary)
                await _hb(session, kind="kea_dhcp.sync", target_type="kea_dhcp_server",
                          target_id=inst.id, target_label=name, ok=True, summary=summary)
            except Exception as exc:
                await session.rollback()
                inst.last_error = str(exc)
                await session.commit()
                log.error("kea_dhcp %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="kea_dhcp.sync", target_type="kea_dhcp_server",
                          target_id=inst.id, target_label=name, ok=False, error=str(exc))

        # ── 獨立 ISC DHCP Server：資料由掃描代理回報，這裡只抓「代理多久沒回報」──
        try:
            if await dhcp_standalone_svc.mark_stale_isc(session, now):
                await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("isc_dhcp stale check failed: %s", exc)

        # ── RustDesk Server（開源版）：資料由專用 RustDesk 代理回報，這裡只抓「代理多久沒回報」──
        try:
            if await rustdesk_svc.mark_stale_rustdesk(session, now):
                await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("rustdesk stale check failed: %s", exc)

        # ── RustDesk 客戶端稽核：保留 400 天 ──
        try:
            if await rustdesk_svc.prune_audit(session, now):
                await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("rustdesk audit prune failed: %s", exc)

        # ── Proxmox（同一 cluster 多節點 → 自動挑健康節點同步，故障換手）──
        pvs = (
            await session.execute(
                select(ProxmoxInstance)
                .where(ProxmoxInstance.enabled.is_(True))
                .order_by(ProxmoxInstance.cluster_id, ProxmoxInstance.created_at)
            )
        ).scalars().all()
        pv_groups: dict[object, list] = {}
        for inst in pvs:
            pv_groups.setdefault(inst.cluster_id, []).append(inst)
        for cluster_id, insts in pv_groups.items():
            interval = timedelta(seconds=min(i.sync_interval_seconds for i in insts))
            lasts = [i.last_sync_at for i in insts if i.last_sync_at]
            if lasts and max(lasts) + interval > now:
                continue
            # 作業表格顯示用的標籤：優先用叢集名稱（ProxmoxInstance 無 name/host 欄，
            # 別直接印 cluster_id UUID），退而用實例 api_url，再退 "proxmox"。
            cname = None
            if cluster_id:
                cname = await session.scalar(
                    select(VirtCluster.name).where(VirtCluster.id == cluster_id)
                )
            pv_label = cname or getattr(insts[0], "api_url", None) or "proxmox"
            try:
                summary = await proxmox_svc.sync_cluster(session, insts)
                await session.commit()
                log.info("proxmox cluster %s: %s", cluster_id, summary.to_dict())
                await _hb(session, kind="proxmox.sync", target_type="proxmox_cluster",
                          target_id=cluster_id, target_label=pv_label, ok=True,
                          summary=summary.to_dict())
            except Exception as exc:
                # 失敗的 transaction 無法 commit，先 rollback 讓 session 恢復可用，
                # 否則下一個 cluster 的查詢會 PendingRollbackError 連鎖中斷整輪
                await session.rollback()
                log.error("proxmox cluster %s sync failed: %s", cluster_id, exc)
                failed += 1
                await _hb(session, kind="proxmox.sync", target_type="proxmox_cluster",
                          target_id=cluster_id, target_label=pv_label, ok=False, error=str(exc))

        # ── DNS servers ──（沒有 sync_interval_seconds 欄；用固定 10 分鐘 throttle）
        dns_interval = timedelta(seconds=600)
        dnss = (
            await session.execute(
                select(DNSServer).where(DNSServer.enabled.is_(True))
            )
        ).scalars().all()
        for srv in dnss:
            last = getattr(srv, "last_pull_at", None) or getattr(srv, "last_sync_at", None)
            if last and last + dns_interval > now:
                continue
            name = srv.name
            try:
                summary = await pull_server(session, srv)
                await session.commit()
                log.info("dns %s: %s", name, summary)
                await _hb(session, kind="dns.sync", target_type="dns_server",
                          target_id=srv.id, target_label=name, ok=True,
                          summary=summary if isinstance(summary, dict) else None)
            except Exception as exc:
                # rollback 讓 session 恢復可用，否則下一個 DNS server 的查詢會連鎖失敗
                await session.rollback()
                log.error("dns %s sync failed: %s", name, exc)
                failed += 1
                await _hb(session, kind="dns.sync", target_type="dns_server",
                          target_id=srv.id, target_label=name, ok=False, error=str(exc))

        # ── 憑證自動抓取來源（URL / SFTP，依各憑證 fetch_interval 節流）──
        try:
            from app.models.certificate import Certificate
            from app.services.cert_fetch import fetch_certificate
            srcs = (await session.execute(
                select(Certificate).where(Certificate.source_type != "none")
            )).scalars().all()
            for c in srcs:
                interval = timedelta(seconds=c.fetch_interval_seconds)
                if c.last_fetch_at and c.last_fetch_at + interval > now:
                    continue
                res = await fetch_certificate(session, c, actor_user_id=None)  # 自行 commit
                if res.get("status") in ("updated", "error"):
                    log.info("cert fetch %s: %s", c.name, res)
        except Exception as exc:
            await session.rollback()
            log.error("cert fetch sweep failed: %s", exc)

        # ── 憑證到期 / 飄移告警 ──（去重保證每輪呼叫也不洗版）
        try:
            from app.services.cert_alert import check_cert_alerts
            stats = await check_cert_alerts(session)
            await session.commit()
            if stats.get("expiry") or stats.get("drift"):
                log.info("cert alerts: %s", stats)
        except Exception as exc:
            await session.rollback()
            log.error("cert alert check failed: %s", exc)

        # ── 稽核鏈驗證與外部錨定 ──
        # 雜湊鏈抓得到中間竄改，**抓不到從尾端整段截斷**（被刪的是還沒人引用的最後幾筆）。
        # 每輪把最新雜湊錨定到資料庫外面，之後那個位置消失或改變就是證據。
        # 驗證是增量的（自上次錨定起），所以每輪的成本與新增筆數成正比，不是整條鏈。
        try:
            from app.services.audit_anchor import verify_and_anchor
            res = await verify_and_anchor(session)
            await session.commit()
            if not res.get("ok"):
                log.error("audit chain verification FAILED: %s", res.get("detail"))
                # 斷鏈是資安事件，不能只寫 log：通知所有管理員（同一種失敗會去重）
                from app.services.audit_anchor import notify_chain_failure
                sent = await notify_chain_failure(session, res)
                await session.commit()
                log.error("audit chain alert sent to %d admin(s)", sent)
        except Exception as exc:
            await session.rollback()
            log.error("audit anchor failed: %s", exc)

        # ── 依網卡 MAC 把 IP 掛回所屬裝置 ──
        # 預設關閉：升級之後突然多出一個每 5 分鐘自動改資料的作業，本身就是不該
        # 發生的事。開啟後也只填空的、不覆寫、不移除，並依十條規則跳過任何有疑慮的
        # 情形。跳過的筆數一起記進 log —— 「全部被守門擋下」不能看起來跟「沒事可做」
        # 一樣。
        try:
            from app.services.ip_device_link import link_by_port_mac
            from app.services.system_config import get_autolink_config
            cfg = await get_autolink_config(session)
            if cfg["enabled"]:
                st = await link_by_port_mac(
                    session, scope_subnet_ids=cfg["scope_subnet_ids"])
                if st.linked or st.skipped_ambiguous or st.skipped_customer:
                    log.info("ip-device autolink: %s", st.summary())
        except Exception as exc:
            await session.rollback()
            log.error("ip-device autolink failed: %s", exc)

        # ── 裝置類型自動判斷：工作站／伺服器（每輪一次）──
        # 只碰「other 而且沒人定過」或「上次就是自動判斷」的裝置，人工設定的一律不動；
        # 依據是這台裝置 IP 上代理回報的作業系統（Wazuh／RustDesk／OCS），其次 nmap，再其次 OCS 機殼。
        try:
            from app.services.device_type_auto import refresh_auto_types
            n_types = await refresh_auto_types(session)
            await session.commit()
            if n_types:
                log.info("device types auto-set: %d", n_types)
        except Exception as exc:
            await session.rollback()
            log.error("device type auto-set failed: %s", exc)

        # ── 未納管位址的目擊：30 天沒再看到就清掉（每輪一次）──
        try:
            from app.services.unmanaged import purge as purge_unmanaged
            n_purged = await purge_unmanaged(session)
            await session.commit()
            if n_purged:
                log.info("unmanaged sightings purged: %d", n_purged)
        except Exception as exc:
            await session.rollback()
            log.error("unmanaged sightings purge failed: %s", exc)

        # ── 變更影響預演：回收沒有心跳的分析（標失敗或重新排隊，由網頁程序啟動）、清除過期的計畫 ──
        try:
            from app.services.change_impact.jobs import reclaim_stale
            from app.services.change_impact.retention import purge as purge_impact
            await reclaim_stale(session)
            gone = await purge_impact(session)
            await session.commit()
            if gone["plans"] or gone["failed_runs"]:
                log.info("change impact purged: %s", gone)
        except Exception as exc:
            await session.rollback()
            log.error("change impact housekeeping failed: %s", exc)

        # ── 偵測到的 DHCP 發放範圍 → 子網路的「位址範圍（集區）」（每輪一次，全站對帳）──
        # 使用者要求（2026-09-27）：子網路上方寫著 DHCP 發放範圍，下面的集區卻是空的。
        # 自動建的跟著上游走；手動建的不動；落點不唯一、跟手動的重疊都不建。
        try:
            from app.services.ip_ranges import sync_auto_dhcp_ranges
            res = await sync_auto_dhcp_ranges(session)
            await session.commit()
            if res["created"] or res["removed"] or res["updated"]:
                log.info("auto DHCP pool ranges: %s", res)
        except Exception as exc:
            await session.rollback()
            log.error("auto DHCP pool ranges failed: %s", exc)

        # ── 上線判定（每輪一次，不依附 LibreNMS）──
        # 以前只在 LibreNMS 同步（而且勾了「用於上線判定」）時重算：沒有 LibreNMS 的站台，
        # 掃描代理或防火牆標成上線的 IP 永遠不會變回離線（2026-09-26 稽核）。放在異常偵測之前，
        # 它讀的是這一輪的結果。
        try:
            await librenms_svc.recompute_effective_status(session)
            await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("liveness recompute failed: %s", exc)

        # ── 異常偵測（排程）──
        # 與 AI 巡檢同樣沿用這個 timer：每輪只判斷「是否已越過設定的時刻」，沒到就跳過。
        # 預設關閉。跑的是同一支 run_detection，差別在通知只發「與上次相比是新的」——
        # 偵測結果是目前的狀態不是事件流，每天把同一個未處理的衝突再吼一次，
        # 只會讓人把整類通知關掉。
        try:
            from app.services.anomaly import run_scheduled
            from app.services.schedule import due as _due
            from app.services.system_config import (
                get_anomaly_config,
                get_anomaly_last_run,
            )

            acfg = await get_anomaly_config(session)
            if acfg.schedule_enabled:
                alast = await get_anomaly_last_run(session)
                if _due(alast, acfg.times, frequency=acfg.frequency,
                        weekdays=acfg.weekdays, month_day=acfg.month_day,
                        interval_minutes=acfg.interval_minutes):
                    rep = await run_scheduled(session)
                    log.info("anomaly scan: %s finding(s)", rep.total())
        except Exception as exc:
            await session.rollback()
            log.error("anomaly scheduled scan failed: %s", exc)

        # ── AI 巡檢 ──
        # 沿用這個 timer 而不是另建一個：每輪只判斷「距上次是否已達設定的間隔」，
        # 沒到就直接跳過。預設關閉，要在 管理 → LLM / AI 明確打開才會跑。
        try:
            from app.models.user import User
            from app.services.ai_audit import due, run_audit
            from app.services.system_config import get_ai_audit_last_run, get_llm_config
            from sqlalchemy import select as _s

            cfg = await get_llm_config(session)
            if cfg.enabled and cfg.ai_audit_enabled:
                # 用獨立記錄的「上次執行時間」，不是最後一筆發現的時間 ——
                # 沒有發現的巡檢什麼都不會寫，靠發現回推會判成從沒跑過而每輪重跑
                last = await get_ai_audit_last_run(session)
                if due(last, cfg.ai_audit_times,
                       frequency=cfg.ai_audit_frequency,
                       weekdays=cfg.ai_audit_weekdays,
                       month_day=cfg.ai_audit_month_day):
                    # 排程沒有「發起者」，取一個管理員當取樣身分 —— 巡檢仍然走 RBAC，
                    # 只是這裡的可見範圍由該管理員決定，而不是無條件全庫。
                    principal = None
                    if cfg.mcp_principal_user_id:
                        principal = await session.get(User, cfg.mcp_principal_user_id)
                    if principal is None:
                        principal = (await session.execute(
                            _s(User).where(User.is_admin.is_(True), User.is_active.is_(True))
                            .order_by(User.created_at).limit(1)
                        )).scalars().first()
                    if principal is None:
                        log.warning("ai audit: no admin to run as, skipped")
                    else:
                        r = await run_audit(session, principal)
                        if r.error:
                            log.error("ai audit failed: %s", r.error)
                        else:
                            log.info("ai audit: %s finding(s)", r.findings)
        except Exception as exc:
            await session.rollback()
            log.error("ai audit check failed: %s", exc)

    # 個別整合連不到對方（防火牆離線、憑證過期…）是**回報事項**，不是這支排程失敗：
    # 錯誤已寫進該實例的 last_error、畫面上看得到、log 也有。以前這裡回 1，於是
    # systemd 把整輪標成 failed，`systemctl status` 永遠紅著 —— 真正壞掉的時候反而
    # 分不出來（客戶與我們自己都因此誤判過一次）。只有「這一輪根本跑不完」才回非零。
    if failed:
        log.info("sync completed with %d integration error(s) — see last_error on each instance",
                 failed)
    return 0


async def _run_and_dispose() -> int:
    """跑完一定要 dispose engine —— 這是短命腳本用 async engine 的必要收尾。

    少了它，連線集區裡的 asyncpg 連線會留到直譯器關閉時才被 GC 回收；那時事件迴圈與
    greenlet 都已經沒了，SQLAlchemy 在 finalizer 裡呼叫 `terminate()` 會炸出
    `RuntimeError: greenlet is being finalized` / `MissingGreenlet`，行程以非零結束。
    systemd 於是把每一輪都記成 failed（我們自己的 prod 24 小時內 259 次），而且
    **排在腳本最後面的 AI 巡檢再也沒被執行過** —— 表面症狀是「排程設了卻不會跑」。
    """
    from app.core.db import engine

    try:
        return await _run()
    finally:
        # dispose 本身出問題也不該蓋掉主要結果，這裡吞掉並記錄就好
        try:
            await engine.dispose()
        except Exception as exc:
            log.warning("engine dispose failed: %s", exc)


def main() -> None:
    sys.exit(asyncio.run(_run_and_dispose()))


if __name__ == "__main__":
    main()
