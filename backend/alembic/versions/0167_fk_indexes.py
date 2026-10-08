"""外鍵欄位補索引（GitHub issue #47 與超大規模環境）

56 個單欄外鍵沒有以它開頭的索引。刪除被參照的那一列時（ON DELETE SET NULL／CASCADE），
PostgreSQL 要在子表裡找出參照它的列 —— 沒有索引就是整張表掃一遍，每刪一列掃一遍：
issue #47 那台裝置的三萬多個埠，清理時光是 device_ports.peer_port_id 的外鍵檢查就要將近兩分鐘；
刪掉一個 /16 子網路（六萬多個 IP）時，每個 IP 都要把 devices／nat_translations／wazuh_agents…
各掃一遍。這些欄位也常是查詢條件（這台裝置有哪些 IP、這台 LibreNMS 的 ARP／FDB）。

可為 NULL 的欄位用部分索引（WHERE col IS NOT NULL）：大多數是 NULL 的欄位（異動記錄的操作者）
索引很小，而 `col = $1` 的外鍵檢查照樣用得上。tests/test_fk_indexes.py 守著，之後新增的外鍵
沒有索引會失敗。

Revision ID: 0167_fk_indexes
Revises: 0166_recog_databases
Create Date: 2026-09-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0167_fk_indexes"
down_revision: str | None = "0166_recog_databases"
branch_labels = None
depends_on = None

# (資料表, 欄位, 可為 NULL)
FK_COLUMNS: list[tuple[str, str, bool]] = [
    ("subnets", "scan_agent_id", True),
    ("subnets", "vlan_id", True),
    ("subnets", "vrf_id", True),
    ("devices", "location_id", True),
    ("devices", "primary_ip_id", True),
    ("devices", "rack_id", True),
    ("ip_addresses", "device_id", True),
    ("nat_translations", "device_id", True),
    ("nat_translations", "dst_ip_id", True),
    ("nat_translations", "src_ip_id", True),
    ("user_group_members", "group_id", False),
    ("ip_requests", "allocated_ip_id", True),
    ("ip_requests", "approver_user_id", True),
    ("ip_request_events", "actor_user_id", True),
    ("librenms_devices", "jt_ipam_device_id", True),
    ("arp_entries", "device_id", True),
    ("arp_entries", "instance_id", True),
    ("fdb_entries", "device_id", True),
    ("fdb_entries", "instance_id", True),
    ("contact_groups", "parent_id", True),
    ("contacts", "group_id", True),
    ("contacts", "tenant_id", True),
    ("contact_assignments", "role_id", True),
    ("asns", "tenant_id", True),
    ("circuits", "tenant_id", True),
    ("circuits", "type_id", True),
    ("wireless_ssids", "tenant_id", True),
    ("wireless_ssids", "vlan_id", True),
    ("wireless_links", "a_device_id", True),
    ("wireless_links", "b_device_id", True),
    ("virt_clusters", "location_id", True),
    ("virt_clusters", "tenant_id", True),
    ("virtual_machines", "device_id", True),
    ("virtual_machines", "primary_ip_id", True),
    ("virtual_machines", "tenant_id", True),
    ("vm_interfaces", "vlan_id", True),
    ("power_panels", "location_id", True),
    ("power_feeds", "rack_id", True),
    ("power_outlets", "device_id", True),
    ("power_outlets", "rack_id", True),
    ("vpn_tunnels", "a_device_id", True),
    ("vpn_tunnels", "b_device_id", True),
    ("opnsense_firewalls", "scope_customer_id", True),
    ("opnsense_firewalls", "scope_location_id", True),
    ("wazuh_agents", "jt_ipam_address_id", True),
    ("background_tasks", "actor_user_id", True),
    ("system_settings", "updated_by", True),
    ("ip_change_log", "actor_user_id", True),
    ("device_ports", "peer_port_id", True),
    ("ip_request_stage_approvals", "approver_user_id", True),
    ("ai_findings", "dismissed_by", True),
    ("dhcp_sightings", "agent_id", True),
    ("agent_probe_jobs", "requested_by", True),
    ("zabbix_hosts", "jt_ipam_address_id", True),
    ("ip_cooldowns", "cleared_by", True),
    ("ip_cooldowns", "released_by", True),
]


def upgrade() -> None:
    for table, col, nullable in FK_COLUMNS:
        op.create_index(f"ix_{table}_{col}", table, [col], if_not_exists=True,
                        postgresql_where=sa.text(f"{col} IS NOT NULL") if nullable else None)


def downgrade() -> None:
    for table, col, _nullable in FK_COLUMNS:
        op.drop_index(f"ix_{table}_{col}", table_name=table, if_exists=True)
