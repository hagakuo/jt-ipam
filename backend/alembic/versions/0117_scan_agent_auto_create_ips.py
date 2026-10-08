"""掃描代理：是否自動建立掃到、但 IPAM 沒登錄的 IP

Revision ID: 0117_scan_agent_auto_create_ips
Revises: 0116_virt_auto_create_ips
Create Date: 2026-08-13

掃描代理原本是**無條件自動建立**——掃到一個 IPAM 沒有的位址就直接建一筆
（discovery_source='scanner'）。這是三類來源裡最後一個還這樣做的：
0115 已把 OPNsense / pfSense 改成開關，0116 是 Proxmox / VMware。

⚠️ **這是行為變更：預設關閉。** 升級後掃描代理不再自動收錄新位址，要在
「掃描代理」頁把這個開關打開才會恢復。理由跟 DHCP 那次一樣：被自動收錄的位址
**從此不再出現在「未授權 IP」異常偵測裡**（那道偵測的判定正是「掃得到、IPAM 沒有」），
所以有人私接一台機器、被掃到，就會安靜地變成一筆正式紀錄。要不要這樣，該由使用者明示。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0117_scan_agent_auto_create_ips"
down_revision = "0116_virt_auto_create_ips"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_agents",
        sa.Column("auto_create_ips", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("scan_agents", "auto_create_ips")
