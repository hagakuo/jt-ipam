"""Palo Alto：站對站 VPN（IPsec）同步開關（2026-10-01）。

以前 Palo Alto 整合沒有抓 VPN，拓樸圖畫不出它的站對站通道。`show vpn flow` 是一支很輕的 op 指令
（一條通道一列），預設開。

Revision ID: 0171_paloalto_sync_vpn
Revises: 0170_mikrotik_phase2
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0171_paloalto_sync_vpn"
down_revision = "0170_mikrotik_phase2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("paloalto_firewalls", sa.Column(
        "sync_vpn", sa.Boolean(), nullable=False, server_default=sa.text("true")))


def downgrade() -> None:
    op.drop_column("paloalto_firewalls", "sync_vpn")
