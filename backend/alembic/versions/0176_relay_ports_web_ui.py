"""主控台中繼的允許埠改在網頁設定（2026-10-02）。

使用者要求：要不要中繼、允許哪些埠，都是管理員在網頁上設定，不必到代理主機下指令；新功能升級後自動可用。
scan_agents 加 relay_ports（預設 22,3389,5900-5910，與原本代理端的預設相同），伺服器在 poll 與每個中繼工作裡
把它交給代理。代理主機的 JT_IPAM_RELAY_PORTS 改成選用的本機限縮。

既有站台升級後行為不變：中繼仍要系統設定與掃描代理頁兩道開關都打開。

Revision ID: 0176_relay_ports_web_ui
Revises: 0175_console_relay
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0176_relay_ports_web_ui"
down_revision = "0175_console_relay"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_agents", sa.Column("relay_ports", sa.String(200), nullable=False,
                                           server_default=sa.text("'22,3389,5900-5910'")))


def downgrade() -> None:
    op.drop_column("scan_agents", "relay_ports")
