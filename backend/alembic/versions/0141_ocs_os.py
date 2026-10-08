"""OCS 作為 OS 來源：ip_addresses.os_ocs（agent 回報的作業系統，走 OS 優先序）。

OCS 是資產代理，回報的 OS 比 nmap 指紋猜測準得多。原本第一版把 OCS 的 OS 寫進
`os_guess`（那是掃描代理的欄位）且只在空值時寫 —— 於是掃描代理誤判成 XP 的 Win11
機器，OCS 的正確 OS 反而蓋不過去。改成獨立欄位、經 os_precedence 排在 scanner 之上。

Revision ID: 0141_ocs_os
Revises: 0140_ocs
Create Date: 2026-09-18
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0141_ocs_os"
down_revision: str | None = "0140_ocs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ip_addresses", sa.Column("os_ocs", sa.String(160)))


def downgrade() -> None:
    op.drop_column("ip_addresses", "os_ocs")
