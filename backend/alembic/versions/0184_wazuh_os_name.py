"""wazuh_agents.os_name：Wazuh 回報的作業系統產品名稱（2026-10-06）

以前只向 Wazuh 拿 os.platform 與 os.version，Windows 11 就顯示成「windows 10.0.26200.9457」
（Windows 11 的核心版本號仍是 10.0）。Wazuh 的 os.name 本來就有「Microsoft Windows 11 Pro」，
存下來優先顯示。舊資料是 NULL，下一輪同步就補上。

Revision ID: 0184_wazuh_os_name
Revises: 0183_rustdesk_web_files
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0184_wazuh_os_name"
down_revision: str | None = "0183_rustdesk_web_files"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("wazuh_agents", sa.Column("os_name", sa.String(length=160), nullable=True))


def downgrade() -> None:
    op.drop_column("wazuh_agents", "os_name")
