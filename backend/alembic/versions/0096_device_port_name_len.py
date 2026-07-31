"""device_ports.name 64 → 255

真實世界的介面名稱可能很長（例：Windows NDIS 過濾介面
「Realtek Gaming 2.5GbE Family Controller-Kaspersky Lab NDIS 6 Filter-0000.」= 71 字），
原本 VARCHAR(64) 在 LibreNMS/Proxmox 同步建 device_ports 時會 StringDataRightTruncation。
放寬到 255。
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0096_device_port_name_len"
down_revision: str | None = "0095_bgtask_trigger"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.alter_column(
        "device_ports", "name",
        existing_type=sa.String(length=64),
        type_=sa.String(length=255),
        existing_nullable=False,
    )


def downgrade() -> None:
    # 收窄前先截斷，避免 >64 的既有值讓 downgrade 失敗
    op.execute("UPDATE device_ports SET name = left(name, 64) WHERE length(name) > 64")
    op.alter_column(
        "device_ports", "name",
        existing_type=sa.String(length=255),
        type_=sa.String(length=64),
        existing_nullable=False,
    )
