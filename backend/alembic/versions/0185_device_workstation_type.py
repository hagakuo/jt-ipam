"""devices.type 加 workstation（工作站：桌機、筆電等使用者電腦）＋ devices.type_source（2026-10-06）

- 以前 Windows 主機一律歸成 server（或維持 other），使用者電腦沒有自己的類型。只加一種「工作站」，
  不分筆電與桌機：沒有 OCS 時沒有任何來源分得出來，機殼類型在裝置頁的 OCS 卡片上本來就看得到。
- type_source：類型是誰定的（manual／import／librenms／proxmox／auto…）。自動判斷只碰
  「other 而且沒人定過」或「上次就是自動判斷」的裝置，人工設定的一律不動。舊資料是 NULL。

Revision ID: 0185_device_workstation_type
Revises: 0184_wazuh_os_name
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0185_device_workstation_type"
down_revision: str | None = "0184_wazuh_os_name"
branch_labels: str | None = None
depends_on: str | None = None

_OLD = ("type IN ('server','switch','router','firewall','ap','storage','ipmi',"
        "'patch_panel','pdu','ups','other')")
_NEW = ("type IN ('server','switch','router','firewall','ap','storage','ipmi',"
        "'patch_panel','pdu','ups','workstation','other')")
# 約束在歷史裡可能被命名慣例首碼（甚至雙重首碼），用 IF EXISTS 全掃再重建（同 0097）
_NAMES = (
    "device_type_valid",
    "ck_devices_device_type_valid",
    "ck_devices_ck_devices_device_type_valid",
)
_CANON = "ck_devices_device_type_valid"


def upgrade() -> None:
    for n in _NAMES:
        op.execute(f'ALTER TABLE devices DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE devices ADD CONSTRAINT "{_CANON}" CHECK ({_NEW})')
    op.add_column("devices", sa.Column("type_source", sa.String(length=16), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "type_source")
    op.execute("UPDATE devices SET type='other' WHERE type = 'workstation'")
    for n in _NAMES:
        op.execute(f'ALTER TABLE devices DROP CONSTRAINT IF EXISTS "{n}"')
    op.execute(f'ALTER TABLE devices ADD CONSTRAINT "{_CANON}" CHECK ({_OLD})')
