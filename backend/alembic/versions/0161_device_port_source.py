"""device_ports.source_origin：連接埠是誰匯入的；LibreNMS 不再回報時同步清掉。

使用者回報（2026-09-27）：主機拔掉一張雙埠網卡、USB 網卡拔掉後，LibreNMS 已經把那些埠標成
deleted，裝置的「連接埠／佈線」卻還列著 —— 同步只新增、從不刪。LibreNMS 的 API 不回傳已刪的埠，
所以只能靠「這次完整讀到的清單裡沒有」判斷；為了不刪到使用者自己建的埠，匯入的埠要記來源。
既有的列維持 NULL，LibreNMS 下次回報時才認領（services/librenms.reconcile_librenms_ports）。

另外偽介面預設樣式加上容器的 veth（`^veth[0-9a-f]+$`）。站台存過樣式清單時新預設不會生效 ——
只有存的清單跟舊預設**完全一樣**（＝沒有真的自訂）才補上；自訂過的不動。

Revision ID: 0161_device_port_source
Revises: 0160_ip_ocs_hw
Create Date: 2026-09-27
"""
from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op

revision: str = "0161_device_port_source"
down_revision: str | None = "0160_ip_ocs_hw"
branch_labels = None
depends_on = None

_OLD_DEFAULTS = [r"^ethernet_\d+$", r"^wireless_\d+$", r"^ppp_\d+$", r"^tunnel_\d+$",
                 r"^loopback_\d+$", r"^isatap_\d+$", r"^teredo_\d+$"]
_VETH = r"^veth[0-9a-f]+$"


def upgrade() -> None:
    op.add_column("device_ports", sa.Column("source_origin", sa.String(64), nullable=True))
    op.create_index("ix_device_ports_source_origin", "device_ports", ["source_origin"])

    bind = op.get_bind()
    row = bind.execute(sa.text("SELECT value FROM system_settings WHERE key = 'device_ports'")).first()
    if row is not None and isinstance(row[0], dict) and row[0].get("ignore_patterns") == _OLD_DEFAULTS:
        value = {**row[0], "ignore_patterns": [*_OLD_DEFAULTS, _VETH]}
        bind.execute(sa.text("UPDATE system_settings SET value = CAST(:v AS jsonb) WHERE key = 'device_ports'"),
                     {"v": json.dumps(value)})


def downgrade() -> None:
    op.drop_index("ix_device_ports_source_origin", table_name="device_ports")
    op.drop_column("device_ports", "source_origin")
