"""RDP 與 VNC 主控台強制改用 guacd 引擎（2026-09-27 使用者指示：預設改 guacd，已安裝的也改過來）。

只動 `console_security` 這筆設定裡的 rdp_engine／vnc_engine；剪貼簿、SFTP 上限、SSH 引擎都留著。
沒有這筆設定的站台不必動 —— 程式的預設值已經是 guacd。
guacd 沒裝起來（例如這個 OS 還沒有預編檔）時，實際連線退回內建引擎（services/console_engine.py），
不會因此整個連不上；升級腳本預設會裝 guacd。

downgrade 不改回來：無從得知每個站台原本選的是什麼。

Revision ID: 0158_console_engine_guacd
Revises: 0157_vpn_tunnel_source_origin
Create Date: 2026-09-27
"""
from __future__ import annotations

from alembic import op

revision: str = "0158_console_engine_guacd"
down_revision: str | None = "0157_vpn_tunnel_source_origin"
branch_labels = None
depends_on = None

FORCE_JSON = '{"rdp_engine": "guacd", "vnc_engine": "guacd"}'
UPGRADE_SQL = (
    """UPDATE system_settings SET value = value || '{"rdp_engine": "guacd", "vnc_engine": "guacd"}'::jsonb """
    "WHERE key = 'console_security'"
)
assert FORCE_JSON in UPGRADE_SQL


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    pass
