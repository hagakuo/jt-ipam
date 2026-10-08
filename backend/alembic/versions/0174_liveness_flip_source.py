"""沒有 LibreNMS 的站台：舊的上線／失聯異動記錄來源改成 system（GitHub #49，2026-10-01）。

上線狀態重算從 2026-09 起每個站台都跑，寫異動記錄時卻寫死 source='librenms'。程式已修（失聯記 system、
上線記實際來源）；這裡修舊資料，但**只在完全沒有 LibreNMS 整合的站台**：有 LibreNMS 的站台分不出哪些
真的是 LibreNMS 看到的，不猜。真正的上線來源已無從得知，一律記 system（比錯誤的 librenms 誠實）。

downgrade 不還原（無法分辨哪些是這裡改的，而且改回去就是把錯的標籤放回來）。

Revision ID: 0174_liveness_flip_source
Revises: 0173_librenms_arp_autocreate
"""
from __future__ import annotations

from alembic import op

revision = "0174_liveness_flip_source"
down_revision = "0173_librenms_arp_autocreate"
branch_labels = None
depends_on = None

FIX_SQL = (
    "UPDATE ip_change_log SET source = 'system' "
    "WHERE field = 'effective_status' AND source = 'librenms' "
    "AND NOT EXISTS (SELECT 1 FROM librenms_instances)"
)


def upgrade() -> None:
    op.execute(FIX_SQL)


def downgrade() -> None:
    pass
