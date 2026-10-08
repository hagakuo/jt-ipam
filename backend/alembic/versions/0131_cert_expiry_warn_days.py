"""每張憑證可各自設定「到期前幾天通知」。

由來：不同憑證的更新流程長短差很多 —— 手動申請的商業憑證要提前一個月準備，
Let's Encrypt 自動續簽的提前七天就夠。用同一個門檻，不是太吵就是太晚。

NULL＝沿用全域預設（系統設定裡的值），所以既有資料不必動，行為也不變。

Revision ID: 0131_cert_expiry_warn_days
Revises: 0130_rack_embed
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0131_cert_expiry_warn_days"
down_revision = "0130_rack_embed"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "certificates",
        sa.Column("expiry_warn_days", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("certificates", "expiry_warn_days")
