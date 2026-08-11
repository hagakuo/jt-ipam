"""subnets.anomaly_enabled：可以把不需要偵測的子網路排除在異常偵測之外

實務問題：未授權 IP 一欄被 169.254.x.x（DHCP 拿不到位址時的自我指派）灌爆 —— 53 筆
全是這個，真正該看的東西被埋掉了。有些網段（訪客、實驗、外包商）本來就不該用這套規則看。

預設 true：既有網段維持現況，要排除的自己去關。

Revision ID: 0106_subnet_anomaly
Revises: 0105_ai_finding_fingerprint
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0106_subnet_anomaly"
down_revision = "0105_ai_finding_fingerprint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "subnets",
        sa.Column("anomaly_enabled", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
    )


def downgrade() -> None:
    op.drop_column("subnets", "anomaly_enabled")
