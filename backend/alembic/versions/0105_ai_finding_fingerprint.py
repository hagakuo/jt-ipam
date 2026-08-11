"""ai_findings.fingerprint：讓「已忽略」在下次巡檢時不會又跳出來

沒有這個欄位的話，每次巡檢都會把同一件事當成全新的發現重新插入 —— 使用者判斷過是誤報、
按了忽略，隔天又整排跳回來。那會讓「忽略」失去意義，最後大家乾脆不看這一頁。

指紋用「分類＋依據資料裡的 IP 清單」算，不用標題：標題是模型每次重寫的，措辭一定會變；
同一件事指到的位址則相當穩定。

Revision ID: 0105_ai_finding_fingerprint
Revises: 0104_dhcp_sightings
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0105_ai_finding_fingerprint"
down_revision = "0104_dhcp_sightings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_findings", sa.Column("fingerprint", sa.String(64), nullable=True))
    op.create_index("ix_ai_findings_fingerprint", "ai_findings", ["fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_ai_findings_fingerprint", table_name="ai_findings")
    op.drop_column("ai_findings", "fingerprint")
