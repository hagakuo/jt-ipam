"""事件規則：事件 → 條件 → 動作

Revision ID: 0127_event_rules
Revises: 0126_ip_cooldown
Create Date: 2026-08-27

在此之前，事件只能「全部送到 webhook」或「符合通知矩陣就通知管理員」—— 沒有條件。
實務上要的幾乎都是有條件的：新增的是**正式環境**網段才通知、發現未授權 IP 而且落在
**伺服器網段**才告警、憑證剩不到 30 天才建工單。

條件刻意做成結構化的資料（欄位／運算子／值），不是可執行的運算式：
規則由使用者輸入，能執行的東西就是一條注入路徑。也因此不提供正規表示式
（會給出 ReDoS 的機會），要比對就用 contains / startswith 這類有界的運算子。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

revision = "0127_event_rules"
down_revision = "0126_ip_cooldown"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "event_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        # 訂閱哪些事件；["*"] = 全部
        sa.Column("events", ARRAY(sa.String()), nullable=False,
                  server_default=sa.text("'{}'::varchar[]")),
        # [{field, op, value}]；全部成立才算命中（AND）
        sa.Column("conditions", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        # [{type: notify_admins|webhook, ...}]
        sa.Column("actions", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("match_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_matched_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_event_rules_enabled", "event_rules", ["enabled"])


def downgrade() -> None:
    op.drop_index("ix_event_rules_enabled", table_name="event_rules")
    op.drop_table("event_rules")
