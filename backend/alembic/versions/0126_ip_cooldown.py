"""IP 釋放後的冷卻期

Revision ID: 0126_ip_cooldown
Revises: 0125_liveness_days
Create Date: 2026-08-27

一個 IP 被釋放之後，外面還有一堆東西指著它：DNS 記錄與快取、防火牆規則、ACL、
憑證的 SAN、監控設定、別人寫死在腳本裡的位址。這些不會在刪除的當下一起消失。

如果馬上把它配給別台機器，症狀會是最難查的那一種：新機器莫名其妙收到不屬於它的
流量、或被舊規則擋掉，而 IPAM 上看起來一切正常。實機上剛好有例子：DNS 上
某個 DNS 名稱仍指著一個早就換手的位址（2026-08-25 追查過的實際案例）。

所以釋放後預設冷卻 30 天。**紀錄獨立成表**而不是放在 ip_addresses：實務上「釋放」
最常見的做法就是把那筆 IP 刪掉，紀錄放在原表會跟著消失，冷卻期也就形同虛設。
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import INET, UUID

revision = "0126_ip_cooldown"
down_revision = "0125_liveness_days"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ip_cooldowns",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("subnet_id", UUID(as_uuid=True),
                  sa.ForeignKey("subnets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", INET(), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("until", sa.DateTime(timezone=True), nullable=False),
        # 保留釋放當下的身分：冷卻期間有人問「這個位址剛剛是誰」，答得出來才有意義
        sa.Column("previous_hostname", sa.Text()),
        sa.Column("previous_mac", sa.Text()),
        sa.Column("reason", sa.Text()),
        sa.Column("released_by", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        # 提前解除（管理員明示）：留下誰、何時、為什麼，不可無痕
        sa.Column("cleared_at", sa.DateTime(timezone=True)),
        sa.Column("cleared_by", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("cleared_reason", sa.Text()),
        sa.UniqueConstraint("subnet_id", "ip", name="uq_ip_cooldown_subnet_ip"),
    )
    op.create_index("ix_ip_cooldowns_until", "ip_cooldowns", ["until"])


def downgrade() -> None:
    op.drop_index("ix_ip_cooldowns_until", table_name="ip_cooldowns")
    op.drop_table("ip_cooldowns")
