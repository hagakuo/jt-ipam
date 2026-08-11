"""wazuh_agents：SCA（資安組態評估）摘要，並移除 0108 的 Indexer 欄位

漏洞（CVE）資料只存在於 Wazuh Indexer，接上去需要一組能讀取整個 SIEM 事件的憑證，
代價與收益不成比例 —— 0108 加的 Indexer 欄位因此撤除（未曾有資料寫入）。
資安體質改用 SCA 呈現：用現有的 manager API 帳號就讀得到。

Revision ID: 0109_wazuh_sca
Revises: 0108_wazuh_indexer
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0109_wazuh_sca"
down_revision = "0108_wazuh_indexer"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for col in ("indexer_url", "indexer_user", "indexer_password_enc",
                "indexer_password_nonce", "indexer_verify_tls"):
        op.drop_column("wazuh_instances", col)
    op.add_column("wazuh_agents", sa.Column("sca_policy", sa.String(128)))
    op.add_column("wazuh_agents", sa.Column("sca_score", sa.Integer()))
    op.add_column("wazuh_agents", sa.Column("sca_pass", sa.Integer()))
    op.add_column("wazuh_agents", sa.Column("sca_fail", sa.Integer()))
    op.add_column("wazuh_agents", sa.Column("sca_policy_count", sa.Integer()))
    op.add_column("wazuh_agents", sa.Column("sca_scanned_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    for col in ("sca_scanned_at", "sca_policy_count", "sca_fail", "sca_pass",
                "sca_score", "sca_policy"):
        op.drop_column("wazuh_agents", col)
    op.add_column("wazuh_instances", sa.Column("indexer_url", sa.Text()))
    op.add_column("wazuh_instances", sa.Column("indexer_user", sa.String(128)))
    op.add_column("wazuh_instances", sa.Column("indexer_password_enc", sa.LargeBinary()))
    op.add_column("wazuh_instances", sa.Column("indexer_password_nonce", sa.LargeBinary()))
    op.add_column("wazuh_instances", sa.Column(
        "indexer_verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()))
