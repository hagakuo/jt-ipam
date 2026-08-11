"""wazuh_instances：Indexer 連線設定（漏洞資料）

Wazuh 4.8 起 `/vulnerability/*` API 已移除，漏洞資訊改由 Wazuh Indexer（OpenSearch）
提供，而且帳密與 manager API 是**兩組不同的憑證**。留空＝不取漏洞資料。

Revision ID: 0108_wazuh_indexer
Revises: 0107_dhcp_reservations
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0108_wazuh_indexer"
down_revision = "0107_dhcp_reservations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("wazuh_instances", sa.Column("indexer_url", sa.Text()))
    op.add_column("wazuh_instances", sa.Column("indexer_user", sa.String(128)))
    op.add_column("wazuh_instances", sa.Column("indexer_password_enc", sa.LargeBinary()))
    op.add_column("wazuh_instances", sa.Column("indexer_password_nonce", sa.LargeBinary()))
    op.add_column("wazuh_instances", sa.Column(
        "indexer_verify_tls", sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    op.drop_column("wazuh_instances", "indexer_verify_tls")
    op.drop_column("wazuh_instances", "indexer_password_nonce")
    op.drop_column("wazuh_instances", "indexer_password_enc")
    op.drop_column("wazuh_instances", "indexer_user")
    op.drop_column("wazuh_instances", "indexer_url")
