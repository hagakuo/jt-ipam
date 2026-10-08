"""移除 wazuh_agents 上兩個從來沒有被寫入過的 CVE 欄位。

`cve_critical_count` / `cve_high_count` 從加進來的那天起就**沒有任何程式在寫**，
三個地方在讀（裝置整合面板、MCP 工具、schema），實機上 46 台 agent 全是 NULL。
前端其實一直沒有顯示它們 —— `DeviceDetail.vue` 裡早就有註解說明原因：Wazuh 4.8 起
manager API 沒有漏洞端點，唯一來源是 Wazuh Indexer，接上去要一組能讀整個 SIEM 事件的
憑證，代價與收益不成比例。

所以留著的只是會誤導人的空欄位：API 與 MCP 回一個永遠是 null 的 `cve_critical`，
看起來像「查過了，沒有漏洞」，其實是「從來沒查過」。那比不回傳更危險。
將來若真的接上 Indexer，再加回來就是了 —— 那時它們才會有值。

Revision ID: 0138_drop_wazuh_cve
Revises: 0137_anomaly_ignore
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0138_drop_wazuh_cve"
down_revision = "0137_anomaly_ignore"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("wazuh_agents", "cve_critical_count")
    op.drop_column("wazuh_agents", "cve_high_count")


def downgrade() -> None:
    op.add_column("wazuh_agents", sa.Column("cve_high_count", sa.Integer(), nullable=True))
    op.add_column("wazuh_agents", sa.Column("cve_critical_count", sa.Integer(), nullable=True))
