"""RustDesk 專用代理、客戶端回報（心跳、系統資訊、連線／檔案稽核、告警）與多訊號對應（2026-10-04）。

改用專用的 RustDesk 代理（agent/jt_ipam_rustdesk_agent.py），不再借用掃描代理：每台 RustDesk 伺服器
有自己的代理金鑰（只存雜湊；明文加密存在 encrypted_secrets，管理員可再檢視）。0177 的 agent_id
（指向掃描代理）拿掉 —— 升級後要在 RustDesk 主機上裝專用代理。

開源版客戶端在沒填「API 伺服器」時，會把回報送到 http://<ID 伺服器>:21114。代理聽這個埠、在本機比對 uuid
後轉給 jt-ipam（docs/SPEC_RUSTDESK_API_zh-TW.md）。

- rustdesk_servers：代理金鑰雜湊、代理狀態、「立即同步」與「測試」的請求／結果、
  receive_reports（網頁上的開關，預設開）、api_port、回報收件狀態
- rustdesk_peers：客戶端回報的系統資訊、最後心跳與其來源位址、對應依據與候選
- rustdesk_audit_events：連線／檔案傳輸／告警／備註

Revision ID: 0178_rustdesk_reports
Revises: 0177_rustdesk
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0178_rustdesk_reports"
down_revision = "0177_rustdesk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("rustdesk_servers", "agent_id")      # 外鍵與唯一限制跟著欄位一起刪
    op.add_column("rustdesk_servers", sa.Column("agent_key_hash", sa.String(64)))
    op.create_index("ix_rustdesk_servers_agent_key_hash", "rustdesk_servers", ["agent_key_hash"], unique=True)
    op.add_column("rustdesk_servers", sa.Column("agent_version", sa.String(32)))
    op.add_column("rustdesk_servers", sa.Column("agent_last_seen_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_servers", sa.Column("agent_source_ip", sa.String(64)))
    op.add_column("rustdesk_servers", sa.Column("agent_hostname", sa.String(255)))
    op.add_column("rustdesk_servers", sa.Column("agent_status", postgresql.JSONB()))
    op.add_column("rustdesk_servers", sa.Column("force_report_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_servers", sa.Column("test_id", sa.String(36)))
    op.add_column("rustdesk_servers", sa.Column("test_requested_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_servers", sa.Column("test_result_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_servers", sa.Column("test_result", postgresql.JSONB()))
    op.add_column("rustdesk_servers", sa.Column("receive_reports", sa.Boolean(), nullable=False,
                                                server_default=sa.true()))
    op.add_column("rustdesk_servers", sa.Column("api_port", sa.Integer(), nullable=False, server_default="21114"))
    op.add_column("rustdesk_servers", sa.Column("last_events_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_servers", sa.Column("events_dropped", postgresql.JSONB()))

    for name, typ in (("hostname", sa.String(255)), ("os_name", sa.String(255)), ("username", sa.String(255)),
                      ("cpu", sa.String(255)), ("memory", sa.String(64)), ("client_version", sa.String(32))):
        op.add_column("rustdesk_peers", sa.Column(name, typ))
    op.add_column("rustdesk_peers", sa.Column("sysinfo_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_peers", sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_peers", sa.Column("active_conns", sa.Integer()))
    op.add_column("rustdesk_peers", sa.Column("report_ip", postgresql.INET()))
    op.add_column("rustdesk_peers", sa.Column("report_ip_at", sa.DateTime(timezone=True)))
    op.add_column("rustdesk_peers", sa.Column("match_evidence", postgresql.JSONB()))
    op.add_column("rustdesk_peers", sa.Column(
        "candidate_address_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ip_addresses.id", ondelete="SET NULL")))
    op.create_index("ix_rustdesk_peers_candidate_address_id", "rustdesk_peers", ["candidate_address_id"])

    op.create_table(
        "rustdesk_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("server_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("rustdesk_servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),            # conn / file / alarm / note
        sa.Column("action", sa.String(8)),                          # conn：new / auth / close
        sa.Column("rustdesk_id", sa.String(100), nullable=False),   # 受控端（送出回報的那台）
        sa.Column("peer_id", sa.String(100)),                       # 對方（控制端）
        sa.Column("peer_name", sa.String(255)),
        sa.Column("ip", postgresql.INET()),                         # 對方的 IP（受控端看到的）
        sa.Column("conn_type", sa.SmallInteger()),
        sa.Column("conn_id", sa.BigInteger()),
        sa.Column("session_id", sa.String(32)),
        sa.Column("alarm_type", sa.SmallInteger()),
        sa.Column("nonce", sa.String(64)),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("detail", postgresql.JSONB()),                    # 檔案清單、告警內容、備註、驗證方式代碼
        sa.Column("src_ip", postgresql.INET()),                     # 回報送進來的來源位址
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_rustdesk_audit_events_server_time", "rustdesk_audit_events", ["server_id", "occurred_at"])
    op.create_index("ix_rustdesk_audit_events_rustdesk_id", "rustdesk_audit_events", ["rustdesk_id"])
    op.create_index("ix_rustdesk_audit_events_peer_id", "rustdesk_audit_events", ["peer_id"])
    op.create_index("uq_rustdesk_audit_events_nonce", "rustdesk_audit_events", ["server_id", "nonce"], unique=True,
                    postgresql_where=sa.text("nonce IS NOT NULL"))


def downgrade() -> None:
    op.drop_table("rustdesk_audit_events")
    op.drop_index("ix_rustdesk_peers_candidate_address_id", table_name="rustdesk_peers")
    for name in ("candidate_address_id", "match_evidence", "report_ip_at", "report_ip", "active_conns",
                 "last_heartbeat_at", "sysinfo_at", "client_version", "memory", "cpu", "username", "os_name",
                 "hostname"):
        op.drop_column("rustdesk_peers", name)
    for name in ("events_dropped", "last_events_at", "api_port", "receive_reports", "test_result",
                 "test_result_at", "test_requested_at", "test_id", "force_report_at", "agent_status",
                 "agent_hostname", "agent_source_ip", "agent_last_seen_at", "agent_version"):
        op.drop_column("rustdesk_servers", name)
    op.drop_index("ix_rustdesk_servers_agent_key_hash", table_name="rustdesk_servers")
    op.drop_column("rustdesk_servers", "agent_key_hash")
    op.execute("DELETE FROM encrypted_secrets WHERE object_type = 'rustdesk_server'")
    op.add_column("rustdesk_servers", sa.Column("agent_id", postgresql.UUID(as_uuid=True),
                                                sa.ForeignKey("scan_agents.id", ondelete="SET NULL"), unique=True))
