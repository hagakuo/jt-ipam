"""`jt-ipam-sync.py` 的每個整合區塊，都必須直接位在同一個 session 區塊底下。

這條測試守的是一個真的發生過、而且很難被發現的事故：某次改動讓 ESXi 區塊少縮排 4 格，
於是 (a) 它跑在**已關閉的 session** 上、(b) **Wazuh 之後的十幾個整合全被縮排進 ESXi 的
for 迴圈裡**。prod 剛好沒有啟用的 ESXi 實例 → 那個迴圈體一次都沒執行 →
Wazuh / LibreNMS / AdGuard / FortiGate / Windows DHCP / Proxmox / DNS / 憑證 / AI 巡檢
全部靜靜停擺，畫面上完全看不出來（AI 巡檢的症狀是「排程設了卻不會跑」）。
外洩的連線還會在行程結束時噴 `greenlet is being finalized`，讓 systemd 每輪都記成失敗。

Python 不會為這種縮排報錯 —— 它只是換了一個意思。所以要用結構檢查把它釘住。
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "jt-ipam-sync.py"

# 每個整合區塊的識別字：出現在該區塊的查詢或呼叫裡
BLOCK_MARKERS = [
    "OPNsenseFirewall",
    "PfSenseFirewall",
    "ESXiInstance",
    "WazuhInstance",
    "LibreNMSInstance",
    "AdGuardInstance",
    "FortiGateFirewall",
    "WindowsDhcpServer",
    "KeaDhcpServer",               # 獨立 Kea DHCP（issue #45）
    "mark_stale_isc",              # 獨立 ISC DHCP：代理多久沒回報
    "mark_stale_rustdesk",         # RustDesk Server（開源版）：代理多久沒回報
    "rustdesk_svc.prune_audit",    # RustDesk 客戶端稽核保留天數
    "ProxmoxInstance",
    "DNSServer",
    "get_ai_audit_last_run",     # AI 巡檢
    "get_anomaly_last_run",      # 異常偵測排程
    "prune_stale_fdb",           # FDB 過期清除
    "check_integration_health",  # 健康告警（整合／代理／系統）
    "check_jump_host_keys",      # 容量與資安告警（DHCP／跳板金鑰／憑證來源）
    "recompute_effective_status",  # 上線判定：每輪一次、不依附 LibreNMS（2026-09-26 稽核）
    "sync_auto_dhcp_ranges",       # 偵測到的 DHCP 發放範圍 → 位址範圍（集區）（2026-09-27）
]


def _run_body() -> tuple[str, list[ast.stmt]]:
    src = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "_run")
    withs = [n for n in fn.body if isinstance(n, ast.AsyncWith)]
    assert len(withs) == 1, "_run() 應該只開一個 async with SessionLocal()"
    return src, withs[0].body


@pytest.mark.parametrize("marker", BLOCK_MARKERS)
def test_every_integration_runs_at_the_top_level_of_the_session_block(marker: str) -> None:
    """每個整合都要是 session 區塊的直接子敘述 —— 不能被巢狀在別的整合的迴圈裡。"""
    src, body = _run_body()
    found = any(marker in (ast.get_source_segment(src, st) or "") for st in body)
    assert found, (
        f"{marker} 的區塊不在 async with SessionLocal() 的第一層 —— "
        "多半是縮排跑掉被包進上一個整合的 for 迴圈，那會讓它在沒有該類型實例時完全不執行"
    )


def test_the_engine_is_disposed_before_exit() -> None:
    """短命腳本一定要 dispose：否則連線留到 GC 才回收，會在行程收尾噴 greenlet 錯誤。"""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "engine.dispose()" in src, "缺少 await engine.dispose()"
