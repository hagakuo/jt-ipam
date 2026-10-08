"""守門：會改資料的端點都要留下稽核。

稽核不是「重要的地方記一下」，而是「**改了東西就要留下誰在什麼時候改了什麼**」。
靠人記得寫是靠不住的 —— 實測掃過一輪，323 個變更型端點裡有 21 個會寫資料卻沒有稽核，
其中包含**群組成員異動**（等同權限變更，而且連是誰做的都沒記）與**代理金鑰輪替**。

這個測試走遍 API，找出「HTTP 方法是 POST/PUT/PATCH/DELETE 且函式內有寫入動作」卻
沒有呼叫稽核的端點。要新增例外必須寫進 `EXEMPT` 並附理由 —— 讓「不記」變成一個
需要說明的決定，而不是忘記。

⚠️ 偵測稽核呼叫時不要用 `\\baudit\\(`：`_audit(` 裡 `_` 和 `a` 之間**不是**單字邊界，
那個寫法會把所有用本地 `_audit()` helper 的檔案誤判成沒有稽核（第一版就是這樣，
把 54 個端點報成缺漏，實際只有 21 個）。
"""

from __future__ import annotations

import ast
import pathlib
import re

MUTATING = {"post", "put", "patch", "delete"}

_WRITES = re.compile(
    r"session\.add\b|session\.add_all\b|session\.delete\b|\.commit\(\)|"
    r"pg_insert\(|table\.update\(|table\.delete\(|update\(\w+\)\.where|delete\(\w+\)\.where"
)
_AUDIT = re.compile(r"\w*audit\w*\(", re.IGNORECASE)

#: 刻意不寫稽核的端點 → 理由。每一筆都是決定，不是遺漏。
EXEMPT: dict[str, str] = {
    # 代理每輪回報，量大；記了會把稽核記錄洗掉，代理活動另有 last_seen 與作業記錄
    "scan_agents.py::agent_report": "代理輪詢回報，高頻",
    "scan_agents.py::agent_job_result": "代理作業回報，高頻",
    "scan_agents.py::agent_dhcpd_report": "代理定期回報 dhcpd 解析結果（每幾分鐘一次），只寫指派給它的那個 ISC DHCP 來源；來源的設定異動另有稽核",
    "rustdesk_agent.py::agent_poll": "RustDesk 專用代理每 10 秒輪詢一次，只更新自己那台伺服器的代理狀態欄；金鑰的產生／檢視／輪替另有稽核",
    "rustdesk_agent.py::agent_report": "RustDesk 代理定期回報裝置清單與線上狀態（每幾分鐘一次），只寫金鑰所屬的那台伺服器；伺服器的設定異動另有稽核",
    "rustdesk_agent.py::agent_events": "RustDesk 代理轉送客戶端的心跳／系統資訊／稽核（每 5 秒一批），這些本身就是稽核資料，另存 rustdesk_audit_events",
    "rustdesk_agent.py::agent_test_result": "RustDesk 代理送回「測試」的逐項結果；發起測試時已稽核",
    "scan_agents.py::agent_job_progress": "代理回報執行中的進度，只更新自己那筆工作的狀態欄；發起探測時已稽核",
    "cert_agents.py::agent_report": "憑證代理回報，高頻",
    # 個人 UI 狀態，不涉及他人可見的資料
    "notifications.py::mark_read": "個人通知已讀狀態",
    "notifications.py::mark_all_read": "個人通知已讀狀態",
    "preferences.py::update_preferences": "個人介面偏好",
    "ai.py::delete_my_conversation": "使用者刪自己的對話（保留政策另有設定）",
    # phpIPAM 相容 API 的 session 操作（登入本身有稽核）
    "user.py::logout": "phpIPAM 相容 API 的 session 結束",
    "user.py::extend": "phpIPAM 相容 API 的 session 延長",
    # 寄出通知本身就會留下通知記錄
    "addresses.py::notify_stale": "寄送失聯提醒，通知本身即記錄",
}


def _unaudited() -> list[str]:
    """回傳「會寫資料、但（直接或透過同檔案的 helper）沒有稽核」的端點。

    要看穿**一層**本地 helper：實際上很多檔案是呼叫 `_audit()` / `_audit_import()` /
    `_diag_guard()` 這種同檔案的小函式去寫稽核。只比對端點本身的字面會產生一堆假警報，
    而會叫的狼太多，這個測試就沒有人理了。
    """
    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "api"
    out: list[str] = []
    for path in sorted(root.rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)

        # 同檔案裡「自己會寫稽核」的函式名
        auditing_helpers = {
            n.name for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
            and _AUDIT.search(ast.get_source_segment(src, n) or "")
        }

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            decs = [d.func if isinstance(d, ast.Call) else d for d in node.decorator_list]
            if not any(isinstance(d, ast.Attribute) and d.attr in MUTATING for d in decs):
                continue
            body = ast.get_source_segment(src, node) or ""
            if not _WRITES.search(body):
                continue                                   # 不寫資料
            if _AUDIT.search(body):
                continue                                   # 自己寫稽核
            called = {
                c.func.id for c in ast.walk(node)
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
            }
            if called & (auditing_helpers - {node.name}):
                continue                                   # 交給同檔案的 helper 寫
            out.append(f"{path.name}::{node.name}")
    return out


def test_every_data_changing_endpoint_is_audited():
    missing = [e for e in _unaudited() if e not in EXEMPT]
    assert not missing, (
        "這些端點會寫資料但沒有稽核。補上 append_audit，或把它加進 EXEMPT 並寫清楚理由：\n  "
        + "\n  ".join(missing)
    )


def test_exempt_list_has_no_stale_entries():
    """例外清單不可以留下已經補了稽核（或已刪除）的項目 —— 那會遮蔽未來的回歸。"""
    current = set(_unaudited())
    stale = [e for e in EXEMPT if e not in current]
    assert not stale, f"EXEMPT 裡這些項目已經不需要豁免了，請移除：{stale}"
