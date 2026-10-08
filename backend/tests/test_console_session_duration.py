"""每一種主控台結束連線時，稽核都要記下連了多久（`duration_seconds`）。

使用者 2026-10-06 問「記錄中有記錄連線多久嗎？」：SSH、RDP、VNC、noVNC、RustDesk 有，SFTP 與 BMC 沒有。
這裡逐一檢查每個主控台寫「結束連線」稽核的那一段程式有帶 duration_seconds，新增主控台時也要登記進來。
"""
from __future__ import annotations

import re
from pathlib import Path

ENDPOINTS = Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints"

#: 主控台檔案 → 結束連線的稽核動作
CLOSE_ACTIONS = {
    "ssh_console.py": "ssh.session_close",
    "sftp_console.py": "sftp_close",
    "rdp_console.py": "rdp.session_close",
    "vnc_console.py": "vnc.session_close",
    "novnc_console.py": "novnc.session_close",
    "bmc_console.py": "bmc.session_close",
    "rustdesk_console.py": "rustdesk.web_session_close",
}


def test_every_console_close_audit_records_the_duration() -> None:
    missing = []
    for name, action in CLOSE_ACTIONS.items():
        src = (ENDPOINTS / name).read_text(encoding="utf-8")
        hits = [m.start() for m in re.finditer(re.escape(f'"{action}"'), src)]
        assert hits, f"{name} 找不到 {action}"
        for pos in hits:
            # 稽核呼叫本身（動作字串前後幾行）要帶 duration_seconds
            window = src[max(0, pos - 400):pos + 400]
            if "duration_seconds" not in window:
                missing.append(f"{name}:{src.count(chr(10), 0, pos) + 1} {action}")
    assert not missing, "結束連線的稽核沒有記連線多久：" + "、".join(missing)


def test_every_console_file_is_registered() -> None:
    """新的 *_console.py 也要登記進 CLOSE_ACTIONS（否則這道守門形同不存在）。"""
    consoles = {p.name for p in ENDPOINTS.glob("*_console.py")}
    assert consoles, "一個主控台檔案都沒找到，路徑錯了"
    assert consoles <= set(CLOSE_ACTIONS), f"沒登記的主控台：{sorted(consoles - set(CLOSE_ACTIONS))}"
