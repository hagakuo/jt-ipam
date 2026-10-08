"""答案裡的位址必須出現在查詢結果裡（GitHub issue #34）。

兩種實際踩到的狀況：
- 工具查無結果，小模型自己編了兩個根本不在這套 IPAM 裡的位址；
- 工具有真資料，但模型在轉述時把位址抄錯（「19 198.51.100.171」）。

提示詞已經寫了「逐字照抄、不要編造」，量化過的小模型還是會犯。事實由確定性檢查把關：
答案裡的位址只要沒在任何工具結果（或使用者自己打的字）裡出現過，就標出來 ——
**不改寫模型的字**，只在後面加一行警告，讓人知道哪幾個不能採信。
"""
from __future__ import annotations

from app.services.ai import _annotate_unverified, unverified_ips


def test_flags_an_address_no_tool_returned() -> None:
    tool = '{"items": {"ip_conflicts": [{"ip": "198.51.100.7"}]}}'
    ans = "發現 198.51.100.7 與 192.0.2.15 有衝突"
    assert unverified_ips(ans, [tool]) == ["192.0.2.15"]


def test_an_address_the_user_typed_is_fine() -> None:
    ans = "192.0.2.15 沒有紀錄"
    assert unverified_ips(ans, ["{}", "請查 192.0.2.15"]) == []


def test_a_malformed_octet_is_flagged() -> None:
    """抄錯的位址不會是合法 IPv4，但照樣會被當成事實讀 —— 一樣要標出來。"""
    assert unverified_ips("見 198.51.100.777", ['{"ip": "198.51.100.7"}']) == ["198.51.100.777"]


def test_netmasks_and_wildcards_are_not_flagged() -> None:
    """/24 = 255.255.255.0 是常識、不是查來的資料，標它只會製造雜訊。"""
    ans = "遮罩是 255.255.255.0，預設路由 0.0.0.0"
    assert unverified_ips(ans, ["{}"]) == []


def test_annotation_appends_a_warning_without_touching_the_answer() -> None:
    convo = [{"role": "tool", "name": "list_anomalies", "content": '{"total": 0}'}]
    out = _annotate_unverified("偵測到 203.0.113.50 衝突", convo, "zh-TW")
    assert out.startswith("偵測到 203.0.113.50 衝突")
    assert "203.0.113.50" in out.split("\n")[-1]


def test_nothing_is_appended_when_every_address_checks_out() -> None:
    convo = [{"role": "tool", "name": "x", "content": '{"ip": "198.51.100.7"}'}]
    assert _annotate_unverified("198.51.100.7 有衝突", convo, "zh-TW") == "198.51.100.7 有衝突"
