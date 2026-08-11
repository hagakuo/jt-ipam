"""AI 對話要答得出「這個 IP 有沒有對外開放、開了哪些埠」。

調查畫面本來就把 NAT 與防火牆規則湊在一起，但只有人點進去才看得到。使用者真正會問的
是一句話的問題，不該要人先知道去哪一頁、再自己讀四張表。

權限：NAT 與防火牆是全域基礎設施資料 —— 與 `list_nat` / `list_firewall_rules` 同一層。
不能因為「以 IP 為單位查」就鬆一級（這個專案在 get_topology 踩過一次）。
"""
from __future__ import annotations

from app.mcp.tools import GLOBAL_READ_TOOLS, TOOLS


def test_the_tool_is_registered_with_a_description_that_matches_how_people_ask():
    t = TOOLS["check_ip_exposure"]
    d = t["description"].lower()
    assert "exposed" in d or "reachable" in d
    assert "port" in d
    assert t["parameters"]["required"] == ["ip"]


def test_it_requires_global_read():
    """只被指派特定物件的部門帳號不該查得到全域防火牆／NAT。"""
    assert "check_ip_exposure" in GLOBAL_READ_TOOLS


def test_it_states_facts_and_does_not_pronounce_on_safety():
    """回傳要說清楚這是事實不是結論 —— 這台該不該對外，只有人知道。"""
    import inspect
    src = inspect.getsource(TOOLS["check_ip_exposure"]["fn"])
    assert "Facts only" in src
    # 不可以自己算出「安全 / 不安全」這種欄位
    assert "is_safe" not in src and "secure" not in src.lower().replace("insecure", "")
